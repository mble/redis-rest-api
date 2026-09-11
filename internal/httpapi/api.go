package httpapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/mble/redis-rest-api/internal/domain"
)

const (
	headerEncoding = "Upstash-Encoding"
	headerFormat   = "Upstash-Response-Format"
	sseMediaType   = "text/event-stream"
	mediaTypeParts = 2
)

var allowedMethods = map[string]struct{}{
	http.MethodGet:  {},
	http.MethodHead: {},
	http.MethodPost: {},
	http.MethodPut:  {},
}

type Service interface {
	Exec(context.Context, string, domain.Command) (any, error)
	ExecRaw(context.Context, string, domain.Command) ([]byte, error)
	Batch(context.Context, string, []domain.Command, domain.BatchMode) ([]domain.Reply, error)
	BatchRaw(context.Context, string, []domain.Command) ([]domain.Reply, error)
	Ping(context.Context) error
	Subscribe(context.Context, string, []string, domain.SubscriptionMode) (domain.Subscription, error)
	Monitor(context.Context, string) (domain.Monitor, error)
}

type Handler struct {
	service       Service
	logger        *slog.Logger
	maxBody       int64
	maxResponse   int64
	requests      limiter
	subscriptions limiter
	monitors      limiter
	writeTimeout  time.Duration
	readiness     readyCache
}

type Options struct {
	MaxBody          int64
	MaxResponse      int64
	MaxInFlight      int
	MaxSubscriptions int
	MaxMonitors      int
	WriteTimeout     time.Duration
	ReadyCacheTTL    time.Duration
}

func New(service Service, logger *slog.Logger, options Options) *Handler {
	return &Handler{
		service:       service,
		logger:        logger,
		maxBody:       options.MaxBody,
		maxResponse:   options.MaxResponse,
		requests:      newLimiter(options.MaxInFlight),
		subscriptions: newLimiter(options.MaxSubscriptions),
		monitors:      newLimiter(options.MaxMonitors),
		writeTimeout:  options.WriteTimeout,
		readiness:     readyCache{ttl: options.ReadyCacheTTL},
	}
}

type limiter chan struct{}

type readyCache struct {
	mu    sync.Mutex
	ttl   time.Duration
	until time.Time
	err   error
}

func (c *readyCache) ping(ctx context.Context, service Service) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	if now.Before(c.until) {
		return c.err
	}

	c.err = service.Ping(ctx)
	c.until = time.Now().Add(c.ttl)

	return c.err
}

func newLimiter(size int) limiter {
	return make(limiter, size)
}

func (l limiter) acquire() bool {
	select {
	case l <- struct{}{}:
		return true
	default:
		return false
	}
}

func (l limiter) release() {
	<-l
}

func (h *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if _, ok := allowedMethods[request.Method]; !ok {
		writer.Header().Set("Allow", "GET, HEAD, POST, PUT")
		writeError(writer, request, http.StatusMethodNotAllowed, "method not allowed")

		return
	}

	switch request.URL.Path {
	case "/livez":
		h.live(writer, request)
	case "/readyz":
		h.ready(writer, request)
	case "/pipeline":
		h.batch(writer, request, domain.BatchPipeline)
	case "/multi-exec":
		h.batch(writer, request, domain.BatchTransaction)
	case "/monitor":
		h.monitor(writer, request)
	default:
		if request.URL.Path == "/subscribe" || strings.HasPrefix(request.URL.Path, "/subscribe/") {
			h.subscribe(writer, request, domain.SubscriptionChannel)
			return
		}
		if request.URL.Path == "/psubscribe" || strings.HasPrefix(request.URL.Path, "/psubscribe/") {
			h.subscribe(writer, request, domain.SubscriptionPattern)
			return
		}

		h.command(writer, request)
	}
}

func (h *Handler) live(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		writeError(writer, request, http.StatusBadRequest, "health endpoint requires GET or HEAD")

		return
	}

	writeJSON(writer, request, http.StatusOK, statusResponse{Status: "ok"})
}

func (h *Handler) ready(writer http.ResponseWriter, request *http.Request) {
	if !h.admit(writer, request, h.requests, "request") {
		return
	}
	defer h.requests.release()

	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		writeError(writer, request, http.StatusBadRequest, "health endpoint requires GET or HEAD")

		return
	}

	if err := h.readiness.ping(request.Context(), h.service); err != nil {
		writeServiceError(writer, request, err)

		return
	}

	writeJSON(writer, request, http.StatusOK, statusResponse{Status: "ok"})
}

func (h *Handler) command(writer http.ResponseWriter, request *http.Request) {
	if !h.admit(writer, request, h.requests, "request") {
		return
	}
	defer h.requests.release()

	options, err := parseOptions(request)
	if err != nil {
		writeError(writer, request, http.StatusBadRequest, err.Error())

		return
	}

	command, err := parseCommand(request, h.maxBody)
	if err != nil {
		writeServiceError(writer, request, err)

		return
	}

	if options.format == formatRESP2 {
		value, rawErr := h.service.ExecRaw(request.Context(), requestToken(request), command)
		if rawErr != nil {
			writeServiceError(writer, request, rawErr)

			return
		}

		status := http.StatusOK
		if len(value) > 0 && value[0] == '-' {
			status = http.StatusBadRequest
		}

		writeRawRESP2(writer, request, status, []domain.Reply{{Value: value}}, h.maxResponse)

		return
	}

	value, err := h.service.Exec(request.Context(), requestToken(request), command)
	if err != nil {
		writeServiceError(writer, request, err)

		return
	}

	value, err = normalize(value, options.encoding, h.maxResponse)
	if err != nil {
		writeEncodeError(writer, request, err)

		return
	}

	writeBoundJSON(writer, request, http.StatusOK, resultResponse{Result: value}, h.maxResponse)
}

func (h *Handler) batch(writer http.ResponseWriter, request *http.Request, mode domain.BatchMode) {
	if !h.admit(writer, request, h.requests, "request") {
		return
	}
	defer h.requests.release()

	if request.Method != http.MethodPost && request.Method != http.MethodPut {
		writeError(writer, request, http.StatusBadRequest, "batch endpoint requires POST or PUT")

		return
	}

	options, err := parseOptions(request)
	if err != nil {
		writeError(writer, request, http.StatusBadRequest, err.Error())

		return
	}

	if mode == domain.BatchTransaction && options.format == formatRESP2 {
		writeError(writer, request, http.StatusBadRequest, "RESP2 is not supported for transactions")

		return
	}

	commands, err := parseCommands(request.Body, h.maxBody)
	if err != nil {
		writeServiceError(writer, request, err)

		return
	}

	var replies []domain.Reply
	if options.format == formatRESP2 {
		replies, err = h.service.BatchRaw(request.Context(), requestToken(request), commands)
	} else {
		replies, err = h.service.Batch(request.Context(), requestToken(request), commands, mode)
	}
	if err != nil {
		writeServiceError(writer, request, err)

		return
	}

	if options.format == formatRESP2 {
		writeRawRESP2(writer, request, http.StatusOK, replies, h.maxResponse)

		return
	}

	response := make([]any, len(replies))
	budget := responseBudget{remaining: h.maxResponse}
	for index, reply := range replies {
		if reply.Err != nil {
			response[index] = errorResponse{Error: cleanError(reply.Err)}
			continue
		}

		value, normalizeErr := normalizeBudget(reply.Value, options.encoding, &budget)
		if normalizeErr != nil {
			writeEncodeError(writer, request, normalizeErr)

			return
		}

		response[index] = resultResponse{Result: value}
	}

	writeBoundJSON(writer, request, http.StatusOK, response, h.maxResponse)
}

func (h *Handler) subscribe(
	writer http.ResponseWriter,
	request *http.Request,
	mode domain.SubscriptionMode,
) {
	if !h.admit(writer, request, h.subscriptions, "subscription") {
		return
	}
	defer h.subscriptions.release()

	if request.Method == http.MethodHead {
		writeError(writer, request, http.StatusBadRequest, "subscription requires a response body")

		return
	}

	if !acceptsSSE(request) {
		writeError(writer, request, http.StatusBadRequest, "subscription requires Accept: text/event-stream")

		return
	}

	command, err := parsePath(request.URL.EscapedPath())
	if err != nil || len(command) < 2 {
		writeError(writer, request, http.StatusBadRequest, "SUBSCRIBE requires a channel")

		return
	}

	channels := make([]string, len(command)-1)
	for index, raw := range command[1:] {
		channel, ok := raw.(string)
		if !ok {
			writeError(writer, request, http.StatusBadRequest, "channel must be a string")

			return
		}

		channels[index] = channel
	}

	stream, err := h.service.Subscribe(request.Context(), requestToken(request), channels, mode)
	if err != nil {
		writeServiceError(writer, request, err)

		return
	}
	defer closeStream(h.logger, stream)

	writer.Header().Set("Cache-Control", "no-cache")
	writer.Header().Set("Content-Type", sseMediaType)
	writer.Header().Set("X-Accel-Buffering", "no")
	writer.WriteHeader(http.StatusOK)

	if err := openStream(writer); err != nil {
		h.logger.Error("response writer cannot flush SSE")

		return
	}

	h.writeEvents(writer, request, stream)
}

func (h *Handler) monitor(writer http.ResponseWriter, request *http.Request) {
	if !h.admit(writer, request, h.monitors, "monitor") {
		return
	}
	defer h.monitors.release()

	if request.Method == http.MethodHead {
		writeError(writer, request, http.StatusBadRequest, "monitor requires a response body")

		return
	}

	if !acceptsSSE(request) {
		writeError(writer, request, http.StatusBadRequest, "monitor requires Accept: text/event-stream")

		return
	}

	stream, err := h.service.Monitor(request.Context(), requestToken(request))
	if err != nil {
		writeServiceError(writer, request, err)

		return
	}
	defer closeMonitor(h.logger, stream)

	writer.Header().Set("Cache-Control", "no-cache")
	writer.Header().Set("Content-Type", sseMediaType)
	writer.Header().Set("X-Accel-Buffering", "no")
	writer.WriteHeader(http.StatusOK)

	if err := openStream(writer); err != nil {
		h.logger.Error("response writer cannot flush SSE")

		return
	}

	if err := writeStream(writer, `"OK"`, h.writeTimeout); err != nil {
		return
	}

	h.writeMonitor(writer, request, stream)
}

func (h *Handler) admit(
	writer http.ResponseWriter,
	request *http.Request,
	limit limiter,
	resource string,
) bool {
	if limit.acquire() {
		return true
	}

	writeError(writer, request, http.StatusTooManyRequests, resource+" capacity exceeded")

	return false
}

func (h *Handler) writeEvents(
	writer http.ResponseWriter,
	request *http.Request,
	stream domain.Subscription,
) {
	for {
		select {
		case event, ok := <-stream.Events():
			if !ok {
				return
			}

			if err := writeStream(writer, formatEvent(event), h.writeTimeout); err != nil {
				return
			}
		case err, ok := <-stream.Errors():
			if ok && err != nil {
				h.logger.Warn("subscription ended", "error", err)
			}

			return
		case <-request.Context().Done():
			return
		}
	}
}

func (h *Handler) writeMonitor(
	writer http.ResponseWriter,
	request *http.Request,
	stream domain.Monitor,
) {
	for {
		select {
		case line, ok := <-stream.Lines():
			if !ok {
				return
			}

			if err := writeStream(writer, line, h.writeTimeout); err != nil {
				return
			}
		case err, ok := <-stream.Errors():
			if ok && err != nil {
				h.logger.Warn("monitor ended", "error", err)
			}

			return
		case <-request.Context().Done():
			return
		}
	}
}

func writeServiceError(writer http.ResponseWriter, request *http.Request, err error) {
	status := http.StatusBadRequest

	switch {
	case errors.Is(err, domain.ErrUnauthorized):
		status = http.StatusUnauthorized
	case errors.Is(err, domain.ErrUnavailable):
		status = http.StatusInternalServerError
	}

	writeError(writer, request, status, cleanError(err))
}

func cleanError(err error) string {
	message := err.Error()
	message = strings.TrimPrefix(message, domain.ErrInvalid.Error()+": ")
	message = strings.TrimPrefix(message, domain.ErrUnavailable.Error()+": ")

	return message
}

func acceptsSSE(request *http.Request) bool {
	for _, value := range strings.Split(request.Header.Get("Accept"), ",") {
		mediaType := strings.TrimSpace(strings.SplitN(value, ";", mediaTypeParts)[0])
		if mediaType == sseMediaType || mediaType == "*/*" {
			return true
		}
	}

	return false
}

func formatEvent(event domain.Event) string {
	if event.Kind == "message" {
		return strings.Join([]string{event.Kind, event.Channel, event.Payload}, ",")
	}
	if event.Kind == "pmessage" {
		return strings.Join([]string{event.Kind, event.Pattern, event.Channel, event.Payload}, ",")
	}

	return fmt.Sprintf("%s,%s,%d", event.Kind, event.Channel, event.Count)
}

func closeStream(logger *slog.Logger, stream domain.Subscription) {
	if err := stream.Close(); err != nil {
		logger.Debug("close subscription", "error", err)
	}
}

func closeMonitor(logger *slog.Logger, stream domain.Monitor) {
	if err := stream.Close(); err != nil {
		logger.Debug("close monitor", "error", err)
	}
}
