package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mble/redis-rest-api/internal/domain"
)

type responseFormat uint8

const (
	formatJSON responseFormat = iota
	formatRESP2
)

type stringEncoding uint8

const (
	encodingPlain stringEncoding = iota
	encodingBase64
)

type responseOptions struct {
	format   responseFormat
	encoding stringEncoding
}

type resultResponse struct {
	Result any `json:"result"`
}

type errorResponse struct {
	Error string `json:"error"`
}

type statusResponse struct {
	Status string `json:"status"`
}

const (
	maxResponseDepth    = 128
	encodedNumberBytes  = 32
	respErrorFrameBytes = len("-\r\n")
)

var errResponseLimit = errors.New("response exceeds maximum size")

func parseOptions(request *http.Request) (responseOptions, error) {
	options := responseOptions{}

	switch strings.ToLower(strings.TrimSpace(request.Header.Get(headerFormat))) {
	case "", "json":
		options.format = formatJSON
	case "resp2":
		options.format = formatRESP2
	default:
		return responseOptions{}, fmt.Errorf("invalid %s header", headerFormat)
	}

	switch strings.ToLower(strings.TrimSpace(request.Header.Get(headerEncoding))) {
	case "":
		options.encoding = encodingPlain
	case "base64":
		options.encoding = encodingBase64
	default:
		return responseOptions{}, fmt.Errorf("invalid %s header", headerEncoding)
	}

	if options.format == formatRESP2 && options.encoding == encodingBase64 {
		return responseOptions{}, fmt.Errorf("%s cannot be combined with RESP2", headerEncoding)
	}

	return options, nil
}

func normalize(value any, encoding stringEncoding, limit int64) (any, error) {
	budget := responseBudget{remaining: limit}

	return normalizeBudget(value, encoding, &budget)
}

func normalizeBudget(value any, encoding stringEncoding, budget *responseBudget) (any, error) {
	return normalizeValue(value, encoding, budget, 0)
}

type responseBudget struct {
	remaining int64
}

func (b *responseBudget) use(size int) error {
	if size < 0 || int64(size) > b.remaining {
		return errResponseLimit
	}

	b.remaining -= int64(size)

	return nil
}

func normalizeValue(value any, encoding stringEncoding, budget *responseBudget, depth int) (any, error) {
	if depth > maxResponseDepth {
		return nil, errors.New("redis response nesting is too deep")
	}

	switch typed := value.(type) {
	case nil:
		return keepValue(nil, len("null"), budget)
	case string:
		return normalizeString(typed, encoding, budget)
	case []byte:
		return normalizeBytes(typed, encoding, budget)
	case int, int8, int16, int32, int64:
		return keepValue(typed, encodedNumberBytes, budget)
	case uint, uint8, uint16, uint32, uint64:
		return keepValue(typed, encodedNumberBytes, budget)
	case float32, float64, bool:
		return keepValue(typed, encodedNumberBytes, budget)
	case []string:
		return normalizeStrings(typed, encoding, budget, depth+1)
	case []any:
		return normalizeSlice(typed, encoding, budget, depth+1)
	case map[string]any:
		values := make(map[string]any, len(typed))
		for key, item := range typed {
			if err := budget.use(len(key)); err != nil {
				return nil, err
			}

			normalized, err := normalizeValue(item, encoding, budget, depth+1)
			if err != nil {
				return nil, err
			}

			values[key] = normalized
		}

		return values, nil
	default:
		return nil, fmt.Errorf("unsupported Redis response type %T", value)
	}
}

func normalizeString(value string, encoding stringEncoding, budget *responseBudget) (any, error) {
	if encoding != encodingBase64 || value == "OK" {
		return keepValue(value, len(value), budget)
	}

	size := base64.StdEncoding.EncodedLen(len(value))
	if err := budget.use(size); err != nil {
		return nil, err
	}

	return base64.StdEncoding.EncodeToString([]byte(value)), nil
}

func normalizeBytes(value []byte, encoding stringEncoding, budget *responseBudget) (any, error) {
	if encoding != encodingBase64 {
		if err := budget.use(len(value)); err != nil {
			return nil, err
		}

		return string(value), nil
	}

	size := base64.StdEncoding.EncodedLen(len(value))
	if err := budget.use(size); err != nil {
		return nil, err
	}

	return base64.StdEncoding.EncodeToString(value), nil
}

func keepValue(value any, size int, budget *responseBudget) (any, error) {
	if err := budget.use(size); err != nil {
		return nil, err
	}

	return value, nil
}

func normalizeStrings(
	values []string,
	encoding stringEncoding,
	budget *responseBudget,
	depth int,
) ([]any, error) {
	normalized := make([]any, len(values))
	for index, value := range values {
		item, err := normalizeValue(value, encoding, budget, depth)
		if err != nil {
			return nil, err
		}

		normalized[index] = item
	}

	return normalized, nil
}

func normalizeSlice(
	values []any,
	encoding stringEncoding,
	budget *responseBudget,
	depth int,
) ([]any, error) {
	normalized := make([]any, len(values))
	for index, value := range values {
		item, err := normalizeValue(value, encoding, budget, depth)
		if err != nil {
			return nil, err
		}

		normalized[index] = item
	}

	return normalized, nil
}

func writeJSON(writer http.ResponseWriter, request *http.Request, status int, value any) {
	body, err := json.Marshal(value)
	if err != nil {
		status = http.StatusInternalServerError
		body = []byte(`{"error":"encode response"}`)
	}

	writeBody(writer, request, status, "application/json", body)
}

func writeBoundJSON(
	writer http.ResponseWriter,
	request *http.Request,
	status int,
	value any,
	limit int64,
) {
	body, err := json.Marshal(value)
	if err != nil {
		writeError(writer, request, http.StatusInternalServerError, "encode response")

		return
	}
	if int64(len(body)) > limit {
		writeError(writer, request, http.StatusBadGateway, errResponseLimit.Error())

		return
	}

	writeBody(writer, request, status, "application/json", body)
}

func writeBody(
	writer http.ResponseWriter,
	request *http.Request,
	status int,
	contentType string,
	body []byte,
) {
	writer.Header().Set("Content-Type", contentType)
	writer.Header().Set("Content-Length", strconv.Itoa(len(body)))
	writer.WriteHeader(status)

	if request.Method == http.MethodHead {
		return
	}

	_, _ = writer.Write(body)
}

func writeError(writer http.ResponseWriter, request *http.Request, status int, message string) {
	writeJSON(writer, request, status, errorResponse{Error: message})
}

func writeRawRESP2(
	writer http.ResponseWriter,
	request *http.Request,
	status int,
	replies []domain.Reply,
	limit int64,
) {
	size, err := rawSize(replies, limit)
	if err != nil {
		writeEncodeError(writer, request, err)

		return
	}

	writer.Header().Set("Content-Type", "application/octet-stream")
	writer.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	writer.WriteHeader(status)

	if request.Method == http.MethodHead {
		return
	}

	for _, reply := range replies {
		if reply.Err != nil {
			_, _ = fmt.Fprintf(writer, "-%s\r\n", respError(cleanError(reply.Err)))
			continue
		}

		raw, _ := reply.Value.([]byte)
		_, _ = writer.Write(raw)
	}
}

func rawSize(replies []domain.Reply, limit int64) (int64, error) {
	budget := responseBudget{remaining: limit}
	for _, reply := range replies {
		if reply.Err != nil {
			size := len(respError(cleanError(reply.Err))) + respErrorFrameBytes
			if err := budget.use(size); err != nil {
				return 0, err
			}

			continue
		}

		raw, ok := reply.Value.([]byte)
		if !ok {
			return 0, errors.New("invalid raw Redis response")
		}
		if err := budget.use(len(raw)); err != nil {
			return 0, err
		}
	}

	return limit - budget.remaining, nil
}

func writeEncodeError(writer http.ResponseWriter, request *http.Request, err error) {
	status := http.StatusInternalServerError
	if errors.Is(err, errResponseLimit) {
		status = http.StatusBadGateway
	}

	writeError(writer, request, status, err.Error())
}

func respError(message string) string {
	message = strings.ReplaceAll(message, "\r", "")
	message = strings.ReplaceAll(message, "\n", "")

	return message
}

func writeSSE(writer io.Writer, value string) error {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")

	for _, line := range strings.Split(value, "\n") {
		if _, err := fmt.Fprintf(writer, "data: %s\n", line); err != nil {
			return err
		}
	}

	_, err := io.WriteString(writer, "\n")

	return err
}

func openStream(writer http.ResponseWriter) error {
	controller := http.NewResponseController(writer)
	if err := controller.Flush(); err != nil {
		return err
	}

	return setDeadline(controller, time.Time{})
}

func writeStream(writer http.ResponseWriter, value string, timeout time.Duration) error {
	controller := http.NewResponseController(writer)
	if err := setDeadline(controller, time.Now().Add(timeout)); err != nil {
		return err
	}
	defer func() {
		_ = setDeadline(controller, time.Time{})
	}()

	if err := writeSSE(writer, value); err != nil {
		return err
	}

	return controller.Flush()
}

func setDeadline(controller *http.ResponseController, deadline time.Time) error {
	err := controller.SetWriteDeadline(deadline)
	if errors.Is(err, http.ErrNotSupported) {
		return nil
	}

	return err
}
