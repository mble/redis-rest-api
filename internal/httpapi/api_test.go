package httpapi

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mble/redis-rest-api/internal/domain"
)

const testBodyLimit = 1024
const testResponseLimit = 1024

const (
	testMaxInFlight      = 8
	testMaxSubscriptions = 4
	testMaxMonitors      = 1
	testWriteTimeout     = time.Second
	testReadyCacheTTL    = time.Second
)

func TestLimiterRejectsExcess(t *testing.T) {
	limiter := newLimiter(1)
	if !limiter.acquire() {
		t.Fatal("expected first admission")
	}
	if limiter.acquire() {
		t.Fatal("expected excess rejection")
	}

	limiter.release()
	if !limiter.acquire() {
		t.Fatal("expected admission after release")
	}
	limiter.release()
}

type fakeService struct {
	token        string
	command      domain.Command
	commands     []domain.Command
	mode         domain.BatchMode
	value        any
	rawValue     []byte
	replies      []domain.Reply
	rawReplies   []domain.Reply
	err          error
	pingErr      error
	pingCalls    int
	subscription domain.Subscription
	monitor      domain.Monitor
	subMode      domain.SubscriptionMode
}

func (f *fakeService) Exec(_ context.Context, token string, command domain.Command) (any, error) {
	f.token = token
	f.command = command

	return f.value, f.err
}

func (f *fakeService) ExecRaw(_ context.Context, token string, command domain.Command) ([]byte, error) {
	f.token = token
	f.command = command

	return f.rawValue, f.err
}

func (f *fakeService) Batch(
	_ context.Context,
	token string,
	commands []domain.Command,
	mode domain.BatchMode,
) ([]domain.Reply, error) {
	f.token = token
	f.commands = commands
	f.mode = mode

	return f.replies, f.err
}

func (f *fakeService) BatchRaw(
	_ context.Context,
	token string,
	commands []domain.Command,
) ([]domain.Reply, error) {
	f.token = token
	f.commands = commands

	return f.rawReplies, f.err
}

func (f *fakeService) Ping(context.Context) error {
	f.pingCalls++

	return f.pingErr
}

func (f *fakeService) Subscribe(
	_ context.Context,
	token string,
	_ []string,
	mode domain.SubscriptionMode,
) (domain.Subscription, error) {
	f.token = token
	f.subMode = mode

	return f.subscription, f.err
}

func (f *fakeService) Monitor(_ context.Context, token string) (domain.Monitor, error) {
	f.token = token

	return f.monitor, f.err
}

func TestPathCommand(t *testing.T) {
	service := &fakeService{value: "OK"}
	request := httptest.NewRequest(http.MethodGet, "/set/a%2Fb/value?_token=secret", http.NoBody)
	response := serve(service, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected HTTP %d, got %d", http.StatusOK, response.Code)
	}
	if service.token != "secret" {
		t.Fatalf("expected query token, got %q", service.token)
	}

	want := domain.Command{"set", "a/b", "value"}
	if !reflect.DeepEqual(service.command, want) {
		t.Fatalf("expected %#v, got %#v", want, service.command)
	}
}

func TestJSONCommand(t *testing.T) {
	service := &fakeService{value: int64(1)}
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`["INCRBY", "key", 2]`))
	request.Header.Set("Authorization", "Bearer secret")
	response := serve(service, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected HTTP %d, got %d: %s", http.StatusOK, response.Code, response.Body.String())
	}

	want := domain.Command{"INCRBY", "key", int64(2)}
	if !reflect.DeepEqual(service.command, want) {
		t.Fatalf("expected %#v, got %#v", want, service.command)
	}
}

func TestPostBodyValue(t *testing.T) {
	service := &fakeService{value: "OK"}
	request := httptest.NewRequest(
		http.MethodPost,
		"/set/key?EX=60&NX&_token=secret",
		strings.NewReader("value"),
	)
	response := serve(service, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected HTTP %d, got %d: %s", http.StatusOK, response.Code, response.Body.String())
	}

	want := domain.Command{"set", "key", []byte("value"), "EX", "60", "NX"}
	if !reflect.DeepEqual(service.command, want) {
		t.Fatalf("expected %#v, got %#v", want, service.command)
	}
}

func TestBearerHeaderPrecedesQuery(t *testing.T) {
	service := &fakeService{}
	request := httptest.NewRequest(http.MethodGet, "/get/key?_token=query", http.NoBody)
	request.Header.Set("Authorization", "Bearer header")
	serve(service, request)

	if service.token != "header" {
		t.Fatalf("expected header token, got %q", service.token)
	}
}

func TestHeadHasNoBody(t *testing.T) {
	service := &fakeService{value: "value"}
	request := httptest.NewRequest(http.MethodHead, "/get/key", http.NoBody)
	response := serve(service, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected HTTP %d, got %d", http.StatusOK, response.Code)
	}
	if response.Body.Len() != 0 {
		t.Fatalf("expected empty body, got %q", response.Body.String())
	}
	if response.Header().Get("Content-Length") == "" {
		t.Fatal("expected GET-equivalent content length")
	}
}

func TestMethodNotAllowed(t *testing.T) {
	service := &fakeService{}
	request := httptest.NewRequest(http.MethodDelete, "/get/key", http.NoBody)
	response := serve(service, request)

	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected HTTP %d, got %d", http.StatusMethodNotAllowed, response.Code)
	}
	if response.Header().Get("Allow") == "" {
		t.Fatal("expected Allow header")
	}
}

func TestMalformedPipeline(t *testing.T) {
	service := &fakeService{}
	request := httptest.NewRequest(http.MethodPost, "/pipeline", strings.NewReader(`[[{"key":"value"}]]`))
	response := serve(service, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected HTTP %d, got %d", http.StatusBadRequest, response.Code)
	}
	if service.commands != nil {
		t.Fatalf("expected no service call, got %#v", service.commands)
	}
}

func TestPipelineResponse(t *testing.T) {
	service := &fakeService{
		replies: []domain.Reply{
			{Value: "value"},
			{Err: errors.New("ERR failed")},
			{Value: []any{"nested", nil}},
		},
	}
	request := httptest.NewRequest(
		http.MethodPost,
		"/pipeline",
		strings.NewReader(`[["GET","key"],["NOPE"],["MGET","a","b"]]`),
	)
	request.Header.Set(headerEncoding, "base64")
	response := serve(service, request)

	want := `[{"result":"dmFsdWU="},{"error":"ERR failed"},{"result":["bmVzdGVk",null]}]`
	if response.Code != http.StatusOK || response.Body.String() != want {
		t.Fatalf("expected HTTP %d with %s, got %d with %s", http.StatusOK, want, response.Code, response.Body.String())
	}
}

func TestRESP2Response(t *testing.T) {
	raw := []byte("*3\r\n$5\r\nvalue\r\n$-1\r\n:3\r\n")
	service := &fakeService{rawValue: raw}
	request := httptest.NewRequest(http.MethodGet, "/mget/a/b/c", http.NoBody)
	request.Header.Set(headerFormat, "resp2")
	response := serve(service, request)

	want := string(raw)
	if response.Code != http.StatusOK || response.Body.String() != want {
		t.Fatalf("expected %q, got HTTP %d with %q", want, response.Code, response.Body.String())
	}
	if response.Header().Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("unexpected content type %q", response.Header().Get("Content-Type"))
	}
}

func TestRESP2Pipeline(t *testing.T) {
	service := &fakeService{
		rawReplies: []domain.Reply{
			{Value: []byte("+OK\r\n")},
			{Err: errors.New("ERR denied\r\ninjected")},
			{Value: []byte("$5\r\nvalue\r\n")},
		},
	}
	request := httptest.NewRequest(http.MethodPost, "/pipeline", strings.NewReader(`[["SET","key","value"],["NOPE"],["GET","key"]]`))
	request.Header.Set(headerFormat, "resp2")
	response := serve(service, request)

	want := "+OK\r\n-ERR deniedinjected\r\n$5\r\nvalue\r\n"
	if response.Code != http.StatusOK || response.Body.String() != want {
		t.Fatalf("expected %q, got HTTP %d with %q", want, response.Code, response.Body.String())
	}
}

func TestRESP2RedisError(t *testing.T) {
	service := &fakeService{rawValue: []byte("-ERR failed\r\n")}
	request := httptest.NewRequest(http.MethodGet, "/get/key/extra", http.NoBody)
	request.Header.Set(headerFormat, "resp2")
	response := serve(service, request)

	if response.Code != http.StatusBadRequest || response.Body.String() != "-ERR failed\r\n" {
		t.Fatalf("unexpected response: HTTP %d with %q", response.Code, response.Body.String())
	}
}

func TestInvalidResponseOptions(t *testing.T) {
	tests := []struct {
		name     string
		format   string
		encoding string
	}{
		{name: "format", format: "xml"},
		{name: "encoding", encoding: "hex"},
		{name: "combined", format: "resp2", encoding: "base64"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/get/key", http.NoBody)
			request.Header.Set(headerFormat, test.format)
			request.Header.Set(headerEncoding, test.encoding)
			response := serve(&fakeService{}, request)

			if response.Code != http.StatusBadRequest {
				t.Fatalf("expected HTTP %d, got %d", http.StatusBadRequest, response.Code)
			}
		})
	}
}

func TestTransactionRejectsRESP2(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/multi-exec", strings.NewReader(`[["PING"]]`))
	request.Header.Set(headerFormat, "resp2")
	response := serve(&fakeService{}, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected HTTP %d, got %d", http.StatusBadRequest, response.Code)
	}
}

func TestBodyLimit(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`["PING","too large"]`))
	response := serveWithLimit(&fakeService{}, request, 8)

	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "exceeds") {
		t.Fatalf("expected body limit error, got HTTP %d with %s", response.Code, response.Body.String())
	}
}

func TestJSONResponseLimit(t *testing.T) {
	service := &fakeService{value: strings.Repeat("x", testResponseLimit+1)}
	request := httptest.NewRequest(http.MethodGet, "/get/key", http.NoBody)
	response := serve(service, request)

	if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "exceeds") {
		t.Fatalf("expected response limit error, got HTTP %d with %s", response.Code, response.Body.String())
	}
}

func TestRESP2ResponseLimit(t *testing.T) {
	service := &fakeService{rawValue: make([]byte, testResponseLimit+1)}
	request := httptest.NewRequest(http.MethodGet, "/get/key", http.NoBody)
	request.Header.Set(headerFormat, "resp2")
	response := serve(service, request)

	if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "exceeds") {
		t.Fatalf("expected response limit error, got HTTP %d with %s", response.Code, response.Body.String())
	}
}

func TestAuthenticationError(t *testing.T) {
	service := &fakeService{err: domain.ErrUnauthorized}
	request := httptest.NewRequest(http.MethodGet, "/get/key", http.NoBody)
	response := serve(service, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected HTTP %d, got %d", http.StatusUnauthorized, response.Code)
	}
}

func TestHealth(t *testing.T) {
	live := serve(&fakeService{}, httptest.NewRequest(http.MethodGet, "/livez", http.NoBody))
	if live.Code != http.StatusOK {
		t.Fatalf("expected live HTTP %d, got %d", http.StatusOK, live.Code)
	}

	ready := serve(
		&fakeService{pingErr: domain.ErrUnavailable},
		httptest.NewRequest(http.MethodGet, "/readyz", http.NoBody),
	)
	if ready.Code != http.StatusInternalServerError {
		t.Fatalf("expected ready HTTP %d, got %d", http.StatusInternalServerError, ready.Code)
	}
}

func TestReadinessCachesRedisPing(t *testing.T) {
	service := &fakeService{}
	handler := newTestHandler(service, testBodyLimit)
	for range 2 {
		request := httptest.NewRequest(http.MethodGet, "/readyz", http.NoBody)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("expected HTTP %d, got %d", http.StatusOK, response.Code)
		}
	}

	if service.pingCalls != 1 {
		t.Fatalf("expected one Redis ping, got %d", service.pingCalls)
	}
}

func TestSubscribeSSE(t *testing.T) {
	events := make(chan domain.Event, 1)
	events <- domain.Event{Kind: "message", Channel: "chat", Payload: "hello"}
	close(events)
	stream := &fakeSubscription{events: events, errors: make(chan error)}
	service := &fakeService{subscription: stream}
	request := httptest.NewRequest(http.MethodPost, "/subscribe/chat", http.NoBody)
	request.Header.Set("Accept", sseMediaType)
	request.Header.Set("Authorization", "Bearer secret")
	response := serve(service, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected HTTP %d, got %d", http.StatusOK, response.Code)
	}
	if response.Body.String() != "data: message,chat,hello\n\n" {
		t.Fatalf("unexpected SSE body %q", response.Body.String())
	}
	if !stream.closed {
		t.Fatal("expected subscription close")
	}
	if service.subMode != domain.SubscriptionChannel {
		t.Fatalf("unexpected subscription mode %d", service.subMode)
	}
}

func TestPSubscribeSSE(t *testing.T) {
	events := make(chan domain.Event, 1)
	events <- domain.Event{
		Kind:    "pmessage",
		Pattern: "news:*",
		Channel: "news:one",
		Payload: "hello",
	}
	close(events)
	stream := &fakeSubscription{events: events, errors: make(chan error)}
	service := &fakeService{subscription: stream}
	request := httptest.NewRequest(http.MethodPost, "/psubscribe/news:*", http.NoBody)
	request.Header.Set("Accept", sseMediaType)
	response := serve(service, request)

	want := "data: pmessage,news:*,news:one,hello\n\n"
	if response.Code != http.StatusOK || response.Body.String() != want {
		t.Fatalf("expected %q, got HTTP %d with %q", want, response.Code, response.Body.String())
	}
	if !stream.closed {
		t.Fatal("expected subscription close")
	}
	if service.subMode != domain.SubscriptionPattern {
		t.Fatalf("unexpected subscription mode %d", service.subMode)
	}
}

func TestMonitorSSE(t *testing.T) {
	lines := make(chan string, 1)
	lines <- `1.0 [0 client] "PING"`
	close(lines)
	stream := &fakeMonitor{lines: lines, errors: make(chan error)}
	request := httptest.NewRequest(http.MethodPost, "/monitor", http.NoBody)
	request.Header.Set("Accept", sseMediaType)
	response := serve(&fakeService{monitor: stream}, request)

	want := "data: \"OK\"\n\ndata: 1.0 [0 client] \"PING\"\n\n"
	if response.Code != http.StatusOK || response.Body.String() != want {
		t.Fatalf("expected %q, got HTTP %d with %q", want, response.Code, response.Body.String())
	}
	if !stream.closed {
		t.Fatal("expected monitor close")
	}
}

func TestStreamSetsPerWriteDeadline(t *testing.T) {
	writer := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	if err := writeStream(writer, "event", testWriteTimeout); err != nil {
		t.Fatal(err)
	}

	if len(writer.deadlines) != 2 {
		t.Fatalf("expected deadline and reset, got %d updates", len(writer.deadlines))
	}
	if writer.deadlines[0].IsZero() || !writer.deadlines[1].IsZero() {
		t.Fatalf("unexpected deadline updates: %v", writer.deadlines)
	}
}

type deadlineRecorder struct {
	*httptest.ResponseRecorder
	deadlines []time.Time
}

func (d *deadlineRecorder) SetWriteDeadline(deadline time.Time) error {
	d.deadlines = append(d.deadlines, deadline)

	return nil
}

type fakeSubscription struct {
	events <-chan domain.Event
	errors <-chan error
	closed bool
}

func (f *fakeSubscription) Events() <-chan domain.Event {
	return f.events
}

func (f *fakeSubscription) Errors() <-chan error {
	return f.errors
}

func (f *fakeSubscription) Close() error {
	f.closed = true

	return nil
}

type fakeMonitor struct {
	lines  <-chan string
	errors <-chan error
	closed bool
}

func (f *fakeMonitor) Lines() <-chan string {
	return f.lines
}

func (f *fakeMonitor) Errors() <-chan error {
	return f.errors
}

func (f *fakeMonitor) Close() error {
	f.closed = true

	return nil
}

func serve(service Service, request *http.Request) *httptest.ResponseRecorder {
	return serveWithLimit(service, request, testBodyLimit)
}

func serveWithLimit(service Service, request *http.Request, limit int64) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	newTestHandler(service, limit).ServeHTTP(response, request)

	return response
}

func newTestHandler(service Service, limit int64) *Handler {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	return New(service, logger, Options{
		MaxBody:          limit,
		MaxResponse:      testResponseLimit,
		MaxInFlight:      testMaxInFlight,
		MaxSubscriptions: testMaxSubscriptions,
		MaxMonitors:      testMaxMonitors,
		WriteTimeout:     testWriteTimeout,
		ReadyCacheTTL:    testReadyCacheTTL,
	})
}
