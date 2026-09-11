package integration_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mble/redis-rest-api/internal/domain"
	"github.com/mble/redis-rest-api/internal/httpapi"
	"github.com/mble/redis-rest-api/internal/redisdb"
	"github.com/mble/redis-rest-api/internal/service"
	"github.com/mble/redis-rest-api/internal/token"
	"github.com/redis/go-redis/v9"
)

const (
	testRedisEnv = "TEST_REDIS_URL"
	testToken    = "integration-token"
	testReadOnly = "integration-read-token"
	testBodyMax  = 1 << 20
	streamWait   = 5 * time.Second
)

func TestHTTPCompatibility(t *testing.T) {
	store, handler := newStack(t)
	defer closeStore(t, store)

	key := "redis-rest-api:integration:key"
	defer deleteKey(t, store, key)

	tests := []struct {
		name       string
		method     string
		path       string
		body       string
		token      string
		headers    map[string]string
		wantStatus int
		wantBody   string
	}{
		{
			name:       "set path",
			method:     http.MethodGet,
			path:       "/set/" + key + "/value",
			token:      testToken,
			wantStatus: http.StatusOK,
			wantBody:   `{"result":"OK"}`,
		},
		{
			name:       "get base64",
			method:     http.MethodGet,
			path:       "/get/" + key,
			token:      testToken,
			headers:    map[string]string{"Upstash-Encoding": "base64"},
			wantStatus: http.StatusOK,
			wantBody:   `{"result":"dmFsdWU="}`,
		},
		{
			name:       "post body value",
			method:     http.MethodPost,
			path:       "/set/" + key + "?EX=60",
			body:       "body/value",
			token:      testToken,
			wantStatus: http.StatusOK,
			wantBody:   `{"result":"OK"}`,
		},
		{
			name:       "get posted value",
			method:     http.MethodGet,
			path:       "/get/" + key,
			token:      testToken,
			wantStatus: http.StatusOK,
			wantBody:   `{"result":"body/value"}`,
		},
		{
			name:       "readonly write",
			method:     http.MethodGet,
			path:       "/set/" + key + "/denied",
			token:      testReadOnly,
			wantStatus: http.StatusBadRequest,
			wantBody:   `{"error":"NOPERM this user has no permissions to run the 'set' command"}`,
		},
		{
			name:       "readonly ping",
			method:     http.MethodGet,
			path:       "/ping",
			token:      testReadOnly,
			wantStatus: http.StatusOK,
			wantBody:   `{"result":"PONG"}`,
		},
		{
			name:       "unsafe server command",
			method:     http.MethodGet,
			path:       "/shutdown",
			token:      testToken,
			wantStatus: http.StatusBadRequest,
			wantBody:   `{"error":"ERR command 'shutdown' is not supported"}`,
		},
		{
			name:       "RESP2",
			method:     http.MethodGet,
			path:       "/get/" + key,
			token:      testToken,
			headers:    map[string]string{"Upstash-Response-Format": "resp2"},
			wantStatus: http.StatusOK,
			wantBody:   "$10\r\nbody/value\r\n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
			request.Header.Set("Authorization", "Bearer "+test.token)
			for key, value := range test.headers {
				request.Header.Set(key, value)
			}

			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)

			if response.Code != test.wantStatus || response.Body.String() != test.wantBody {
				t.Fatalf(
					"expected HTTP %d with %q, got %d with %q",
					test.wantStatus,
					test.wantBody,
					response.Code,
					response.Body.String(),
				)
			}
		})
	}

	t.Run("pipeline retains errors", func(t *testing.T) {
		body := `[["SET","` + key + `","value"],["INCR","` + key + `"],["GET","` + key + `"]]`
		response := runBatch(handler, "/pipeline", body)
		want := `[{"result":"OK"},{"error":"ERR value is not an integer or out of range"},{"result":"value"}]`

		if response.Code != http.StatusOK || response.Body.String() != want {
			t.Fatalf("expected %q, got HTTP %d with %q", want, response.Code, response.Body.String())
		}
	})

	t.Run("transaction continues after runtime error", func(t *testing.T) {
		body := `[["SET","` + key + `","value"],["INCR","` + key + `"],["GET","` + key + `"]]`
		response := runBatch(handler, "/multi-exec", body)
		want := `[{"result":"OK"},{"error":"ERR value is not an integer or out of range"},{"result":"value"}]`

		if response.Code != http.StatusOK || response.Body.String() != want {
			t.Fatalf("expected %q, got HTTP %d with %q", want, response.Code, response.Body.String())
		}
	})

	t.Run("RESP2 pipeline", func(t *testing.T) {
		body := `[["SET","` + key + `","value"],["GET","` + key + `"]]`
		request := httptest.NewRequest(http.MethodPost, "/pipeline", strings.NewReader(body))
		request.Header.Set("Authorization", "Bearer "+testToken)
		request.Header.Set("Upstash-Response-Format", "resp2")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)

		want := "+OK\r\n$5\r\nvalue\r\n"
		if response.Code != http.StatusOK || response.Body.String() != want {
			t.Fatalf("expected %q, got HTTP %d with %q", want, response.Code, response.Body.String())
		}
	})

	t.Run("command metadata", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "/command/count", http.NoBody)
		request.Header.Set("Authorization", "Bearer "+testToken)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)

		if response.Code != http.StatusOK || !strings.HasPrefix(response.Body.String(), `{"result":`) {
			t.Fatalf("unexpected response: HTTP %d with %q", response.Code, response.Body.String())
		}
	})
}

func TestStreams(t *testing.T) {
	store, _ := newStack(t)
	defer closeStore(t, store)

	ctx, cancel := context.WithTimeout(t.Context(), streamWait)
	defer cancel()

	channel := "redis-rest-api:integration:channel"
	subscription, err := store.Subscribe(ctx, []string{channel}, domain.SubscriptionChannel)
	if err != nil {
		t.Fatal(err)
	}
	defer closeSubscription(t, subscription)

	waitForEvent(t, ctx, subscription, "subscribe")
	if _, publishErr := store.Exec(ctx, domain.Command{"PUBLISH", channel, "message"}); publishErr != nil {
		t.Fatal(publishErr)
	}

	event := waitForEvent(t, ctx, subscription, "message")
	if event.Channel != channel || event.Payload != "message" {
		t.Fatalf("unexpected message: %#v", event)
	}

	pattern := "redis-rest-api:integration:*"
	patternStream, err := store.Subscribe(ctx, []string{pattern}, domain.SubscriptionPattern)
	if err != nil {
		t.Fatal(err)
	}
	defer closeSubscription(t, patternStream)

	waitForEvent(t, ctx, patternStream, "psubscribe")
	if _, publishErr := store.Exec(ctx, domain.Command{"PUBLISH", channel, "pattern"}); publishErr != nil {
		t.Fatal(publishErr)
	}

	patternEvent := waitForEvent(t, ctx, patternStream, "pmessage")
	if patternEvent.Pattern != pattern || patternEvent.Channel != channel || patternEvent.Payload != "pattern" {
		t.Fatalf("unexpected pattern message: %#v", patternEvent)
	}

	monitor, err := store.Monitor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer closeMonitor(t, monitor)

	if _, pingErr := store.Exec(ctx, domain.Command{"PING"}); pingErr != nil {
		t.Fatal(pingErr)
	}

	select {
	case line := <-monitor.Lines():
		if !strings.Contains(strings.ToUpper(line), "PING") {
			t.Fatalf("expected PING monitor line, got %q", line)
		}
	case streamErr := <-monitor.Errors():
		t.Fatal(streamErr)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func newStack(t *testing.T) (*redisdb.Client, http.Handler) {
	t.Helper()

	uri := os.Getenv(testRedisEnv)
	if uri == "" {
		t.Skipf("set %s to run integration tests", testRedisEnv)
	}

	options, err := redis.ParseURL(uri)
	if err != nil {
		t.Fatal(err)
	}
	store := redisdb.New(options)

	if pingErr := store.Ping(t.Context()); pingErr != nil {
		closeStore(t, store)
		t.Fatal(pingErr)
	}

	catalog, err := store.Catalog(t.Context())
	if err != nil {
		closeStore(t, store)
		t.Fatal(err)
	}

	tokens, err := token.Load("", testToken, testReadOnly)
	if err != nil {
		closeStore(t, store)
		t.Fatal(err)
	}

	apiService := service.New(store, tokens, catalog)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	return store, httpapi.New(apiService, logger, httpapi.Options{
		MaxBody:          testBodyMax,
		MaxInFlight:      32,
		MaxSubscriptions: 8,
		MaxMonitors:      1,
		WriteTimeout:     time.Second,
	})
}

func runBatch(handler http.Handler, path, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+testToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	return response
}

func waitForEvent(
	t *testing.T,
	ctx context.Context,
	stream domain.Subscription,
	kind string,
) domain.Event {
	t.Helper()

	for {
		select {
		case event := <-stream.Events():
			if event.Kind == kind {
				return event
			}
		case err := <-stream.Errors():
			t.Fatal(err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
}

func deleteKey(t *testing.T, store *redisdb.Client, key string) {
	t.Helper()

	if _, err := store.Exec(t.Context(), domain.Command{"DEL", key}); err != nil {
		t.Errorf("delete integration key: %v", err)
	}
}

func closeStore(t *testing.T, store *redisdb.Client) {
	t.Helper()

	if err := store.Close(); err != nil {
		t.Errorf("close Redis: %v", err)
	}
}

func closeSubscription(t *testing.T, stream domain.Subscription) {
	t.Helper()

	if err := stream.Close(); err != nil {
		t.Errorf("close subscription: %v", err)
	}
}

func closeMonitor(t *testing.T, stream domain.Monitor) {
	t.Helper()

	if err := stream.Close(); err != nil {
		t.Errorf("close monitor: %v", err)
	}
}
