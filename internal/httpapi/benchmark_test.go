package httpapi

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const benchmarkBodyLimit = 1 << 20

func BenchmarkParsePath(b *testing.B) {
	for b.Loop() {
		_, err := parsePath("/set/a%2Fb/value")
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseBatch10(b *testing.B) {
	body := `[["GET","key"],["GET","key"],["GET","key"],["GET","key"],["GET","key"],` +
		`["GET","key"],["GET","key"],["GET","key"],["GET","key"],["GET","key"]]`
	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_, err := parseCommands(strings.NewReader(body), benchmarkBodyLimit)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHandlerGET(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := New(&fakeService{value: "value"}, logger, Options{
		MaxBody:          benchmarkBodyLimit,
		MaxResponse:      benchmarkBodyLimit,
		MaxInFlight:      1,
		MaxSubscriptions: 1,
		MaxMonitors:      1,
		WriteTimeout:     time.Second,
		ReadyCacheTTL:    time.Second,
	})
	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		request := httptest.NewRequest(http.MethodGet, "/get/key", http.NoBody)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
	}
}
