package httpapi

import (
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

const metricStatusClasses = 6

type metrics struct {
	enabled    bool
	requests   atomic.Uint64
	completed  atomic.Uint64
	rejected   atomic.Uint64
	active     atomic.Int64
	durationNS atomic.Uint64
	responses  [metricStatusClasses]atomic.Uint64
}

func (m *metrics) start() {
	m.requests.Add(1)
	m.active.Add(1)
}

func (m *metrics) finish(status int, duration time.Duration) {
	m.active.Add(-1)
	m.completed.Add(1)
	if duration > 0 {
		m.durationNS.Add(uint64(duration))
	}

	class := status / 100
	if class < 1 || class >= metricStatusClasses {
		class = 0
	}
	m.responses[class].Add(1)
}

func (m *metrics) reject() {
	if !m.enabled {
		return
	}

	m.rejected.Add(1)
}

func (m *metrics) write(writer http.ResponseWriter, request *http.Request, handler *Handler) {
	if !m.enabled {
		http.NotFound(writer, request)

		return
	}
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		writer.Header().Set("Allow", "GET, HEAD")
		writeError(writer, request, http.StatusMethodNotAllowed, "metrics endpoint requires GET or HEAD")

		return
	}

	var body strings.Builder
	writeMetric(&body, "redis_rest_http_requests_total", m.requests.Load())
	writeMetric(&body, "redis_rest_http_requests_active", m.active.Load())
	writeMetric(&body, "redis_rest_http_requests_capacity", cap(handler.requests))
	writeMetric(&body, "redis_rest_http_requests_rejected_total", m.rejected.Load())
	writeMetric(&body, "redis_rest_http_request_duration_seconds_sum", float64(m.durationNS.Load())/float64(time.Second))
	writeMetric(&body, "redis_rest_http_request_duration_seconds_count", m.completed.Load())
	writeMetric(&body, "redis_rest_subscriptions_active", len(handler.subscriptions))
	writeMetric(&body, "redis_rest_subscriptions_capacity", cap(handler.subscriptions))
	writeMetric(&body, "redis_rest_monitors_active", len(handler.monitors))
	writeMetric(&body, "redis_rest_monitors_capacity", cap(handler.monitors))

	for class := 1; class < metricStatusClasses; class++ {
		_, _ = fmt.Fprintf(
			&body,
			"redis_rest_http_responses_total{class=\"%dxx\"} %d\n",
			class,
			m.responses[class].Load(),
		)
	}

	writeBody(
		writer,
		request,
		http.StatusOK,
		"text/plain; version=0.0.4; charset=utf-8",
		[]byte(body.String()),
	)
}

func writeMetric(writer *strings.Builder, name string, value any) {
	_, _ = fmt.Fprintf(writer, "%s %v\n", name, value)
}

type metricWriter struct {
	http.ResponseWriter
	status int
}

func (w *metricWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}

	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *metricWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}

	return w.ResponseWriter.Write(body)
}

func (w *metricWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *metricWriter) statusCode() int {
	if w.status == 0 {
		return http.StatusOK
	}

	return w.status
}
