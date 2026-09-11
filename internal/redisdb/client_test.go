package redisdb

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mble/redis-rest-api/internal/domain"
	"github.com/redis/go-redis/v9"
)

const (
	monitorHandshakeWait = 20 * time.Millisecond
	testWait             = 200 * time.Millisecond
)

func TestDialUsesConfiguredDialer(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { closeConn(t, server) })

	called := false
	options := &redis.Options{
		Addr: "unused:6379",
		Dialer: func(context.Context, string, string) (net.Conn, error) {
			called = true

			return client, nil
		},
	}

	conn, err := dial(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeConn(t, conn) })

	if !called {
		t.Fatal("expected configured dialer call")
	}
}

func TestMonitorHandshakeTimesOut(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { closeConn(t, server) })

	go func() {
		_, _ = io.Copy(io.Discard, server)
	}()

	options := &redis.Options{
		Addr:        "unused:6379",
		ReadTimeout: monitorHandshakeWait,
		Dialer: func(context.Context, string, string) (net.Conn, error) {
			return client, nil
		},
	}
	store := New(options)
	done := make(chan error, 1)

	go func() {
		conn, _, err := store.monitorConn(t.Context())
		if conn != nil {
			_ = conn.Close()
		}

		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, domain.ErrUnavailable) {
			t.Fatalf("expected unavailable error, got %v", err)
		}
	case <-time.After(testWait):
		_ = server.Close()
		<-done

		t.Fatal("monitor handshake did not time out")
	}
}

func closeConn(t *testing.T, conn net.Conn) {
	t.Helper()

	if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Errorf("close connection: %v", err)
	}
}

func TestWriteCommand(t *testing.T) {
	var output bytes.Buffer
	writer := bufio.NewWriter(&output)

	if err := writeCommand(writer, []string{"SET", "key", "value"}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}

	want := "*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n"
	if output.String() != want {
		t.Fatalf("expected %q, got %q", want, output.String())
	}
}

func TestReadSimple(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		want      string
		wantError string
	}{
		{name: "status", input: "+OK\r\n", want: "OK"},
		{name: "Redis error", input: "-ERR denied\r\n", wantError: "ERR denied"},
		{name: "unexpected", input: "$2\r\n", wantError: "unexpected RESP prefix"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, err := readSimple(bufio.NewReader(bytes.NewBufferString(test.input)))
			if value != test.want {
				t.Fatalf("expected %q, got %q", test.want, value)
			}
			if test.wantError == "" && err != nil {
				t.Fatal(err)
			}
			if test.wantError != "" && (err == nil || !bytes.Contains([]byte(err.Error()), []byte(test.wantError))) {
				t.Fatalf("expected error containing %q, got %v", test.wantError, err)
			}
		})
	}
}

func TestClassify(t *testing.T) {
	if classify(nil) != nil {
		t.Fatal("expected nil")
	}
	if !errors.Is(classify(io.EOF), domain.ErrUnavailable) {
		t.Fatalf("expected unavailable classification, got %v", classify(io.EOF))
	}
	if !errors.Is(classify(redis.Nil), redis.Nil) {
		t.Fatalf("expected Redis error, got %v", classify(redis.Nil))
	}
}
