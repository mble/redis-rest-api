package app

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/mble/redis-rest-api/internal/config"
)

const (
	testMaxHeaderBytes = 32 << 10
	testWriteTimeout   = 10 * time.Second
)

func TestServerBoundsWritesAndHeaders(t *testing.T) {
	cfg := config.Config{
		ListenAddr:        ":0",
		ReadHeaderTimeout: time.Second,
		ReadTimeout:       time.Second,
		WriteTimeout:      testWriteTimeout,
		IdleTimeout:       time.Second,
		MaxHeaderBytes:    testMaxHeaderBytes,
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := newServer(context.Background(), &cfg, http.NotFoundHandler(), logger)

	if server.WriteTimeout != testWriteTimeout {
		t.Fatalf("expected %s write timeout, got %s", testWriteTimeout, server.WriteTimeout)
	}
	if server.MaxHeaderBytes != testMaxHeaderBytes {
		t.Fatalf("expected %d header bytes, got %d", testMaxHeaderBytes, server.MaxHeaderBytes)
	}
}

func TestRedisOptions(t *testing.T) {
	cfg := config.Config{
		RedisURI:     "redis://user:pass@redis.example:6380/2",
		DialTimeout:  time.Second,
		RedisTimeout: 2 * time.Second,
	}

	options, err := redisOptions(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	if options.Addr != "redis.example:6380" || options.Username != "user" || options.Password != "pass" || options.DB != 2 {
		t.Fatalf("unexpected Redis options: %#v", options)
	}
	if options.ClientName != clientName || options.Protocol != 2 || options.PoolSize < 1 || options.PoolSize > maxPoolSize {
		t.Fatalf("unexpected client options: %#v", options)
	}
	if options.MaxActiveConns != options.PoolSize {
		t.Fatalf("expected %d active connections, got %d", options.PoolSize, options.MaxActiveConns)
	}
	if options.PoolFIFO {
		t.Fatal("expected lower-overhead LIFO pool")
	}
}

func TestSkipVerifyRequiresTLS(t *testing.T) {
	cfg := config.Config{
		RedisURI:        "redis://127.0.0.1:6379",
		DialTimeout:     time.Second,
		RedisTimeout:    time.Second,
		RedisSkipVerify: true,
	}

	if _, err := redisOptions(&cfg); err == nil {
		t.Fatal("expected TLS validation error")
	}
}

func TestRedisPoolOptions(t *testing.T) {
	cfg := config.Config{
		RedisURI:        "redis://127.0.0.1:6379",
		DialTimeout:     time.Second,
		RedisTimeout:    time.Second,
		RedisPoolSize:   24,
		RedisMinIdle:    4,
		RedisPipeBuffer: 64 << 10,
		RedisPipePool:   6,
	}

	options, err := redisOptions(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	if options.PoolSize != 24 || options.MaxActiveConns != 24 || options.MinIdleConns != 4 {
		t.Fatalf("unexpected pool options: %#v", options)
	}
	if options.PipelineReadBufferSize != 64<<10 || options.PipelineWriteBufferSize != 64<<10 {
		t.Fatalf("unexpected pipeline buffers: %#v", options)
	}
	if options.PipelinePoolSize != 6 {
		t.Fatalf("unexpected pipeline pool: %#v", options)
	}
}
