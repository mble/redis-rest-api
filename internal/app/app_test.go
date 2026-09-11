package app

import (
	"testing"
	"time"

	"github.com/mble/redis-rest-api/internal/config"
)

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
