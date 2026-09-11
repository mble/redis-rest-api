package config

import (
	"io"
	"strings"
	"testing"
)

func TestDefaults(t *testing.T) {
	config, err := Parse(nil, func(string) string { return "" }, io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	if config.ListenAddr != defaultListenAddr {
		t.Fatalf("expected %q, got %q", defaultListenAddr, config.ListenAddr)
	}
	if config.RedisURI != defaultRedisURI {
		t.Fatalf("expected %q, got %q", defaultRedisURI, config.RedisURI)
	}
	if config.TokenFile != defaultTokenFile {
		t.Fatalf("expected %q, got %q", defaultTokenFile, config.TokenFile)
	}
}

func TestEnvironment(t *testing.T) {
	values := map[string]string{
		envListenAddr: ":9000",
		envRedisURI:   "rediss://redis.example:6380",
		envStandard:   "secret",
		envLogLevel:   "debug",
	}
	getenv := func(key string) string {
		return values[key]
	}

	config, err := Parse(nil, getenv, io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	if config.ListenAddr != ":9000" || config.RedisURI != values[envRedisURI] {
		t.Fatalf("unexpected environment config: %#v", config)
	}
	if config.TokenFile != "" || config.StandardToken != "secret" {
		t.Fatalf("unexpected token config: %#v", config)
	}
}

func TestFlagsOverrideEnvironment(t *testing.T) {
	getenv := func(key string) string {
		if key == envListenAddr {
			return ":9000"
		}

		return ""
	}

	config, err := Parse([]string{"-listen-addr", ":7000", "-max-body-bytes", "2048"}, getenv, io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	if config.ListenAddr != ":7000" || config.MaxBody != 2048 {
		t.Fatalf("unexpected flag config: %#v", config)
	}
}

func TestInvalidConfig(t *testing.T) {
	tests := [][]string{
		{"-tls-cert", "cert.pem"},
		{"-max-body-bytes", "0"},
		{"-redis-timeout", "0s"},
		{"-redis-pool-size", "4097"},
		{"-redis-pool-size", "2", "-redis-min-idle", "3"},
		{"-redis-pipeline-buffer-bytes", "65536"},
		{"-max-in-flight", "0"},
		{"-max-subscriptions", "-1"},
		{"-max-monitors", "65537"},
		{"-log-level", "trace"},
		{"positional"},
	}

	for _, args := range tests {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			_, err := Parse(args, func(string) string { return "" }, io.Discard)
			if err == nil {
				t.Fatalf("expected error for %v", args)
			}
		})
	}
}
