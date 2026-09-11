package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"time"
)

const (
	defaultListenAddr            = ":8081"
	defaultRedisURI              = "redis://127.0.0.1:6379"
	defaultTokenFile             = "redis-users.json" // #nosec G101 -- This is a path, not a credential.
	defaultMaxBody         int64 = 1 << 20
	maxBodyLimit           int64 = 64 << 20
	defaultRedisTimeout          = 2 * time.Second
	defaultHeaderTimeout         = 5 * time.Second
	defaultReadTimeout           = 10 * time.Second
	defaultIdleTimeout           = 60 * time.Second
	defaultShutdownTimeout       = 10 * time.Second
)

const (
	envListenAddr = "REDIS_REST_ADDR"
	envRedisURI   = "REDIS_URL"
	envTokenFile  = "REDIS_REST_TOKEN_FILE" // #nosec G101 -- This names a path variable.
	envStandard   = "REDIS_REST_TOKEN"
	envReadOnly   = "REDIS_REST_READ_ONLY_TOKEN"
	envTLSCert    = "REDIS_REST_TLS_CERT"
	envTLSKey     = "REDIS_REST_TLS_KEY"
	envLogLevel   = "REDIS_REST_LOG_LEVEL"
	envSkipVerify = "REDIS_REST_REDIS_INSECURE_SKIP_VERIFY"
)

type Getter func(string) string

type Config struct {
	ListenAddr        string
	RedisURI          string
	TokenFile         string
	StandardToken     string
	ReadOnlyToken     string
	TLSCertFile       string
	TLSKeyFile        string
	LogLevel          string
	MaxBody           int64
	DialTimeout       time.Duration
	RedisTimeout      time.Duration
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration
	RedisSkipVerify   bool
	ShowVersion       bool
}

func Parse(args []string, getenv Getter, output io.Writer) (Config, error) {
	config := defaults(getenv)
	flags := flag.NewFlagSet("redis-rest-api", flag.ContinueOnError)
	flags.SetOutput(output)

	flags.StringVar(&config.ListenAddr, "listen-addr", config.ListenAddr, "HTTP listen address")
	flags.StringVar(&config.RedisURI, "redis-uri", config.RedisURI, "Redis URI")
	flags.StringVar(&config.TokenFile, "token-file", config.TokenFile, "hashed REST token file")
	flags.StringVar(&config.TLSCertFile, "tls-cert", config.TLSCertFile, "HTTP TLS certificate")
	flags.StringVar(&config.TLSKeyFile, "tls-key", config.TLSKeyFile, "HTTP TLS private key")
	flags.StringVar(&config.LogLevel, "log-level", config.LogLevel, "debug, info, warn, or error")
	flags.Int64Var(&config.MaxBody, "max-body-bytes", config.MaxBody, "maximum request body")
	flags.DurationVar(&config.DialTimeout, "redis-dial-timeout", config.DialTimeout, "Redis dial timeout")
	flags.DurationVar(&config.RedisTimeout, "redis-timeout", config.RedisTimeout, "Redis read and write timeout")
	flags.DurationVar(&config.ReadHeaderTimeout, "read-header-timeout", config.ReadHeaderTimeout, "HTTP header timeout")
	flags.DurationVar(&config.ReadTimeout, "read-timeout", config.ReadTimeout, "HTTP request read timeout")
	flags.DurationVar(&config.IdleTimeout, "idle-timeout", config.IdleTimeout, "HTTP idle timeout")
	flags.DurationVar(&config.ShutdownTimeout, "shutdown-timeout", config.ShutdownTimeout, "graceful shutdown timeout")
	flags.BoolVar(&config.RedisSkipVerify, "redis-insecure-skip-verify", config.RedisSkipVerify, "skip Redis TLS verification")
	flags.BoolVar(&config.ShowVersion, "version", false, "print version")

	if err := flags.Parse(args); err != nil {
		return Config{}, err
	}

	if flags.NArg() != 0 {
		return Config{}, fmt.Errorf("unexpected arguments: %v", flags.Args())
	}

	if err := config.validate(); err != nil {
		return Config{}, err
	}

	return config, nil
}

func defaults(getenv Getter) Config {
	standard := getenv(envStandard)
	readOnly := getenv(envReadOnly)
	tokenFile := getenv(envTokenFile)
	if tokenFile == "" && standard == "" && readOnly == "" {
		tokenFile = defaultTokenFile
	}

	return Config{
		ListenAddr:        envOr(getenv, envListenAddr, defaultListenAddr),
		RedisURI:          envOr(getenv, envRedisURI, defaultRedisURI),
		TokenFile:         tokenFile,
		StandardToken:     standard,
		ReadOnlyToken:     readOnly,
		TLSCertFile:       getenv(envTLSCert),
		TLSKeyFile:        getenv(envTLSKey),
		LogLevel:          envOr(getenv, envLogLevel, "info"),
		MaxBody:           defaultMaxBody,
		DialTimeout:       defaultRedisTimeout,
		RedisTimeout:      defaultRedisTimeout,
		ReadHeaderTimeout: defaultHeaderTimeout,
		ReadTimeout:       defaultReadTimeout,
		IdleTimeout:       defaultIdleTimeout,
		ShutdownTimeout:   defaultShutdownTimeout,
		RedisSkipVerify:   envBool(getenv(envSkipVerify)),
	}
}

func (c *Config) validate() error {
	if c.ListenAddr == "" {
		return errors.New("listen address is empty")
	}

	if c.RedisURI == "" {
		return errors.New("redis URI is empty")
	}

	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		return errors.New("HTTP TLS certificate and key must be set together")
	}

	if c.MaxBody < 1 || c.MaxBody > maxBodyLimit {
		return fmt.Errorf("max body must be between 1 and %d bytes", maxBodyLimit)
	}

	if c.DialTimeout <= 0 || c.RedisTimeout <= 0 {
		return errors.New("redis timeouts must be positive")
	}

	if c.ReadHeaderTimeout <= 0 || c.ReadTimeout <= 0 || c.IdleTimeout <= 0 || c.ShutdownTimeout <= 0 {
		return errors.New("HTTP timeouts must be positive")
	}

	switch c.LogLevel {
	case "debug", "info", "warn", "error":
		return nil
	default:
		return fmt.Errorf("invalid log level %q", c.LogLevel)
	}
}

func envOr(getenv Getter, key, fallback string) string {
	value := getenv(key)
	if value != "" {
		return value
	}

	return fallback
}

func envBool(raw string) bool {
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false
	}

	return value
}
