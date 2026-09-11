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
	defaultListenAddr             = ":8081"
	defaultRedisURI               = "redis://127.0.0.1:6379"
	defaultTokenFile              = "redis-users.json" // #nosec G101 -- This is a path, not a credential.
	defaultMaxBody          int64 = 1 << 20
	maxBodyLimit            int64 = 64 << 20
	defaultMaxResponse      int64 = 16 << 20
	maxResponseLimit        int64 = 512 << 20
	defaultRedisTimeout           = 2 * time.Second
	defaultHeaderTimeout          = 5 * time.Second
	defaultReadTimeout            = 10 * time.Second
	defaultWriteTimeout           = 10 * time.Second
	defaultIdleTimeout            = 60 * time.Second
	defaultShutdownTimeout        = 10 * time.Second
	defaultReadyCacheTTL          = time.Second
	defaultMaxHeaderBytes         = 32 << 10
	defaultMaxInFlight            = 256
	defaultMaxSubscriptions       = 128
	defaultMaxMonitors            = 1
	maxConcurrency                = 65536
	maxPoolSize                   = 4096
	maxRedisBuffer                = 1 << 20
	maxHeaderBytes                = 1 << 20
	maxReadyCacheTTL              = time.Minute
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
	MaxResponse       int64
	DialTimeout       time.Duration
	RedisTimeout      time.Duration
	RedisPoolSize     int
	RedisMinIdle      int
	RedisPipeBuffer   int
	RedisPipePool     int
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration
	ReadyCacheTTL     time.Duration
	MaxHeaderBytes    int
	MaxInFlight       int
	MaxSubscriptions  int
	MaxMonitors       int
	Metrics           bool
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
	flags.Int64Var(&config.MaxResponse, "max-response-bytes", config.MaxResponse, "maximum HTTP response body")
	flags.DurationVar(&config.DialTimeout, "redis-dial-timeout", config.DialTimeout, "Redis dial timeout")
	flags.DurationVar(&config.RedisTimeout, "redis-timeout", config.RedisTimeout, "Redis read and write timeout")
	flags.IntVar(&config.RedisPoolSize, "redis-pool-size", config.RedisPoolSize, "Redis connection pool size; zero selects automatically")
	flags.IntVar(&config.RedisMinIdle, "redis-min-idle", config.RedisMinIdle, "minimum idle Redis connections")
	flags.IntVar(&config.RedisPipeBuffer, "redis-pipeline-buffer-bytes", config.RedisPipeBuffer, "dedicated Redis pipeline buffer; zero disables")
	flags.IntVar(&config.RedisPipePool, "redis-pipeline-pool-size", config.RedisPipePool, "dedicated Redis pipeline pool size")
	flags.DurationVar(&config.ReadHeaderTimeout, "read-header-timeout", config.ReadHeaderTimeout, "HTTP header timeout")
	flags.DurationVar(&config.ReadTimeout, "read-timeout", config.ReadTimeout, "HTTP request read timeout")
	flags.DurationVar(&config.WriteTimeout, "write-timeout", config.WriteTimeout, "HTTP response write timeout")
	flags.DurationVar(&config.IdleTimeout, "idle-timeout", config.IdleTimeout, "HTTP idle timeout")
	flags.DurationVar(&config.ShutdownTimeout, "shutdown-timeout", config.ShutdownTimeout, "graceful shutdown timeout")
	flags.DurationVar(&config.ReadyCacheTTL, "ready-cache-ttl", config.ReadyCacheTTL, "Redis readiness cache duration")
	flags.IntVar(&config.MaxHeaderBytes, "max-header-bytes", config.MaxHeaderBytes, "maximum HTTP request header size")
	flags.IntVar(&config.MaxInFlight, "max-in-flight", config.MaxInFlight, "maximum concurrent command requests")
	flags.IntVar(&config.MaxSubscriptions, "max-subscriptions", config.MaxSubscriptions, "maximum subscription streams")
	flags.IntVar(&config.MaxMonitors, "max-monitors", config.MaxMonitors, "maximum monitor streams; zero disables")
	flags.BoolVar(&config.Metrics, "metrics", config.Metrics, "expose Prometheus metrics at /metrics")
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
		MaxResponse:       defaultMaxResponse,
		DialTimeout:       defaultRedisTimeout,
		RedisTimeout:      defaultRedisTimeout,
		ReadHeaderTimeout: defaultHeaderTimeout,
		ReadTimeout:       defaultReadTimeout,
		WriteTimeout:      defaultWriteTimeout,
		IdleTimeout:       defaultIdleTimeout,
		ShutdownTimeout:   defaultShutdownTimeout,
		ReadyCacheTTL:     defaultReadyCacheTTL,
		MaxHeaderBytes:    defaultMaxHeaderBytes,
		MaxInFlight:       defaultMaxInFlight,
		MaxSubscriptions:  defaultMaxSubscriptions,
		MaxMonitors:       defaultMaxMonitors,
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
	if c.MaxResponse < 1 || c.MaxResponse > maxResponseLimit {
		return fmt.Errorf("max response must be between 1 and %d bytes", maxResponseLimit)
	}
	if err := c.validateRedis(); err != nil {
		return err
	}
	if err := c.validateHTTP(); err != nil {
		return err
	}

	switch c.LogLevel {
	case "debug", "info", "warn", "error":
		return nil
	default:
		return fmt.Errorf("invalid log level %q", c.LogLevel)
	}
}

func (c *Config) validateRedis() error {
	if c.DialTimeout <= 0 || c.RedisTimeout <= 0 {
		return errors.New("redis timeouts must be positive")
	}
	if c.RedisPoolSize < 0 || c.RedisPoolSize > maxPoolSize {
		return fmt.Errorf("redis pool size must be between 0 and %d", maxPoolSize)
	}
	if c.RedisMinIdle < 0 || c.RedisPipePool < 0 {
		return errors.New("redis pool counts cannot be negative")
	}
	if c.RedisMinIdle > maxPoolSize || c.RedisPipePool > maxPoolSize {
		return fmt.Errorf("redis pool counts must not exceed %d", maxPoolSize)
	}
	if c.RedisPoolSize > 0 && c.RedisMinIdle > c.RedisPoolSize {
		return errors.New("redis minimum idle connections exceed pool size")
	}
	if c.RedisPipeBuffer < 0 || c.RedisPipeBuffer > maxRedisBuffer {
		return fmt.Errorf("redis pipeline buffer must be between 0 and %d bytes", maxRedisBuffer)
	}
	if (c.RedisPipeBuffer == 0) != (c.RedisPipePool == 0) {
		return errors.New("redis pipeline buffer and pool size must be set together")
	}

	return nil
}

func (c *Config) validateHTTP() error {
	if c.ReadHeaderTimeout <= 0 || c.ReadTimeout <= 0 || c.WriteTimeout <= 0 || c.IdleTimeout <= 0 || c.ShutdownTimeout <= 0 {
		return errors.New("HTTP timeouts must be positive")
	}
	if c.ReadyCacheTTL <= 0 || c.ReadyCacheTTL > maxReadyCacheTTL {
		return fmt.Errorf("ready cache TTL must be between 1ns and %s", maxReadyCacheTTL)
	}
	if c.MaxHeaderBytes < 1 || c.MaxHeaderBytes > maxHeaderBytes {
		return fmt.Errorf("max header must be between 1 and %d bytes", maxHeaderBytes)
	}
	if c.MaxInFlight < 1 || c.MaxInFlight > maxConcurrency {
		return fmt.Errorf("maximum in-flight requests must be between 1 and %d", maxConcurrency)
	}
	if c.MaxSubscriptions < 0 || c.MaxSubscriptions > maxConcurrency {
		return fmt.Errorf("maximum subscriptions must be between 0 and %d", maxConcurrency)
	}
	if c.MaxMonitors < 0 || c.MaxMonitors > maxConcurrency {
		return fmt.Errorf("maximum monitors must be between 0 and %d", maxConcurrency)
	}

	return nil
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
