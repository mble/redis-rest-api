package app

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"runtime"
	"time"

	"github.com/mble/redis-rest-api/internal/config"
	"github.com/mble/redis-rest-api/internal/httpapi"
	"github.com/mble/redis-rest-api/internal/redisdb"
	"github.com/mble/redis-rest-api/internal/service"
	"github.com/mble/redis-rest-api/internal/token"
	"github.com/redis/go-redis/v9"
)

const (
	clientName         = "redis-rest-api"
	poolPerProc        = 10
	maxPoolSize        = 1024
	startupPingTimeout = 5 * time.Second
)

type Build struct {
	Version string
	Commit  string
}

func Run(
	ctx context.Context,
	args []string,
	build Build,
	stdout io.Writer,
	stderr io.Writer,
	getenv config.Getter,
) error {
	cfg, err := config.Parse(args, getenv, stderr)
	if err != nil {
		return err
	}

	if cfg.ShowVersion {
		_, writeErr := fmt.Fprintf(stdout, "redis-rest-api %s (%s)\n", build.Version, build.Commit)

		return writeErr
	}

	logger := newLogger(stderr, cfg.LogLevel)
	tokens, err := token.Load(cfg.TokenFile, cfg.StandardToken, cfg.ReadOnlyToken)
	if err != nil {
		return err
	}

	redisOptions, err := redisOptions(&cfg)
	if err != nil {
		return err
	}

	store := redisdb.New(redisOptions)
	defer closeStore(logger, store)

	startupCtx, cancel := context.WithTimeout(ctx, startupPingTimeout)
	defer cancel()

	if pingErr := store.Ping(startupCtx); pingErr != nil {
		return fmt.Errorf("connect to Redis: %w", pingErr)
	}

	catalog, err := store.Catalog(startupCtx)
	if err != nil {
		return fmt.Errorf("load Redis command catalog: %w", err)
	}

	apiService := service.New(store, tokens, catalog)
	handler := httpapi.New(apiService, logger, httpapi.Options{
		MaxBody:          cfg.MaxBody,
		MaxResponse:      cfg.MaxResponse,
		MaxInFlight:      cfg.MaxInFlight,
		MaxSubscriptions: cfg.MaxSubscriptions,
		MaxMonitors:      cfg.MaxMonitors,
		WriteTimeout:     cfg.WriteTimeout,
	})
	server := newServer(ctx, &cfg, handler, logger)

	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	serveErrors := make(chan error, 1)
	go serve(server, listener, &cfg, serveErrors)

	logger.Info("server started", "address", listener.Addr().String(), "tls", cfg.TLSCertFile != "")

	select {
	case <-ctx.Done():
	case err := <-serveErrors:
		if err != nil {
			return err
		}
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown HTTP server: %w", err)
	}

	logger.Info("server stopped")

	return nil
}

func redisOptions(cfg *config.Config) (*redis.Options, error) {
	options, err := redis.ParseURL(cfg.RedisURI)
	if err != nil {
		return nil, fmt.Errorf("parse Redis URI: %w", err)
	}

	options.ClientName = clientName
	options.Protocol = 2
	options.DialTimeout = cfg.DialTimeout
	options.ReadTimeout = cfg.RedisTimeout
	options.WriteTimeout = cfg.RedisTimeout
	poolSize := cfg.RedisPoolSize
	if poolSize == 0 {
		poolSize = min(poolPerProc*runtime.GOMAXPROCS(0), maxPoolSize)
	}

	options.PoolFIFO = false
	options.PoolSize = poolSize
	options.MaxActiveConns = poolSize
	options.MinIdleConns = cfg.RedisMinIdle
	options.PipelineReadBufferSize = cfg.RedisPipeBuffer
	options.PipelineWriteBufferSize = cfg.RedisPipeBuffer
	options.PipelinePoolSize = cfg.RedisPipePool

	if options.TLSConfig != nil {
		options.TLSConfig.MinVersion = tls.VersionTLS12
	}

	if cfg.RedisSkipVerify {
		if options.TLSConfig == nil {
			return nil, errors.New("redis TLS verification can only be disabled for a rediss URI")
		}

		options.TLSConfig.InsecureSkipVerify = true // #nosec G402 -- Explicit development option.
	}

	return options, nil
}

func newServer(ctx context.Context, cfg *config.Config, handler http.Handler, logger *slog.Logger) *http.Server {
	return &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		MaxHeaderBytes:    cfg.MaxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelError),
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		BaseContext: func(net.Listener) context.Context {
			return context.WithoutCancel(ctx)
		},
	}
}

func serve(server *http.Server, listener net.Listener, cfg *config.Config, serveErrors chan<- error) {
	var err error
	if cfg.TLSCertFile != "" {
		err = server.ServeTLS(listener, cfg.TLSCertFile, cfg.TLSKeyFile)
	} else {
		err = server.Serve(listener)
	}

	if errors.Is(err, http.ErrServerClosed) {
		serveErrors <- nil
		return
	}

	serveErrors <- fmt.Errorf("serve HTTP: %w", err)
}

func newLogger(writer io.Writer, level string) *slog.Logger {
	levels := map[string]slog.Level{
		"debug": slog.LevelDebug,
		"info":  slog.LevelInfo,
		"warn":  slog.LevelWarn,
		"error": slog.LevelError,
	}

	handler := slog.NewJSONHandler(writer, &slog.HandlerOptions{Level: levels[level]})

	return slog.New(handler)
}

func closeStore(logger *slog.Logger, store *redisdb.Client) {
	if err := store.Close(); err != nil {
		logger.Warn("close Redis", "error", err)
	}
}
