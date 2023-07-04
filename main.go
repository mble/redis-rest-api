package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"strings"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
)

type Config struct {
	RedisURI                string
	RedisAddr               string
	RedisUser               string
	RedisPassword           string
	MapFile                 string
	TLSCertFile             string
	TLSKeyFile              string
	CPUProfile              bool
	RedisInsecureSkipVerify bool
}

func newRedisOpts(cfg *Config) (*redis.Options, error) {
	const (
		redisDialTimeout  = 2 * time.Second
		redisReadTimeout  = 2 * time.Second
		redisWriteTimeout = 2 * time.Second
		redisDB           = 0
		redisClientName   = "redis-rest-api"
	)

	var redisPoolSize = 20 * runtime.NumCPU()

	if cfg.RedisURI != "" {
		opts, err := redis.ParseURL(cfg.RedisURI)
		if err != nil {
			return nil, err
		}

		opts.DialTimeout = redisDialTimeout
		opts.ReadTimeout = redisReadTimeout
		opts.WriteTimeout = redisWriteTimeout
		opts.ClientName = redisClientName
		opts.PoolSize = redisPoolSize

		if strings.HasPrefix(cfg.RedisURI, "rediss") && cfg.RedisInsecureSkipVerify {
			opts.TLSConfig = &tls.Config{
				InsecureSkipVerify: true,
			} // #nosec G402 -- InsecureSkipVerify is required for self-signed certs
		}

		return opts, nil
	}

	return &redis.Options{
		Addr:         cfg.RedisAddr,
		DB:           redisDB,
		DialTimeout:  redisDialTimeout,
		ReadTimeout:  redisReadTimeout,
		WriteTimeout: redisWriteTimeout,
		ClientName:   "redis-rest-api",
		PoolSize:     redisPoolSize,
		PoolFIFO:     true,
	}, nil
}

func newRedisClient(opts *redis.Options) *redis.Client {
	client := redis.NewClient(opts)
	return client
}

type serverCfg struct {
	TLSConfig         *tls.Config
	ListenAddr        string
	ReadTimeout       time.Duration
	ReadHeaderTimeout time.Duration
	IdleTimeout       time.Duration
}

func newServer(ctx context.Context, cfg serverCfg, rc *redis.Client, um UserMap, auth authFunc) *http.Server {
	const maxBytes int64 = 1048576 // 1 MiB

	mux := http.NewServeMux()
	mux.HandleFunc("/", rootHandler(ctx, rc, um, auth))
	mux.HandleFunc("/pipeline", pipelineHandler(ctx, rc, um, auth))
	mux.HandleFunc("/multi-exec", txHandler(ctx, rc, um, auth))
	wrappedMux := http.MaxBytesHandler(mux, maxBytes)

	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           wrappedMux,
		ReadTimeout:       cfg.ReadTimeout,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		TLSConfig:         cfg.TLSConfig,
	}

	return server
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	const (
		shutdownTimeout = 10 * time.Second
		timeout         = 2 * time.Second
	)

	cfg := &Config{}
	srvCfg := &serverCfg{
		ReadTimeout:       timeout,
		ReadHeaderTimeout: timeout,
		IdleTimeout:       timeout,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	flag.StringVar(&srvCfg.ListenAddr, "listen-addr", ":8081", "address to listen on")
	flag.StringVar(&cfg.RedisURI, "redis-uri", "", "redis URI (overrides other redis options)")
	flag.StringVar(&cfg.RedisAddr, "redis-addr", "localhost:6379", "address of redis server")
	flag.StringVar(&cfg.RedisUser, "redis-user", "default", "redis user to AUTH as")
	flag.StringVar(&cfg.RedisPassword, "redis-password", "", "redis user password to AUTH with")
	flag.StringVar(&cfg.MapFile, "map-file", "redis-users.json", "filepath containing user map")
	flag.StringVar(&cfg.TLSCertFile, "tls-cert", "", "TLS certificate file")
	flag.StringVar(&cfg.TLSKeyFile, "tls-key", "", "TLS key file")
	flag.BoolVar(&cfg.CPUProfile, "profile", false, "Create a CPU profile")
	flag.BoolVar(&cfg.RedisInsecureSkipVerify, "redis-insecure-skip-verify", false, "set insecureSkipVerify for Redis connection over TLS")

	showVersion := flag.Bool("version", false, "print version and exit")

	flag.Parse()

	if *showVersion {
		fmt.Printf("Version: %s\nBuild: %s\n", Version, Build)
		os.Exit(0)
	}

	if cfg.CPUProfile {
		f, err := os.Create("cpu.prof")
		if err != nil {
			log.Println("could not create CPU profile: ", err)
			return
		}

		defer f.Close()

		if err := pprof.StartCPUProfile(f); err != nil {
			log.Println("could not start CPU profile: ", err)
			return
		}

		defer pprof.StopCPUProfile()
	}

	ctx := context.Background()

	um, err := loadUsers(cfg.MapFile)
	if err != nil {
		log.Println(err)
		return
	}

	ropts, err := newRedisOpts(cfg)
	if err != nil {
		log.Println(err)
		return
	}

	rc := newRedisClient(ropts)

	srv := newServer(ctx, *srvCfg, rc, um, authenticate)

	go func() {
		if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
			log.Println("Serving HTTPS on ", srv.Addr)

			if err := srv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile); !errors.Is(err, http.ErrServerClosed) {
				log.Printf("TLS server error: %v", err)
				return
			}
		} else {
			log.Println("Serving HTTP on ", srv.Addr)

			if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
				log.Printf("HTTP server error: %v", err)
				return
			}
		}

		log.Println("Stopped serving new connections.")
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	shutdownCtx, shutdownRelease := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shutdownRelease()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("HTTP shutdown error: %v", err)
	}
}
