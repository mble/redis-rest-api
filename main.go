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
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
)

type Config struct {
	ListenAddr    string
	RedisAddr     string
	RedisUser     string
	RedisPassword string
	MapFile       string
	TLSCertFile   string
	TLSKeyFile    string
	CPUProfile    bool
}

func newRedisOpts(cfg *Config) *redis.Options {
	const (
		redisDialTimeout  = 2 * time.Second
		redisReadTimeout  = 2 * time.Second
		redisWriteTimeout = 2 * time.Second
		redisDB           = 0
	)

	var redisPoolSize = 20 & runtime.NumCPU()

	return &redis.Options{
		Addr:         cfg.RedisAddr,
		DB:           redisDB,
		DialTimeout:  redisDialTimeout,
		ReadTimeout:  redisReadTimeout,
		WriteTimeout: redisWriteTimeout,
		ClientName:   "redis-rest-api",
		PoolSize:     redisPoolSize,
		PoolFIFO:     true,
	}
}

func newRedisClient(opts *redis.Options) *redis.Client {
	client := redis.NewClient(opts)
	return client
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	const (
		shutdownTimeout         = 10 * time.Second
		serverReadTimeout       = 2 * time.Second
		serverReadHeaderTimeout = 2 * time.Second
		serverIdleTimeout       = 2 * time.Second
	)

	cfg := &Config{}

	flag.StringVar(&cfg.ListenAddr, "listen-addr", ":8081", "address to listen on")
	flag.StringVar(&cfg.RedisAddr, "redis-addr", "localhost:6379", "address of redis server")
	flag.StringVar(&cfg.RedisUser, "redis-user", "default", "redis user to AUTH as")
	flag.StringVar(&cfg.RedisPassword, "redis-password", "", "redis user password to AUTH with")
	flag.StringVar(&cfg.MapFile, "map-file", "redis-users.json", "filepath containing user map")
	flag.StringVar(&cfg.TLSCertFile, "tls-cert", "test-cert.pem", "TLS certificate file")
	flag.StringVar(&cfg.TLSKeyFile, "tls-key", "test-key.pem", "TLS key file")
	flag.BoolVar(&cfg.CPUProfile, "profile", false, "Create a CPU profile")

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

	ropts := newRedisOpts(cfg)
	rc := newRedisClient(ropts)

	const maxBytes int64 = 1048576 // 1 MiB

	mux := http.NewServeMux()
	mux.HandleFunc("/", rootHandler(ctx, rc, um, authenticate))
	mux.HandleFunc("/pipeline", pipelineHandler(ctx, rc, um, authenticate))
	mux.HandleFunc("/multi-exec", txHandler(ctx, rc, um, authenticate))
	wrappedMux := http.MaxBytesHandler(mux, maxBytes)

	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           wrappedMux,
		ReadTimeout:       serverReadTimeout,
		ReadHeaderTimeout: serverReadHeaderTimeout,
		IdleTimeout:       serverIdleTimeout,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	go func() {
		if err := server.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile); !errors.Is(err, http.ErrServerClosed) {
			log.Printf("HTTP server error: %v", err)
			return
		}

		log.Println("Stopped serving new connections.")
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	shutdownCtx, shutdownRelease := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shutdownRelease()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("HTTP shutdown error: %v", err)
	}
}
