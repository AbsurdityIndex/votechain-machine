package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/votechain/votechain-machine/internal/config"
	"github.com/votechain/votechain-machine/internal/logging"
	"github.com/votechain/votechain-machine/internal/service"
	"github.com/votechain/votechain-machine/internal/storage/postgres"
)

func main() {
	configPath := flag.String("config", "configs/relay.yaml", "path to relay config")
	flag.Parse()

	cfg, err := config.LoadRelay(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}
	logger := logging.NewJSONLogger()

	store, err := postgres.Open(context.Background(), cfg.Storage.PostgresDSN, cfg.Storage.MaxConns, cfg.Storage.MinConns)
	if err != nil {
		logger.Error("failed to open store", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer store.Close()

	relay, err := service.NewAnchorRelay(store, cfg, logger)
	if err != nil {
		logger.Error("failed to build anchor relay", slog.String("error", err.Error()))
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		logger.Info("shutdown signal received", slog.String("signal", sig.String()))
		cancel()
	}()

	logger.Info("anchor relay started", slog.Int("batch_size", cfg.Relay.BatchSize), slog.Int("required_acks", cfg.Relay.RequiredAcks))
	if err := relay.Run(ctx, time.Duration(cfg.Relay.PollIntervalSeconds)*time.Second); err != nil {
		logger.Error("anchor relay stopped with error", slog.String("error", err.Error()))
		os.Exit(1)
	}
	logger.Info("anchor relay stopped")
}
