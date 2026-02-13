package app

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/votechain/votechain-machine/internal/api"
	"github.com/votechain/votechain-machine/internal/config"
	"github.com/votechain/votechain-machine/internal/logging"
	"github.com/votechain/votechain-machine/internal/service"
	"github.com/votechain/votechain-machine/internal/storage/postgres"
)

type ObserverApplication struct {
	Server *http.Server
	Store  *postgres.Store
}

func BuildObserver(ctx context.Context, cfg *config.ObserverConfig, logger *slog.Logger) (*ObserverApplication, error) {
	store, err := postgres.Open(ctx, cfg.Storage.PostgresDSN, cfg.Storage.MaxConns, cfg.Storage.MinConns)
	if err != nil {
		return nil, fmt.Errorf("open postgres store: %w", err)
	}

	svc := service.NewObserver(store, cfg)
	handler := api.NewObserverHandler(svc)
	env := logging.Environment{
		Service: cfg.Logging.Service,
		Version: cfg.Logging.Version,
		Commit:  cfg.Logging.Commit,
		Region:  cfg.Logging.Region,
	}
	root := logging.Middleware(logger, env)(handler.Router())

	server := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           root,
		ReadTimeout:       time.Duration(cfg.Server.ReadTimeoutSeconds) * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      time.Duration(cfg.Server.WriteTimeoutSeconds) * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	return &ObserverApplication{Server: server, Store: store}, nil
}

func (a *ObserverApplication) Shutdown(ctx context.Context) error {
	defer a.Store.Close()
	return a.Server.Shutdown(ctx)
}
