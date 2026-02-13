package app

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/votechain/votechain-machine/internal/api"
	"github.com/votechain/votechain-machine/internal/config"
	machinecrypto "github.com/votechain/votechain-machine/internal/crypto"
	"github.com/votechain/votechain-machine/internal/logging"
	"github.com/votechain/votechain-machine/internal/service"
	"github.com/votechain/votechain-machine/internal/storage/ledgerpostgres"
)

type LedgerNodeApplication struct {
	Server *http.Server
	Store  *ledgerpostgres.Store
}

func BuildLedgerNode(ctx context.Context, cfg *config.LedgerNodeConfig, logger *slog.Logger) (*LedgerNodeApplication, error) {
	signer, err := machinecrypto.LoadSigner(cfg.Keys.SigningPrivateKeyPath, cfg.Keys.SigningPublicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load signing keys: %w", err)
	}

	store, err := ledgerpostgres.Open(ctx, cfg.Storage.PostgresDSN, cfg.Storage.MaxConns, cfg.Storage.MinConns, cfg.Node.Role)
	if err != nil {
		return nil, fmt.Errorf("open ledger store: %w", err)
	}

	svc, err := service.NewLedgerNode(service.LedgerNodeParams{
		Store:      store,
		Signer:     signer,
		NodeRole:   cfg.Node.Role,
		WriteToken: cfg.Security.WriteToken,
		Service:    cfg.Logging.Service,
		Version:    cfg.Logging.Version,
	})
	if err != nil {
		store.Close()
		return nil, fmt.Errorf("build ledger node service: %w", err)
	}

	handler := api.NewLedgerNodeHandler(svc, 8<<20)
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
	return &LedgerNodeApplication{Server: server, Store: store}, nil
}

func (a *LedgerNodeApplication) Shutdown(ctx context.Context) error {
	defer a.Store.Close()
	return a.Server.Shutdown(ctx)
}
