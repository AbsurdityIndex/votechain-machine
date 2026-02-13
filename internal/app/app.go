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
	"github.com/votechain/votechain-machine/internal/storage"
	"github.com/votechain/votechain-machine/internal/storage/postgres"
)

type Application struct {
	Server *http.Server
	Store  storage.Store
}

func New(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*Application, error) {
	signer, err := machinecrypto.LoadSigner(cfg.Keys.SigningPrivateKeyPath, cfg.Keys.SigningPublicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load signing keys: %w", err)
	}

	store, err := postgres.Open(ctx, cfg.Storage.PostgresDSN, cfg.Storage.MaxConns, cfg.Storage.MinConns)
	if err != nil {
		return nil, fmt.Errorf("open postgres store: %w", err)
	}

	svc, err := service.New(service.Params{
		Store:          store,
		Signer:         signer,
		MachineID:      cfg.Machine.MachineID,
		PrecinctID:     cfg.Machine.PrecinctID,
		JurisdictionID: cfg.Machine.JurisdictionID,
		Mode:           cfg.Machine.Mode,
		ServiceName:    cfg.Logging.Service,
		Version:        cfg.Logging.Version,
		ExportDir:      cfg.Sync.ExportDir,
		ChallengeTTL:   time.Duration(cfg.Election.ChallengeTTLSeconds) * time.Second,
	})
	if err != nil {
		store.Close()
		return nil, fmt.Errorf("build machine service: %w", err)
	}

	handler := api.NewHandler(svc, logger)
	router := handler.Router()
	if *cfg.Security.EnableIPAllow {
		mw, err := api.IPAllowListMiddleware(cfg.Security.TrustedCIDRs)
		if err != nil {
			store.Close()
			return nil, fmt.Errorf("configure machine ip allow list: %w", err)
		}
		router = mw(router)
	}
	if *cfg.Security.EnableBearerAuth {
		router = api.BearerAuthMiddleware(cfg.Security.BearerToken)(router)
	}
	env := logging.Environment{
		Service:    cfg.Logging.Service,
		Version:    cfg.Logging.Version,
		Commit:     cfg.Logging.Commit,
		Region:     cfg.Logging.Region,
		MachineID:  cfg.Machine.MachineID,
		PrecinctID: cfg.Machine.PrecinctID,
	}
	root := logging.Middleware(logger, env)(router)

	server := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           root,
		ReadTimeout:       time.Duration(cfg.Server.ReadTimeoutSeconds) * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      time.Duration(cfg.Server.WriteTimeoutSeconds) * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	return &Application{Server: server, Store: store}, nil
}

func (a *Application) Shutdown(ctx context.Context) error {
	defer a.Store.Close()
	return a.Server.Shutdown(ctx)
}
