package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type LedgerNodeConfig struct {
	Server struct {
		Listen                 string `yaml:"listen"`
		ReadTimeoutSeconds     int    `yaml:"read_timeout_seconds"`
		WriteTimeoutSeconds    int    `yaml:"write_timeout_seconds"`
		ShutdownTimeoutSeconds int    `yaml:"shutdown_timeout_seconds"`
	} `yaml:"server"`

	Storage struct {
		PostgresDSN string `yaml:"postgres_dsn"`
		MaxConns    int32  `yaml:"max_conns"`
		MinConns    int32  `yaml:"min_conns"`
	} `yaml:"storage"`

	Node struct {
		Role string `yaml:"role"`
	} `yaml:"node"`

	Security struct {
		WriteToken       string `yaml:"write_token"`
		EnforceSecureTLS *bool  `yaml:"enforce_secure_transport"`
	} `yaml:"security"`

	Keys struct {
		SigningPrivateKeyPath string `yaml:"signing_private_key_path"`
		SigningPublicKeyPath  string `yaml:"signing_public_key_path"`
	} `yaml:"keys"`

	Logging struct {
		Service string `yaml:"service"`
		Version string `yaml:"version"`
		Commit  string `yaml:"commit"`
		Region  string `yaml:"region"`
	} `yaml:"logging"`
}

func LoadLedgerNode(path string) (*LedgerNodeConfig, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read ledger node config: %w", err)
	}
	var cfg LedgerNodeConfig
	if err := yaml.Unmarshal(buf, &cfg); err != nil {
		return nil, fmt.Errorf("parse ledger node config yaml: %w", err)
	}
	cfg.expandEnv()
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *LedgerNodeConfig) applyDefaults() {
	if c.Server.Listen == "" {
		c.Server.Listen = "127.0.0.1:8301"
	}
	if c.Server.ReadTimeoutSeconds <= 0 {
		c.Server.ReadTimeoutSeconds = 15
	}
	if c.Server.WriteTimeoutSeconds <= 0 {
		c.Server.WriteTimeoutSeconds = 30
	}
	if c.Server.ShutdownTimeoutSeconds <= 0 {
		c.Server.ShutdownTimeoutSeconds = 20
	}
	if c.Storage.MaxConns <= 0 {
		c.Storage.MaxConns = 15
	}
	if c.Storage.MinConns < 0 {
		c.Storage.MinConns = 0
	}
	if c.Security.EnforceSecureTLS == nil {
		c.Security.EnforceSecureTLS = boolPtr(true)
	}
	if c.Logging.Service == "" {
		c.Logging.Service = "votechain-ledger-node"
	}
	if c.Logging.Version == "" {
		c.Logging.Version = "dev"
	}
	if c.Logging.Commit == "" {
		c.Logging.Commit = "unknown"
	}
	if c.Logging.Region == "" {
		c.Logging.Region = "ledger"
	}
}

func (c *LedgerNodeConfig) validate() error {
	if c.Storage.PostgresDSN == "" {
		return errors.New("storage.postgres_dsn is required")
	}
	if *c.Security.EnforceSecureTLS && dsnUsesInsecureSSL(c.Storage.PostgresDSN) {
		return errors.New("storage.postgres_dsn must use sslmode=require|verify-ca|verify-full when enforce_secure_transport is enabled")
	}
	if c.Node.Role == "" {
		return errors.New("node.role is required")
	}
	switch c.Node.Role {
	case "federal", "state", "oversight":
	default:
		return errors.New("node.role must be one of federal|state|oversight")
	}
	if c.Security.WriteToken == "" {
		return errors.New("security.write_token is required")
	}
	if c.Keys.SigningPrivateKeyPath == "" {
		return errors.New("keys.signing_private_key_path is required")
	}
	if c.Keys.SigningPublicKeyPath == "" {
		return errors.New("keys.signing_public_key_path is required")
	}
	return nil
}

func (c *LedgerNodeConfig) expandEnv() {
	c.Storage.PostgresDSN = os.ExpandEnv(strings.TrimSpace(c.Storage.PostgresDSN))
	c.Security.WriteToken = os.ExpandEnv(strings.TrimSpace(c.Security.WriteToken))
	c.Keys.SigningPrivateKeyPath = os.ExpandEnv(strings.TrimSpace(c.Keys.SigningPrivateKeyPath))
	c.Keys.SigningPublicKeyPath = os.ExpandEnv(strings.TrimSpace(c.Keys.SigningPublicKeyPath))
}
