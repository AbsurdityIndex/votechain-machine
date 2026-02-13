package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type IngestConfig struct {
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

	Security struct {
		BearerToken         string   `yaml:"bearer_token"`
		TrustedCIDRs        []string `yaml:"trusted_cidrs"`
		MaxBodyBytes        int64    `yaml:"max_body_bytes"`
		EnableIPAllowList   *bool    `yaml:"enable_ip_allow_list"`
		EnableBearerAuth    *bool    `yaml:"enable_bearer_auth"`
		RequireMachineKeyID *bool    `yaml:"require_machine_key_id"`
		EnforceSecureTLS    *bool    `yaml:"enforce_secure_transport"`
	} `yaml:"security"`

	MachineRegistry struct {
		Path string `yaml:"path"`
	} `yaml:"machine_registry"`

	Logging struct {
		Service string `yaml:"service"`
		Version string `yaml:"version"`
		Commit  string `yaml:"commit"`
		Region  string `yaml:"region"`
	} `yaml:"logging"`
}

func LoadIngest(path string) (*IngestConfig, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read ingest config: %w", err)
	}
	var cfg IngestConfig
	if err := yaml.Unmarshal(buf, &cfg); err != nil {
		return nil, fmt.Errorf("parse ingest config yaml: %w", err)
	}
	cfg.expandEnv()
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *IngestConfig) applyDefaults() {
	if c.Server.Listen == "" {
		c.Server.Listen = "127.0.0.1:8181"
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
		c.Storage.MaxConns = 20
	}
	if c.Storage.MinConns < 0 {
		c.Storage.MinConns = 0
	}
	if c.Security.MaxBodyBytes <= 0 {
		c.Security.MaxBodyBytes = 64 << 20
	}
	if c.Security.EnableBearerAuth == nil {
		c.Security.EnableBearerAuth = boolPtr(true)
	}
	if c.Security.EnableIPAllowList == nil {
		c.Security.EnableIPAllowList = boolPtr(true)
	}
	if c.Security.RequireMachineKeyID == nil {
		c.Security.RequireMachineKeyID = boolPtr(true)
	}
	if c.Security.EnforceSecureTLS == nil {
		c.Security.EnforceSecureTLS = boolPtr(true)
	}
	if c.Logging.Service == "" {
		c.Logging.Service = "votechain-ingest"
	}
	if c.Logging.Version == "" {
		c.Logging.Version = "dev"
	}
	if c.Logging.Commit == "" {
		c.Logging.Commit = "unknown"
	}
	if c.Logging.Region == "" {
		c.Logging.Region = "central-ingest"
	}
}

func (c *IngestConfig) validate() error {
	if c.Storage.PostgresDSN == "" {
		return errors.New("storage.postgres_dsn is required")
	}
	if *c.Security.EnforceSecureTLS && dsnUsesInsecureSSL(c.Storage.PostgresDSN) {
		return errors.New("storage.postgres_dsn must use sslmode=require|verify-ca|verify-full when enforce_secure_transport is enabled")
	}
	if *c.Security.EnableBearerAuth && c.Security.BearerToken == "" {
		return errors.New("security.bearer_token is required when bearer auth is enabled")
	}
	if *c.Security.EnableIPAllowList && len(c.Security.TrustedCIDRs) == 0 {
		return errors.New("security.trusted_cidrs is required when ip allow list is enabled")
	}
	if c.MachineRegistry.Path == "" {
		return errors.New("machine_registry.path is required")
	}
	return nil
}

func boolPtr(v bool) *bool {
	return &v
}

func (c *IngestConfig) expandEnv() {
	c.Storage.PostgresDSN = os.ExpandEnv(strings.TrimSpace(c.Storage.PostgresDSN))
	c.Security.BearerToken = os.ExpandEnv(strings.TrimSpace(c.Security.BearerToken))
	c.MachineRegistry.Path = os.ExpandEnv(strings.TrimSpace(c.MachineRegistry.Path))
}
