package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config captures machine-local runtime settings for an air-gapped polling place device.
type Config struct {
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

	Machine struct {
		MachineID      string `yaml:"machine_id"`
		PrecinctID     string `yaml:"precinct_id"`
		JurisdictionID string `yaml:"jurisdiction_id"`
		Mode           string `yaml:"mode"`
	} `yaml:"machine"`

	Keys struct {
		SigningPrivateKeyPath string `yaml:"signing_private_key_path"`
		SigningPublicKeyPath  string `yaml:"signing_public_key_path"`
	} `yaml:"keys"`

	Election struct {
		ChallengeTTLSeconds int `yaml:"challenge_ttl_seconds"`
	} `yaml:"election"`

	Security struct {
		BearerToken      string   `yaml:"bearer_token"`
		TrustedCIDRs     []string `yaml:"trusted_cidrs"`
		EnableIPAllow    *bool    `yaml:"enable_ip_allow_list"`
		EnableBearerAuth *bool    `yaml:"enable_bearer_auth"`
		EnforceAirGap    *bool    `yaml:"enforce_air_gap_mode"`
		EnforceSecureTLS *bool    `yaml:"enforce_secure_transport"`
	} `yaml:"security"`

	Sync struct {
		ExportDir string `yaml:"export_dir"`
	} `yaml:"sync"`

	Logging struct {
		Service string `yaml:"service"`
		Version string `yaml:"version"`
		Commit  string `yaml:"commit"`
		Region  string `yaml:"region"`
	} `yaml:"logging"`
}

// Load reads and validates config from disk.
func Load(path string) (*Config, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(buf, &cfg); err != nil {
		return nil, fmt.Errorf("parse config yaml: %w", err)
	}
	cfg.expandEnv()
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.Sync.ExportDir, 0o700); err != nil {
		return nil, fmt.Errorf("create export directory: %w", err)
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Server.Listen == "" {
		c.Server.Listen = "127.0.0.1:8080"
	}
	if c.Server.ReadTimeoutSeconds <= 0 {
		c.Server.ReadTimeoutSeconds = 10
	}
	if c.Server.WriteTimeoutSeconds <= 0 {
		c.Server.WriteTimeoutSeconds = 20
	}
	if c.Server.ShutdownTimeoutSeconds <= 0 {
		c.Server.ShutdownTimeoutSeconds = 15
	}
	if c.Machine.Mode == "" {
		c.Machine.Mode = "air-gapped"
	}
	if c.Election.ChallengeTTLSeconds <= 0 {
		c.Election.ChallengeTTLSeconds = 120
	}
	if c.Security.EnableBearerAuth == nil {
		c.Security.EnableBearerAuth = boolPtr(true)
	}
	if c.Security.EnableIPAllow == nil {
		c.Security.EnableIPAllow = boolPtr(true)
	}
	if c.Security.EnforceAirGap == nil {
		c.Security.EnforceAirGap = boolPtr(true)
	}
	if c.Security.EnforceSecureTLS == nil {
		c.Security.EnforceSecureTLS = boolPtr(true)
	}
	if len(c.Security.TrustedCIDRs) == 0 {
		c.Security.TrustedCIDRs = []string{
			"127.0.0.1/32",
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
		}
	}
	if c.Storage.MaxConns <= 0 {
		c.Storage.MaxConns = 12
	}
	if c.Storage.MinConns < 0 {
		c.Storage.MinConns = 0
	}
	if c.Logging.Service == "" {
		c.Logging.Service = "votechain-machine"
	}
	if c.Logging.Version == "" {
		c.Logging.Version = "dev"
	}
	if c.Logging.Commit == "" {
		c.Logging.Commit = "unknown"
	}
	if c.Logging.Region == "" {
		c.Logging.Region = "polling-place"
	}
}

func (c *Config) validate() error {
	if c.Storage.PostgresDSN == "" {
		return errors.New("storage.postgres_dsn is required")
	}
	if c.Machine.MachineID == "" {
		return errors.New("machine.machine_id is required")
	}
	if c.Machine.PrecinctID == "" {
		return errors.New("machine.precinct_id is required")
	}
	if c.Machine.JurisdictionID == "" {
		return errors.New("machine.jurisdiction_id is required")
	}
	if c.Keys.SigningPrivateKeyPath == "" {
		return errors.New("keys.signing_private_key_path is required")
	}
	if c.Keys.SigningPublicKeyPath == "" {
		return errors.New("keys.signing_public_key_path is required")
	}
	if c.Sync.ExportDir == "" {
		return errors.New("sync.export_dir is required")
	}
	if *c.Security.EnforceSecureTLS && dsnUsesInsecureSSL(c.Storage.PostgresDSN) {
		return errors.New("storage.postgres_dsn must use sslmode=require|verify-ca|verify-full when enforce_secure_transport is enabled")
	}
	switch strings.TrimSpace(strings.ToLower(c.Machine.Mode)) {
	case "air-gapped", "connected":
	default:
		return errors.New("machine.mode must be one of air-gapped|connected")
	}
	if *c.Security.EnableBearerAuth && strings.TrimSpace(c.Security.BearerToken) == "" {
		return errors.New("security.bearer_token is required when bearer auth is enabled")
	}
	if *c.Security.EnableIPAllow && len(c.Security.TrustedCIDRs) == 0 {
		return errors.New("security.trusted_cidrs is required when ip allow list is enabled")
	}
	for i, cidr := range c.Security.TrustedCIDRs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("security.trusted_cidrs[%d] is invalid: %w", i, err)
		}
	}
	if strings.EqualFold(strings.TrimSpace(c.Machine.Mode), "air-gapped") && *c.Security.EnforceAirGap {
		if !*c.Security.EnableIPAllow {
			return errors.New("security.enable_ip_allow_list must be true in enforced air-gapped mode")
		}
		host, _, err := net.SplitHostPort(strings.TrimSpace(c.Server.Listen))
		if err == nil {
			host = strings.TrimSpace(host)
			if host == "0.0.0.0" || host == "::" || host == "" {
				return errors.New("server.listen must not bind all interfaces in enforced air-gapped mode")
			}
		}
		if host := dsnHost(c.Storage.PostgresDSN); host != "" {
			if !isLoopbackHost(host) && !strings.EqualFold(host, "localhost") {
				return fmt.Errorf("storage.postgres_dsn host must be localhost/loopback in enforced air-gapped mode, got %q", host)
			}
		}
	}
	return nil
}

func (c *Config) expandEnv() {
	c.Storage.PostgresDSN = os.ExpandEnv(strings.TrimSpace(c.Storage.PostgresDSN))
	c.Keys.SigningPrivateKeyPath = os.ExpandEnv(strings.TrimSpace(c.Keys.SigningPrivateKeyPath))
	c.Keys.SigningPublicKeyPath = os.ExpandEnv(strings.TrimSpace(c.Keys.SigningPublicKeyPath))
	c.Sync.ExportDir = os.ExpandEnv(strings.TrimSpace(c.Sync.ExportDir))
	c.Security.BearerToken = os.ExpandEnv(strings.TrimSpace(c.Security.BearerToken))
}
