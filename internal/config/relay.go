package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type RelayConfig struct {
	Storage struct {
		PostgresDSN string `yaml:"postgres_dsn"`
		MaxConns    int32  `yaml:"max_conns"`
		MinConns    int32  `yaml:"min_conns"`
	} `yaml:"storage"`

	Security struct {
		EnforceSecureTLS *bool `yaml:"enforce_secure_transport"`
	} `yaml:"security"`

	Relay struct {
		PollIntervalSeconds int `yaml:"poll_interval_seconds"`
		BatchSize           int `yaml:"batch_size"`
		RequiredAcks        int `yaml:"required_acks"`
		MaxBackoffSeconds   int `yaml:"max_backoff_seconds"`
	} `yaml:"relay"`

	Nodes []RelayNode `yaml:"nodes"`

	Logging struct {
		Service string `yaml:"service"`
		Version string `yaml:"version"`
		Commit  string `yaml:"commit"`
		Region  string `yaml:"region"`
	} `yaml:"logging"`
}

type RelayNode struct {
	Role             string `yaml:"role"`
	URL              string `yaml:"url"`
	WriteToken       string `yaml:"write_token"`
	AckKeyID         string `yaml:"ack_key_id"`
	AckPublicKeyPath string `yaml:"ack_public_key_path"`
	TimeoutSeconds   int    `yaml:"timeout_seconds"`
}

func LoadRelay(path string) (*RelayConfig, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read relay config: %w", err)
	}
	var cfg RelayConfig
	if err := yaml.Unmarshal(buf, &cfg); err != nil {
		return nil, fmt.Errorf("parse relay config yaml: %w", err)
	}
	cfg.expandEnv()
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *RelayConfig) applyDefaults() {
	if c.Storage.MaxConns <= 0 {
		c.Storage.MaxConns = 10
	}
	if c.Storage.MinConns < 0 {
		c.Storage.MinConns = 0
	}
	if c.Security.EnforceSecureTLS == nil {
		c.Security.EnforceSecureTLS = boolPtr(true)
	}
	if c.Relay.PollIntervalSeconds <= 0 {
		c.Relay.PollIntervalSeconds = 10
	}
	if c.Relay.BatchSize <= 0 {
		c.Relay.BatchSize = 50
	}
	if c.Relay.RequiredAcks <= 0 {
		c.Relay.RequiredAcks = 2
	}
	if c.Relay.MaxBackoffSeconds <= 0 {
		c.Relay.MaxBackoffSeconds = 600
	}
	if c.Logging.Service == "" {
		c.Logging.Service = "votechain-anchor-relay"
	}
	if c.Logging.Version == "" {
		c.Logging.Version = "dev"
	}
	if c.Logging.Commit == "" {
		c.Logging.Commit = "unknown"
	}
	if c.Logging.Region == "" {
		c.Logging.Region = "relay"
	}
	for i := range c.Nodes {
		if c.Nodes[i].TimeoutSeconds <= 0 {
			c.Nodes[i].TimeoutSeconds = 10
		}
	}
}

func (c *RelayConfig) validate() error {
	if c.Storage.PostgresDSN == "" {
		return errors.New("storage.postgres_dsn is required")
	}
	if *c.Security.EnforceSecureTLS && dsnUsesInsecureSSL(c.Storage.PostgresDSN) {
		return errors.New("storage.postgres_dsn must use sslmode=require|verify-ca|verify-full when enforce_secure_transport is enabled")
	}
	if len(c.Nodes) == 0 {
		return errors.New("nodes are required")
	}
	if c.Relay.RequiredAcks > len(c.Nodes) {
		return errors.New("relay.required_acks cannot exceed number of nodes")
	}
	allowedRoles := map[string]struct{}{
		"federal":   {},
		"state":     {},
		"oversight": {},
	}
	seenRoles := make(map[string]struct{}, len(c.Nodes))
	for i, n := range c.Nodes {
		if n.Role == "" {
			return fmt.Errorf("nodes[%d].role is required", i)
		}
		if _, ok := allowedRoles[n.Role]; !ok {
			return fmt.Errorf("nodes[%d].role must be one of federal|state|oversight", i)
		}
		if _, exists := seenRoles[n.Role]; exists {
			return fmt.Errorf("duplicate node role in relay config: %s", n.Role)
		}
		seenRoles[n.Role] = struct{}{}
		if n.URL == "" {
			return fmt.Errorf("nodes[%d].url is required", i)
		}
		if *c.Security.EnforceSecureTLS && !isHTTPSURL(n.URL) {
			return fmt.Errorf("nodes[%d].url must be https when enforce_secure_transport is enabled", i)
		}
		if n.WriteToken == "" {
			return fmt.Errorf("nodes[%d].write_token is required", i)
		}
		if n.AckKeyID == "" {
			return fmt.Errorf("nodes[%d].ack_key_id is required", i)
		}
		if n.AckPublicKeyPath == "" {
			return fmt.Errorf("nodes[%d].ack_public_key_path is required", i)
		}
	}
	for role := range allowedRoles {
		if _, ok := seenRoles[role]; !ok {
			return fmt.Errorf("missing required relay node role: %s", role)
		}
	}
	return nil
}

func (c *RelayConfig) expandEnv() {
	c.Storage.PostgresDSN = os.ExpandEnv(strings.TrimSpace(c.Storage.PostgresDSN))
	for i := range c.Nodes {
		c.Nodes[i].URL = os.ExpandEnv(strings.TrimSpace(c.Nodes[i].URL))
		c.Nodes[i].WriteToken = os.ExpandEnv(strings.TrimSpace(c.Nodes[i].WriteToken))
		c.Nodes[i].AckKeyID = os.ExpandEnv(strings.TrimSpace(c.Nodes[i].AckKeyID))
		c.Nodes[i].AckPublicKeyPath = os.ExpandEnv(strings.TrimSpace(c.Nodes[i].AckPublicKeyPath))
	}
}
