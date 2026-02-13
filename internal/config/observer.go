package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type ObserverConfig struct {
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
		URL            string `yaml:"url"`
		BearerToken    string `yaml:"bearer_token"`
		TimeoutSeconds int    `yaml:"timeout_seconds"`
	} `yaml:"machine"`

	Ingest struct {
		URL            string `yaml:"url"`
		BearerToken    string `yaml:"bearer_token"`
		TimeoutSeconds int    `yaml:"timeout_seconds"`
	} `yaml:"ingest"`

	Nodes []ObserverNode `yaml:"nodes"`

	Security struct {
		EnforceSecureTLS *bool `yaml:"enforce_secure_transport"`
	} `yaml:"security"`

	Logging struct {
		Service string `yaml:"service"`
		Version string `yaml:"version"`
		Commit  string `yaml:"commit"`
		Region  string `yaml:"region"`
	} `yaml:"logging"`
}

type ObserverNode struct {
	Role           string `yaml:"role"`
	URL            string `yaml:"url"`
	TimeoutSeconds int    `yaml:"timeout_seconds"`
}

func LoadObserver(path string) (*ObserverConfig, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read observer config: %w", err)
	}
	var cfg ObserverConfig
	if err := yaml.Unmarshal(buf, &cfg); err != nil {
		return nil, fmt.Errorf("parse observer config yaml: %w", err)
	}
	cfg.expandEnv()
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *ObserverConfig) applyDefaults() {
	if c.Server.Listen == "" {
		c.Server.Listen = "127.0.0.1:8282"
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
	if c.Storage.MaxConns <= 0 {
		c.Storage.MaxConns = 8
	}
	if c.Storage.MinConns < 0 {
		c.Storage.MinConns = 0
	}
	if c.Machine.TimeoutSeconds <= 0 {
		c.Machine.TimeoutSeconds = 5
	}
	if c.Ingest.TimeoutSeconds <= 0 {
		c.Ingest.TimeoutSeconds = 5
	}
	for i := range c.Nodes {
		if c.Nodes[i].TimeoutSeconds <= 0 {
			c.Nodes[i].TimeoutSeconds = 5
		}
	}
	if c.Security.EnforceSecureTLS == nil {
		c.Security.EnforceSecureTLS = boolPtr(true)
	}
	if c.Logging.Service == "" {
		c.Logging.Service = "votechain-observer"
	}
	if c.Logging.Version == "" {
		c.Logging.Version = "dev"
	}
	if c.Logging.Commit == "" {
		c.Logging.Commit = "unknown"
	}
	if c.Logging.Region == "" {
		c.Logging.Region = "observer"
	}
}

func (c *ObserverConfig) validate() error {
	if c.Storage.PostgresDSN == "" {
		return errors.New("storage.postgres_dsn is required")
	}
	if *c.Security.EnforceSecureTLS && dsnUsesInsecureSSL(c.Storage.PostgresDSN) {
		return errors.New("storage.postgres_dsn must use sslmode=require|verify-ca|verify-full when enforce_secure_transport is enabled")
	}
	if c.Ingest.URL == "" {
		return errors.New("ingest.url is required")
	}
	if *c.Security.EnforceSecureTLS {
		if !isHTTPSURL(c.Ingest.URL) {
			return errors.New("ingest.url must be https when enforce_secure_transport is enabled")
		}
		if strings.TrimSpace(c.Machine.URL) != "" && !isHTTPSURL(c.Machine.URL) {
			return errors.New("machine.url must be https when enforce_secure_transport is enabled")
		}
	}
	if len(c.Nodes) == 0 {
		return errors.New("nodes are required")
	}
	for i, n := range c.Nodes {
		if n.Role == "" {
			return fmt.Errorf("nodes[%d].role is required", i)
		}
		if n.URL == "" {
			return fmt.Errorf("nodes[%d].url is required", i)
		}
		if *c.Security.EnforceSecureTLS && !isHTTPSURL(n.URL) {
			return fmt.Errorf("nodes[%d].url must be https when enforce_secure_transport is enabled", i)
		}
	}
	return nil
}

func (c *ObserverConfig) expandEnv() {
	c.Storage.PostgresDSN = os.ExpandEnv(strings.TrimSpace(c.Storage.PostgresDSN))
	c.Machine.URL = os.ExpandEnv(strings.TrimSpace(c.Machine.URL))
	c.Machine.BearerToken = os.ExpandEnv(strings.TrimSpace(c.Machine.BearerToken))
	c.Ingest.URL = os.ExpandEnv(strings.TrimSpace(c.Ingest.URL))
	c.Ingest.BearerToken = os.ExpandEnv(strings.TrimSpace(c.Ingest.BearerToken))
	for i := range c.Nodes {
		c.Nodes[i].URL = os.ExpandEnv(strings.TrimSpace(c.Nodes[i].URL))
	}
}
