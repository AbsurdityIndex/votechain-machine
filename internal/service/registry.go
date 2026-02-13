package service

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"strings"

	machinecrypto "github.com/votechain/votechain-machine/internal/crypto"
	"gopkg.in/yaml.v3"
)

type MachineIdentity struct {
	MachineID      string
	PrecinctID     string
	JurisdictionID string
	KeyID          string
	PublicKey      ed25519.PublicKey
}

type MachineRegistry struct {
	byMachineID map[string]MachineIdentity
}

type registryFile struct {
	Machines []registryEntry `yaml:"machines"`
}

type registryEntry struct {
	MachineID      string `yaml:"machine_id"`
	PrecinctID     string `yaml:"precinct_id"`
	JurisdictionID string `yaml:"jurisdiction_id"`
	KeyID          string `yaml:"key_id"`
	PublicKey      string `yaml:"public_key"`
	PublicKeyPath  string `yaml:"public_key_path"`
}

func LoadMachineRegistry(path string) (*MachineRegistry, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read machine registry: %w", err)
	}
	var file registryFile
	if err := yaml.Unmarshal(buf, &file); err != nil {
		return nil, fmt.Errorf("parse machine registry yaml: %w", err)
	}
	if len(file.Machines) == 0 {
		return nil, errors.New("machine registry is empty")
	}
	registry := &MachineRegistry{byMachineID: make(map[string]MachineIdentity, len(file.Machines))}
	for i, entry := range file.Machines {
		if entry.MachineID == "" {
			return nil, fmt.Errorf("machine[%d] machine_id is required", i)
		}
		if entry.PrecinctID == "" {
			return nil, fmt.Errorf("machine[%d] precinct_id is required", i)
		}
		if entry.JurisdictionID == "" {
			return nil, fmt.Errorf("machine[%d] jurisdiction_id is required", i)
		}
		if entry.KeyID == "" {
			return nil, fmt.Errorf("machine[%d] key_id is required", i)
		}
		pubRaw := strings.TrimSpace(entry.PublicKey)
		if entry.PublicKeyPath != "" {
			keyBuf, err := os.ReadFile(entry.PublicKeyPath)
			if err != nil {
				return nil, fmt.Errorf("machine[%d] read public_key_path: %w", i, err)
			}
			pubRaw = string(keyBuf)
		}
		if pubRaw == "" {
			return nil, fmt.Errorf("machine[%d] public_key or public_key_path is required", i)
		}
		pub, err := machinecrypto.ParsePublicKey(pubRaw)
		if err != nil {
			return nil, fmt.Errorf("machine[%d] parse public key: %w", i, err)
		}
		if _, exists := registry.byMachineID[entry.MachineID]; exists {
			return nil, fmt.Errorf("duplicate machine_id in registry: %s", entry.MachineID)
		}
		registry.byMachineID[entry.MachineID] = MachineIdentity{
			MachineID:      entry.MachineID,
			PrecinctID:     entry.PrecinctID,
			JurisdictionID: entry.JurisdictionID,
			KeyID:          entry.KeyID,
			PublicKey:      pub,
		}
	}
	return registry, nil
}

func (r *MachineRegistry) Lookup(machineID string) (MachineIdentity, bool) {
	if r == nil {
		return MachineIdentity{}, false
	}
	identity, ok := r.byMachineID[machineID]
	return identity, ok
}
