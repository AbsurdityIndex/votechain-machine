package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadRelayRejectsRogueRole(t *testing.T) {
	path := writeRelayConfigForTest(t, `
storage:
  postgres_dsn: "postgres://user:pass@localhost:5432/db?sslmode=disable"
security:
  enforce_secure_transport: false
relay:
  required_acks: 2
nodes:
  - role: "federal"
    url: "http://127.0.0.1:8301"
    write_token: "tok"
    ack_key_id: "ed25519:a"
    ack_public_key_path: "/tmp/a.pem"
  - role: "state"
    url: "http://127.0.0.1:8302"
    write_token: "tok"
    ack_key_id: "ed25519:b"
    ack_public_key_path: "/tmp/b.pem"
  - role: "rogue"
    url: "http://127.0.0.1:8309"
    write_token: "tok"
    ack_key_id: "ed25519:c"
    ack_public_key_path: "/tmp/c.pem"
`)
	_, err := LoadRelay(path)
	if err == nil || !strings.Contains(err.Error(), "must be one of federal|state|oversight") {
		t.Fatalf("expected unauthorized role error, got %v", err)
	}
}

func TestLoadRelayRejectsInsecurePostgresWhenSecureTransportEnabled(t *testing.T) {
	path := writeRelayConfigForTest(t, `
storage:
  postgres_dsn: "postgres://user:pass@localhost:5432/db?sslmode=disable"
relay:
  required_acks: 2
nodes:
  - role: "federal"
    url: "https://ledger-federal.local"
    write_token: "tok"
    ack_key_id: "ed25519:a"
    ack_public_key_path: "/tmp/a.pem"
  - role: "state"
    url: "https://ledger-state.local"
    write_token: "tok"
    ack_key_id: "ed25519:b"
    ack_public_key_path: "/tmp/b.pem"
  - role: "oversight"
    url: "https://ledger-oversight.local"
    write_token: "tok"
    ack_key_id: "ed25519:c"
    ack_public_key_path: "/tmp/c.pem"
`)
	_, err := LoadRelay(path)
	if err == nil || !strings.Contains(err.Error(), "storage.postgres_dsn must use sslmode") {
		t.Fatalf("expected secure postgres transport error, got %v", err)
	}
}

func TestLoadRelayRejectsHTTPNodeURLWhenSecureTransportEnabled(t *testing.T) {
	path := writeRelayConfigForTest(t, `
storage:
  postgres_dsn: "postgres://user:pass@localhost:5432/db?sslmode=require"
relay:
  required_acks: 2
nodes:
  - role: "federal"
    url: "http://127.0.0.1:8301"
    write_token: "tok"
    ack_key_id: "ed25519:a"
    ack_public_key_path: "/tmp/a.pem"
  - role: "state"
    url: "https://ledger-state.local"
    write_token: "tok"
    ack_key_id: "ed25519:b"
    ack_public_key_path: "/tmp/b.pem"
  - role: "oversight"
    url: "https://ledger-oversight.local"
    write_token: "tok"
    ack_key_id: "ed25519:c"
    ack_public_key_path: "/tmp/c.pem"
`)
	_, err := LoadRelay(path)
	if err == nil || !strings.Contains(err.Error(), "nodes[0].url must be https") {
		t.Fatalf("expected secure node url error, got %v", err)
	}
}

func TestLoadRelayRejectsDuplicateRole(t *testing.T) {
	path := writeRelayConfigForTest(t, `
storage:
  postgres_dsn: "postgres://user:pass@localhost:5432/db?sslmode=disable"
security:
  enforce_secure_transport: false
relay:
  required_acks: 2
nodes:
  - role: "federal"
    url: "http://127.0.0.1:8301"
    write_token: "tok"
    ack_key_id: "ed25519:a"
    ack_public_key_path: "/tmp/a.pem"
  - role: "state"
    url: "http://127.0.0.1:8302"
    write_token: "tok"
    ack_key_id: "ed25519:b"
    ack_public_key_path: "/tmp/b.pem"
  - role: "state"
    url: "http://127.0.0.1:8303"
    write_token: "tok"
    ack_key_id: "ed25519:c"
    ack_public_key_path: "/tmp/c.pem"
`)
	_, err := LoadRelay(path)
	if err == nil || !strings.Contains(err.Error(), "duplicate node role") {
		t.Fatalf("expected duplicate role error, got %v", err)
	}
}

func TestLoadRelayRejectsMissingRole(t *testing.T) {
	path := writeRelayConfigForTest(t, `
storage:
  postgres_dsn: "postgres://user:pass@localhost:5432/db?sslmode=disable"
security:
  enforce_secure_transport: false
relay:
  required_acks: 2
nodes:
  - role: "federal"
    url: "http://127.0.0.1:8301"
    write_token: "tok"
    ack_key_id: "ed25519:a"
    ack_public_key_path: "/tmp/a.pem"
  - role: "state"
    url: "http://127.0.0.1:8302"
    write_token: "tok"
    ack_key_id: "ed25519:b"
    ack_public_key_path: "/tmp/b.pem"
`)
	_, err := LoadRelay(path)
	if err == nil || !strings.Contains(err.Error(), "missing required relay node role: oversight") {
		t.Fatalf("expected missing role error, got %v", err)
	}
}

func writeRelayConfigForTest(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "relay.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write test config: %v", err)
	}
	return path
}
