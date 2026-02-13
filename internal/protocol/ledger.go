package protocol

import (
	"encoding/json"
	"time"
)

type LedgerAppendRequest struct {
	EventID    string          `json:"event_id"`
	BundleID   string          `json:"bundle_id"`
	EventType  string          `json:"event_type"`
	Payload    json.RawMessage `json:"payload"`
	RecordedAt time.Time       `json:"recorded_at"`
	Source     string          `json:"source"`
}

type LedgerAck struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Sig string `json:"sig"`
}

type LedgerAppendResponse struct {
	NodeRole   string    `json:"node_role"`
	EntryIndex int64     `json:"entry_index"`
	EntryHash  string    `json:"entry_hash"`
	RecordedAt time.Time `json:"recorded_at"`
	Ack        LedgerAck `json:"ack"`
}

type LedgerEntry struct {
	NodeRole     string          `json:"node_role"`
	EntryIndex   int64           `json:"entry_index"`
	EntryHash    string          `json:"entry_hash"`
	PreviousHash string          `json:"previous_hash,omitempty"`
	EventID      string          `json:"event_id"`
	BundleID     string          `json:"bundle_id"`
	EventType    string          `json:"event_type"`
	Payload      json.RawMessage `json:"payload"`
	RecordedAt   time.Time       `json:"recorded_at"`
	CreatedAt    time.Time       `json:"created_at"`
}
