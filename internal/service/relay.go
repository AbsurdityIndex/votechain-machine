package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/votechain/votechain-machine/internal/config"
	machinecrypto "github.com/votechain/votechain-machine/internal/crypto"
	"github.com/votechain/votechain-machine/internal/protocol"
	"github.com/votechain/votechain-machine/internal/storage/postgres"
)

type AnchorRelay struct {
	store         *postgres.Store
	nodes         []config.RelayNode
	requiredAcks  int
	batchSize     int
	maxBackoff    time.Duration
	httpClients   map[string]*http.Client
	nodePublicKey map[string]ed25519.PublicKey
	nodeAckKeyID  map[string]string
	logger        *slog.Logger
}

func NewAnchorRelay(store *postgres.Store, cfg *config.RelayConfig, logger *slog.Logger) (*AnchorRelay, error) {
	clients := make(map[string]*http.Client, len(cfg.Nodes))
	pubKeys := make(map[string]ed25519.PublicKey, len(cfg.Nodes))
	ackKeyIDs := make(map[string]string, len(cfg.Nodes))
	for _, node := range cfg.Nodes {
		clients[node.Role] = &http.Client{Timeout: time.Duration(node.TimeoutSeconds) * time.Second}
		keyBuf, err := os.ReadFile(node.AckPublicKeyPath)
		if err != nil {
			return nil, fmt.Errorf("read ack public key for node %s: %w", node.Role, err)
		}
		pub, err := machinecrypto.ParsePublicKey(string(keyBuf))
		if err != nil {
			return nil, fmt.Errorf("parse ack public key for node %s: %w", node.Role, err)
		}
		pubKeys[node.Role] = pub
		ackKeyIDs[node.Role] = node.AckKeyID
	}
	return &AnchorRelay{
		store:         store,
		nodes:         cfg.Nodes,
		requiredAcks:  cfg.Relay.RequiredAcks,
		batchSize:     cfg.Relay.BatchSize,
		maxBackoff:    time.Duration(cfg.Relay.MaxBackoffSeconds) * time.Second,
		httpClients:   clients,
		nodePublicKey: pubKeys,
		nodeAckKeyID:  ackKeyIDs,
		logger:        logger,
	}, nil
}

func (r *AnchorRelay) Run(ctx context.Context, pollInterval time.Duration) error {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	if err := r.ProcessBatch(ctx); err != nil {
		r.logger.Error("relay batch failed", slog.String("error", err.Error()))
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := r.ProcessBatch(ctx); err != nil {
				r.logger.Error("relay batch failed", slog.String("error", err.Error()))
			}
		}
	}
}

func (r *AnchorRelay) ProcessBatch(ctx context.Context) error {
	items, err := r.store.FetchPendingOutbox(ctx, r.batchSize)
	if err != nil {
		return err
	}
	if len(items) == 0 {
		return nil
	}

	for _, item := range items {
		if err := r.processItem(ctx, item); err != nil {
			r.logger.Error("relay item failed",
				slog.Int64("outbox_id", item.ID),
				slog.String("bundle_id", item.BundleID),
				slog.String("error", err.Error()),
			)
		}
	}
	return nil
}

func (r *AnchorRelay) processItem(ctx context.Context, item postgres.AnchorOutboxItem) error {
	ackSummaries := make([]map[string]any, 0, len(r.nodes))
	failures := make([]string, 0)
	recordedAt := time.Now().UTC()

	for _, node := range r.nodes {
		resp, err := r.sendToNode(ctx, node, item, recordedAt)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s:%v", node.Role, err))
			continue
		}
		ackSummaries = append(ackSummaries, map[string]any{
			"role":        node.Role,
			"entry_index": resp.EntryIndex,
			"entry_hash":  resp.EntryHash,
			"ack":         resp.Ack,
		})
	}

	if len(ackSummaries) >= r.requiredAcks {
		if err := r.store.MarkOutboxSent(ctx, item.ID, map[string]any{
			"acks":          ackSummaries,
			"required_acks": r.requiredAcks,
			"total_nodes":   len(r.nodes),
			"sent_at":       time.Now().UTC(),
		}); err != nil {
			return err
		}
		r.logger.Info("relay item sent",
			slog.Int64("outbox_id", item.ID),
			slog.String("bundle_id", item.BundleID),
			slog.Int("ack_count", len(ackSummaries)),
		)
		return nil
	}

	attempts := item.Attempts + 1
	backoff := computeBackoff(attempts, r.maxBackoff)
	next := time.Now().UTC().Add(backoff)
	lastError := strings.Join(failures, "; ")
	if lastError == "" {
		lastError = fmt.Sprintf("insufficient acks: got %d want %d", len(ackSummaries), r.requiredAcks)
	}
	if err := r.store.MarkOutboxRetry(ctx, item.ID, attempts, next, truncate(lastError, 1500)); err != nil {
		return err
	}
	return nil
}

func (r *AnchorRelay) sendToNode(ctx context.Context, node config.RelayNode, item postgres.AnchorOutboxItem, recordedAt time.Time) (protocol.LedgerAppendResponse, error) {
	var resp protocol.LedgerAppendResponse
	reqBody := protocol.LedgerAppendRequest{
		EventID:    fmt.Sprintf("outbox_%d", item.ID),
		BundleID:   item.BundleID,
		EventType:  item.EventType,
		Payload:    item.Payload,
		RecordedAt: recordedAt,
		Source:     "votechain-anchor-relay",
	}
	raw, err := protocol.CanonicalJSON(reqBody)
	if err != nil {
		return resp, err
	}
	url := strings.TrimRight(node.URL, "/") + "/v1/ledger/append"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return resp, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-VoteChain-Write-Token", node.WriteToken)

	client := r.httpClients[node.Role]
	httpResp, err := client.Do(httpReq)
	if err != nil {
		return resp, err
	}
	defer httpResp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(httpResp.Body, 2<<20))
	if err != nil {
		return resp, err
	}
	if httpResp.StatusCode != http.StatusOK {
		return resp, fmt.Errorf("status %d body=%s", httpResp.StatusCode, string(body))
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return resp, err
	}
	if resp.NodeRole != node.Role {
		return resp, fmt.Errorf("node role mismatch: got %s want %s", resp.NodeRole, node.Role)
	}
	if err := r.verifyAck(node, reqBody, resp); err != nil {
		return resp, err
	}
	return resp, nil
}

func (r *AnchorRelay) verifyAck(node config.RelayNode, req protocol.LedgerAppendRequest, resp protocol.LedgerAppendResponse) error {
	if resp.Ack.Alg != "ed25519" {
		return fmt.Errorf("unsupported ack alg: %s", resp.Ack.Alg)
	}
	expectedKeyID := r.nodeAckKeyID[node.Role]
	if expectedKeyID != "" && resp.Ack.Kid != expectedKeyID {
		return fmt.Errorf("ack key id mismatch: got %s want %s", resp.Ack.Kid, expectedKeyID)
	}
	pub, ok := r.nodePublicKey[node.Role]
	if !ok {
		return fmt.Errorf("missing public key for node role %s", node.Role)
	}
	payload := struct {
		NodeRole   string    `json:"node_role"`
		EntryIndex int64     `json:"entry_index"`
		EntryHash  string    `json:"entry_hash"`
		EventID    string    `json:"event_id"`
		RecordedAt time.Time `json:"recorded_at"`
		KeyID      string    `json:"kid"`
	}{
		NodeRole:   resp.NodeRole,
		EntryIndex: resp.EntryIndex,
		EntryHash:  resp.EntryHash,
		EventID:    req.EventID,
		RecordedAt: resp.RecordedAt,
		KeyID:      resp.Ack.Kid,
	}
	raw, err := protocol.CanonicalJSON(payload)
	if err != nil {
		return err
	}
	if !machinecrypto.Verify(pub, raw, resp.Ack.Sig) {
		return fmt.Errorf("invalid ack signature")
	}
	return nil
}

func computeBackoff(attempts int, max time.Duration) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	backoff := time.Duration(1<<uint(min(attempts, 10))) * 5 * time.Second
	if backoff > max {
		return max
	}
	return backoff
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
