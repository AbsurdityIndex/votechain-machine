package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/votechain/votechain-machine/internal/config"
	"github.com/votechain/votechain-machine/internal/protocol"
	"github.com/votechain/votechain-machine/internal/storage/postgres"
)

type ObserverService struct {
	store        *postgres.Store
	machineURL   string
	machineToken string
	hasMachine   bool
	ingestURL    string
	ingestToken  string
	nodes        []config.ObserverNode
	clients      map[string]*http.Client
	service      string
	version      string
}

type ObserverStatus struct {
	Service     string            `json:"service"`
	Version     string            `json:"version"`
	Timestamp   time.Time         `json:"timestamp"`
	Overall     string            `json:"overall"`
	Machine     ComponentStatus   `json:"machine"`
	Ingest      ComponentStatus   `json:"ingest"`
	IngestData  IngestDataStatus  `json:"ingest_data"`
	Blockchain  BlockchainStatus  `json:"blockchain"`
	Consistency ConsistencyStatus `json:"consistency"`
}

type ComponentStatus struct {
	URL        string `json:"url"`
	Healthy    bool   `json:"healthy"`
	StatusCode int    `json:"status_code,omitempty"`
	Error      string `json:"error,omitempty"`
}

type IngestDataStatus struct {
	BundleCount    int        `json:"bundle_count"`
	ReceiptCount   int        `json:"receipt_count"`
	OutboxPending  int        `json:"outbox_pending"`
	OutboxSent     int        `json:"outbox_sent"`
	LatestBundleID string     `json:"latest_bundle_id,omitempty"`
	LatestBundleAt *time.Time `json:"latest_bundle_at,omitempty"`
}

type BlockchainStatus struct {
	Nodes []NodeStatus `json:"nodes"`
}

type NodeStatus struct {
	Role        string `json:"role"`
	URL         string `json:"url"`
	Healthy     bool   `json:"healthy"`
	StatusCode  int    `json:"status_code,omitempty"`
	Error       string `json:"error,omitempty"`
	LatestIndex int64  `json:"latest_index,omitempty"`
	LatestHash  string `json:"latest_hash,omitempty"`
	ConsensusAt string `json:"consensus_entry_hash,omitempty"`
}

type ConsistencyStatus struct {
	Status               string            `json:"status"`
	HealthyNodes         int               `json:"healthy_nodes"`
	RequiredNodes        int               `json:"required_nodes"`
	MinCommonIndex       int64             `json:"min_common_index"`
	MaxIndex             int64             `json:"max_index"`
	IndexSkew            int64             `json:"index_skew"`
	ConsensusEntryHashes map[string]string `json:"consensus_entry_hashes,omitempty"`
	Details              string            `json:"details,omitempty"`
}

func NewObserver(store *postgres.Store, cfg *config.ObserverConfig) *ObserverService {
	clients := make(map[string]*http.Client, len(cfg.Nodes)+2)
	hasMachine := strings.TrimSpace(cfg.Machine.URL) != ""
	if hasMachine {
		clients["machine"] = &http.Client{Timeout: time.Duration(cfg.Machine.TimeoutSeconds) * time.Second}
	}
	clients["ingest"] = &http.Client{Timeout: time.Duration(cfg.Ingest.TimeoutSeconds) * time.Second}
	for _, n := range cfg.Nodes {
		clients[n.Role] = &http.Client{Timeout: time.Duration(n.TimeoutSeconds) * time.Second}
	}
	return &ObserverService{
		store:        store,
		machineURL:   strings.TrimRight(cfg.Machine.URL, "/"),
		machineToken: cfg.Machine.BearerToken,
		hasMachine:   hasMachine,
		ingestURL:    strings.TrimRight(cfg.Ingest.URL, "/"),
		ingestToken:  cfg.Ingest.BearerToken,
		nodes:        cfg.Nodes,
		clients:      clients,
		service:      cfg.Logging.Service,
		version:      cfg.Logging.Version,
	}
}

func (s *ObserverService) Status(ctx context.Context) (ObserverStatus, error) {
	snap, err := s.store.GetIngestSnapshot(ctx)
	if err != nil {
		return ObserverStatus{}, Internal("read ingest snapshot", err)
	}

	machine := ComponentStatus{URL: "", Healthy: true}
	if s.hasMachine {
		machine = s.checkComponent(ctx, "machine", s.machineURL+"/healthz", s.machineToken)
	}
	ingest := s.checkComponent(ctx, "ingest", s.ingestURL+"/healthz", s.ingestToken)

	nodes := make([]NodeStatus, 0, len(s.nodes))
	for _, n := range s.nodes {
		nodes = append(nodes, s.checkNode(ctx, n))
	}
	consistency := s.evaluateConsistency(ctx, nodes)

	overall := "ok"
	if (!machine.Healthy && s.hasMachine) || !ingest.Healthy || consistency.Status == "fail" {
		overall = "fail"
	} else if consistency.Status == "degraded" || snap.OutboxPending > 0 {
		overall = "degraded"
	}

	return ObserverStatus{
		Service:   s.service,
		Version:   s.version,
		Timestamp: time.Now().UTC(),
		Overall:   overall,
		Machine:   machine,
		Ingest:    ingest,
		IngestData: IngestDataStatus{
			BundleCount:    snap.BundleCount,
			ReceiptCount:   snap.ReceiptCount,
			OutboxPending:  snap.OutboxPending,
			OutboxSent:     snap.OutboxSent,
			LatestBundleID: snap.LatestBundleID,
			LatestBundleAt: snap.LatestBundleAt,
		},
		Blockchain:  BlockchainStatus{Nodes: nodes},
		Consistency: consistency,
	}, nil
}

func (s *ObserverService) MarkdownReport(status ObserverStatus) string {
	var b strings.Builder
	b.WriteString("# VoteChain Working Group Demo Status\n\n")
	b.WriteString(fmt.Sprintf("- Timestamp: %s\n", status.Timestamp.Format(time.RFC3339)))
	b.WriteString(fmt.Sprintf("- Overall: **%s**\n", strings.ToUpper(status.Overall)))
	b.WriteString(fmt.Sprintf("- Ingest bundles: %d\n", status.IngestData.BundleCount))
	b.WriteString(fmt.Sprintf("- Ingest receipts: %d\n", status.IngestData.ReceiptCount))
	b.WriteString(fmt.Sprintf("- Outbox pending: %d\n", status.IngestData.OutboxPending))
	b.WriteString(fmt.Sprintf("- Outbox sent: %d\n", status.IngestData.OutboxSent))
	if status.IngestData.LatestBundleID != "" {
		b.WriteString(fmt.Sprintf("- Latest bundle: %s\n", status.IngestData.LatestBundleID))
	}
	b.WriteString("\n## Components\n\n")
	if s.hasMachine {
		b.WriteString(fmt.Sprintf("- Machine: %s\n", healthWord(status.Machine.Healthy)))
	} else {
		b.WriteString("- Machine: not-configured\n")
	}
	b.WriteString(fmt.Sprintf("- Ingest: %s\n", healthWord(status.Ingest.Healthy)))
	b.WriteString("\n## Blockchain Nodes\n\n")
	for _, n := range status.Blockchain.Nodes {
		if n.Healthy {
			b.WriteString(fmt.Sprintf("- %s: %s (latest_index=%d)\n", n.Role, healthWord(true), n.LatestIndex))
		} else {
			b.WriteString(fmt.Sprintf("- %s: %s (%s)\n", n.Role, healthWord(false), n.Error))
		}
	}
	b.WriteString("\n## Consistency\n\n")
	b.WriteString(fmt.Sprintf("- Status: %s\n", strings.ToUpper(status.Consistency.Status)))
	b.WriteString(fmt.Sprintf("- Healthy nodes: %d/%d\n", status.Consistency.HealthyNodes, status.Consistency.RequiredNodes))
	b.WriteString(fmt.Sprintf("- Min common index: %d\n", status.Consistency.MinCommonIndex))
	b.WriteString(fmt.Sprintf("- Index skew: %d\n", status.Consistency.IndexSkew))
	if status.Consistency.Details != "" {
		b.WriteString(fmt.Sprintf("- Details: %s\n", status.Consistency.Details))
	}
	return b.String()
}

func (s *ObserverService) checkComponent(ctx context.Context, clientKey, url, bearer string) ComponentStatus {
	client := s.clients[clientKey]
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ComponentStatus{URL: url, Healthy: false, Error: err.Error()}
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := client.Do(req)
	if err != nil {
		return ComponentStatus{URL: url, Healthy: false, Error: err.Error()}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	healthy := resp.StatusCode >= 200 && resp.StatusCode < 300
	status := ComponentStatus{URL: url, Healthy: healthy, StatusCode: resp.StatusCode}
	if !healthy {
		status.Error = fmt.Sprintf("status=%d", resp.StatusCode)
	}
	return status
}

func (s *ObserverService) checkNode(ctx context.Context, node config.ObserverNode) NodeStatus {
	url := strings.TrimRight(node.URL, "/") + "/healthz"
	client := s.clients[node.Role]
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return NodeStatus{Role: node.Role, URL: node.URL, Healthy: false, Error: err.Error()}
	}
	resp, err := client.Do(req)
	if err != nil {
		return NodeStatus{Role: node.Role, URL: node.URL, Healthy: false, Error: err.Error()}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return NodeStatus{Role: node.Role, URL: node.URL, Healthy: false, StatusCode: resp.StatusCode, Error: fmt.Sprintf("status=%d", resp.StatusCode)}
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return NodeStatus{Role: node.Role, URL: node.URL, Healthy: false, StatusCode: resp.StatusCode, Error: "invalid health payload"}
	}
	status := NodeStatus{Role: node.Role, URL: node.URL, Healthy: true, StatusCode: resp.StatusCode}
	if v, ok := payload["latest_index"].(float64); ok {
		status.LatestIndex = int64(v)
	}
	if v, ok := payload["latest_hash"].(string); ok {
		status.LatestHash = v
	}
	return status
}

func (s *ObserverService) evaluateConsistency(ctx context.Context, nodes []NodeStatus) ConsistencyStatus {
	status := ConsistencyStatus{Status: "ok", RequiredNodes: len(nodes)}
	healthy := make([]NodeStatus, 0, len(nodes))
	for _, n := range nodes {
		if n.Healthy {
			healthy = append(healthy, n)
		}
	}
	status.HealthyNodes = len(healthy)
	if len(healthy) < 2 {
		status.Status = "fail"
		status.Details = "fewer than two healthy ledger nodes"
		return status
	}

	minIdx := healthy[0].LatestIndex
	maxIdx := healthy[0].LatestIndex
	for _, n := range healthy[1:] {
		if n.LatestIndex < minIdx {
			minIdx = n.LatestIndex
		}
		if n.LatestIndex > maxIdx {
			maxIdx = n.LatestIndex
		}
	}
	status.MinCommonIndex = minIdx
	status.MaxIndex = maxIdx
	status.IndexSkew = maxIdx - minIdx

	if minIdx <= 0 {
		if status.IndexSkew > 0 {
			status.Status = "degraded"
			status.Details = "nodes have no shared committed entry yet"
		} else {
			status.Details = "no ledger entries committed yet"
		}
		return status
	}

	hashes := map[string]string{}
	for i, n := range healthy {
		entry, err := s.fetchLedgerEntry(ctx, n.Role, n.URL, minIdx)
		if err != nil {
			status.Status = "fail"
			status.Details = fmt.Sprintf("failed to read entry %d from %s: %v", minIdx, n.Role, err)
			return status
		}
		hashes[n.Role] = entry.EntryHash
		healthy[i].ConsensusAt = entry.EntryHash
	}
	status.ConsensusEntryHashes = hashes

	uniq := map[string]struct{}{}
	for _, h := range hashes {
		uniq[h] = struct{}{}
	}
	if len(uniq) > 1 {
		status.Status = "fail"
		status.Details = fmt.Sprintf("hash divergence at common index %d", minIdx)
		return status
	}
	if status.IndexSkew > 0 {
		status.Status = "degraded"
		status.Details = "nodes are healthy but not yet at equal height"
		return status
	}
	status.Status = "ok"
	status.Details = "nodes are consistent"
	return status
}

func (s *ObserverService) fetchLedgerEntry(ctx context.Context, role, baseURL string, index int64) (protocol.LedgerEntry, error) {
	client := s.clients[role]
	url := fmt.Sprintf("%s/v1/ledger/entries/%d", strings.TrimRight(baseURL, "/"), index)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return protocol.LedgerEntry{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return protocol.LedgerEntry{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return protocol.LedgerEntry{}, fmt.Errorf("status=%d body=%s", resp.StatusCode, string(body))
	}
	var entry protocol.LedgerEntry
	dec := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&entry); err != nil {
		return protocol.LedgerEntry{}, err
	}
	return entry, nil
}

func healthWord(ok bool) string {
	if ok {
		return "healthy"
	}
	return "unhealthy"
}

func SortedRoles(nodes []NodeStatus) []string {
	roles := make([]string, 0, len(nodes))
	for _, n := range nodes {
		roles = append(roles, n.Role)
	}
	sort.Strings(roles)
	return roles
}
