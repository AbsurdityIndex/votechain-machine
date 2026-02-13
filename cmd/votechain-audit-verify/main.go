package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	machinecrypto "github.com/votechain/votechain-machine/internal/crypto"
	"github.com/votechain/votechain-machine/internal/protocol"
	"github.com/votechain/votechain-machine/internal/service"
	"gopkg.in/yaml.v3"
)

type DatasetRow struct {
	SessionUID   string `json:"session_uid"`
	MachineID    string `json:"machine_id"`
	SessionIndex int    `json:"session_index"`
	VoterID      string `json:"voter_id"`
	Spoiled      bool   `json:"spoiled"`
	Selection    string `json:"selection"`
}

type SessionResult struct {
	SessionUID         string `json:"session_uid"`
	MachineID          string `json:"machine_id"`
	SessionIndex       int    `json:"session_index"`
	VoterID            string `json:"voter_id"`
	Spoiled            bool   `json:"spoiled"`
	Selection          string `json:"selection"`
	CastOK             bool   `json:"cast_ok"`
	ReceiptOK          bool   `json:"receipt_ok"`
	ReceiptID          string `json:"receipt_id"`
	BundleID           string `json:"bundle_id"`
	BundleArchivePath  string `json:"bundle_archive_path"`
	AirgapIngestStatus string `json:"airgap_ingest_status"`
	IngestStatus       string `json:"ingest_status"`
}

type RunReport struct {
	Summary  map[string]any  `json:"summary"`
	Sessions []SessionResult `json:"sessions"`
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

type LedgerHealth struct {
	Service     string `json:"service"`
	NodeRole    string `json:"node_role"`
	LatestIndex int64  `json:"latest_index"`
	LatestHash  string `json:"latest_hash"`
}

type ObserverStatus struct {
	Overall    string `json:"overall"`
	IngestData struct {
		OutboxPending int `json:"outbox_pending"`
		OutboxSent    int `json:"outbox_sent"`
		BundleCount   int `json:"bundle_count"`
		ReceiptCount  int `json:"receipt_count"`
	} `json:"ingest_data"`
	Consistency struct {
		Status string `json:"status"`
	} `json:"consistency"`
}

type CandidateTally struct {
	Candidate string `json:"candidate"`
	Votes     int    `json:"votes"`
}

type AuditSummary struct {
	GeneratedAtUTC        string           `json:"generated_at_utc"`
	DatasetPath           string           `json:"dataset_path"`
	RunReportPath         string           `json:"run_report_path"`
	BundleArchiveDir      string           `json:"bundle_archive_dir"`
	ExpectedSessions      int              `json:"expected_sessions"`
	ExpectedSpoiled       int              `json:"expected_spoiled"`
	ExpectedCast          int              `json:"expected_cast"`
	ObservedCastOK        int              `json:"observed_cast_ok"`
	ObservedReceiptOK     int              `json:"observed_receipt_ok"`
	BundleCount           int              `json:"bundle_count"`
	BundleVerifyOK        int              `json:"bundle_verify_ok"`
	BundleVerifyFail      int              `json:"bundle_verify_fail"`
	BundleReceiptCount    int              `json:"bundle_receipt_count"`
	CandidateTallies      []CandidateTally `json:"candidate_tallies"`
	Winner                string           `json:"winner"`
	WinnerVotes           int              `json:"winner_votes"`
	ObserverOverall       string           `json:"observer_overall"`
	ObserverConsistency   string           `json:"observer_consistency"`
	ObserverOutboxPending int              `json:"observer_outbox_pending"`
	ObserverOutboxSent    int              `json:"observer_outbox_sent"`
	ObserverBundleCount   int              `json:"observer_bundle_count"`
	ObserverReceiptCount  int              `json:"observer_receipt_count"`
	LedgerFederalIndex    int64            `json:"ledger_federal_index"`
	LedgerStateIndex      int64            `json:"ledger_state_index"`
	LedgerOversightIndex  int64            `json:"ledger_oversight_index"`
	LedgerFederalHash     string           `json:"ledger_federal_hash"`
	LedgerStateHash       string           `json:"ledger_state_hash"`
	LedgerOversightHash   string           `json:"ledger_oversight_hash"`
	VerificationPassed    bool             `json:"verification_passed"`
}

type SignedAuditReport struct {
	Summary        AuditSummary `json:"summary"`
	AuditSignature struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Sig string `json:"sig"`
	} `json:"audit_signature"`
}

func main() {
	datasetPath := flag.String("dataset", "", "path to mock election dataset json")
	runReportPath := flag.String("run-report", "", "path to mock election run report json")
	bundleArchiveDir := flag.String("bundle-archive-dir", "", "path to archived bundle directory (optional, defaults from run-report summary)")
	machineRegistryPath := flag.String("machine-registry", "configs/compose/machine-registry.yaml", "path to machine registry yaml")
	registryKeyDir := flag.String("registry-key-dir", "deployments/compose/keys", "fallback directory for registry public key files")
	observerURL := flag.String("observer-url", "http://127.0.0.1:8282", "observer base URL")
	federalURL := flag.String("ledger-federal-url", "http://127.0.0.1:8301", "federal ledger base URL")
	stateURL := flag.String("ledger-state-url", "http://127.0.0.1:8302", "state ledger base URL")
	oversightURL := flag.String("ledger-oversight-url", "http://127.0.0.1:8303", "oversight ledger base URL")
	auditPrivateKey := flag.String("audit-private-key", "deployments/compose/keys/audit-signing-private.pem", "audit signing private key path")
	auditPublicKey := flag.String("audit-public-key", "deployments/compose/keys/audit-signing-public.pem", "audit signing public key path")
	outPath := flag.String("out", "", "output path for signed audit report json")
	flag.Parse()

	if *datasetPath == "" || *runReportPath == "" {
		fmt.Fprintln(os.Stderr, "-dataset and -run-report are required")
		os.Exit(1)
	}

	dataset, err := readDataset(*datasetPath)
	if err != nil {
		fail("read dataset", err)
	}
	runReport, err := readRunReport(*runReportPath)
	if err != nil {
		fail("read run report", err)
	}

	archiveDir := strings.TrimSpace(*bundleArchiveDir)
	if archiveDir == "" {
		if v, ok := runReport.Summary["bundle_archive_dir"].(string); ok {
			archiveDir = strings.TrimSpace(v)
		}
	}
	if archiveDir == "" {
		fail("resolve bundle archive dir", errors.New("bundle archive dir is required"))
	}

	identities, err := loadMachineIdentities(*machineRegistryPath, *registryKeyDir)
	if err != nil {
		fail("load machine identities", err)
	}

	bundlePaths, err := listBundleFiles(archiveDir)
	if err != nil {
		fail("list bundle archive", err)
	}

	verify := service.BundleVerifier{RequireMachineKeyID: true}
	bundleCount := 0
	bundleVerifyOK := 0
	bundleVerifyFail := 0
	bundleReceiptCount := 0
	seenBundleIDs := make(map[string]struct{}, len(bundlePaths))
	for _, path := range bundlePaths {
		bundle, err := readBundle(path)
		if err != nil {
			fail("decode bundle "+path, err)
		}
		bundleCount++
		bundleReceiptCount += len(bundle.Receipts)
		if _, exists := seenBundleIDs[bundle.BundleID]; exists {
			fail("verify bundles", fmt.Errorf("duplicate bundle id in archive: %s", bundle.BundleID))
		}
		seenBundleIDs[bundle.BundleID] = struct{}{}

		identity, ok := identities[bundle.MachineID]
		if !ok {
			bundleVerifyFail++
			continue
		}
		result, err := verify.Verify(bundle, identity)
		if err != nil || result.Status != "ok" {
			bundleVerifyFail++
			continue
		}
		bundleVerifyOK++
	}

	observer, err := fetchObserver(*observerURL)
	if err != nil {
		fail("fetch observer", err)
	}
	fed, err := fetchLedger(*federalURL)
	if err != nil {
		fail("fetch federal ledger", err)
	}
	state, err := fetchLedger(*stateURL)
	if err != nil {
		fail("fetch state ledger", err)
	}
	oversight, err := fetchLedger(*oversightURL)
	if err != nil {
		fail("fetch oversight ledger", err)
	}

	expectedSessions := len(dataset)
	expectedSpoiled := 0
	candidateVotes := map[string]int{}
	for _, row := range dataset {
		if row.Spoiled {
			expectedSpoiled++
			continue
		}
		candidateVotes[row.Selection]++
	}
	expectedCast := expectedSessions - expectedSpoiled

	observedCastOK := 0
	observedReceiptOK := 0
	for _, s := range runReport.Sessions {
		if s.CastOK {
			observedCastOK++
		}
		if s.ReceiptOK {
			observedReceiptOK++
		}
	}

	tallies := make([]CandidateTally, 0, len(candidateVotes))
	for k, v := range candidateVotes {
		tallies = append(tallies, CandidateTally{Candidate: k, Votes: v})
	}
	sort.Slice(tallies, func(i, j int) bool {
		if tallies[i].Votes == tallies[j].Votes {
			return tallies[i].Candidate < tallies[j].Candidate
		}
		return tallies[i].Votes > tallies[j].Votes
	})
	winner := ""
	winnerVotes := 0
	if len(tallies) > 0 {
		winner = tallies[0].Candidate
		winnerVotes = tallies[0].Votes
	}

	ledgerHashesMatch := fed.LatestHash != "" && fed.LatestHash == state.LatestHash && state.LatestHash == oversight.LatestHash
	ledgerIndexesMatch := fed.LatestIndex == state.LatestIndex && state.LatestIndex == oversight.LatestIndex

	verificationPassed := all(
		bundleCount == expectedSessions,
		bundleVerifyFail == 0,
		bundleVerifyOK == expectedSessions,
		bundleReceiptCount == expectedCast,
		observedCastOK == expectedCast,
		observedReceiptOK == expectedCast,
		observer.IngestData.BundleCount >= expectedSessions,
		observer.IngestData.ReceiptCount >= expectedCast,
		observer.IngestData.OutboxPending == 0,
		observer.Consistency.Status == "ok",
		ledgerIndexesMatch,
		ledgerHashesMatch,
		fed.LatestIndex >= int64(expectedSessions),
	)

	summary := AuditSummary{
		GeneratedAtUTC:        time.Now().UTC().Format(time.RFC3339Nano),
		DatasetPath:           *datasetPath,
		RunReportPath:         *runReportPath,
		BundleArchiveDir:      archiveDir,
		ExpectedSessions:      expectedSessions,
		ExpectedSpoiled:       expectedSpoiled,
		ExpectedCast:          expectedCast,
		ObservedCastOK:        observedCastOK,
		ObservedReceiptOK:     observedReceiptOK,
		BundleCount:           bundleCount,
		BundleVerifyOK:        bundleVerifyOK,
		BundleVerifyFail:      bundleVerifyFail,
		BundleReceiptCount:    bundleReceiptCount,
		CandidateTallies:      tallies,
		Winner:                winner,
		WinnerVotes:           winnerVotes,
		ObserverOverall:       observer.Overall,
		ObserverConsistency:   observer.Consistency.Status,
		ObserverOutboxPending: observer.IngestData.OutboxPending,
		ObserverOutboxSent:    observer.IngestData.OutboxSent,
		ObserverBundleCount:   observer.IngestData.BundleCount,
		ObserverReceiptCount:  observer.IngestData.ReceiptCount,
		LedgerFederalIndex:    fed.LatestIndex,
		LedgerStateIndex:      state.LatestIndex,
		LedgerOversightIndex:  oversight.LatestIndex,
		LedgerFederalHash:     fed.LatestHash,
		LedgerStateHash:       state.LatestHash,
		LedgerOversightHash:   oversight.LatestHash,
		VerificationPassed:    verificationPassed,
	}

	signer, err := machinecrypto.LoadSigner(*auditPrivateKey, *auditPublicKey)
	if err != nil {
		fail("load audit signer", err)
	}
	payload, err := protocol.CanonicalJSON(summary)
	if err != nil {
		fail("canonicalize audit summary", err)
	}
	sig := signer.Sign(payload)

	var report SignedAuditReport
	report.Summary = summary
	report.AuditSignature.Alg = "ed25519"
	report.AuditSignature.Kid = signer.KeyID
	report.AuditSignature.Sig = sig

	outputPath := strings.TrimSpace(*outPath)
	if outputPath == "" {
		outputPath = defaultOutputPath()
	}
	if err := writeJSON(outputPath, report); err != nil {
		fail("write audit report", err)
	}

	fmt.Printf("audit_report:%s\n", outputPath)
	fmt.Printf("winner:%s votes=%d\n", summary.Winner, summary.WinnerVotes)
	fmt.Printf("verification_passed:%t\n", summary.VerificationPassed)
	if !summary.VerificationPassed {
		os.Exit(1)
	}
}

func readDataset(path string) ([]DatasetRow, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []DatasetRow
	if err := decodeStrictJSON(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func readRunReport(path string) (RunReport, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return RunReport{}, err
	}
	var out RunReport
	if err := decodeStrictJSON(raw, &out); err != nil {
		return RunReport{}, err
	}
	return out, nil
}

func loadMachineIdentities(registryPath, keyDir string) (map[string]service.MachineIdentity, error) {
	buf, err := os.ReadFile(registryPath)
	if err != nil {
		return nil, err
	}
	var file registryFile
	if err := yaml.Unmarshal(buf, &file); err != nil {
		return nil, err
	}
	if len(file.Machines) == 0 {
		return nil, errors.New("machine registry is empty")
	}
	out := make(map[string]service.MachineIdentity, len(file.Machines))
	for i, m := range file.Machines {
		if m.MachineID == "" || m.PrecinctID == "" || m.JurisdictionID == "" || m.KeyID == "" {
			return nil, fmt.Errorf("registry entry %d is missing required fields", i)
		}
		pub, err := resolvePublicKey(m, keyDir)
		if err != nil {
			return nil, fmt.Errorf("resolve registry key for %s: %w", m.MachineID, err)
		}
		out[m.MachineID] = service.MachineIdentity{
			MachineID:      m.MachineID,
			PrecinctID:     m.PrecinctID,
			JurisdictionID: m.JurisdictionID,
			KeyID:          m.KeyID,
			PublicKey:      pub,
		}
	}
	return out, nil
}

func resolvePublicKey(entry registryEntry, keyDir string) (ed25519.PublicKey, error) {
	raw := strings.TrimSpace(entry.PublicKey)
	if raw != "" {
		return machinecrypto.ParsePublicKey(raw)
	}
	if entry.PublicKeyPath == "" {
		return nil, errors.New("public_key or public_key_path is required")
	}

	tryPaths := make([]string, 0, 2)
	tryPaths = append(tryPaths, entry.PublicKeyPath)
	if keyDir != "" {
		tryPaths = append(tryPaths, filepath.Join(keyDir, filepath.Base(entry.PublicKeyPath)))
	}

	var lastErr error
	for _, p := range tryPaths {
		buf, err := os.ReadFile(p)
		if err != nil {
			lastErr = err
			continue
		}
		return machinecrypto.ParsePublicKey(string(buf))
	}
	if lastErr == nil {
		lastErr = errors.New("unable to read key file")
	}
	return nil, lastErr
}

func listBundleFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	files := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(e.Name()), ".json") {
			continue
		}
		files = append(files, filepath.Join(dir, e.Name()))
	}
	sort.Strings(files)
	return files, nil
}

func readBundle(path string) (protocol.ExportBundle, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return protocol.ExportBundle{}, err
	}
	var out protocol.ExportBundle
	if err := decodeStrictJSON(raw, &out); err != nil {
		return protocol.ExportBundle{}, err
	}
	return out, nil
}

func fetchObserver(baseURL string) (ObserverStatus, error) {
	var out ObserverStatus
	if err := fetchJSON(context.Background(), strings.TrimRight(baseURL, "/")+"/v1/observer/status", &out); err != nil {
		return out, err
	}
	return out, nil
}

func fetchLedger(baseURL string) (LedgerHealth, error) {
	var out LedgerHealth
	if err := fetchJSON(context.Background(), strings.TrimRight(baseURL, "/")+"/healthz", &out); err != nil {
		return out, err
	}
	return out, nil
}

func fetchJSON(ctx context.Context, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 12 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d body=%s", resp.StatusCode, string(body))
	}
	return json.Unmarshal(body, out)
}

func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}

func defaultOutputPath() string {
	stamp := time.Now().UTC().Format("20060102T150405Z")
	return filepath.Join("deployments", "compose", "reports", fmt.Sprintf("mock-election-audit-%s.json", stamp))
}

func decodeStrictJSON(raw []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("json payload must contain a single value")
	}
	return nil
}

func all(values ...bool) bool {
	for _, v := range values {
		if !v {
			return false
		}
	}
	return true
}

func fail(step string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", step, err)
	os.Exit(1)
}
