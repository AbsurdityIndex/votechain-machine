package protocol

import "time"

// ElectionManifest is the local election definition loaded onto a polling-place machine.
type ElectionManifest struct {
	ElectionID      string    `json:"election_id"`
	JurisdictionID  string    `json:"jurisdiction_id"`
	ManifestID      string    `json:"manifest_id"`
	NotBefore       time.Time `json:"not_before"`
	NotAfter        time.Time `json:"not_after"`
	EligibilityKey  string    `json:"eligibility_key,omitempty"`
	ReceiptKeyID    string    `json:"receipt_key_id"`
	Contests        []Contest `json:"contests"`
	SourceBundleSHA string    `json:"source_bundle_sha256"`
}

type Contest struct {
	ContestID string         `json:"contest_id"`
	Type      string         `json:"type"`
	Title     string         `json:"title"`
	Options   []ContestEntry `json:"options"`
}

type ContestEntry struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

type LoadElectionRequest struct {
	Manifest ElectionManifest `json:"manifest"`
}

type LoadElectionResponse struct {
	Status         string    `json:"status"`
	ElectionID     string    `json:"election_id"`
	ManifestID     string    `json:"manifest_id"`
	JurisdictionID string    `json:"jurisdiction_id"`
	LoadedAt       time.Time `json:"loaded_at"`
}

type ChallengeResponse struct {
	ChallengeID string    `json:"challenge_id"`
	Challenge   string    `json:"challenge"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type EligibilityProof struct {
	CredentialPub string `json:"credential_pub"`
	ProofBlob     string `json:"proof_blob"`
	Signature     string `json:"signature,omitempty"`
}

type EncryptedBallot struct {
	BallotID           string `json:"ballot_id"`
	Ciphertext         string `json:"ciphertext"`
	BallotHash         string `json:"ballot_hash"`
	WrappedBallotKey   string `json:"wrapped_ballot_key"`
	WrappedBallotKeyEP string `json:"wrapped_ballot_key_epk"`
}

type CastBallotRequest struct {
	IdempotencyKey string           `json:"idempotency_key"`
	ElectionID     string           `json:"election_id"`
	ManifestID     string           `json:"manifest_id"`
	ChallengeID    string           `json:"challenge_id"`
	Challenge      string           `json:"challenge"`
	Nullifier      string           `json:"nullifier"`
	Proof          EligibilityProof `json:"eligibility_proof"`
	Ballot         EncryptedBallot  `json:"encrypted_ballot"`
}

type VotechainAnchor struct {
	EventType   string `json:"event_type"`
	TxID        string `json:"tx_id"`
	STHRootHash string `json:"sth_root_hash"`
}

type CastReceipt struct {
	ReceiptID  string          `json:"receipt_id"`
	MachineID  string          `json:"machine_id"`
	PrecinctID string          `json:"precinct_id"`
	ElectionID string          `json:"election_id"`
	ManifestID string          `json:"manifest_id"`
	BallotHash string          `json:"ballot_hash"`
	BBLeafHash string          `json:"bb_leaf_hash"`
	BBSTH      SignedTreeHead  `json:"bb_sth"`
	Anchor     VotechainAnchor `json:"votechain_anchor"`
	IssuedAt   time.Time       `json:"issued_at"`
	KeyID      string          `json:"kid"`
	Signature  string          `json:"sig"`
}

type CastResponse struct {
	Status      string      `json:"status"`
	CastReceipt CastReceipt `json:"cast_receipt"`
}

type VerifyReceiptRequest struct {
	Receipt CastReceipt `json:"receipt"`
}

type VerifyCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Details string `json:"details,omitempty"`
}

type VerifyReceiptResponse struct {
	Status string        `json:"status"`
	Checks []VerifyCheck `json:"checks"`
}

type SignedTreeHead struct {
	TreeSize  int       `json:"tree_size"`
	RootHash  string    `json:"root_hash"`
	Timestamp time.Time `json:"timestamp"`
	KeyID     string    `json:"kid"`
	Signature string    `json:"sig"`
}

type ExportBundle struct {
	BundleID      string         `json:"bundle_id"`
	CreatedAt     time.Time      `json:"created_at"`
	MachineID     string         `json:"machine_id"`
	PrecinctID    string         `json:"precinct_id"`
	ElectionID    string         `json:"election_id"`
	ManifestID    string         `json:"manifest_id"`
	FinalSTH      SignedTreeHead `json:"final_sth"`
	LeafHashes    []string       `json:"leaf_hashes"`
	Receipts      []CastReceipt  `json:"receipts"`
	IntegrityHash string         `json:"integrity_hash"`
	KeyID         string         `json:"kid"`
	Signature     string         `json:"sig"`
}

type ClosePollsResponse struct {
	Status       string         `json:"status"`
	ClosedAt     time.Time      `json:"closed_at"`
	BundlePath   string         `json:"bundle_path"`
	BundleSHA256 string         `json:"bundle_sha256"`
	FinalSTH     SignedTreeHead `json:"final_sth"`
	BallotCount  int            `json:"ballot_count"`
}

type IngestBundleRequest struct {
	Bundle ExportBundle `json:"bundle"`
}

type IngestBundleResponse struct {
	Status     string        `json:"status"`
	BundleID   string        `json:"bundle_id"`
	MachineID  string        `json:"machine_id"`
	PrecinctID string        `json:"precinct_id"`
	ElectionID string        `json:"election_id"`
	ReceivedAt time.Time     `json:"received_at"`
	Checks     []VerifyCheck `json:"checks"`
}

type ErrorResponse struct {
	Error ErrorBody `json:"error"`
}

type ErrorBody struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

type HealthResponse struct {
	Service     string `json:"service"`
	Version     string `json:"version"`
	MachineID   string `json:"machine_id"`
	Mode        string `json:"mode"`
	ElectionID  string `json:"election_id,omitempty"`
	ManifestID  string `json:"manifest_id,omitempty"`
	PollsClosed bool   `json:"polls_closed"`
	BallotCount int    `json:"ballot_count"`
	CurrentSTH  string `json:"current_sth_root_hash,omitempty"`
}
