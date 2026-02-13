package protocol

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

var b64u = base64.RawURLEncoding

func CanonicalJSON(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func SHA256B64u(in []byte) string {
	h := sha256.Sum256(in)
	return b64u.EncodeToString(h[:])
}

func SHA256Hex(in []byte) string {
	h := sha256.Sum256(in)
	return hex.EncodeToString(h[:])
}

func HashCanonical(v any) (string, error) {
	b, err := CanonicalJSON(v)
	if err != nil {
		return "", err
	}
	return SHA256B64u(b), nil
}

func RandomID(prefix string) (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("random id: %w", err)
	}
	return prefix + "_" + hex.EncodeToString(buf), nil
}

func BallotLeafHash(payload any) (string, error) {
	canonical, err := CanonicalJSON(payload)
	if err != nil {
		return "", err
	}
	body := append([]byte("votechain:bb:leaf:v1:"), canonical...)
	return SHA256B64u(body), nil
}

func ComputeNullifier(credentialPub, electionID string) string {
	seed := []byte("votechain:nullifier:v1:" + credentialPub + ":" + electionID)
	return "0x" + SHA256Hex(seed)
}
