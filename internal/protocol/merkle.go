package protocol

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

type MerkleStep struct {
	Side string `json:"side"`
	Hash string `json:"hash"`
}

type MerkleProof struct {
	LeafHash  string       `json:"leaf_hash"`
	RootHash  string       `json:"root_hash"`
	TreeSize  int          `json:"tree_size"`
	LeafIndex int          `json:"leaf_index"`
	Path      []MerkleStep `json:"path"`
}

func ComputeMerkleRoot(leafHashes []string) (string, error) {
	if len(leafHashes) == 0 {
		empty := sha256.Sum256([]byte("votechain:bb:empty:v1"))
		return base64.RawURLEncoding.EncodeToString(empty[:]), nil
	}
	level := make([][]byte, 0, len(leafHashes))
	for _, leaf := range leafHashes {
		b, err := base64.RawURLEncoding.DecodeString(leaf)
		if err != nil {
			return "", err
		}
		level = append(level, b)
	}
	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			left := level[i]
			right := left
			if i+1 < len(level) {
				right = level[i+1]
			}
			next = append(next, nodeHash(left, right))
		}
		level = next
	}
	return base64.RawURLEncoding.EncodeToString(level[0]), nil
}

func ComputeInclusionProof(leafHashes []string, leafIndex int) (*MerkleProof, error) {
	if leafIndex < 0 || leafIndex >= len(leafHashes) {
		return nil, errors.New("leaf index out of range")
	}
	level := make([][]byte, 0, len(leafHashes))
	for _, leaf := range leafHashes {
		b, err := base64.RawURLEncoding.DecodeString(leaf)
		if err != nil {
			return nil, err
		}
		level = append(level, b)
	}
	path := make([]MerkleStep, 0)
	idx := leafIndex
	for len(level) > 1 {
		isRight := idx%2 == 1
		siblingIdx := idx + 1
		side := "right"
		if isRight {
			siblingIdx = idx - 1
			side = "left"
		}
		sibling := level[idx]
		if siblingIdx >= 0 && siblingIdx < len(level) {
			sibling = level[siblingIdx]
		}
		path = append(path, MerkleStep{
			Side: side,
			Hash: base64.RawURLEncoding.EncodeToString(sibling),
		})
		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			left := level[i]
			right := left
			if i+1 < len(level) {
				right = level[i+1]
			}
			next = append(next, nodeHash(left, right))
		}
		idx = idx / 2
		level = next
	}
	return &MerkleProof{
		LeafHash:  leafHashes[leafIndex],
		RootHash:  base64.RawURLEncoding.EncodeToString(level[0]),
		TreeSize:  len(leafHashes),
		LeafIndex: leafIndex,
		Path:      path,
	}, nil
}

func VerifyInclusionProof(proof *MerkleProof) (bool, error) {
	acc, err := base64.RawURLEncoding.DecodeString(proof.LeafHash)
	if err != nil {
		return false, err
	}
	for _, step := range proof.Path {
		sibling, err := base64.RawURLEncoding.DecodeString(step.Hash)
		if err != nil {
			return false, err
		}
		switch step.Side {
		case "left":
			acc = nodeHash(sibling, acc)
		case "right":
			acc = nodeHash(acc, sibling)
		default:
			return false, errors.New("invalid proof side")
		}
	}
	return base64.RawURLEncoding.EncodeToString(acc) == proof.RootHash, nil
}

func nodeHash(left, right []byte) []byte {
	msg := make([]byte, 0, len("votechain:bb:node:v1:")+len(left)+len(right))
	msg = append(msg, []byte("votechain:bb:node:v1:")...)
	msg = append(msg, left...)
	msg = append(msg, right...)
	h := sha256.Sum256(msg)
	out := make([]byte, len(h))
	copy(out, h[:])
	return out
}
