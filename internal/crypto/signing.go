package crypto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

type Signer struct {
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
	KeyID   string
}

func LoadSigner(privatePath, publicPath string) (*Signer, error) {
	priv, err := loadPrivateKey(privatePath)
	if err != nil {
		return nil, err
	}
	pub, err := loadPublicKey(publicPath)
	if err != nil {
		return nil, err
	}
	if !bytesEqual(priv.Public().(ed25519.PublicKey), pub) {
		return nil, errors.New("public key does not match private key")
	}
	kid := keyID(pub)
	return &Signer{Private: priv, Public: pub, KeyID: kid}, nil
}

func (s *Signer) Sign(payload []byte) string {
	sig := ed25519.Sign(s.Private, payload)
	return base64.RawURLEncoding.EncodeToString(sig)
}

func Verify(pub ed25519.PublicKey, payload []byte, signature string) bool {
	sig, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, payload, sig)
}

func ParsePublicKey(encoded string) (ed25519.PublicKey, error) {
	buf := strings.TrimSpace(encoded)
	if strings.HasPrefix(buf, "-----BEGIN") {
		block, _ := pem.Decode([]byte(buf))
		if block == nil {
			return nil, errors.New("invalid public key pem")
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse public key pem: %w", err)
		}
		pk, ok := parsed.(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("public key is not ed25519")
		}
		return pk, nil
	}
	b, err := decodeLooseBase64(buf)
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key length %d invalid", len(b))
	}
	return ed25519.PublicKey(b), nil
}

func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	data := strings.TrimSpace(string(buf))
	if strings.HasPrefix(data, "-----BEGIN") {
		block, _ := pem.Decode(buf)
		if block == nil {
			return nil, errors.New("invalid private key pem")
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse pkcs8 private key: %w", err)
		}
		pk, ok := parsed.(ed25519.PrivateKey)
		if !ok {
			return nil, errors.New("private key is not ed25519")
		}
		return pk, nil
	}
	b, err := decodeLooseBase64(data)
	if err != nil {
		return nil, err
	}
	switch len(b) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(b), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(b), nil
	default:
		return nil, fmt.Errorf("private key length %d invalid", len(b))
	}
}

func loadPublicKey(path string) (ed25519.PublicKey, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}
	return ParsePublicKey(string(buf))
}

func decodeLooseBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	candidates := []func(string) ([]byte, error){
		base64.RawURLEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.StdEncoding.DecodeString,
	}
	for _, fn := range candidates {
		if b, err := fn(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("key is not valid base64")
}

func keyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return "ed25519:" + hex.EncodeToString(h[:8])
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
