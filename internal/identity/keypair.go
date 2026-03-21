// @gate-project: Gate
// @gate-path: internal/identity/keypair.go
// KeyPair manages the Gate Ed25519 signing keypair.
// The private key never leaves this package.
// The public key is served at GET /gate/public-key for service verification.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

const (
	privKeyType = "ED25519 PRIVATE KEY"
	pubKeyType  = "ED25519 PUBLIC KEY"
)

// KeyPair holds the Gate signing keypair.
type KeyPair struct {
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
}

// LoadOrGenerate loads an existing keypair from keyPath, or generates
// and saves a new one if the file does not exist.
func LoadOrGenerate(keyPath string) (*KeyPair, error) {
	expanded := expandHome(keyPath)
	if _, err := os.Stat(expanded); os.IsNotExist(err) {
		return generate(expanded)
	}
	return load(expanded)
}

// PublicKeyBase64 returns the base64-encoded DER representation of the public key.
// This is the value served at GET /gate/public-key.
func (kp *KeyPair) PublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(kp.Public)
}

func generate(path string) (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	if err := save(path, priv, pub); err != nil {
		return nil, err
	}
	return &KeyPair{Private: priv, Public: pub}, nil
}

func load(path string) (*KeyPair, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != privKeyType {
		return nil, fmt.Errorf("invalid key file: expected PEM block %q", privKeyType)
	}
	if len(block.Bytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid key size: got %d, want %d", len(block.Bytes), ed25519.PrivateKeySize)
	}
	priv := ed25519.PrivateKey(block.Bytes)
	pub := priv.Public().(ed25519.PublicKey)
	return &KeyPair{Private: priv, Public: pub}, nil
}

func save(path string, priv ed25519.PrivateKey, pub ed25519.PublicKey) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create key dir: %w", err)
	}
	block := &pem.Block{Type: privKeyType, Bytes: []byte(priv)}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
		return fmt.Errorf("write key file: %w", err)
	}
	return nil
}

func expandHome(path string) string {
	if len(path) >= 2 && path[:2] == "~/" {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return filepath.Join(home, path[2:])
	}
	return path
}
