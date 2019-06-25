package lib

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
)

// Signature is made up of two numbers.
type Signature struct {
	R, S *big.Int
}

// Result .
type Result struct {
	Message    string            `json:"message"`
	Signature  Signature         `json:"signature"`
	PubKey     ecdsa.PublicKey   `json:"pubkey"`
	PrivateKey *ecdsa.PrivateKey `json:"-"`
}

// NewResult generates the stuff ...
func NewResult(message string) (*Result, error) {
	result := &Result{
		Message: message,
	}

	// Generate private key.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("%s", err)
	}
	result.PrivateKey = privateKey

	// Get the signature.
	hash := sha256.Sum256([]byte(result.Message))
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])

	if err != nil {
		return nil, fmt.Errorf("%s", err)
	}
	sig := Signature{
		R: r,
		S: s,
	}
	result.Signature = sig

	result.PubKey = result.PrivateKey.PublicKey

	return result, nil
}

// FormatOutput is a convenience method to give us the out in the format that we want.
// Sample format:
// {
//   "message":"your@email.com",
//   "signature":"MGUCMGrxqpS689zQEi5yoBElG41u6U7eKX7ZzaXmXr0C5HgNXlJbiiVQYUS0ZOBxsLU4UgIxAL9AAgkRBUQ7/3EKQag4MjRflAxbfpbGmxb6ar9d4bGZ8FDQkUe6cnCIRleaxFnu2A==",
//   "pubkey":"-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEDUlT2XxqQAR3PBjeL2D8pQJdghFyBXWI\n/7RvD8Tsdv1YVFwqkJNEC3lNS4Gp7a19JfcrI/8fabLI+yPZBPZjtvuwRoauvGC6\nwdBrL2nzrZxZL4ZsUVNbWnG4SmqQ1f2k\n-----END PUBLIC KEY-----\n"
// }
func (r *Result) FormatOutput() []byte {
	b, err := json.Marshal(r)
	if err != nil {
		return []byte(fmt.Sprintf("failed to format for output %s", err))
	}

	return b
}
