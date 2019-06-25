package lib

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

// Signature is made up of two numbers.
type Signature struct {
	r, s *big.Int
}

// Result .
type Result struct {
	Message    string
	Signature  Signature
	PubKey     ecdsa.PublicKey
	PrivateKey *ecdsa.PrivateKey
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
		r: r,
		s: s,
	}
	result.Signature = sig

	result.PubKey = result.PrivateKey.PublicKey

	return result, nil
}
