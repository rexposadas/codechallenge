package lib

import (
	"crypto/ecdsa"
	"crypto/md5"
	"crypto/rand"
	"hash"
	"io"
	"math/big"
	"testing"
)

// Test to see if we generate the correct keys.
func TestResult(t *testing.T) {
	msg := "simple tests"

	result, err := NewResult(msg)
	if err != nil {
		t.Fatalf("failed to generate keys %s", err)
	}

	var h hash.Hash
	h = md5.New()
	r := big.NewInt(0)
	s := big.NewInt(0)

	io.WriteString(h, msg)
	signhash := h.Sum(nil)

	r, s, err = ecdsa.Sign(rand.Reader, result.PrivateKey, signhash)
	if err != nil {
		t.Fatalf("failed to sign %s", err)
	}

	signature := r.Bytes()
	signature = append(signature, s.Bytes()...)

	// Verify.
	pubkey := result.PrivateKey.Public().(*ecdsa.PublicKey)
	if verified := ecdsa.Verify(pubkey, signhash, r, s); !verified {
		t.Fatal("not verified")
	}
}
