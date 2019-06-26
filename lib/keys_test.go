package lib

import (
	"crypto/ecdsa"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"hash"
	"io"
	"math/big"
	"testing"
)

// Test to see if we generate the correct keys.
func TestResult(t *testing.T) {
	msg := "simple tests"

	//  Generate the keys for a given msg input.
	result, err := NewKeys(msg)
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

// Test to see if the output the application generates is correct.
func TestOutput(t *testing.T) {
	msg := []byte("rexposadas@gmail.com")

	//  Generate the keys for a given msg input.
	output, err := NewKeys(string(msg))
	if err != nil {
		t.Fatalf("failed to generate keys %s", err)
	}
	output.FormatOutput()

	der, err := base64.StdEncoding.DecodeString(output.SignatureOutput)
	if err != nil {
		t.Fatalf("failed to get decode signature %s", err)
	}
	// unmarshal the R and S components of the ASN.1-encoded signature into our
	// signature data structure
	sig := &Signature{}
	_, err = asn1.Unmarshal(der, sig)
	if err != nil {
		t.Fatalf("failed to get signature data %s", err)
	}

	h := hashHelper(msg)

	pubkey, err := loadPublicKey(output.EncodedPubKey)
	if err != nil {
		t.Fatalf("failed to load public key %s %s", output.EncodedPubKey, err)
	}

	if valid := ecdsa.Verify(
		pubkey,
		h,
		sig.R,
		sig.S,
	); !valid {
		t.Fatal("verify failed")
	}

}
func loadPublicKey(publicKey string) (*ecdsa.PublicKey, error) {
	// decode the key, assuming it's in PEM format
	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		return nil, errors.New("Failed to decode PEM public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("Failed to parse ECDSA public key")
	}
	switch pub := pub.(type) {
	case *ecdsa.PublicKey:
		return pub, nil
	}
	return nil, errors.New("Unsupported public key type")
}

// Helper function to compute the SHA256 hash of the given string of bytes.
func hashHelper(b []byte) []byte {
	h := sha256.New()
	h.Write(b)

	// compute the SHA256 hash
	return h.Sum(nil)
}
