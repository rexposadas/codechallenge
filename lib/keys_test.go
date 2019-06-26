package lib

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"testing"
)

// Test to see if we generate the correct keys.
func TestResult(t *testing.T) {
	msg := "simple tests"

	//  Generate the keys for a given msg input.
	result, err := GenerateKeys(msg)
	if err != nil {
		t.Fatalf("failed to generate keys %s", err)
	}

	signhash := toSha256([]byte(msg))
	r, s, err := ecdsa.Sign(rand.Reader, result.PrivateKey, signhash)
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

// Verify that the application output is correct.
func TestOutput(t *testing.T) {
	msg := []byte("rexposadas@gmail.com")

	//  Generate the keys for a given msg input.
	output, err := GenerateKeys(string(msg))
	if err != nil {
		t.Fatalf("failed to generate keys %s", err)
	}
	output.FormatOutput()

	// Parse out the signature.
	der, err := base64.StdEncoding.DecodeString(output.EncodedSignature)
	if err != nil {
		t.Fatalf("failed to get decode signature %s", err)
	}
	// Unmarshal the R and S components of the ASN.1-encoded signature into our signature data structure
	sig := &ECDSASignature{}
	_, err = asn1.Unmarshal(der, sig)
	if err != nil {
		t.Fatalf("failed to get signature data %s", err)
	}

	h := toSha256(msg)
	pubkey, err := loadPublicKey(output.PEMEncodedPubKey)
	if err != nil {
		t.Fatalf("failed to load public key %s %s", output.PEMEncodedPubKey, err)
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
		return nil, fmt.Errorf("Failed to parse ECDSA public key %s", err)
	}
	switch pub := pub.(type) {
	case *ecdsa.PublicKey:
		return pub, nil
	}
	return nil, errors.New("Unsupported public key type")
}
