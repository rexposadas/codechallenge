package lib

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
)

// ECDSASignature is the signature represented by two numbers.
type ECDSASignature struct {
	R *big.Int
	S *big.Int
}

// String used primarily to format the output.
// Returns a base64 encoded string.
func (s *ECDSASignature) String() string {
	b, err := asn1.Marshal(ECDSASignature{s.R, s.S})
	if err != nil {
		return fmt.Sprintf("failed to marshal signature %s", err)
	}

	return base64.StdEncoding.EncodeToString(b)
}

// Keys is the result of our key generation process.
// This struct is also used when output the results.
type Keys struct {
	// For internal use and shold not be used as part of the response to the caller
	// of application, hence the "-" json tag.
	Signature  ECDSASignature    `json:"-"`
	PrivateKey *ecdsa.PrivateKey `json:"-"`

	// Used for displaying the output.
	Message         string `json:"message"`
	SignatureOutput string `json:"signature"`

	// Used for storing keys to the files.
	EncodedPubKey     string `json:"pubkey"`
	EncodedPrivateKey string `json:"-"`
}

// NewKeys generates the private and public keys as well as the signature.
// msg is the string used to generate the signature.
func NewKeys(msg string) (*Keys, error) {
	result := &Keys{
		Message: msg,
	}

	// Generate private key.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("%s", err)
	}
	result.PrivateKey = privateKey

	// Generate the signature.
	hash := sha256.Sum256([]byte(result.Message))
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("%s", err)
	}
	result.Signature = ECDSASignature{
		R: r,
		S: s,
	}

	return result, nil
}

// FormatOutput is a convenience method to give us the output in the format that we want.
// Sample format:
// {
// 	"message": "rexposadas@gmail.com",
// 	"signature": "MEQCIAvemZT/CUbRTPRo9t06fGWJwwbZ4+z2Dp8CFeak0ZU9AiA0biuIursqiXWdm9JwqFZUzvjBNr6lgHit1aIbVrwZxg==",
// 	"pubkey": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsNaitNL0ceFEiipvT+9Ou/ZfOTt+\nXR8B5139C8g7+l9pXgCdxsT5v/LT8/WslI9RRwXuTWWBxqIVsnOLR+4tdw==\n-----END PUBLIC KEY-----\n"
// }
func (k *Keys) FormatOutput() []byte {
	// Returning a sensible error if we cannot encode the keys.
	if err := k.Encode(); err != nil {
		return []byte("issues encoding the keys")
	}
	// Format the outputs variables.
	k.SignatureOutput = k.Signature.String()

	b, err := json.Marshal(k)
	if err != nil {
		return []byte(fmt.Sprintf("failed to format for output %s", err))
	}

	return b
}

// Encode encodes the private and public keys to PEM.  We use this encoding to serialize to a file as well.
func (k *Keys) Encode() error {
	encodedPrivateKey, err := x509.MarshalECPrivateKey(k.PrivateKey)
	if err != nil {
		return err
	}
	k.EncodedPrivateKey = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedPrivateKey}))

	x509EncodedPub, err := x509.MarshalPKIXPublicKey(k.PrivateKey.Public())
	if err != nil {
		return err
	}
	k.EncodedPubKey = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub}))

	return nil
}
