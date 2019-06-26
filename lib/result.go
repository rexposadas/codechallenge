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

// String used, primarily, to format the output.
func (s *Signature) String() string {
	r := s.R.Bytes()
	all := (append(r, s.S.Bytes()...))

	return fmt.Sprintf("%x", all)
}

// Keys is the result of our key generation process.
// This struct is also used when output the results.
type Keys struct {
	// For internal use and shold not be used as part of the response to the caller
	// of application, hence the "-" json tag.
	Signature  Signature         `json:"-"`
	PrivateKey *ecdsa.PrivateKey `json:"-"`

	// Member variables that will be used for the output.
	Message         string `json:"message"`
	SignatureOutput string `json:"signature"`
	PubKey          string `json:"pubkey"`
}

// NewKeys generates the the private and public keys.
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

	return result, nil
}

// FormatOutput is a convenience method to give us the out in the format that we want.
// Sample format:
// {
//   "message":"your@email.com",
//   "signature":"MGUCMGrxqpS689zQEi5yoBElG41u6U7eKX7ZzaXmXr0C5HgNXlJbiiVQYUS0ZOBxsLU4UgIxAL9AAgkRBUQ7/3EKQag4MjRflAxbfpbGmxb6ar9d4bGZ8FDQkUe6cnCIRleaxFnu2A==",
//   "pubkey":"-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEDUlT2XxqQAR3PBjeL2D8pQJdghFyBXWI\n/7RvD8Tsdv1YVFwqkJNEC3lNS4Gp7a19JfcrI/8fabLI+yPZBPZjtvuwRoauvGC6\nwdBrL2nzrZxZL4ZsUVNbWnG4SmqQ1f2k\n-----END PUBLIC KEY-----\n"
// }
func (r *Keys) FormatOutput() []byte {

	// Format the outputs variables.
	r.SignatureOutput = r.Signature.String()

	// Format Public Key .
	x := r.PrivateKey.X.Bytes()
	all := append(x, r.PrivateKey.Y.Bytes()...)
	r.PubKey = fmt.Sprintf("%x", all)

	b, err := json.Marshal(r)
	if err != nil {
		return []byte(fmt.Sprintf("failed to format for output %s", err))
	}

	return b
}
