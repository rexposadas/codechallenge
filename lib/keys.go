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
	"os"
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
	Message          string `json:"message"`
	EncodedSignature string `json:"signature"`

	// Used for storing keys to the files.
	PEMEncodedPubKey     string `json:"pubkey"`
	PEMEncodedPrivateKey string `json:"-"`
}

// ProcessMessage processcess the msg parameter and returns the keys with the signature.
//
// This function does the following:
// 1. Generate the private and public keys if they do not exist in the file system.
// 	a. If they keys exists in the file system, load them.
//	b. if they had to be create, write them to the file system.
// 2. Generate the signature using the msg parameter.
// 3. Prepare the Key struct to be output in the proper format.
func ProcessMessage(msg string) (*Keys, error) {
	// Check if they keys are in the file system.
	keys, err := loadKeysFromFile(msg)
	if err == nil {
		return keys, nil
	}

	// At this point, we didn't find the keys in the file system. Generate them.
	keys, err = GenerateKeys(msg)
	if err != nil {
		return nil, err
	}

	return keys, nil
}

// GenerateKeys generates the private and public keys as well as the signature.
// msg is the string used to generate the signature.
func GenerateKeys(msg string) (*Keys, error) {
	result := &Keys{
		Message: msg,
	}

	// Generate private key.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("%s", err)
	}
	result.PrivateKey = privateKey

	result.PEMEncode()
	result.GenerateSignature()
	result.WriteToFile()

	return result, nil
}

// GenerateSignature sets the Signature member variable given the message.
// At this point, we assume that his object already has a handle to the message.
func (k *Keys) GenerateSignature() error {
	if k.Message == "" {
		return fmt.Errorf("missing message")
	}
	// Generate the signature.
	hash := sha256.Sum256([]byte(k.Message))
	r, s, err := ecdsa.Sign(rand.Reader, k.PrivateKey, hash[:])
	if err != nil {
		return fmt.Errorf("%s", err)
	}
	k.Signature = ECDSASignature{
		R: r,
		S: s,
	}
	return nil
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
	if err := k.PEMEncode(); err != nil {
		return []byte("issues encoding the keys")
	}
	// Format the outputs variables.
	k.EncodedSignature = k.Signature.String()

	b, err := json.Marshal(k)
	if err != nil {
		return []byte(fmt.Sprintf("failed to format for output %s", err))
	}

	return b
}

// PEMEncode encodes the private and public keys to PEM.  We use this encoding to serialize to a file as well.
func (k *Keys) PEMEncode() error {
	encodedPrivateKey, err := x509.MarshalECPrivateKey(k.PrivateKey)
	if err != nil {
		return err
	}
	k.PEMEncodedPrivateKey = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedPrivateKey}))

	x509EncodedPub, err := x509.MarshalPKIXPublicKey(k.PrivateKey.Public())
	if err != nil {
		return err
	}
	k.PEMEncodedPubKey = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub}))

	return nil
}

// WriteToFile writes the private and public keys to the file system.
func (k *Keys) WriteToFile() error {
	privateKeyFilename, publicKeyFilename := fileName(k.Message)

	f, err := os.Create(privateKeyFilename)
	if err != nil {
		return fmt.Errorf("failed to create private key file %s %s", privateKeyFilename, err)
	}
	defer f.Close()
	f.Write([]byte(k.PEMEncodedPrivateKey))

	pubFile, err := os.Create(publicKeyFilename)
	if err != nil {
		return fmt.Errorf("failed to create public key file %s %s", publicKeyFilename, err)
	}
	defer pubFile.Close()
	pubFile.Write([]byte(k.PEMEncodedPubKey))

	return nil
}
