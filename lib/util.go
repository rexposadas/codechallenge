package lib

import (
	"bufio"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"hash/fnv"
	"os"
)

// This file contains convenience functions.

// Helper function to compute the SHA256 hash of the given string of bytes.
func toSha256(b []byte) []byte {
	h := sha256.New()
	h.Write(b)

	// compute the SHA256 hash
	return h.Sum(nil)
}

// hashedName was created to have a predictable and reliable way of naming our files.
func hashedName(s string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(s))
	return h.Sum32()
}

// Returns the filename given our filename nomenclature:
// id_<hashed msg>     for the private key
// id_<hashed msg>.pub for the public key
//
// The first returned value is the private key file name.
// The second returned value is the public key file name.
func fileName(msg string) (string, string) {
	m := hashedName(msg)
	return fmt.Sprintf("id_%v", m), fmt.Sprintf("id_%v.pub", m)
}

// Determine if we have the keys in the file system. If they are, then return them.
// If not, return an error.
//
// The msg parameter is used to find the file using our basic file nomenclature:

func loadKeysFromFile(msg string) (*Keys, error) {
	privateFileName, publicFileName := fileName(msg)

	// Check if the files exist.
	if _, err := os.Stat(privateFileName); err != nil {
		return nil, fmt.Errorf("missing private key file %s", err)
	}

	if _, err := os.Stat(publicFileName); err != nil {
		return nil, fmt.Errorf("missing public key file %s", err)
	}

	// At this point, we know that the files exists.  Read them and load them to a Keys struct.
	loadedKeys := &Keys{
		Message: msg,
	}

	// Read the private file first. The private key will be used to produce the signature.
	privateKeyFile, err := os.Open(privateFileName)
	if err != nil {
		return nil, fmt.Errorf("failed to open privatekey file %s %s", privateFileName, err)
	}
	defer privateKeyFile.Close()

	pemfileinfo, _ := privateKeyFile.Stat()
	var size = pemfileinfo.Size()
	pembytes := make([]byte, size)
	buffer := bufio.NewReader(privateKeyFile)
	_, err = buffer.Read(pembytes)
	data, _ := pem.Decode([]byte(pembytes))

	privateKey, _ := x509.ParseECPrivateKey(data.Bytes)
	loadedKeys.PrivateKey = privateKey

	// Load the public key. For our purpose, the public key is there so that we can, ultimately, add it to the output.
	pubKeyFile, err := os.Open(publicFileName)
	if err != nil {
		return nil, fmt.Errorf("failed to open privatekey file %s %s", publicFileName, err)
	}
	defer pubKeyFile.Close()

	publicFileInfo, _ := pubKeyFile.Stat()
	publicKeyBytes := make([]byte, publicFileInfo.Size())
	loadedKeys.PEMEncodedPubKey = string(publicKeyBytes)

	// Generate the signature
	if err := loadedKeys.GenerateSignature(); err != nil {
		return nil, fmt.Errorf("failed to generate signature from loaded files %s", err)
	}

	return loadedKeys, nil
}
