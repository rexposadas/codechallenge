package lib

import "crypto/sha256"

// This file contains convenience functions.

// Helper function to compute the SHA256 hash of the given string of bytes.
func toSha256(b []byte) []byte {
	h := sha256.New()
	h.Write(b)

	// compute the SHA256 hash
	return h.Sum(nil)
}
