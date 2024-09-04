package vault

import (
	"crypto/rand"
	"fmt"
)


// newKeyBytes returns a byte slice with keySize random bytes.
func newKeyBytes() [keySize]byte {
	var bytes [keySize]byte

	_, err := rand.Read(bytes[:])
	if err != nil {
		panic(fmt.Errorf("Could not newKeyBytes: %v", err))
	}

	return bytes
}

// newTokenBytes returns a byte slice with tokenSize random bytes.
func newTokenBytes() [tokenSize]byte {
	var bytes [tokenSize]byte

	_, err := rand.Read(bytes[:])
	if err != nil {
		panic(fmt.Errorf("Could not newTokenBytes: %v", err))
	}

	return bytes
}

// newRandomBytes returns a byte slice with size random bytes.
func newRandomBytes(size int) []byte {
	var bytes [size]byte

	_, err := rand.Read(bytes[:])
	if err != nil {
		panic(fmt.Errorf("Could not newRandomBytes: %v", err))
	}

	return bytes[:]
}
