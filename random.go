package lckbx

import (
	"crypto/rand"
	"encoding/base32"
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

// newNonceBytes returns a byte slice with nonceSize random bytes.
func newNonceBytes() []byte {
	var bytes [nonceSize]byte

	_, err := rand.Read(bytes[:])
	if err != nil {
		panic(fmt.Errorf("Could not newNonceBytes: %v", err))
	}

	return bytes[:]
}

// newRecoveryPhrase returns a new randomly generated recovery pass phrase.
func newRecoveryPhrase() string {
	var bytes [minPassphraseLength]byte
	var encoder = base32.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567").WithPadding(base32.NoPadding)

	_, err := rand.Read(bytes[:])
	if err != nil {
		panic(fmt.Errorf("Could not newRecoveryKey: %v", err))
	}

	phrase := encoder.EncodeToString(bytes[:])

	return phrase[:minPassphraseLength]
}
