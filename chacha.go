package vault

import (
	"crypto/cipher"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	nonceSize = 24
)

// The xChaCha struct encrypts and decrypts data using XChaCha20Poly1305.
type xChaCha struct {
	aead      cipher.AEAD
	nonceSize int
}

func (x xChaCha) Decrypt(ciphertext, ad []byte) ([]byte, error) {
	var plaintext []byte

	if ciphertext == nil {
		return plaintext, fmt.Errorf("could not XChaCha.Decrypt: ciphertext is nil")
	}

	if len(ciphertext) < x.nonceSize {
		return plaintext, fmt.Errorf("could not XChaCha.Decrypt: ciphertext is too short")
	}

	if (ad == nil) || (len(ad) == 0) {
		return plaintext, fmt.Errorf("could not XChaCha.Decrypt: missing associated data")
	}

	if len(ad) < tokenSize {
		return plaintext, fmt.Errorf("could not XChaCha.Decrypt: associated data is too short.")
	}

	// Split nonce and ciphertext.
	nonce := ciphertext[:x.nonceSize]
	encrypted := ciphertext[x.nonceSize:]

	// Decrypt the message and check it wasn't tampered with.
	plaintext, err := x.aead.Open(nil, nonce, encrypted, ad)
	if err != nil {
		return nil, fmt.Errorf("could not XChaCha.Decrypt: %v", err)
	}

	return plaintext, nil
}

func (x xChaCha) Encrypt(plaintext, ad []byte) ([]byte, error) {
	var ciphertext []byte

	if (ad == nil) || (len(ad) == 0) {
		return ciphertext, fmt.Errorf("could not XChaCha.Encrypt: missing associated data")
	}

	if len(ad) < tokenSize {
		return ciphertext, fmt.Errorf("could not XChaCha.Encrypt: associated data is too short.")
	}

	nonce := newNonceBytes()
	encrypted := x.aead.Seal(nil, nonce, plaintext, ad)
	ciphertext = append(nonce, encrypted...)

	return ciphertext, nil
}

// NewXChaChaCrypter creates a new XChaCha object, which satisfies the crypter
// interface and is based on the XChaCha20Poly1305 cipher.
func newXChaChaCrypter(key []byte) xChaCha {
	if len(key) < keySize {
		panic(fmt.Sprintf("could not newXChaChaCrytper: key is too short"))
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		panic(fmt.Sprintf("could not newXChaChaCrypter: %v", err))
	}

	return xChaCha{
		aead:      aead,
		nonceSize: nonceSize,
	}
}
