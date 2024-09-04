package vault

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// The XChaCha struct encrypts and decrypts data using XChaCha20Poly1305.
type XChaCha struct {
	aead cipher.AEAD
}

func (x *XChaCha) Decrypt(ciphertext, ad []byte) ([]byte, error) {
	var plaintext []byte

	if ciphertext == nil {
		return plaintext, nil
	}

	if len(ciphertext) < x.aead.NonceSize() {
		return plaintext, fmt.Errorf("could not XChaCha.Decrypt: ciphertext is too short")
	}

	if len(ad) == 0 {
		return plaintext, fmt.Errorf("could not XChaCha.Decrypt: missing authenticated data")
	}

	// Split nonce and ciphertext.
	nonce := ciphertext[:x.aead.NonceSize()]
	encrypted := ciphertext[x.aead.NonceSize():]

	// Decrypt the message and check it wasn't tampered with.
	plaintext, err := x.aead.Open(nil, nonce, encrypted, ad)
	if err != nil {
		return nil, fmt.Errorf("could not XChaCha.Decrypt: %v", err)
	}

	return plaintext, nil
}


func (x *XChaCha) Encrypt(plaintext, ad []byte) ([]byte, error) {
	var ciphertext []byte

	if len(ad) == 0 {
		return ciphertext, fmt.Errorf("could not XChaCha.Encrypt: missing authenticated data")
	}

	nonce := newRandomBytes(x.aead.NonceSize())
	encrypted := x.aead.Seal(nil, nonce, plaintext, ad)
	ciphertext := append(nonce, encrypted...)

	return ciphertext, nil
}


// NewV1Crypter creates a new crypter based on the XChaCha20Poly1305 cipher.
func NewV1Crypter(key CryptKey) XChaCha {
	var c XChaCha20Poly1305

	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return panic("could not NewXChaCha20Poly1305: %v", err)
	}

	c.aead = aead

	return c
}