package vault

import (
	"fmt"
	"testing"
)

var (
	cryptKeyBytes       = []byte("FEDCBA9876543210FEDCBA9876543210")
	noAssociatedData    = []byte("")
	shortAssociatedData = []byte("0123456789abcdef0123456789abcde")
	goodAssociatedData  = []byte("0123456789abcdef0123456789abcdef")
	plaintext           = []byte("The rain in Spain falls mainly in the plain.")
)

func testChaChaCrypter(t *testing.T) {
	fmt.Println(t.Name())

	crypter := NewV1Crypter(cryptKeyBytes)
	_, err := crypter.Encrypt(plaintext, noAssociatedData)
	if err == nil {
		t.Fatal("Expected error, received nil")
	}

	_, err = crypter.Encrypt(plaintext, shortAssociatedData)
	if err == nil {
		t.Fatal("Expected error, received nil")
	}

	encrypted, err := crypter.Encrypt(plaintext, goodAssociatedData)
	if err != nil {
		t.Fatal("Expected no error, received", err)
	}

	_, err = crypter.Decrypt(encrypted, noAssociatedData)
	if err == nil {
		t.Fatal("Expected error, received nil")
	}

	_, err = crypter.Decrypt(encrypted, shortAssociatedData)
	if err == nil {
		t.Fatal("Expected error, received nil")
	}

	decrypted, err := crypter.Decrypt(encrypted, goodAssociatedData)
	if err != nil {
		t.Fatal("Expected no error, received", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Fatal("Expected", string(plaintext), ", received", string(decrypted))
	}
}
