package lckbx

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

func TestCrypter(t *testing.T) {
	t.Run("Test xChaChaCrypter", testXChaChaCrypter)

	// Test the NewCrypter function after all crypters are tested.
	t.Run("Test NewCrypter", testNewCrypter)
}

func testNewCrypter(t *testing.T) {
	fmt.Println(t.Name())

	// Test xChaCha crypter
	crypterVersion, err := parseVersionToken(xChaChaCrypterVersion)
	if err != nil {
		t.Fatal("Expected no error, received", err)
	}

	c := NewCrypter(crypterVersion)
	c.ChangeKey(cryptKeyBytes)

	encrypted, _ := c.Encrypt(plaintext, goodAssociatedData)
	decrypted, _ := c.Decrypt(encrypted, goodAssociatedData)

	if string(decrypted) != string(plaintext) {
		t.Fatal("Expected", string(plaintext), ", received", string(decrypted))
	}
}
