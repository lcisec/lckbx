package lckbx

import (
	"fmt"
	"testing"
)

func testXChaChaCrypter(t *testing.T) {
	fmt.Println(t.Name())

	t.Run("Test Encrypt", testXChaChaEncrypt)
	t.Run("Test Decrypt", testXChaChaDecrypt)
	t.Run("Test RoundTrip", testXChaChaRoundTrip)
}

func testXChaChaEncrypt(t *testing.T) {
	fmt.Println(t.Name())

	version, _ := parseVersionToken(xChaChaCrypterVersion)
	crypter := NewCrypter(version)

	_, err := crypter.Encrypt(nil, nil)
	if err == nil {
		t.Fatal("Expected error since no key has been set, received nil")
	}

	err = crypter.ChangeKey(cryptKeyBytes)
	if err != nil {
		t.Fatalf("Expected no error, received %v", err)
	}

	_, err = crypter.Encrypt(plaintext, noAssociatedData)
	if err == nil {
		t.Fatal("Expected error because no associated data, received nil")
	}

	_, err = crypter.Encrypt(plaintext, shortAssociatedData)
	if err == nil {
		t.Fatal("Expected error because short associated data, received nil")
	}

	_, err = crypter.Encrypt(plaintext, goodAssociatedData)
	if err != nil {
		t.Fatal("Expected no error, received", err)
	}
}

func testXChaChaDecrypt(t *testing.T) {
	fmt.Println(t.Name())

	version, _ := parseVersionToken(xChaChaCrypterVersion)
	crypter := NewCrypter(version)

	_, err := crypter.Decrypt(nil, nil)
	if err == nil {
		t.Fatal("Expected error since no key has been set, received nil")
	}

	err = crypter.ChangeKey(cryptKeyBytes)
	if err != nil {
		t.Fatalf("Expected no error, received %v", err)
	}

	encrypted, err := crypter.Encrypt(plaintext, goodAssociatedData)
	if err != nil {
		t.Fatalf("Expected no error, received %v", err)
	}

	_, err = crypter.Decrypt(encrypted, noAssociatedData)
	if err == nil {
		t.Fatal("Expected error, received nil")
	}

	_, err = crypter.Decrypt(encrypted, shortAssociatedData)
	if err == nil {
		t.Fatal("Expected error, received nil")
	}

	_, err = crypter.Decrypt(encrypted, goodAssociatedData)
	if err != nil {
		t.Fatal("Expected no error, received", err)
	}
}

func testXChaChaRoundTrip(t *testing.T) {
	fmt.Println(t.Name())

	version, _ := parseVersionToken(xChaChaCrypterVersion)
	crypter := NewCrypter(version)
	crypter.ChangeKey(cryptKeyBytes)

	encrypted, _ := crypter.Encrypt(plaintext, goodAssociatedData)
	decrypted, _ := crypter.Decrypt(encrypted, goodAssociatedData)

	if string(decrypted) != string(plaintext) {
		t.Fatal("Expected", string(plaintext), ", received", string(decrypted))
	}
}
