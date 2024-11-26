package vault

import (
	"fmt"
	"strings"
	"testing"
)

var (
	keysetDatabase      = "keyset_test.db"
	keysetEncryptionKey = []byte{118, 252, 88, 61, 49, 10, 153, 183, 89, 126, 199, 34, 146, 149, 60, 66, 118, 115, 234, 49, 121, 57, 39, 46, 252, 161, 43, 218, 73, 46, 229, 78}
	keysetTestToken     = "kt_J23BPOHMXA5FMYNHEBYB6HKOUD5G5THP7YEWTFLMWBJKZ2TRSNEQ"
)

func testKeyset(t *testing.T) {
	t.Run("Test New Keyset", testNewKeyset)
	t.Run("Test Keyset Items", testKeysetItems)
	t.Run("Test Keyset Derivation", testKeysetDerivation)
	t.Run("Test Keyset Storage", testKeysetStorage)
}

func getCrypterStorer() (crypter, storer) {
	crypterVersion, _ := parseVersionToken(xChaChaCrypterVersion)
	crypter := NewCrypter(keysetEncryptionKey, crypterVersion)

	storer, _ := NewStore(keysetDatabase)

	return crypter, &storer
}

func testNewKeyset(t *testing.T) {
	fmt.Println(t.Name())

	ksid, _ := parseKeysetToken(keysetTestToken)
	ks := NewKeyset(ksid)

	if len(ks.Keys) != 1 {
		t.Fatal("Expected 1 key in Keyset, found", len(ks.Keys))
	}

	key, ok := ks.Keys[ks.Latest.String()]
	if !ok {
		t.Fatal("Expected", ks.Latest.String(), "in Keyset.Keys, but was not found")
	}

	if !strings.HasPrefix(key.BaseKey.String(), baseKeyPrefix) {
		t.Fatal("Expected BaseKey, found", key.BaseKey.String())
	}

	if key.DeriverVersion.String() != argonBlakeDeriverVersion {
		t.Fatal("Expected", argonBlakeDeriverVersion, ", received", key.DeriverVersion.String())
	}

}

func testKeysetItems(t *testing.T) {
	fmt.Println(t.Name())
}

func testKeysetDerivation(t *testing.T) {
	fmt.Println(t.Name())
}

func testKeysetStorage(t *testing.T) {
	fmt.Println(t.Name())
}
