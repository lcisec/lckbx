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
	keysetBadVersion    = "vt_6FLNEXXJ2WRZXJ3T3SZKH3CSM5YREJXT3ZZ5VZDIPYDUKVMBFVNA"
	keysetBaseKey       = "bk_IUFKMB36LWM4B3TYBVYAZ2TKT4PJNKRNOANYKAARZFTHGDLSRU3A"
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

	if key.InUse != true {
		t.Fatal("Expected key to be marked in use but it was not")
	}
}

func testKeysetItems(t *testing.T) {
	fmt.Println(t.Name())

	// Create a new Keyset to work with.
	ksid, _ := parseKeysetToken(keysetTestToken)
	ks := NewKeyset(ksid)

	// Get the first KeysetItem and its version token.
	fVersion := ks.Latest
	fKey, err := ks.GetLatestKey()
	if err != nil {
		t.Fatal("Expected no error, received", err)
	}

	// Add a second key and ensure the Latest value was updated.
	dv, _ := parseVersionToken(argonBlakeDeriverVersion)
	bk, _ := parseBaseKey(keysetBaseKey)
	sVersion := ks.AddKey(bk, dv)
	sKey, _ := ks.GetLatestKey()

	if sVersion.String() != ks.Latest.String() {
		t.Fatal("Expected", sVersion, ", received", ks.Latest)
	}

	if sKey.BaseKey.String() != keysetBaseKey {
		t.Fatal("Expected", keysetBaseKey, ", received", sKey.BaseKey)
	}

	// Verify we can get the first key by it's version token.
	fKey2, err := ks.GetKey(fVersion)
	if err != nil {
		t.Fatal("Expected no error, received", err)
	}

	if fKey.BaseKey.String() != fKey2.BaseKey.String() {
		t.Fatal("Expected", fKey.BaseKey, ", received", fKey2.BaseKey)
	}

	// Ensure we get an error when trying to delete the latest key, an in use
	// key, or a non-existent key.
	err = ks.DeleteKey(sVersion)
	if err == nil {
		t.Fatal("Expected error for deleting latest key, no error received.")
	}

	err = ks.DeleteKey(fVersion)
	if err == nil {
		t.Fatal("Expected error for deleting in use key, no error received.")
	}

	badVersion, _ := parseVersionToken(keysetBadVersion)
	err = ks.DeleteKey(badVersion)
	if err == nil {
		t.Fatal("Expected error for deleting non-existent key, no error received.")
	}

	// Mark the first key as not in use and attempt to delete it. No errors
	// should be received.
	err = ks.Unused(fVersion)
	if err != nil {
		t.Fatal("Expected no error, received", err)
	}

	err = ks.DeleteKey(fVersion)
	if err != nil {
		t.Fatal("Expected no error, received", err)
	}

	// Set the Latest version to a non-existent value so that we can test
	// deleting the last key.
	ks.Latest = badVersion

	err = ks.DeleteKey(sVersion)
	if err == nil {
		t.Fatal("Expected error for deleting last available key, no error received.")
	}
}

func testKeysetDerivation(t *testing.T) {
	fmt.Println(t.Name())
}

func testKeysetStorage(t *testing.T) {
	fmt.Println(t.Name())
}
