package lckbx

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

var (
	keysetDatabase         = "keyset_test.db"
	keysetEncryptionKey    = []byte{118, 252, 88, 61, 49, 10, 153, 183, 89, 126, 199, 34, 146, 149, 60, 66, 118, 115, 234, 49, 121, 57, 39, 46, 252, 161, 43, 218, 73, 46, 229, 78}
	keysetTestToken        = "kt_J23BPOHMXA5FMYNHEBYB6HKOUD5G5THP7YEWTFLMWBJKZ2TRSNEQ"
	keysetBadVersion       = "vt_6FLNEXXJ2WRZXJ3T3SZKH3CSM5YREJXT3ZZ5VZDIPYDUKVMBFVNA"
	keysetBaseKey          = "bk_IUFKMB36LWM4B3TYBVYAZ2TKT4PJNKRNOANYKAARZFTHGDLSRU3A"
	keysetItemToken        = "it_GJSQX4U5YHQRMQNFZT7RPYLBZZ2ORNBI3JLPGJNFRWMAN5SH4UZQ"
	keysetMetadataToken    = "mt_TCVM43ZF5YSSZCH74KO3F7FHMS2GKBTDMNPPI4KBWMRDJDGPTTHA"
	keysetItemCryptKey     = "ck_VHBBWL2GEWDAUGVNQLZ2VPJTVP4IY4WQ4OWUPCQYTB6MLOP4JREQ"
	keysetMetadataCryptKey = "ck_GPH2E7OFIQUTK7VOGFEWDTUWHKBF7Y3CHGVMO5M6MGVEEGSLKM2Q"
)

func TestKeyset(t *testing.T) {
	t.Run("Test New Keyset", testNewKeyset)
	t.Run("Test Keyset Equality", testKeysetEquality)
	t.Run("Test Keyset Items", testKeysetItems)
	t.Run("Test Keyset Purge", testKeysetPurge)
	t.Run("Test Keyset Derivation", testKeysetDerivation)
	t.Run("Test Keyset Storage", testKeysetStorage)
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

func testKeysetEquality(t *testing.T) {
	ksid, err := parseKeysetToken(keysetTestToken)
	if err != nil {
		t.Fatal("Expected", keysetTestToken, ", received", ksid)
	}
	kid := NewVersionToken()
	dv, _ := parseVersionToken(argonBlakeDeriverVersion)
	bk, _ := parseBaseKey(keysetBaseKey)

	ksItem := KeysetItem{
		BaseKey:        bk,
		DeriverVersion: dv,
		InUse:          true,
	}

	// Create two identical Keysets and ensure they are equal.
	ks1 := &Keyset{
		KeysetId: ksid,
		mutex:    &sync.RWMutex{},
		Keys:     make(map[string]KeysetItem),
		Latest:   kid,
	}

	ks1.Keys[kid.String()] = ksItem

	ks2 := &Keyset{
		KeysetId: ksid,
		mutex:    &sync.RWMutex{},
		Keys:     make(map[string]KeysetItem),
		Latest:   kid,
	}

	ks2.Keys[kid.String()] = ksItem

	if !ks1.Equal(ks2) {
		t.Fatalf("Expected equal keysets, received \n%+v\n%+v\n", ks1, ks2)
	}

	ks2.AddKey(bk, dv)

	if ks1.Equal(ks2) {
		t.Fatalf("Expected unequal keysets, received \n%+v\n%+v\n", ks1, ks2)
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

	if !fKey.Equal(fKey2) {
		t.Fatal("Expected retrieved key to equal generated key.")
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

func testKeysetPurge(t *testing.T) {
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

	// Add a second key to the Keyset.
	dv, _ := parseVersionToken(argonBlakeDeriverVersion)
	bk, _ := parseBaseKey(keysetBaseKey)
	ks.AddKey(bk, dv)

	// Mark the first key as no longer in use and verify it.
	ks.Unused(fVersion)
	fKey, err = ks.GetKey(fVersion)
	if err != nil {
		t.Fatal("Expected no error, received", err)
	}

	if fKey.InUse != false {
		t.Fatal("Expected key to be marked as not in use.")
	}

	// Purge the key and verify it is no longer in the Keyset Keys.
	ks.PurgeKeys()
	_, err = ks.GetKey(fVersion)
	if err == nil {
		t.Fatalf("Expected error after key purge, received nil.")
	}
}

func testKeysetDerivation(t *testing.T) {
	fmt.Println(t.Name())

	// Create a new Keyset to work with.
	ksid, _ := parseKeysetToken(keysetTestToken)
	ks := NewKeyset(ksid)

	// Since we don't know the initial random key generated when the Keyset
	// was created, we need to add a new BaseKey to test the key derivation.
	dv, _ := parseVersionToken(argonBlakeDeriverVersion)
	bk, _ := parseBaseKey(keysetBaseKey)
	lVersion := ks.AddKey(bk, dv)

	// Test derivation for Items
	itemToken, _ := parseItemToken(keysetItemToken)
	ck, err := ks.GetNewItemKey(itemToken)
	if err != nil {
		t.Fatal("Expected no error, received", err)
	}

	if ck.String() != keysetItemCryptKey {
		t.Fatal("Expected item crypt key", keysetItemCryptKey, ", received", ck)
	}

	ck, err = ks.GetItemKey(lVersion, itemToken)
	if err != nil {
		t.Fatal("Expected no error, received", err)
	}

	if ck.String() != keysetItemCryptKey {
		t.Fatal("Expected item crypt key", keysetItemCryptKey, ", received", ck)
	}

	// Test derivation for Metadata
	metadataToken, _ := parseMetadataToken(keysetMetadataToken)
	ck, err = ks.GetNewMetadataKey(metadataToken)
	if err != nil {
		t.Fatal("Expected no error, received", err)
	}

	if ck.String() != keysetMetadataCryptKey {
		t.Fatal("Expected item crypt key", keysetMetadataCryptKey, ", received", ck)
	}

	ck, err = ks.GetMetadataKey(lVersion, metadataToken)
	if err != nil {
		t.Fatal("Expected no error, received", err)
	}

	if ck.String() != keysetMetadataCryptKey {
		t.Fatal("Expected item crypt key", keysetMetadataCryptKey, ", received", ck)
	}
}

func testKeysetStorage(t *testing.T) {
	fmt.Println(t.Name())

	crypterVersion, _ := parseVersionToken(xChaChaCrypterVersion)
	crypter := NewCrypter(crypterVersion)
	crypter.ChangeKey(keysetEncryptionKey)

	storer, _ := NewStore(keysetDatabase)

	// Create a new Keyset to work with.
	ksid, _ := parseKeysetToken(keysetTestToken)
	ks := NewKeyset(ksid)

	err := ks.Save(&storer, crypter)
	if err != nil {
		t.Fatal("Expected no error, received", err)
	}

	ks2, err := NewKeysetFromStore(&storer, crypter, ksid)
	if err != nil {
		t.Fatal("Expected no error, received", err)
	}

	if !ks.Equal(ks2) {
		t.Fatal("Expected stored Keyset to equal created Keyset")
	}
}
