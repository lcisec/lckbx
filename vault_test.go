package vault

import (
	"fmt"
	"testing"
)

var (
	vaultUser     = "vault"
	shortPassword = "0123456789abcd"
	goodPassword  = "0123456789abcdef"
	badPassword   = "0123456789abcdee"
)

func TestVault(t *testing.T) {
	// Ensure basic storage functions work as expected.
	t.Run("Test NewStore", testNewStore)
	t.Run("Test StoreRWD", testStoreRWD)
	t.Run("Test Store Backup", testStoreBackup)

	// Ensure tokens and keys work as expected.
	t.Run("Test Tokens", testTokens)
	t.Run("Test Keys", testKeys)

	// Ensure data storage functions work as expected.
	t.Run("Test Store UserId", testStoreUserId)
	t.Run("Test Store User", testStoreUser)
	t.Run("Test Store Keyset", testStoreKeyset)
	t.Run("Test Store Metadata", testStoreMetadata)
	t.Run("Test Store Item", testStoreItem)

	// Ensure encryption and derivation work as expected.
	t.Run("Test Deriver", testDeriver)
	t.Run("Test Crypter", testCrypter)

	// Ensure individual data types work as expected
	t.Run("Test Keyset", testKeyset)
	t.Run("Test Metadata", testMetadata)
	t.Run("Test Note Item", testNoteItem)
	t.Run("Test User", testUser)

	// Ensure vault functions work as expected
	t.Run("Test Registration", testRegister)
	t.Run("Test Login", testLogin)
	t.Run("Test Password Change", testChangePassword)

	// End-to-end testing
	//t.Run("End-to-End Test", testVaultEndToEnd)
}

func testRegister(t *testing.T) {
	fmt.Println(t.Name())

	store, err := NewStore("register_test.db")
	if err != nil {
		t.Fatalf("Expected no error, received %v", err)
	}

	// Register a new user with a short password
	err = register(&store, vaultUser, shortPassword)
	if err == nil {
		t.Fatal("Expected error for short password, received nil")
	}

	// Register a new user with a good password
	err = register(&store, vaultUser, goodPassword)
	if err != nil {
		t.Fatalf("Expected no error, received %v", err)
	}

	// Register the same user a second time
	err = register(&store, vaultUser, goodPassword)
	if err == nil {
		t.Fatalf("Expected error for existing user, received nil")
	}
}

func testLogin(t *testing.T) {
	fmt.Println(t.Name())

	store, err := NewStore("login_test.db")
	if err != nil {
		t.Fatalf("Expected no error, received %v", err)
	}

	// Register a user.
	err = register(&store, vaultUser, goodPassword)
	if err != nil {
		t.Fatalf("Expected no error, received %v", err)
	}

	// Attempt to login with a bad password.
	_, _, _, err = login(&store, vaultUser, badPassword)
	if err == nil {
		t.Fatalf("Expected error with bad password, received nil")
	}

	// Attempt to login with a good password.
	user, keyset, metadata, err := login(&store, vaultUser, goodPassword)
	if user.UserName != vaultUser {
		t.Fatal("Expected", vaultUser, ", received", user.UserName)
	}

	if user.KeysetId != keyset.KeysetId {
		t.Fatal("Expected", keyset.KeysetId, ", received", user.KeysetId)
	}

	if user.MetadataId != metadata.MetadataId {
		t.Fatal("Expected", metadata.MetadataId, ", received", user.MetadataId)
	}
}

func testChangePassword(t *testing.T) {
	fmt.Println(t.Name())

	store, err := NewStore("password_test.db")
	if err != nil {
		t.Fatalf("Expected no error, received %v", err)
	}

	// Register a user.
	err = register(&store, vaultUser, goodPassword)
	if err != nil {
		t.Fatalf("Expected no error, received %v", err)
	}

	// Login with the good password.
	u1, ks1, md1, err := login(&store, vaultUser, goodPassword)

	// Change the password.
	err = changePassword(&store, vaultUser, goodPassword, badPassword)
	if err != nil {
		t.Fatalf("Expected no error, received %v", err)
	}

	// Login with the updated password.
	u2, ks2, md2, err := login(&store, vaultUser, badPassword)

	// Users should be equal
	if !u1.Equal(u2) {
		t.Fatalf("Expected users to be equal, received\n%v\n%v", u1, u2)
	}

	// Keysets will not be equal because a password change adds a new key to
	// the map, which updates the latest value. Check what we can to ensure
	// the Keyset is what we expect.
	if ks1.KeysetId != ks2.KeysetId {
		t.Fatalf("Expected keyset Ids to be equal, received %s %s", ks1.KeysetId, ks2.KeysetId)
	}

	// Since login calls purgeUnusedKeys, we should only expect one key in the
	// list.
	if len(ks2.Keys) != 1 {
		t.Fatalf("Expected two keys in new Keyset found %d", len(ks2.Keys))
	}

	// The latest key in each keyset should be different since changing the
	// password added a new key.
	ksi1, _ := ks1.GetLatestKey()
	ksi2, _ := ks2.GetLatestKey()

	if ksi1.Equal(ksi2) {
		t.Fatalf("Expected Keyset items to be unequal, received \n%v\n%v", ksi1, ksi2)
	}

	// Metadatas should be equal
	if !md1.Equal(md2) {
		t.Fatalf("Expected metadatas to be equal, received\n%v\n%v", md1, md2)
	}
}

// Register a user, login as the user, add an item.
// Login as the user, read the item, update the item.
// Login as the user, read the updated item.
// Change password
// Login as user and read item.
// func testVaultEndToEnd(t *testing.T) {
// 	store := NewStore("end-to-end-test.db")

// 	err := registerUser(store, username, shortPassword)
// 	if err == nil {
// 		t.Fatal("Expected error for short password, received nil")
// 	}

// 	err := registerUser(store, username, goodPassword)
// 	if err != nil {
// 		t.Fatalf("Expected no error, received %v", err)
// 	}

// }
