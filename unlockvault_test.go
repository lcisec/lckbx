package vault

import (
	"testing"
)

var (
	unlockedVaultUser = "uv_user"
	vaultNote1        = "Original note."
	vaultNote2        = "Updated note."
)

func TestUnlockVault(t *testing.T) {
	// t.Run("Test Key Purge", testPurgeKeys)
	// t.Run("Test Login", testLogin)
	// t.Run("Test Password Change", testChangePassword)
}

// func buildVault(path string) Vault {
// 	store, err := NewStore(path)
// 	if err != nil {
// 		t.Fatalf("Expected no error, received %v", err)
// 	}

// 	vault, err := NewVault(&store)
// 	if err != nil {
// 		t.Fatalf("Expected no error, received %v", err)
// 	}

// 	// Register a new user with a good password
// 	err = vault.Register(unlockedVaultUser, vaultGoodPassword)
// 	if err != nil {
// 		t.Fatalf("Expected no error, received %v", err)
// 	}

// }

// func testPurgeKeys(t *testing.T) {
// 	fmt.Println(t.Name())

// 	vault := buildVault("purge_keys_test.db")

// }

// func testLogin(t *testing.T) {
// 	fmt.Println(t.Name())

// 	store, err := NewStore("login_test.db")
// 	if err != nil {
// 		t.Fatalf("Expected no error, received %v", err)
// 	}

// 	// Register a user.
// 	err = register(&store, vaultUser, vaultGoodPassword)
// 	if err != nil {
// 		t.Fatalf("Expected no error, received %v", err)
// 	}

// 	// Attempt to login with a bad password.
// 	_, _, _, err = login(&store, vaultUser, vaultBadPassword)
// 	if err == nil {
// 		t.Fatalf("Expected error with bad password, received nil")
// 	}

// 	// Attempt to login with a good password.
// 	user, keyset, metadata, err := login(&store, vaultUser, vaultGoodPassword)
// 	if user.UserName != vaultUser {
// 		t.Fatal("Expected", vaultUser, ", received", user.UserName)
// 	}

// 	if user.KeysetId != keyset.KeysetId {
// 		t.Fatal("Expected", keyset.KeysetId, ", received", user.KeysetId)
// 	}

// 	if user.MetadataId != metadata.MetadataId {
// 		t.Fatal("Expected", metadata.MetadataId, ", received", user.MetadataId)
// 	}
// }

// func testChangePassword(t *testing.T) {
// 	fmt.Println(t.Name())

// 	store, err := NewStore("password_test.db")
// 	if err != nil {
// 		t.Fatalf("Expected no error, received %v", err)
// 	}

// 	// Register a user.
// 	err = register(&store, vaultUser, vaultGoodPassword)
// 	if err != nil {
// 		t.Fatalf("Expected no error, received %v", err)
// 	}

// 	// Login with the good password.
// 	u1, ks1, md1, err := login(&store, vaultUser, vaultGoodPassword)

// 	// Change the password.
// 	err = changePassword(&store, vaultUser, vaultGoodPassword, vaultBadPassword)
// 	if err != nil {
// 		t.Fatalf("Expected no error, received %v", err)
// 	}

// 	// Login with the updated password.
// 	u2, ks2, md2, err := login(&store, vaultUser, vaultBadPassword)

// 	// Users should be equal
// 	if !u1.Equal(u2) {
// 		t.Fatalf("Expected users to be equal, received\n%v\n%v", u1, u2)
// 	}

// 	// Keysets will not be equal because a password change adds a new key to
// 	// the map, which updates the latest value. Check what we can to ensure
// 	// the Keyset is what we expect.
// 	if ks1.KeysetId != ks2.KeysetId {
// 		t.Fatalf("Expected keyset Ids to be equal, received %s %s", ks1.KeysetId, ks2.KeysetId)
// 	}

// 	// Since login calls purgeUnusedKeys, we should only expect one key in the
// 	// list.
// 	if len(ks2.Keys) != 1 {
// 		t.Fatalf("Expected two keys in new Keyset found %d", len(ks2.Keys))
// 	}

// 	// The latest key in each keyset should be different since changing the
// 	// password added a new key.
// 	ksi1, _ := ks1.GetLatestKey()
// 	ksi2, _ := ks2.GetLatestKey()

// 	if ksi1.Equal(ksi2) {
// 		t.Fatalf("Expected Keyset items to be unequal, received \n%v\n%v", ksi1, ksi2)
// 	}

// 	// Metadatas should be equal
// 	if !md1.Equal(md2) {
// 		t.Fatalf("Expected metadatas to be equal, received\n%v\n%v", md1, md2)
// 	}
// }

// // End-to-end Testing
// // 1. Register a user, login as the user, add an item, logout.
// // 2. Login as the user, read the item, update the item, logout.
// // 3. Login as the user, read the updated item.
// // 4. Change password, logout before reencryption
// // 5. Login as user and read item.
// // 6. Allow reencryption to take place, logout.
// // 7. Login and allow key purge to take place.
// // 8. Verify key purge and ensure we can still read item.
// func testVaultEndToEnd(t *testing.T) {
// 	store := NewStore("end-to-end-test.db")

// 	// 1.  Register a user
// 	err := registerUser(store, username, goodPassword)
// 	if err != nil {
// 		t.Fatal("Expected no error when registering, received", err)
// 	}

// 	// 1.a Login as the user
// 	user, ks, md, err := login(store, username, goodPassword)
// 	if err != nil {
// 		t.Fatal("Expected no error when logging in, received", err)
// 	}

// 	err := registerUser(store, username, goodPassword)
// 	if err != nil {
// 		t.Fatalf("Expected no error, received %v", err)
// 	}

// }
