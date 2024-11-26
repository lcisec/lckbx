package vault

import (
	"testing"
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
	// t.Run("Test Metadata", testMetadata)
	// t.Run("Test Item", testItem)
	// t.Run("Test User", testUser)

	// End-to-end testing
	// Register a user, login as the user, add an item.
	// Login as the user, read the item, update the item.
	// Login as the user, read the updated item.
	// Change password
	// Login as user and read item.

}
