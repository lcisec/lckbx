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

	// // Ensure data storage functions work as expected.
	// t.Run("Test Store User", testStoreUser)
	// t.Run("Test Store Keyset", testStoreKeyset)
	// t.Run("Test Store Metadata", testStoreMetadata)
	// t.Run("Test Store Item", testStoreItem)

	// // End-to-end testing

}
