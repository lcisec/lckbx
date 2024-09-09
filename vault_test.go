package vault

import (
	"testing"
)

func TestVault(t *testing.T) {
	// Ensure basic storage functions work as expected.
	testNewStore(t)
	testStoreRWD(t)
	testStoreBackup(t)

	// // Ensure tokens and keys work as expected.
	// testTokens(t)
	// testKeys(t)

	// // Ensure data storage functions work as expected.
	// testStoreUser(t)
	// testStoreKeyset(t)
	// testStoreMetadata(t)
	// testStoreItem(t)

	// // End-to-end testing

}
