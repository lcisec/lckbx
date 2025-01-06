package vault

import ()

type UnlockedVault struct {
	derive   deriver
	store    storer
	user     User
	keyset   Keyset
	metadata Metadata
}

// Purge Keys
//  1. Read through all MetadataItems to get a list of active keys.
//  2. Read through all of the Keyset keys and if any of them are not in use,
//     set Key.Inuse to false.
//  3. Purge unused keys.
func purgeUnusedKeys(ks Keyset, md Metadata) {
	// 1. Read through all MetadataItems to get a list of active keys.
	inUseKeys := md.GetInUseKeys()

	// 2. Read through all of the Keyset keys and if any of them are not in
	//    use, set Key.InUse to false.
	for keyId := range ks.Keys {
		kid, _ := parseVersionToken(keyId)
		inUse := false

		for _, inUseKey := range inUseKeys {
			if inUseKey == keyId {
				inUse = true
				break
			}
		}

		// The keyId is not in the list of inUseKeys, mark the key as unused.
		if inUse == false {
			ks.Unused(kid)
		}
	}

	// 3. Purge unused keys.
	ks.PurgeKeys()
}

// Reencrypt
// The reencrypt function is started at login and runs in the background until
// logout.
//  1. Read through all of the MetadataItems to determine which Items are not
//     encrypted using the latest key.
//  2. When an item is found, reencrypt the item with the latest key.
//  3. Update the Metadata Items by adding a new ItemMetadata entry and then
//     deleting the old entry.
//

// Add Item
//  1. Create Item
//  2. Create ItemMetadata
//  3. Add Item to Database
//  4. Add ItemMetadata to Metadata
//  5. Save the Metadata to the database.

// Delete Item
//  1. Create Item
//  2. Create ItemMetadata
//  3. Add Item to Database
//  4. Add ItemMetadata to Metadata
//  5. Save the Metadata to the database.
