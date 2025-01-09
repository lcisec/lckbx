package vault

import ()

type UnlockedVault struct {
	derive   deriver
	store    storer
	crypt    crypter
	user     User
	keyset   Keyset
	metadata Metadata
}

// Purge Keys
// the purgeUnusedKeys function removes keys from the keyset if they are no
// longer in use. It is started after login and runs in the background.
//  1. Read through all MetadataItems to get a list of active keys.
//  2. Read through all of the Keyset keys and if any of them are not in use,
//     set Key.Inuse to false.
//  3. Purge unused keys.
func (u *UnlockedVault) purgeUnusedKeys() {
	// 1. Read through all MetadataItems to get a list of active keys.
	inUseKeys := u.metadata.GetInUseKeys()

	// 2. Read through all of the Keyset keys and if any of them are not in
	//    use, set Key.InUse to false.
	for keyId := range u.keyset.Keys {
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
			u.keyset.Unused(kid)
		}
	}

	// 3. Purge unused keys.
	u.keyset.PurgeKeys()
}

// Update Encryption
// The updateEncryption function ensures each item is encrypted with the most
// recent key in the keyset. It is started after login and runs in the
// background.
//  1. Read through all of the MetadataItems to determine which Items are not
//     encrypted using the latest key.
//  2. When an item is found, reencrypt the item with the latest key and save
//     the reencrypted item to the database.
func (u *UnlockedVault) updateEncryption() error {
	failed := make([string]string)

	// 1.  Read through all of the MetadataItems to determine which Items are
	//     not encrypted using the latest key.
	for mdId, item := range u.metadata.Items {
		if item.KeyVersion.String() != u.keyset.Latest.String() {
			// 2.  When an item is found, reencrypt the item with the latest
			//     key.
			// 2.a Get the key used to encrypt the item.
			oldKey, err := u.keyset.GetItemKey(item.KeyVersion, item.ItemId)
			if err != nil {
				failed[item.ItemId] = err.String()
				break
			}

			// 2.b Create a new crypter with the old key.
			crypt, err := NewCrypter()
			if err != nil {
				failed[item.ItemId] = err.String()
				break
			}

			err = crypt.ChangeKey(oldKey)
			if err != nil {
				failed[item.ItemId] = err.String()
				break
			}

			// 2.c Load the encrypted item from the database.
			item, err := NewNoteItemFromStore(u.store, crypt, item.ItemId)
			if err != nil {
				failed[item.ItemId] = err.String()
				break
			}

			// 2.d Update the crypter with the latest key.
			err = crypt.ChangeKey(keyset.GetLatestKey())
			if err != nil {
				failed[item.ItemId] = err.String()
				break
			}

			// 2.e. Save the reencrypted item to the database.
			err = item.Save(u.store, crypt)
			if err != nil {
				failed[item.ItemId] = err.String()
				break
			}
		}
	}

	if len(failed) != 0 {
		return fmt.Errorf("failed to UnlockedVault.updateEncryption for %+v", failed)
	}

	return nil
}

// Add Item
//  1. Create ItemMetadata
//  2. Add Item to Database
//  3. Add ItemMetadata to Metadata
//  4. Save the Metadata to the database.
func (u *UnlockedVault) AddItem(i Item) error {

}

// Delete Item
//  1. Delete Item from the database.
//  2. Delete ItemMetadata from Metadata
//  3. Save the Metadata to the database.
func (u *UnlockedVault) DeleteItem(i Item) error {

}
