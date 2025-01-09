package vault

import (
	"fmt"
)

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
	failed := make(map[string]string)

	// 1.  Read through all of the MetadataItems to determine which Items are
	//     not encrypted using the latest key.
	for _, item := range u.metadata.Items {
		if item.KeyVersion.String() != u.keyset.Latest.String() {
			// 2.  When an item is found, reencrypt the item with the latest
			//     key.
			// 2.a Get the key used to encrypt the item.
			oldKey, err := u.keyset.GetItemKey(item.KeyVersion, item.ItemId)
			if err != nil {
				failed[item.ItemId.String()] = err.Error()
				break
			}

			// 2.b Create a new crypter with the old key.
			err = u.crypt.ChangeKey(oldKey[:])
			if err != nil {
				failed[item.ItemId.String()] = err.Error()
				break
			}

			// 2.c Load the encrypted item from the database.
			item, err := NewNoteItemFromStore(u.store, u.crypt, item.ItemId)
			if err != nil {
				failed[item.ItemId.String()] = err.Error()
				break
			}

			// 2.d Update the crypter with the latest key.
			newKey, err := u.keyset.GetNewItemKey(item.ItemId)
			if err != nil {
				failed[item.ItemId.String()] = err.Error()
				break
			}

			err = u.crypt.ChangeKey(newKey[:])
			if err != nil {
				failed[item.ItemId.String()] = err.Error()
				break
			}

			// 2.e. Save the reencrypted item to the database.
			err = item.Save(u.store, u.crypt)
			if err != nil {
				failed[item.ItemId.String()] = err.Error()
				break
			}
		}
	}

	if len(failed) != 0 {
		return fmt.Errorf("failed to UnlockedVault.updateEncryption for %+v", failed)
	}

	return nil
}

// Add NoteItem
//  1. Add Item to database
//  2. Create ItemMetadata and add it to Metadata
//  3. Save the Metadata to the database.
func (u *UnlockedVault) AddNoteItem(name string, n NoteItem) error {
	// 1.  Add Item to database
	// 1.a Derive a new key for encrypting this item.
	newKey, err := u.keyset.GetNewItemKey(n.ItemId)
	if err != nil {
		return fmt.Errorf("could not UnlockedVault.AddNoteItem: %v", err)
	}

	// 1.b Update the crypter with the new key
	err = u.crypt.ChangeKey(newKey[:])
	if err != nil {
		return fmt.Errorf("could not UnlockedVault.AddNoteItem: %v", err)
	}

	// 1.c Save the item to the database
	err = n.Save(u.store, u.crypt)
	if err != nil {
		return fmt.Errorf("could not UnlockedVault.AddNoteItem: %v", err)
	}

	imd := NewItemMetadata(name, n.ItemId, u.keyset.Latest)
	u.metadata.AddItem(imd)

	// 3.  Save the Metadata to the database
	// 3.a Derive the CryptKey used to encrypt the Metadata
	key, err := u.keyset.GetNewMetadataKey(u.user.MetadataId)
	if err != nil {
		return fmt.Errorf("could not UnlockedVault.AddNoteItem: %v", err)
	}

	// 3.b Update our crypter with the derived CryptKey and save the
	//     encrypted Metadata to the database.
	u.crypt.ChangeKey(key[:])
	err = u.metadata.Save(u.store, u.crypt)
	if err != nil {
		return fmt.Errorf("could not UnlockedVault.AddNoteItem: %v", err)
	}

	return nil
}

// Delete NoteItem
//  1. Delete Item from the database.
//  2. Delete ItemMetadata from Metadata
//  3. Save the Metadata to the database.
func (u *UnlockedVault) DeleteItem(iid ItemToken) error {
	// 1.  Delete Item from database
	err := u.store.DeleteItem(iid)
	if err != nil {
		return fmt.Errorf("could not UnlockedVault.DeleteNoteItem: %v", err)
	}

	// 2.  Delete ItemMetadata from Metadata
	u.metadata.DeleteItem(iid)

	// 3. Save Metadata to the database
	// 3.a Derive the CryptKey used to encrypt the Metadata
	key, err := u.keyset.GetNewMetadataKey(u.user.MetadataId)
	if err != nil {
		return fmt.Errorf("could not UnlockedVault.AddNoteItem: %v", err)
	}

	// 3.b Update our crypter with the derived CryptKey and save the
	//     encrypted Metadata to the database.
	u.crypt.ChangeKey(key[:])
	err = u.metadata.Save(u.store, u.crypt)
	if err != nil {
		return fmt.Errorf("could not UnlockedVault.AddNoteItem: %v", err)
	}

	return nil
}
