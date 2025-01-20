package lckbx

import (
	"fmt"
)

type UnlockedBox struct {
	derive   deriver
	store    storer
	crypt    crypter
	user     *User
	keyset   *Keyset
	metadata *Metadata
}

// Purge Keys
// the purgeUnusedKeys function removes keys from the keyset if they are no
// longer in use. It is started after login and runs in the background.
//  1. Read through all MetadataItems to get a list of active keys.
//  2. Read through all of the Keyset keys and if any of them are not in use,
//     set Key.Inuse to false.
//  3. Purge unused keys.
func (u *UnlockedBox) purgeUnusedKeys() {
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
func (u *UnlockedBox) updateEncryption() error {
	failed := make(map[string]string)

	// Get a list of map keys for the metadata Items
	var mapKeys []string
	for k := range u.metadata.Items {
		mapKeys = append(mapKeys, k)
	}

	// 1.  Read through all of the MetadataItems to determine which Items are
	//     not encrypted using the latest key.
	for _, mk := range mapKeys {
		item := u.metadata.Items[mk]

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
			note, err := NewNoteItemFromStore(u.store, u.crypt, item.ItemId)
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

			// 2.e Update the item KeyVersion
			u.metadata.Items[mk] = NewItemMetadata(item.Name, item.ItemId, u.keyset.Latest)

			// 2.f Save the reencrypted item to the database.
			err = note.Save(u.store, u.crypt)
			if err != nil {
				failed[item.ItemId.String()] = err.Error()
				break
			}
		}
	}

	err := u.metadata.Save(u.store, u.crypt)
	if err != nil {
		return fmt.Errorf("failed to UnlockedBox.updateEncryption %v", err)
	}

	if len(failed) != 0 {
		return fmt.Errorf("failed to UnlockedBox.updateEncryption for %+v", failed)
	}

	return nil
}

// Add NoteItem
//  1. Add Item to database
//  2. Create ItemMetadata and add it to Metadata
//  3. Save the Metadata to the database.
func (u *UnlockedBox) AddNoteItem(n NoteItem) error {
	// 1.  Add Item to database
	// 1.a Derive a new key for encrypting this item.
	newKey, err := u.keyset.GetNewItemKey(n.ItemId)
	if err != nil {
		return fmt.Errorf("could not UnlockedBox.AddNoteItem: %v", err)
	}

	// 1.b Update the crypter with the new key
	err = u.crypt.ChangeKey(newKey[:])
	if err != nil {
		return fmt.Errorf("could not UnlockedBox.AddNoteItem: %v", err)
	}

	// 1.c Save the item to the database
	err = n.Save(u.store, u.crypt)
	if err != nil {
		return fmt.Errorf("could not UnlockedBox.AddNoteItem: %v", err)
	}

	imd := NewItemMetadata(n.Name, n.ItemId, u.keyset.Latest)
	u.metadata.AddItem(imd)

	// 3.  Save the Metadata to the database
	// 3.a Derive the CryptKey used to encrypt the Metadata
	key, err := u.keyset.GetNewMetadataKey(u.user.MetadataId)
	if err != nil {
		return fmt.Errorf("could not UnlockedBox.AddNoteItem: %v", err)
	}

	// 3.b Update our crypter with the derived CryptKey and save the
	//     encrypted Metadata to the database.
	u.crypt.ChangeKey(key[:])
	err = u.metadata.Save(u.store, u.crypt)
	if err != nil {
		return fmt.Errorf("could not UnlockedBox.AddNoteItem: %v", err)
	}

	return nil
}

// Update NoteItem
//  1. Get the ItemMetadata for the NoteItem
//  2. Generate the encryption key for the NoteItem
//  3. Save the updated NoteItem
//  4. Update the ItemMetadata Name to match the NoteItem name
//  5. Save the Metadata.
func (u *UnlockedBox) UpdateNoteItem(n NoteItem) error {
	// 1.  Get the ItemMetadata for the NoteItem
	imd, err := u.metadata.GetItem(n.ItemId)
	if err != nil {
		return fmt.Errorf("could not UnlockedBox.UpdateNoteItem: %v", err)
	}

	// 2.  Derive the key for encrypting this item.
	key, err := u.keyset.GetItemKey(imd.KeyVersion, n.ItemId)
	if err != nil {
		return fmt.Errorf("could not UnlockedBox.UpdateNoteItem: %v", err)
	}

	// 3.  Save the updated NoteItem
	// 3.a Update the crypter with the new key
	err = u.crypt.ChangeKey(key[:])
	if err != nil {
		return fmt.Errorf("could not UnlockedBox.UpdateNoteItem: %v", err)
	}

	// 3.b Save the item to the database
	err = n.Save(u.store, u.crypt)
	if err != nil {
		return fmt.Errorf("could not UnlockedBox.UpdateNoteItem: %v", err)
	}

	// 4.  Update the ItemMetadata Name to match the NoteItem Name
	imd.Name = n.Name
	u.metadata.AddItem(imd)

	// 5.  Save the Metadata
	// 5.a Derive the CryptKey used to encrypt the Metadata
	key, err = u.keyset.GetNewMetadataKey(u.user.MetadataId)
	if err != nil {
		return fmt.Errorf("could not UnlockedBox.UpdateNoteItem: %v", err)
	}

	// 5.b Update our crypter with the derived CryptKey and save the
	//     encrypted Metadata to the database.
	u.crypt.ChangeKey(key[:])
	err = u.metadata.Save(u.store, u.crypt)
	if err != nil {
		return fmt.Errorf("could not UnlockedBox.UpdateNoteItem: %v", err)
	}

	return nil
}

// Delete NoteItem
//  1. Delete Item from the database.
//  2. Delete ItemMetadata from Metadata
//  3. Save the Metadata to the database.
func (u *UnlockedBox) DeleteItem(iid ItemToken) error {
	// 1.  Delete Item from database
	err := u.store.DeleteItem(iid)
	if err != nil {
		return fmt.Errorf("could not UnlockedBox.DeleteNoteItem: %v", err)
	}

	// 2.  Delete ItemMetadata from Metadata
	u.metadata.DeleteItem(iid)

	// 3. Save Metadata to the database
	// 3.a Derive the CryptKey used to encrypt the Metadata
	key, err := u.keyset.GetNewMetadataKey(u.user.MetadataId)
	if err != nil {
		return fmt.Errorf("could not UnlockedBox.AddNoteItem: %v", err)
	}

	// 3.b Update our crypter with the derived CryptKey and save the
	//     encrypted Metadata to the database.
	u.crypt.ChangeKey(key[:])
	err = u.metadata.Save(u.store, u.crypt)
	if err != nil {
		return fmt.Errorf("could not UnlockedBox.AddNoteItem: %v", err)
	}

	return nil
}

// GetUserName returns the username associated with the unlocked box.
func (u *UnlockedBox) GetUserName() string {
	return u.user.UserName
}

// GetItemList returns a mapping of item Names and ItemIds.
func (u *UnlockedBox) GetItemList() []ItemMetadata {
	return u.metadata.GetItems()
}

// GetItem returns the NoteItem associated with the given ItemId.
func (u *UnlockedBox) GetItem(iid ItemToken) (NoteItem, error) {
	var ni NoteItem

	key, err := u.keyset.GetNewItemKey(iid)
	if err != nil {
		return ni, fmt.Errorf("could not UnlockedBox.GetItem: %v", err)
	}

	u.crypt.ChangeKey(key[:])

	ni, err = NewNoteItemFromStore(u.store, u.crypt, iid)
	if err != nil {
		return ni, fmt.Errorf("could not UnlockedBox.GetItem %s: %v", iid, err)
	}

	return ni, nil
}

// Lock will set a random key on the crypter and set the User, Keyset, and
// Metadata to nil to make this UnlockedBox useless.
func (u *UnlockedBox) Lock() {
	key := NewCryptKey()
	u.crypt.ChangeKey(key[:])
	u.user = nil
	u.keyset = nil
	u.metadata = nil
}
