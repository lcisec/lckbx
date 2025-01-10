package lckbx

import (
	"fmt"
	"testing"
)

var (
	unlockedBoxDB        = "unlocked_test.db"
	unlockedBoxUser      = "ub_user"
	unlockedBoxNoteName  = "A Note"
	unlockedBoxNoteData1 = []byte("Original note.")
	unlockedBoxNoteData2 = []byte("Updated note.")
)

// End-to-end test for an UnlockedBox
// 1. Create a LockedBox and register a user.
// 2. Login as the user, add an item, logout.
// 3. Login as the user, read the item, update the item, logout.
// 4. Login as the user, read the updated item.
// 5. Change password and ensure we can still read the item.
// 6. Run reencryption and key purge routines.
// 7. Verify key purge and ensure we can still read item.
func TestUnlockedBox(t *testing.T) {
	fmt.Println(t.Name())

	// 1.  Create a LockedBox and register a user.
	// 1.a Create a new store for testing
	store, err := NewStore(unlockedBoxDB)
	if err != nil {
		t.Fatalf("Expected no error, received %v", err)
	}

	// 1.b Create a new LockedBox with the given store.
	lb, err := NewLockedBox(&store)
	if err != nil {
		t.Fatalf("Expected no error, received %v", err)
	}

	// 1.c Register a new user with a good password
	err = lb.Register(unlockedBoxUser, lockedBoxGoodPassword)
	if err != nil {
		t.Fatalf("Expected no error, received %v", err)
	}

	// 2.  Login as the user, add an item, lock the UnlockedBox
	// 2.a Login as the user
	ub, err := lb.Login(unlockedBoxUser, lockedBoxGoodPassword)
	if err != nil {
		t.Fatalf("Expected no error, received %v", err)
	}

	// 2.b Create a new NoteItem and add data to it.
	n := NewNoteItem()
	iid := n.ItemId
	n.Name = unlockedBoxNoteName
	n.Data = unlockedBoxNoteData1

	// 2.c Add the NoteItem to the database.
	err = ub.AddNoteItem(n)
	if err != nil {
		t.Fatalf("Expected no error, received %v", err)
	}

	// 2.d Lock the UnlockedBox
	ub.Lock()

	// 3.  Login as the user, read the item, update the item, logout.
	// 3.a Login as the user
	ub, err = lb.Login(unlockedBoxUser, lockedBoxGoodPassword)
	if err != nil {
		t.Fatalf("Expected no error, received %v", err)
	}

	// 3.b Update our crypt key
	key, _ := ub.keyset.GetNewItemKey(n.ItemId)
	ub.crypt.ChangeKey(key[:])

	// 3.c Read the item from the store and make sure it is the same as what
	//     we saved.
	n2, err := NewNoteItemFromStore(ub.store, ub.crypt, iid)
	if err != nil {
		t.Fatalf("Expected no error, received %v", err)
	}

	if !n2.Equal(n) {
		t.Fatalf("Expected NoteItems to be equal, received: \n%+v\n%+v\n", n, n2)
	}

	// 3.d Update and save the NoteItem
	n2.Data = unlockedBoxNoteData2
	err = ub.UpdateNoteItem(n2)
	if err != nil {
		t.Fatalf("Expected no error, received: %v", err)
	}

	// 3.e Lock the UnlockedBox
	ub.Lock()

	// 4. Login as the user, read the updated item.
	// 4.a Login as the user
	ub, err = lb.Login(unlockedBoxUser, lockedBoxGoodPassword)
	if err != nil {
		t.Fatalf("Expected no error, received %v", err)
	}

	// 4.b Update our crypt key
	key, _ = ub.keyset.GetNewItemKey(n.ItemId)
	ub.crypt.ChangeKey(key[:])

	// 4.c Read the item from the store and make sure it is the same as what
	//     we saved.
	n3, err := NewNoteItemFromStore(ub.store, ub.crypt, iid)
	if err != nil {
		t.Fatalf("Expected no error, received %v", err)
	}

	if !n3.Equal(n2) {
		t.Fatalf("Expected NoteItems to be equal, received: \n%+v\n%+v\n", n2, n3)
	}

	// 4.d Lock the UnlockedBox
	ub.Lock()

	// 5.  Change password and ensure we can still read the item
	err = lb.ChangePassword(unlockedBoxUser, lockedBoxGoodPassword, lockedBoxBadPassword)
	if err != nil {
		t.Fatalf("Expected no error, received %v", err)
	}

	// 5.a Login as the user
	ub, err = lb.Login(unlockedBoxUser, lockedBoxBadPassword)
	if err != nil {
		t.Fatalf("Expected no error, received %v", err)
	}

	// 5.b Ensure we have two keys in our keyset now.
	if len(ub.keyset.Keys) != 2 {
		t.Fatalf("Expected two keys in our keyset, found %d", len(ub.keyset.Keys))
	}

	// 5.c Update our crypt key. We have to get the key by version ID because
	//     we changed passwords and the latest key is no longer the correct
	//     key.
	imd, _ := ub.metadata.GetItem(n.ItemId)
	key, _ = ub.keyset.GetItemKey(imd.KeyVersion, n.ItemId)
	ub.crypt.ChangeKey(key[:])

	// 5.d Read the item from the store and make sure it is the same as what
	//     we saved.
	n4, err := NewNoteItemFromStore(ub.store, ub.crypt, iid)
	if err != nil {
		t.Fatalf("Expected no error, received %v", err)
	}

	if !n4.Equal(n3) {
		t.Fatalf("Expected NoteItems to be equal, received: \n%+v\n%+v\n", n3, n4)
	}

	// 6. Run reencryption and key purge routines.
	err = ub.updateEncryption()
	if err != nil {
		t.Fatalf("Expected no error, received %v", err)
	}

	ub.purgeUnusedKeys()

	// 7. Verify key purge and ensure we can still read item.
	// 7.a Ensure we have only one key in our keyset now.
	if len(ub.keyset.Keys) != 1 {
		t.Fatalf("Expected one key in our keyset, found %d", len(ub.keyset.Keys))
	}

	// 7.b Update our crypt key
	key, _ = ub.keyset.GetNewItemKey(n.ItemId)
	ub.crypt.ChangeKey(key[:])

	// 7.c Read the item from the store and make sure it is the same as what
	//     we saved.
	n5, err := NewNoteItemFromStore(ub.store, ub.crypt, iid)
	if err != nil {
		t.Fatalf("Expected no error, received %v", err)
	}

	if !n5.Equal(n4) {
		t.Fatalf("Expected NoteItems to be equal, received: \n%+v\n%+v\n", n4, n5)
	}
}
