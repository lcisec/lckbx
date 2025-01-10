package lckbx

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// The NoteItem struct holds a note.
type NoteItem struct {
	ItemId ItemToken
	Name   string
	Data   []byte
}

func (n *NoteItem) Equal(n2 NoteItem) bool {
	return n.ItemId.String() == n2.ItemId.String() &&
		n.Name == n2.Name &&
		bytes.Equal(n.Data, n2.Data)
}

func (n *NoteItem) bytes(crypt crypter) ([]byte, error) {
	var encrypted []byte

	bytes, err := json.Marshal(n)
	if err != nil {
		return encrypted, fmt.Errorf("could not NoteItem.Bytes: %v", err)
	}

	encrypted, err = crypt.Encrypt(bytes, []byte(n.ItemId.String()))
	if err != nil {
		return encrypted, fmt.Errorf("could not NoteItem.Bytes: %v", err)
	}

	return encrypted, nil
}

// Save stores the NoteItem as encrypted bytes in the given storer.
func (n *NoteItem) Save(store storer, crypt crypter) error {
	bytes, err := n.bytes(crypt)
	if err != nil {
		return fmt.Errorf("could not NoteItem.Save: %v", err)
	}

	err = store.SaveItem(n.ItemId, bytes)
	if err != nil {
		return fmt.Errorf("could not NoteItem.Save: %v", err)
	}

	return nil
}

// NewNoteItem creates a new NoteItem object.
func NewNoteItem() NoteItem {
	return NoteItem{
		ItemId: NewItemToken(),
		Name:   "",
		Data:   make([]byte, 1),
	}
}

// newNoteItemFromBytes creates a new NoteItem object from encrypted bytes.
func newNoteItemFromBytes(crypt crypter, encrypted []byte, ad []byte) (NoteItem, error) {
	var note NoteItem

	plaintext, err := crypt.Decrypt(encrypted, ad)
	if err != nil {
		return note, err
	}

	err = json.Unmarshal(plaintext, &note)
	if err != nil {
		return note, err
	}

	return note, nil
}

func NewNoteItemFromStore(store storer, crypt crypter, iid ItemToken) (NoteItem, error) {
	var note NoteItem

	bytes, err := store.GetItem(iid)
	if err != nil {
		return note, fmt.Errorf("could not NewNoteItemFromStore: %v", err)
	}

	note, err = newNoteItemFromBytes(crypt, bytes, []byte(iid.String()))
	if err != nil {
		return note, fmt.Errorf("could not NewNoteItemFromStore: %v", err)
	}

	return note, nil
}
