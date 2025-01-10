package vault

import (
	"bytes"
	"fmt"
	"testing"
)

var (
	noteDatabase = "note_test.db"
	noteName1    = "Spain"
	noteData1    = []byte("The rain in Spain falls mainly in the plain.")
	noteName2    = "Fox"
	noteData2    = []byte("The quick brown fox jumps over the lazy dog.")
)

func TestNoteItem(t *testing.T) {
	t.Run("Test New NoteItem", testNewNoteItem)
	t.Run("Test NoteItem Equality", testNoteItemEquality)
	t.Run("Test NoteItem Storage", testNoteItemStorage)
}

func testNewNoteItem(t *testing.T) {
	fmt.Println(t.Name())

	note := NewNoteItem()

	note.Data = noteData1
	if !bytes.Equal(note.Data, noteData1) {
		t.Fatalf("Expected %s, received %s", noteData1, note.Data)
	}
}

func testNoteItemEquality(t *testing.T) {
	iid := NewItemToken()

	// Create two identical NoteItems and ensure they are equal.
	note1 := NoteItem{
		ItemId: iid,
		Name:   noteName1,
		Data:   noteData1,
	}

	note2 := NoteItem{
		ItemId: iid,
		Name:   noteName1,
		Data:   noteData1,
	}

	if !note1.Equal(note2) {
		t.Fatalf("Expected equal NoteItem, received \n%+v\n%+v\n", note1, note2)
	}

	// Modify one of the objects and ensure they are unequal.
	note2.Name = noteName2
	if note1.Equal(note2) {
		t.Fatalf("Expected unequal NoteItems, received \n%+v\n%+v\n", note1, note2)
	}

	note2.Name = noteName1
	note2.Data = noteData2

	if note1.Equal(note2) {
		t.Fatalf("Expected unequal NoteItems, received \n%+v\n%+v\n", note1, note2)
	}
}

func testNoteItemStorage(t *testing.T) {
	fmt.Println(t.Name())

	crypterVersion, _ := parseVersionToken(xChaChaCrypterVersion)
	crypter := NewCrypter(crypterVersion)
	crypter.ChangeKey(userEncryptionKey)

	storer, _ := NewStore(noteDatabase)

	// Create a new NoteItem to work with.
	note1 := NewNoteItem()
	note1.Name = noteName1
	note1.Data = noteData1

	// Save the NoteItem object to the database, retrieve it, verify the
	// retrieved NoteItem matches the original.
	err := note1.Save(&storer, crypter)
	if err != nil {
		t.Fatal("Expected no error, received", err)
	}

	note2, err := NewNoteItemFromStore(&storer, crypter, note1.ItemId)
	if err != nil {
		t.Fatal("Expected no error, received", err)
	}

	if !note1.Equal(note2) {
		t.Fatal("Expected stored NoteItem to equal created NoteItem")
	}
}
