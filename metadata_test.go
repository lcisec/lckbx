package vault

import (
	"fmt"
	"sync"
	"testing"
)

var (
	metadataDatabase      = "metadata_test.db"
	metadataEncryptionKey = []byte{118, 252, 88, 61, 49, 10, 153, 183, 89, 126, 199, 34, 146, 149, 60, 66, 118, 115, 234, 49, 121, 57, 39, 46, 252, 161, 43, 218, 73, 46, 229, 78}
	metadataTestToken     = "mt_6SAQXDCNAPLEOACUIFPQI6HW3R5DF4U3LZHT2GOZCTHPNHLN7B5Q"
)

func testMetadata(t *testing.T) {
	t.Run("Test New Metadata", testNewMetadata)
	t.Run("Test Metadata Equality", testMetadataEquality)
	t.Run("Test Metadata Items", testMetadataItems)
	t.Run("Test Metadata Storage", testMetadataStorage)
}

func testNewMetadata(t *testing.T) {
	fmt.Println(t.Name())

	mdid, _ := parseMetadataToken(metadataTestToken)
	md := NewMetadata(mdid)

	if len(md.Items) != 0 {
		t.Fatal("Expected 0 MetadataItems in Metadata, found", len(md.Items))
	}
}

func testMetadataEquality(t *testing.T) {
	mdId, err := parseMetadataToken(metadataTestToken)
	if err != nil {
		t.Fatal("Expected", metadataTestToken, ", received", mdId, err)
	}

	iid := NewItemToken()
	kid := NewVersionToken()

	mdItem := ItemMetadata{
		ItemId:     iid,
		Name:       "Metadata Item 1",
		KeyVersion: kid,
	}

	// Create two identical Metadata objects and ensure they are equal.
	md1 := Metadata{
		MetadataId: mdId,
		mutex:      &sync.RWMutex{},
		Items:      make(map[string]ItemMetadata),
	}

	md2 := Metadata{
		MetadataId: mdId,
		mutex:      &sync.RWMutex{},
		Items:      make(map[string]ItemMetadata),
	}

	if !md1.Equal(md2) {
		t.Fatalf("Expected equal Metadata, received \n%+v\n%+v\n", md1, md2)
	}

	// Modify one of the objects and ensure they are unequal.
	md2.AddItem(mdItem)

	if md1.Equal(md2) {
		t.Fatalf("Expected unequal Metadata, received \n%+v\n%+v\n", md1, md2)
	}
}

func testMetadataItems(t *testing.T) {
	fmt.Println(t.Name())

	// Create a new Metadata to work with.
	mid, _ := parseMetadataToken(metadataTestToken)
	md := NewMetadata(mid)
	kid := NewVersionToken()

	// Create a ItemMetadata to work with.
	iid := NewItemToken()
	mdItem := ItemMetadata{
		ItemId:     iid,
		Name:       "Metadata Item 1",
		KeyVersion: kid,
	}

	// Add the item to the Metadata
	md.AddItem(mdItem)

	// Get the item from the Metadata
	mdItem2, err := md.GetItem(iid)
	if err != nil {
		t.Fatalf("Expected no error, received %v", err)
	}

	if !mdItem.Equal(mdItem2) {
		t.Fatalf("Expected equal MetadataItem, received \n%+v\n%+v\n", mdItem, mdItem2)
	}

	// Update the item, save it, fetch it, and ensure they are still equal
	mdItem.Name = "Metadata Item 2"
	md.AddItem(mdItem)

	mdItem2, err = md.GetItem(iid)
	if err != nil {
		t.Fatalf("Expected no error, received %v", err)
	}

	if !mdItem.Equal(mdItem2) {
		t.Fatalf("Expected equal ItemMetadata, received \n%+v\n%+v\n", mdItem, mdItem2)
	}

	// Delete the ItemMetadata object and ensure we cannot fetch it.
	md.DeleteItem(iid)

	_, err = md.GetItem(iid)
	if err == nil {
		t.Fatalf("Expected error since ItemMetadata was deleted, no error received.")
	}
}

func testMetadataStorage(t *testing.T) {
	fmt.Println(t.Name())

	crypterVersion, _ := parseVersionToken(xChaChaCrypterVersion)
	crypter := NewCrypter(metadataEncryptionKey, crypterVersion)
	storer, _ := NewStore(metadataDatabase)

	// Create a new Metadata to work with.
	mid, _ := parseMetadataToken(metadataTestToken)
	md := NewMetadata(mid)

	// Create a MetadataItem to work with.
	iid := NewItemToken()
	kid := NewVersionToken()

	mdItem := ItemMetadata{
		ItemId:     iid,
		Name:       "Metadata Item 1",
		KeyVersion: kid,
	}

	// Add the item to the Metadata
	md.AddItem(mdItem)

	// Save the Metadata object to the database, retrieve it, verify the
	// retrieved matches the original.
	err := md.Save(&storer, crypter)
	if err != nil {
		t.Fatal("Expected no error, received", err)
	}

	md2, err := NewMetadataFromStore(&storer, crypter, mid)
	if err != nil {
		t.Fatal("Expected no error, received", err)
	}

	if !md.Equal(md2) {
		t.Fatal("Expected stored Metadata to equal created Metadata")
	}
}
