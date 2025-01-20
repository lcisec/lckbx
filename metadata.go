package lckbx

import (
	"encoding/json"
	"fmt"
	"sync"
)

type ItemMetadata struct {
	ItemId     ItemToken
	Name       string
	KeyVersion VersionToken
}

// Equal determines if two KeysetItem objects are the same.
func (i *ItemMetadata) Equal(i2 ItemMetadata) bool {
	return i.ItemId.String() == i2.ItemId.String() &&
		i.Name == i2.Name &&
		i.KeyVersion.String() == i2.KeyVersion.String()
}

func NewItemMetadata(name string, iid ItemToken, kv VersionToken) ItemMetadata {
	return ItemMetadata{
		ItemId:     iid,
		Name:       name,
		KeyVersion: kv,
	}
}

type Metadata struct {
	MetadataId MetadataToken
	mutex      *sync.RWMutex
	Items      map[string]ItemMetadata
}

// Equal determines if two Metadata objects are the same.
func (m *Metadata) Equal(m2 *Metadata) bool {
	equal := true

	if m.MetadataId.String() != m2.MetadataId.String() {
		equal = false
	}

	if len(m.Items) != len(m2.Items) {
		equal = false
	}

	for mapKey, mdi := range m.Items {
		mdiId, _ := parseItemToken(mapKey)
		mdi2, err := m2.GetItem(mdiId)
		if err != nil {
			equal = false
			break
		}

		if !mdi.Equal(mdi2) {
			equal = false
			break
		}
	}

	return equal
}

func (m *Metadata) AddItem(i ItemMetadata) {
	m.mutex.Lock()
	m.Items[i.ItemId.String()] = i
	m.mutex.Unlock()
}

func (m *Metadata) DeleteItem(iid ItemToken) {
	m.mutex.Lock()
	delete(m.Items, iid.String())
	m.mutex.Unlock()
}

func (m *Metadata) GetItem(iid ItemToken) (ItemMetadata, error) {
	var item ItemMetadata

	m.mutex.RLock()
	item, ok := m.Items[iid.String()]
	m.mutex.RUnlock()

	if !ok {
		return item, fmt.Errorf("could not Metadata.GetItem: item not found")
	}

	return item, nil
}

func (m *Metadata) GetItems() []ItemMetadata {
	var items []ItemMetadata

	for _, val := range m.Items {
		items = append(items, val)
	}

	return items
}

func (m *Metadata) GetInUseKeys() []string {
	var keys []string

	for _, item := range m.Items {
		keys = append(keys, item.KeyVersion.String())
	}

	return keys
}

// bytes returns the Metadata as encrypted bytes using the given crypter.
func (m *Metadata) bytes(crypt crypter) ([]byte, error) {
	var encrypted []byte

	bytes, err := json.Marshal(m)
	if err != nil {
		return encrypted, err
	}

	encrypted, err = crypt.Encrypt(bytes, []byte(m.MetadataId.String()))
	if err != nil {
		return encrypted, err
	}

	return encrypted, nil
}

// Save stores the Metadata as encrypted bytes in the given storer.
func (m *Metadata) Save(store storer, crypt crypter) error {
	bytes, err := m.bytes(crypt)
	if err != nil {
		return fmt.Errorf("could not Metadata.Save: %v", err)
	}

	err = store.SaveMetadata(m.MetadataId, bytes)
	if err != nil {
		return fmt.Errorf("could no Metadata.Save: %v", err)
	}

	return nil
}

// NewMetadata creates a new Metadata object.
func NewMetadata(mid MetadataToken) *Metadata {
	return &Metadata{
		MetadataId: mid,
		mutex:      &sync.RWMutex{},
		Items:      make(map[string]ItemMetadata),
	}
}

// NewMetadataFromBytes creates a new Metadata object from encrypted bytes.
func newMetadataFromBytes(crypt crypter, encrypted []byte, ad []byte) (Metadata, error) {
	var md Metadata

	plaintext, err := crypt.Decrypt(encrypted, ad)
	if err != nil {
		return md, err
	}

	err = json.Unmarshal(plaintext, &md)
	if err != nil {
		return md, err
	}

	md.mutex = &sync.RWMutex{}

	return md, nil
}

func NewMetadataFromStore(store storer, crypt crypter, mid MetadataToken) (*Metadata, error) {
	var md Metadata

	bytes, err := store.GetMetadata(mid)
	if err != nil {
		return &md, fmt.Errorf("could not NewMetadataFromStore: %v", err)
	}

	md, err = newMetadataFromBytes(crypt, bytes, []byte(mid.String()))
	if err != nil {
		return &md, fmt.Errorf("could not NewMetadataFromStore: %v", err)
	}

	return &md, nil
}
