package vault

import (
	"encoding/json"
	"fmt"
	"sync"
)

// keysetItem stores a BaseKey and the number of Items encrypted with that
// key.
type KeysetItem struct {
	Key   BaseKey
	Count uint64
}

// Keyset holds a map of BaseKeys that are used to encrypt Items. Triggering
// events such as password change, will cause a new keysetItem to be added to
// the Keyset. The client will reencrypt Items to the lastest BaseKey as
// needed. Once there are no longer any items encrypted with that keysetItem,
// it is removed from the KeySet.
//
// Thank you Sophie Schmeig for this idea:
// https://bughunters.google.com/blog/6182336647790592/cryptographic-agility-and-key-rotation
type Keyset struct {
	KeysetId KeysetToken
	Latest   VersionToken
	mutex    *sync.RWMutex
	Keys     map[string]KeysetItem
}

// AddKey adds a new BaseKey to the Keyset and updates the Latest value to
// reflect the new version.
func (k *Keyset) AddKey(bk BaseKey) VersionToken {
	version := NewVersionToken()
	ksItem := KeysetItem{
		Key:   bk,
		Count: 0,
	}

	k.mutex.Lock()
	k.Keys[version.String()] = ksItem
	k.Latest = version
	k.mutex.Unlock()

	return version
}

// DeleteKey deletes the BaseKey, identified by the VersionToken, from the
// KeySet.
func (k *Keyset) DeleteKey(v VersionToken) error {
	ksItem, err := k.GetKey(v)
	if err != nil {
		return fmt.Errorf("could not Keyset.DeleteKey: %v", err)
	}

	if ksItem.Count != 0 {
		return fmt.Errorf("could not Keyset.DeleteKey: key is still in use")
	}

	k.mutex.Lock()
	delete(k.Keys, v.String())
	k.mutex.Unlock()

	return nil
}

// GetKey returns the KeysetItem, as identified by the VersionToken, if it exists.
func (k *Keyset) GetKey(v VersionToken) (KeysetItem, error) {
	var ki KeysetItem

	k.mutex.RLock()
	ki, ok := k.Keys[v.String()]
	k.mutex.RUnlock()

	if !ok {
		return ki, fmt.Errorf("could not Keyset.GetKey: KeysetItem not found")
	}

	return ki, nil
}

// GetLatestKey returns the most recently generated BaseKey.
func (k *Keyset) GetLatestKey() (KeysetItem, error) {
	return k.GetKey(k.Latest)
}

// bytes returns the Keyset as encrypted bytes using the given crypter.
func (k *Keyset) bytes(crypt crypter) ([]byte, error) {
	var encrypted []byte

	bytes, err := json.Marshal(k)
	if err != nil {
		return encrypted, err
	}

	encrypted, err = crypt.Encrypt(bytes, []byte(k.KeysetId.String()))
	if err != nil {
		return encrypted, err
	}

	return encrypted, nil
}

// Save stores the Keyset as encrypted bytes in the given storer.
func (k *Keyset) Save(store storer, crypt crypter, ksid KeysetToken) error {
	bytes, err := k.bytes(crypt)
	if err != nil {
		return fmt.Errorf("could not Keyset.Save: %v", err)
	}

	err = store.SaveKeyset(ksid, bytes)
	if err != nil {
		return fmt.Errorf("could no Keyset.Save: %v", err)
	}

	return nil
}

// NewKeyset creates a new Keyset object with it's first BaseKey.
func NewKeyset(kid KeysetToken) Keyset {
	ks := Keyset{
		KeysetId: kid,
		mutex:    &sync.RWMutex{},
		Keys:     make(map[string]KeysetItem),
	}

	ks.AddKey(newBaseKey())

	return ks
}

// newKeysetFromBytes creates a new Keyset object from encrypted bytes.
func newKeysetFromBytes(crypt crypter, encrypted []byte, ad []byte) (Keyset, error) {
	var ks Keyset

	plaintext, err := crypt.Decrypt(encrypted, ad)
	if err != nil {
		return ks, fmt.Errorf("could not NewKeysetFromBytes: %v", err)
	}

	err = json.Unmarshal(plaintext, &ks)
	if err != nil {
		return ks, fmt.Errorf("could not NewKeysetFromBytes: %v", err)
	}

	return ks, nil
}

func NewKeysetFromStore(store storer, crypt crypter, kid KeysetToken) (Keyset, error) {
	var ks Keyset

	bytes, err := store.GetKeyset(kid)
	if err != nil {
		return ks, fmt.Errorf("could not NewKeysetFromStore: %v", err)
	}

	ks, err = newKeysetFromBytes(crypt, bytes, []byte(kid.String()))
	if err != nil {
		return ks, fmt.Errorf("could not NewNewsetFromStore: %v", err)
	}

	return ks, nil
}
