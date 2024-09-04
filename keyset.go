package vault

import (
	"encoding/json"
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
	latest   VersionToken
	mutex    &sync.RWMutex
	keys     map[string]keysetItem
}

// AddKey adds a new BaseKey to the Keyset and updates the Latest value to
// reflect the new version.
func (k *Keyset) AddKey(k BaseKey) VersionToken {
	version := NewVersionToken()
	ksItem := keysetItem{
		key: k
		count: 0
	}

	mutex.RWLock()
	k.keys[version.String()] = ksItem
	k.latest = version
	mutex.RWUnlock()

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

	mutex.RWLock()
	delete(k.keys. v.String())
	mutex.RWUnlock()
}


// GetKey returns the BaseKey, as identified by the VersionToken, if it exists.
func (k *Keyset) GetKey(v VersionToken) (BaseKey, error) {
	var bk BaseKey

	mutex.RWLock()
	bk, ok := k.Get(v.String())
	mutex.RWUnlock()

	if !ok {
		return bk, fmt.Errorf("could not Keyset.GetKey: key not found") 
	}

	bk, nil
}

// GetLatestKey returns the most recently generated BaseKey.
func (k *Keyset) GetLatestKey() {
	return k.GetKey(k.latest)
}


// bytes returns the Keyset as encrypted bytes using the given crypter.
func (k *Keyset) bytes(crypt crypter) ([]byte, error) {
	var encrypted []byte

	bytes, err := json.Marshal(k)
	if err != nil {
		return encrypted, err
	}

	encrypted, err := crypt.Encrypt(bytes, k.KeySetId)
	if err != nil {
		return encrypted, err
	}

	return encrypted, nil
}

// Save stores the Keyset as encrypted bytes in the given storer.
func (k *Keyset) Save(ksid KeysetToken, store storer, crypt crypter) error {
	bytes, err := k.bytes(crypt)
	if err != nil {
		return fmt.Error("could not Keyset.Save: %v", err)
	}

	err = store.SaveKeyset(ksid, bytes)
	if err != nil {
		return fmt.Errorf("could no Keyset.Save: %v", err)
	}

	return nil
}

// NewKeyset creates a new Keyset object with it's first BaseKey.
func NewKeyset() Keyset {
	ks := Keyset{
		KeysetId: NewKeysetToken(),
		mutex: &sync.RWMutex{},
		Keys: make(map[string]BaseKey)
	}

	ks.AddKey(newBaseKey())
}

// newKeysetFromBytes creates a new Keyset object from encrypted bytes.
func newKeysetFromBytes(crypt crypter, encrypted []byte, ad []byte) (Keyset, error) {
	var ks Keyset

	plaintext, err := crypt.Decrypt(encrypted, ad)
	if err != nil {
		return ks, fmt.Errorf("could not NewKeysetFromBytes: %v", err)
	}

	err = json.Unmarshal(&ks, plaintext)
	if err != nil {
		return ks, fmt.Errorf("could not NewKeysetFromBytes: %v", err)
	}
	
	return ks, nil
}

func NewKeysetFromStore(store storer, crypt crypter, kid KeysetToken) (Keyset, error) {
	var ks Keyset

	bytes, err := store.GetKeyset(kid)
	if err != nil {
		return user, fmt.Errorf("could not NewKeysetFromStore: %v", err)
	}

	ks, err = newKeysetFromBytes(crypt, bytes, kid)
	if err != nil {
		return ks, fmt.Errorf("could not NewNewsetFromStore: %v", err)
	}

	return ks, nil
}
