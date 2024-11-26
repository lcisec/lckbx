package vault

import (
	"encoding/json"
	"fmt"
	"sync"
)

// keysetItem stores a BaseKey and the VersionToken of the deriver used to
// generate additional keys from the BaseKey.
type KeysetItem struct {
	BaseKey        BaseKey
	DeriverVersion VersionToken
}

// Keyset holds a map of KeySetItems that contain the key material for
// encrypting Metadata and Items. Triggering events such as password change,
// will cause a new KeysetItem to be added to the Keyset. The client will
// reencrypt Metadata and Items to the lastest BaseKey as needed.
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
func (k *Keyset) AddKey(bk BaseKey, dv VersionToken) VersionToken {
	version := NewVersionToken()
	ksItem := KeysetItem{
		BaseKey:        bk,
		DeriverVersion: dv,
	}

	k.mutex.Lock()
	k.Keys[version.String()] = ksItem
	k.Latest = version
	k.mutex.Unlock()

	return version
}

// GetNewItemKey derives a new CryptKey for an Item using the latest BaseKey
// and an ItemToken.
func (k *Keyset) GetNewItemKey(iid ItemToken) (CryptKey, error) {
	ck, err := k.GetItemKey(k.Latest, iid)
	if err != nil {
		return ck, fmt.Errorf("could not Keyset.GetNewItemKey: %v", err)
	}

	return ck, nil
}

// GetItemKey derives a CryptKey for an Item using the specified BaseKey and
// ItemToken.
func (k *Keyset) GetItemKey(v VersionToken, iid ItemToken) (CryptKey, error) {
	var ck CryptKey

	ki, err := k.GetKey(v)
	if err != nil {
		return ck, fmt.Errorf("could not Keyset.GetItemKey: %v", err)
	}

	deriver := NewDeriver(ki.DeriverVersion)

	ck, err = deriver.DeriveCryptKey(ki.BaseKey, []byte(iid.String()))
	if err != nil {
		return ck, fmt.Errorf("could not Keyset.GetItemKey: %v", err)
	}

	return ck, nil
}

// GetNewMetadataKey derives a new CryptKey for a Metadata object using the
// latest BaseKey and a MetadataToken.
func (k *Keyset) GetNewMetadataKey(mid MetadataToken) (CryptKey, error) {
	ck, err := k.GetMetadataKey(k.Latest, mid)
	if err != nil {
		return ck, fmt.Errorf("could not Keyset.GetNewMetadataKey: %v", err)
	}

	return ck, nil
}

// GetMetadataKey derives a CryptKey for a Metadata object using the specified
// BaseKey and MetadataToken.
func (k *Keyset) GetMetadataKey(v VersionToken, mid MetadataToken) (CryptKey, error) {
	var ck CryptKey

	ki, err := k.GetKey(v)
	if err != nil {
		return ck, fmt.Errorf("could not Keyset.GetMetadataKey: %v", err)
	}

	deriver := NewDeriver(ki.DeriverVersion)

	ck, err = deriver.DeriveCryptKey(ki.BaseKey, []byte(mid.String()))
	if err != nil {
		return ck, fmt.Errorf("could not Keyset.GetMetadataKey: %v", err)
	}

	return ck, nil
}

// deleteKey deletes the BaseKey, identified by the VersionToken, from the
// KeySet.
func (k *Keyset) deleteKey(v VersionToken) error {
	if len(k.Keys) == 1 {
		return fmt.Errorf("could not deleteKey: only available key")
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

// Save encrypts the Keyset using the given crypter and then saves the
// encrypted bytes in the given storer.
func (k *Keyset) Save(store storer, crypt crypter) error {
	bytes, err := k.bytes(crypt)
	if err != nil {
		return fmt.Errorf("could not Keyset.Save: %v", err)
	}

	err = store.SaveKeyset(k.KeysetId, bytes)
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

	version, _ := parseVersionToken(argonBlakeDeriverVersion)
	ks.AddKey(newBaseKey(), version)

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

// NewKeysetFromStore retrieves the encrypted Keyset bytes from the given
// storer, decrypts the bytes, and returns a Keyset.
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
