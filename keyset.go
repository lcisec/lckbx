package vault

import (
	"encoding/json"
	"fmt"
	"sync"
)

// keysetItem stores a BaseKey, the VersionToken of the deriver used to
// generate additional keys from the BaseKey, and the VersionToken of the
// crypter used for encryption.
type KeysetItem struct {
	BaseKey        BaseKey
	DeriverVersion VersionToken
	CrypterVersion VersionToken
	InUse          bool
}

// Equal determines if two KeysetItem objects are the same.
func (k *KeysetItem) Equal(k2 KeysetItem) bool {
	return k.BaseKey.String() == k2.BaseKey.String() &&
		k.DeriverVersion.String() == k2.DeriverVersion.String() &&
		k.CrypterVersion.String() == k2.CrypterVersion.String() &&
		k.InUse == k2.InUse
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

// Equal determines if two Keyset objects are the same.
func (k *Keyset) Equal(k2 Keyset) bool {
	equal := true

	if k.KeysetId.String() != k2.KeysetId.String() {
		equal = false
	}

	if k.Latest.String() != k2.Latest.String() {
		equal = false
	}

	if len(k.Keys) != len(k2.Keys) {
		equal = false
	}

	for mapKey, ks := range k.Keys {
		ksid, _ := parseVersionToken(mapKey)
		ks2, err := k2.GetKey(ksid)
		if err != nil {
			equal = false
			break
		}

		if !ks.Equal(ks2) {
			equal = false
			break
		}
	}

	return equal
}

// AddKey adds a new BaseKey to the Keyset and updates the Latest value to
// reflect the new version.
func (k *Keyset) AddKey(bk BaseKey, dv VersionToken) VersionToken {
	version := NewVersionToken()
	ksItem := KeysetItem{
		BaseKey:        bk,
		DeriverVersion: dv,
		InUse:          true,
	}

	k.mutex.Lock()
	k.Keys[version.String()] = ksItem
	k.Latest = version
	k.mutex.Unlock()

	return version
}

// Unused marks a KeysetItem in the Keyset as no longer in use so that it can
// be purged.
func (k *Keyset) Unused(v VersionToken) error {
	if len(k.Keys) == 1 {
		return fmt.Errorf("could not Keyset.Unused: only available key")
	}

	if v.String() == k.Latest.String() {
		return fmt.Errorf("could not Keyset.Unused: latest key")
	}
	
	key, err := k.GetKey(v)
	if err != nil {
		return fmt.Errorf("could not Keyset.Unused: %s does not exist", v)
	}

	key.InUse = false

	k.mutex.Lock()
	k.Keys[v.String()] = key
	k.mutex.Unlock()

	return nil
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

// DeleteKey deletes the BaseKey, identified by the VersionToken, from the
// KeySet.
func (k *Keyset) DeleteKey(v VersionToken) error {
	if len(k.Keys) == 1 {
		return fmt.Errorf("could not Keyset.DeleteKey: only available key")
	}

	if v.String() == k.Latest.String() {
		return fmt.Errorf("could not Keyset.Deletekey: latest key")
	}

	key, err := k.GetKey(v)
	if err != nil {
		return fmt.Errorf("could not Keyset.Deletekey: %s does not exist", v.String())
	}

	if key.InUse {
		return fmt.Errorf("could not Keyset.Deletekey: still in use")
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

// PurgeKeys removes any unused keys as long as they are safe to delete.
func (k *Keyset) PurgeKeys() {
	for keyId := range k.Keys {
		kid, _ := parseVersionToken(keyId)

		k.DeleteKey(kid)
	}
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

	ks.mutex = &sync.RWMutex{}

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
