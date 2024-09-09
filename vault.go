package vault

import (
	"fmt"
)

// getKeysAndTokens derives our AuthKey, AuthToken, and CryptKey using the
// given deriver, username, and password.
func getKeysAndToken(d deriver, username, password string, uid UserToken) (AuthKey, AuthToken, CryptKey, error) {
	var ak AuthKey
	var at AuthToken
	var ck CryptKey

	baseKey, err := d.DeriveBaseKey(username, password)
	if err != nil {
		return ak, at, ck, err
	}

	ak, err = d.DeriveAuthKey(baseKey)
	if err != nil {
		return ak, at, ck, err
	}

	at, err = d.DeriveAuthToken(baseKey, uid)
	if err != nil {
		return ak, at, ck, err
	}

	ck, err = d.DeriveCryptKey(baseKey, nil)
	if err != nil {
		return ak, at, ck, err
	}

	return ak, at, ck, nil
}

// Register
//  1. Generate a random recovery key
//  2. Derive an AuthID, AuthKey, and CryptKey.
//  3. Create a user and save it to the store, using the AuthId as the key and
//     encrypting it with the AuthKey.
//  4. Generate a new KeySet and ItemMetadata for the user.
//  5. Encrypt the Keyset with the recovery key and save it.
//  6. Encrypt the Keyset with the derived encryption key and save it.
//  7. Encrypt the Metadata with the derived encryption key and save it.
func registerUser(store storer, username, password string) (CryptKey, error) {
	recoveryKey := NewCryptKey()
	user := NewUser(username)
	deriver := NewV1Deriver()
	keyset := NewKeyset(user.KeysetId)
	metadata := NewMetadata(user.MetadataId)

	ak, at, ck, err := getKeysAndToken(&deriver, username, password, user.UserId)
	if err != nil {
		return recoveryKey, fmt.Errorf("could not registerUser: %v", err)
	}

	uCrypt := NewV1Crypter(ak[:])
	err = user.Create(store, &uCrypt, at)
	if err != nil {
		return recoveryKey, fmt.Errorf("could not registerUser: %v", err)
	}

	// Need to clean up the new user if any of these error out.
	rCrypt := NewV1Crypter(recoveryKey[:])
	err = keyset.Save(store, &rCrypt, user.RecoveryKeyId)
	if err != nil {
		// user.CleanUp()
		return recoveryKey, fmt.Errorf("could not registerUser: %v", err)
	}

	crypt := NewV1Crypter(ck[:])
	err = keyset.Save(store, &crypt, user.KeysetId)
	if err != nil {
		// user.CleanUp()
		return recoveryKey, fmt.Errorf("could not registerUser: %v", err)
	}

	err = metadata.Save(store, &crypt)
	if err != nil {
		// user.CleanUp()
		return recoveryKey, fmt.Errorf("could not registerUser: %v", err)
	}

	return recoveryKey, nil
}

// Login
// 1. Get the userID from the database
// 2. Derive an AuthToken, AuthKey, and CryptKey.
// 3. Get the user from the store using the AuthToken and AuthKey
// 4. Get the Keyset from the store using the user's KeysetId
// 5. Get the Metadata from the store using the user's MetadataId
func login(store storer, username, password string) (Keyset, Metadata, error) {
	var ks Keyset
	var md Metadata

	deriver := NewV1Deriver()
	userId := store.GetUserId(username)

	ak, at, ck, err := getKeysAndToken(&deriver, username, password, userId)
	if err != nil {
		return ks, md, fmt.Errorf("could not login: %v", err)
	}

	// Get our user from the database
	aCrypt := NewV1Crypter(ak[:])
	user, err := NewUserFromStore(store, &aCrypt, at, userId)
	if err != nil {
		return ks, md, fmt.Errorf("could not login: %v", err)
	}

	crypt := NewV1Crypter(ck[:])
	ks, err = NewKeysetFromStore(store, &crypt, user.KeysetId)
	if err != nil {
		return ks, md, fmt.Errorf("could not login: %v", err)
	}

	md, err = NewMetadataFromStore(store, &crypt, user.MetadataId)
	if err != nil {
		return ks, md, fmt.Errorf("could not login: %v", err)
	}

	return ks, md, nil
}
