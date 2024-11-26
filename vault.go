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
//  1. Generate a random recovery phrase (that will act like a password.)
//  2. Create a new User, Keyset, and Metadata.
//  3. Store the User and Keyset encrypted with the user's password.
//  4. Store the User and Keyset encrypted with the recovery password.
//  5. Store the Metadata encrypted with the Metadata key in the keyset.
//  6. Return the recovery key to the user.
func registerUser(store storer, username, password string) (string, error) {
	recoveryPhrase := newRecoveryPhrase()
	user := NewUser(username)
	keyset := NewKeyset(user.KeysetId)
	metadata := NewMetadata(user.MetadataId)

	err := storeUser(store, username, password, user, keyset)
	if err != nil {
		return recoveryPhrase, fmt.Errorf("could not registerUser: %v", err)
	}

	err = storeUser(store, username, recoveryPhrase, user, keyset)
	if err != nil {
		// cleanup User
		return recoveryPhrase, fmt.Errorf("could not registerUser: %v", err)
	}

	key, err := keyset.GetNewMetadataKey(user.MetadataId)
	if err != nil {
		return recoveryPhrase, fmt.Errorf("could not registerUser: %v", err)
	}

	crypterVersion, err := parseVersionToken(xChaChaCrypterVersion)
	if err != nil {
		return recoveryPhrase, fmt.Errorf("could not regiserUser: %v", err)
	}

	crypt := NewCrypter(key[:], crypterVersion)
	err = metadata.Save(store, crypt)
	if err != nil {
		return recoveryPhrase, fmt.Errorf("could not registerUser: %v", err)
	}

	return recoveryPhrase, nil
}

// storeUser
//  1. Derive an AuthKey, AuthToken, and CryptKey from the username and password.
//  2. Save the User to the store using the derived AuthId and AuthKey.
//  3. Save the Keyset to the store using the derived encryption key.
func storeUser(store storer, username, password string, user User, keyset Keyset) error {
	deriverVersion, err := parseVersionToken(argonBlakeDeriverVersion)
	if err != nil {
		return fmt.Errorf("could not storeUser: %v", err)
	}

	crypterVersion, err := parseVersionToken(xChaChaCrypterVersion)
	if err != nil {
		return fmt.Errorf("could not storeUser: %v", err)
	}

	deriver := NewDeriver(deriverVersion)

	ak, at, ck, err := getKeysAndToken(deriver, username, password, user.UserId)
	if err != nil {
		return fmt.Errorf("could not storeUser: %v", err)
	}

	crypt := NewCrypter(ak[:], crypterVersion)
	err = user.Create(store, crypt, at)
	if err != nil {
		return fmt.Errorf("could not storeUser: %v", err)
	}

	crypt = NewCrypter(ck[:], crypterVersion)
	err = keyset.Save(store, crypt)
	if err != nil {
		return fmt.Errorf("could not storeUser: %v", err)
	}

	return nil
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

	deriverVersion, err := parseVersionToken(argonBlakeDeriverVersion)
	if err != nil {
		return ks, md, fmt.Errorf("could not login: %v", err)
	}

	crypterVersion, err := parseVersionToken(xChaChaCrypterVersion)
	if err != nil {
		return ks, md, fmt.Errorf("could not login: %v", err)
	}

	deriver := NewDeriver(deriverVersion)
	userId := store.GetUserId(username)

	ak, at, ck, err := getKeysAndToken(deriver, username, password, userId)
	if err != nil {
		return ks, md, fmt.Errorf("could not login: %v", err)
	}

	// Get our user from the database
	uCrypt := NewCrypter(ak[:], crypterVersion)
	user, err := NewUserFromStore(store, uCrypt, at, userId)
	if err != nil {
		return ks, md, fmt.Errorf("could not login: %v", err)
	}

	kCrypt := NewCrypter(ck[:], crypterVersion)
	ks, err = NewKeysetFromStore(store, kCrypt, user.KeysetId)
	if err != nil {
		return ks, md, fmt.Errorf("could not login: %v", err)
	}

	key, err := ks.GetNewMetadataKey(user.MetadataId)
	if err != nil {
		return ks, md, fmt.Errorf("could not registerUser: %v", err)
	}

	mCrypt := NewCrypter(key[:], crypterVersion)
	md, err = NewMetadataFromStore(store, mCrypt, user.MetadataId)
	if err != nil {
		return ks, md, fmt.Errorf("could not login: %v", err)
	}

	return ks, md, nil
}

// Change Password
//  1. Use current password or recovery key to get
//  2. Generate a random recovery key
//  3. Derive an AuthID, AuthKey, and CryptKey.
//  4. Create a user and save it to the store, using the AuthId as the key and
//     encrypting it with the AuthKey.
//  5. Generate a new KeySet and ItemMetadata for the user.
//  6. Encrypt the Keyset with the recovery key and save it.
//  7. Encrypt the Keyset with the derived encryption key and save it.
//  8. Encrypt the Metadata with the derived encryption key and save it.

// Purge Keys
//  1. Read through all MetadataItems to get a list of active keys.
//  2. Read through all of the Keyset keys and if any of them are not active,
//     purge it.
//  3. This should be run on each login.

// Reencrypt
// The reencrypt function is started at login and runs in the background until
// logout.
//  1. Read through all of the MetadataItems to determine which Items are not
//     encrypted using the latest key.
//  2. When an item is found, reencrypt the item with the latest key.
//  3. Update the Metadata Items by adding a new ItemMetadata entry and then
//     deleting the old entry.
//
