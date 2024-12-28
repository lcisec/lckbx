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
//  1. Create a new User, Keyset, and Metadata.
//  2. Store the User and Keyset encrypted with the user's password.
//  3. Store the Metadata encrypted with the Metadata key derived from the
//     keyset.
func register(store storer, username, password string) error {
	// 1. Create a new User, Keyset, and Metadata.
	user := NewUser(username)
	keyset := NewKeyset(user.KeysetId)
	metadata := NewMetadata(user.MetadataId)

	// 2.  Store the User and Keyset encrypted with the user's password.
	// 2.a Parse the deriver version token and get a NewDeriver.
	deriverVersion, err := parseVersionToken(argonBlakeDeriverVersion)
	if err != nil {
		return fmt.Errorf("could not registerUser: %v", err)
	}

	deriver := NewDeriver(deriverVersion)

	// 2.b Derive the needed Keys and Tokens from the username, password,
	//     and User Id.
	ak, at, ck, err := getKeysAndToken(deriver, username, password, user.UserId)
	if err != nil {
		return fmt.Errorf("could not registerUser: %v", err)
	}

	// 2.c Parse the crypter version token.
	crypterVersion, err := parseVersionToken(xChaChaCrypterVersion)
	if err != nil {
		return fmt.Errorf("could not registerUser: %v", err)
	}

	// 2.d Get a NewCrypter based on the AuthKey and create the new encrypted
	//     user account in the database.
	crypt := NewCrypter(ak[:], crypterVersion)
	err = user.Create(store, crypt, at)
	if err != nil {
		return fmt.Errorf("could not registerUser: %v", err)
	}

	// 2.e Get a NewCrypter based on the CryptKey and save the encrypted
	//     Keyset to the database.
	crypt = NewCrypter(ck[:], crypterVersion)
	err = keyset.Save(store, crypt)
	if err != nil {
		return fmt.Errorf("could not registerUser: %v", err)
	}

	// 3.  Store the Metadata encrypted with the MetadataKey derived from the
	//     Keyset.
	// 3.a Derive a new CryptKey to encrypt the Metadata
	key, err := keyset.GetNewMetadataKey(user.MetadataId)
	if err != nil {
		return fmt.Errorf("could not registerUser: %v", err)
	}

	// 3.b Create a NewCrypter based on the derived CryptKey and save the
	//     encrypted Metadata to the database.
	crypt = NewCrypter(key[:], crypterVersion)
	err = metadata.Save(store, crypt)
	if err != nil {
		return fmt.Errorf("could not registerUser: %v", err)
	}

	return nil
}

// Login
// 1. Get the UserId from the database using the given username.
// 2. Derive an AuthToken, AuthKey, and CryptKey for the user.
// 3. Get the User from the store using the AuthToken and AuthKey
// 4. Get the Keyset from the store using the user's KeysetId
// 5. Get the Metadata from the store using the user's MetadataId.
// 6. Purge any unused keys.
// 7. Return the User, Keyset, and Metadata if there are no errors.
func login(store storer, username, password string) (User, Keyset, Metadata, error) {
	var ks Keyset
	var md Metadata
	var u User

	// 1.  Get the UserId from the database using the given username.
	userId := store.GetUserId(username)

	// 2.  Derive an AuthToken, AuthKey, and CryptKey for the user.
	// 2.a Parse the deriver version token.
	deriverVersion, err := parseVersionToken(argonBlakeDeriverVersion)
	if err != nil {
		return u, ks, md, fmt.Errorf("could not login: %v", err)
	}

	// 2.b Create a new driver based on the version token.
	deriver := NewDeriver(deriverVersion)

	// 2.c Derive the user's keys and tokens.
	ak, at, ck, err := getKeysAndToken(deriver, username, password, userId)
	if err != nil {
		return u, ks, md, fmt.Errorf("could not login: %v", err)
	}

	// 3.  Get the User from the store using the AuthToken and AuthKey
	// 3.a Parse the crypter version token.
	crypterVersion, err := parseVersionToken(xChaChaCrypterVersion)
	if err != nil {
		return u, ks, md, fmt.Errorf("could not login: %v", err)
	}

	// 3.b Create a NewCrypter with the AuthKey and load the encrypted User
	//     from the store.
	uCrypt := NewCrypter(ak[:], crypterVersion)
	u, err = NewUserFromStore(store, uCrypt, at, userId)
	if err != nil {
		return u, ks, md, fmt.Errorf("could not login: %v", err)
	}

	// 4.  Get the Keyset from the store using the user's KeysetId.
	// 4.a Create a NewCrypter using the derived CryptKey and load the
	//     encrypted Keyset from the store.
	kCrypt := NewCrypter(ck[:], crypterVersion)
	ks, err = NewKeysetFromStore(store, kCrypt, u.KeysetId)
	if err != nil {
		return u, ks, md, fmt.Errorf("could not login: %v", err)
	}

	// 5.  Get the Metadata from the store using the user's MetadataId
	// 5.a Derive the CryptKey for the Metadata.
	key, err := ks.GetNewMetadataKey(u.MetadataId)
	if err != nil {
		return u, ks, md, fmt.Errorf("could not login: %v", err)
	}

	// 5.b Create a NewCrypter using the derived CryptKey and load the
	//     encrypted Metadata from the store.
	mCrypt := NewCrypter(key[:], crypterVersion)
	md, err = NewMetadataFromStore(store, mCrypt, u.MetadataId)
	if err != nil {
		return u, ks, md, fmt.Errorf("could not login: %v", err)
	}

	// 6. Purge any unused keys.
	purgeUnusedKeys(ks, md)

	// 7. Return the User, Keyset, and Metadata if there are no errors.
	return u, ks, md, nil
}

// Change Password
//  1. Get the User, Keyset, and Metadata by logging in.
//  2. Derive a new AuthID, AuthKey, and CryptKey from the new password.
//  3. Add a new BaseKey to the Keyset.
//  4. Save the User and Keyset to the store encrypted with the new CryptKey.
//  5. Save the Metadata encrypted with the new Metadata key in the keyset.
func changePassword(store storer, username, oldPassword, newPassword string) error {
	// 1.  Get the User, Keyset, and Metadata by logging in.
	user, keyset, metadata, err := login(store, username, oldPassword)
	if err != nil {
		return fmt.Errorf("could not changePassword: %v", err)
	}

	// 2.  Derive a new AuthID, AuthKey, and CryptKey from the new password.
	// 2.a Parse the deriver version token and get a NewDeriver.
	deriverVersion, err := parseVersionToken(argonBlakeDeriverVersion)
	if err != nil {
		return fmt.Errorf("could not changePassword: %v", err)
	}

	deriver := NewDeriver(deriverVersion)

	// 2.b Derive the needed Keys and Tokens from the username, new password,
	//     and User Id.
	ak, at, ck, err := getKeysAndToken(deriver, username, newPassword, user.UserId)
	if err != nil {
		return fmt.Errorf("could not changePassword: %v", err)
	}

	// 3. Add a new BaseKey to the Keyset
	keyset.AddKey(newBaseKey(), deriverVersion)

	// 4.  Save the User and Keyset to the store
	// 4.a Parse the crypter version token.
	crypterVersion, err := parseVersionToken(xChaChaCrypterVersion)
	if err != nil {
		return fmt.Errorf("could not changePassword: %v", err)
	}

	// 4.b Get a NewCrypter based on the new AuthKey and update the encrypted
	//     User in the database.
	crypt := NewCrypter(ak[:], crypterVersion)
	err = user.Save(store, crypt, at)
	if err != nil {
		return fmt.Errorf("could not changePassword: %v", err)
	}

	// 4.c Get a NewCrypter based on the new CryptKey and save the encrypted
	//     Keyset to the database.
	crypt = NewCrypter(ck[:], crypterVersion)
	err = keyset.Save(store, crypt)
	if err != nil {
		return fmt.Errorf("could not changePassword: %v", err)
	}

	// 3.  Store the Metadata encrypted with the MetadataKey derived from the
	//     Keyset.
	// 3.a Derive a new CryptKey to encrypt the Metadata
	key, err := keyset.GetNewMetadataKey(user.MetadataId)
	if err != nil {
		return fmt.Errorf("could not changePassword: %v", err)
	}

	// 3.b Create a NewCrypter based on the derived CryptKey and save the
	//     encrypted Metadata to the database.
	crypt = NewCrypter(key[:], crypterVersion)
	err = metadata.Save(store, crypt)
	if err != nil {
		return fmt.Errorf("could not changePassword: %v", err)
	}

	return nil
}

// Purge Keys
//  1. Read through all MetadataItems to get a list of active keys.
//  2. Read through all of the Keyset keys and if any of them are not in use,
//     set Key.Inuse to false.
//  3. Purge unused keys.
func purgeUnusedKeys(ks Keyset, md Metadata) {
	// 1. Read through all MetadataItems to get a list of active keys.
	inUseKeys := md.GetInUseKeys()

	// 2. Read through all of the Keyset keys and if any of them are not in
	//    use, set Key.InUse to false.
	for keyId := range ks.Keys {
		kid, _ := parseVersionToken(keyId)
		inUse := false

		for _, inUseKey := range inUseKeys {
			if inUseKey == keyId {
				inUse = true
				break
			}
		}

		// The keyId is not in the list of inUseKeys, mark the key as unused.
		if inUse == false {
			ks.Unused(kid)
		}
	}

	// 3. Purge unused keys.
	ks.PurgeKeys()
}

// Reencrypt
// The reencrypt function is started at login and runs in the background until
// logout.
//  1. Read through all of the MetadataItems to determine which Items are not
//     encrypted using the latest key.
//  2. When an item is found, reencrypt the item with the latest key.
//  3. Update the Metadata Items by adding a new ItemMetadata entry and then
//     deleting the old entry.
//
