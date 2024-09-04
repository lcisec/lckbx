package vault

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

	at, err := d.DeriveAuthToken(baseKey, uid)
	if err != nil {
		return ak, at, ck, err
	}

	cryptKey, err := d.DeriveCryptKey(baseKey)
	if err != nil {
		return ak, at, ck, err
	}

	return ak, at, ck, nil
}

// Register
// 1. Generate a random recovery key
// 2. Derive an AuthID, AuthKey, and CryptKey.
// 3. Create a user and save it to the store, using the AuthId as the key and
//    encrypting it with the AuthKey.
// 4. Generate a new KeySet and ItemMetadata for the user.
// 5. Encrypt the Keyset with the recovery key and save it.
// 6. Encrypt the Keyset with the derived encryption key and save it.
// 7. Encrypt the Metadata with the derived encryption key and save it.
func registerUser(store Storer, username, password string) (CryptKey, error) {
	recoveryKey := NewCryptKey()
	user := NewUser(username)
	deriver := NewV1Deriver()
	keyset :=  NewKeySet(user.KeysetId)
	items := NewItemMetadata()

	ak, at, ck, err := getKeysAndToken(deriver, username, password, user.UserId)
	if err != nil {
		return rk, fmt.Errorf("could not registerUser: %v", err)
	}
	
	err = user.Create(store, at, NewV1Crypter(ak))
	if err != nil {
		return rk, fmt.Errorf("could not registerUser: %v", err)
	}
	
	// Need to clean up the new user if any of these error out.
	err = keyset.Save(store, NewV1Crypter(rk), user.RecoveryId)
	if err != nil {
		user.CleanUp()
		return rk, fmt.Errorf("could not registerUser: %v", err)
	}

	err = keyset.Save(store, NewV1Crypter(ck), user.UserId)
	if err != nil {
		user.CleanUp()
		return rk, fmt.Errorf("could not registerUser: %v", err)
	}

	err = items.Save(store, NewV1Crypter(ck), user.MetadataId)
	if err != nil {
		user.CleanUp()
		return rk, fmt.Errorf("could not registerUser: %v", err)
	}

	return rk, nil
}


// Login
// 1. Get the userID from the database
// 2. Derive an AuthToken, AuthKey, and CryptKey.
// 3. Get the user from the store using the AuthToken and AuthKey
// 4. Get the Keyset from the store using the user's KeysetId
// 5. Get the Metadata from the store using the user's MetadataId
func login(store Storer, username, password string) (Keyset, MetaData, error) {
	var ks Keyset
	var md Metadata

	deriver := NewV1Deriver()
	userId := store.GetUserId(username)

	ak, at, ck, err := getKeysAndToken(deriver, username, password, userId)
	if err != nil {
		return ks, md, fmt.Errorf("could not login: %v", err)
	}

	// Get our user from the database
	crypter := NewV1Crypter(authKey)
	user, err := NewUserFromStore(storer, crypter, authToken)
	if err != nil {
		return ks, md, fmt.Errorf("could not login: %v", err)
	}

	crypter = NewV1Crypter(cryptKey)
	ks, err = NewKeysetFromStore(storer, crypter, user.KeysetId)
	if err != nil {
		return ks, md, fmt.Errorf("could not login: %v", err)
	}

	md, err = NewMetadataFromStore(storer, crypter, user.MetadataId)
	if err != nil {
		return ks, md, fmt.Errorf("could not login: %v", err)
	}

	return ks, md, nil
}