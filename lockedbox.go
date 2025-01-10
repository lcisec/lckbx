package lckbx

import (
	"fmt"
)

type LockedBox struct {
	crypt  crypter
	derive deriver
	store  storer
}

// Register
//  1. Create a new User, Keyset, and Metadata.
//  2. Derive the user's keys and tokens.
//  3. Store the User and Keyset encrypted with the user's password.
//  4. Store the Metadata encrypted with the Metadata key derived from the
//     keyset.
func (l *LockedBox) Register(username, password string) error {
	// 1. Create a new User, Keyset, and Metadata.
	user := NewUser(username)
	keyset := NewKeyset(user.KeysetId)
	metadata := NewMetadata(user.MetadataId)

	// 2.  Derive the user's keys and tokens.
	baseKey, err := l.derive.DeriveBaseKey(username, password)
	if err != nil {
		return fmt.Errorf("could not LockedBox.Register: %v", err)
	}

	ak, err := l.derive.DeriveAuthKey(baseKey)
	if err != nil {
		return fmt.Errorf("could not LockedBox.Register: %v", err)
	}

	at, err := l.derive.DeriveAuthToken(baseKey, user.UserId)
	if err != nil {
		return fmt.Errorf("could not LockedBox.Register: %v", err)
	}

	ck, err := l.derive.DeriveCryptKey(baseKey, nil)
	if err != nil {
		return fmt.Errorf("could not LockedBox.Register: %v", err)
	}

	// 3.  Store the User and Keyset encrypted with the user's password.
	// 3.a Update our crypter to use the derived AuthKey and create the new
	//     encrypted user account in the database.
	l.crypt.ChangeKey(ak[:])
	err = user.Create(l.store, l.crypt, at)
	if err != nil {
		return fmt.Errorf("could not LockedBox.Register: %v", err)
	}

	// 3.b Update our crypter to use the derived CryptKey and save the
	//     encrypted Keyset to the database.
	l.crypt.ChangeKey(ck[:])
	err = keyset.Save(l.store, l.crypt)
	if err != nil {
		return fmt.Errorf("could not LockedBox.Register: %v", err)
	}

	// 4.  Store the Metadata encrypted with the MetadataKey derived from the
	//     Keyset.
	// 3.a Derive a new CryptKey to encrypt the Metadata
	key, err := keyset.GetNewMetadataKey(user.MetadataId)
	if err != nil {
		return fmt.Errorf("could not LockedBox.Register: %v", err)
	}

	// 3.b Update our crypter with the derived CryptKey and save the
	//     encrypted Metadata to the database.
	l.crypt.ChangeKey(key[:])
	err = metadata.Save(l.store, l.crypt)
	if err != nil {
		return fmt.Errorf("could not LockedBox.Register: %v", err)
	}

	return nil
}

// Login
// 1. Get the UserId from the database using the given username.
// 2. Derive an AuthToken, AuthKey, and CryptKey for the user.
// 3. Get the User from the store using the AuthToken and AuthKey
// 4. Get the Keyset from the store using the user's KeysetId
// 5. Get the Metadata from the store using the user's MetadataId.
// 6. Return the UnlockedBox if there are no errors.
func (l *LockedBox) Login(username, password string) (UnlockedBox, error) {
	var ub UnlockedBox

	// 1.  Get the UserId from the database using the given username.
	userId := l.store.GetUserId(username)

	// 2.  Derive an AuthToken, AuthKey, and CryptKey for the user.
	baseKey, err := l.derive.DeriveBaseKey(username, password)
	if err != nil {
		return ub, fmt.Errorf("could not LockedBox.Login: %v", err)
	}

	ak, err := l.derive.DeriveAuthKey(baseKey)
	if err != nil {
		return ub, fmt.Errorf("could not LockedBox.Login: %v", err)
	}

	at, err := l.derive.DeriveAuthToken(baseKey, userId)
	if err != nil {
		return ub, fmt.Errorf("could not LockedBox.Login: %v", err)
	}

	ck, err := l.derive.DeriveCryptKey(baseKey, nil)
	if err != nil {
		return ub, fmt.Errorf("could not LockedBox.Login: %v", err)
	}

	// 3.  Get the User from the store using the AuthToken and AuthKey
	// 3.a Update our crypter to use the AuthKey and load the encrypted User
	//     from the store.
	l.crypt.ChangeKey(ak[:])
	u, err := NewUserFromStore(l.store, l.crypt, at, userId)
	if err != nil {
		return ub, fmt.Errorf("could not LockedBox.Login: %v", err)
	}

	// 4.  Get the Keyset from the store using the user's KeysetId.
	// 4.a Update our crypter to use the derived CryptKey and load the
	//     encrypted Keyset from the store.
	l.crypt.ChangeKey(ck[:])
	ks, err := NewKeysetFromStore(l.store, l.crypt, u.KeysetId)
	if err != nil {
		return ub, fmt.Errorf("could not LockedBox.Login: %v", err)
	}

	// 5.  Get the Metadata from the store using the user's MetadataId
	// 5.a Derive the CryptKey for the Metadata.
	key, err := ks.GetNewMetadataKey(u.MetadataId)
	if err != nil {
		return ub, fmt.Errorf("could not LockedBox.Login: %v", err)
	}

	// 5.b Update our crypter to use the derived CryptKey and load the
	//     encrypted Metadata from the store.
	l.crypt.ChangeKey(key[:])
	md, err := NewMetadataFromStore(l.store, l.crypt, u.MetadataId)
	if err != nil {
		return ub, fmt.Errorf("could not LockedBox.Login: %v", err)
	}

	ub.derive = l.derive
	ub.store = l.store
	ub.crypt = l.crypt
	ub.user = u
	ub.keyset = ks
	ub.metadata = md

	// 6. Return an UnlockedBox if there are no errors.
	return ub, nil
}

// Change Password
//  1. Login to get an UnlockedBox.
//  2. Derive a new AuthID, AuthKey, and CryptKey from the new password.
//  3. Add a new BaseKey to the Keyset.
//  4. Save the User and Keyset to the store encrypted with the new keys.
//  5. Save the Metadata encrypted with the new Metadata key in the keyset.
func (l *LockedBox) ChangePassword(username, oldPassword, newPassword string) error {
	// 1.  Login to get an UnlockedBox
	ub, err := l.Login(username, oldPassword)
	if err != nil {
		return fmt.Errorf("could not LockedBox.ChangePassword: %v", err)
	}

	// 2.  Derive a new AuthToken, AuthKey, and CryptKey for the user from the
	//     newPassword.
	baseKey, err := l.derive.DeriveBaseKey(username, newPassword)
	if err != nil {
		return fmt.Errorf("could not LockedBox.ChangePassword: %v", err)
	}

	ak, err := l.derive.DeriveAuthKey(baseKey)
	if err != nil {
		return fmt.Errorf("could not LockedBox.ChangePassword: %v", err)
	}

	at, err := l.derive.DeriveAuthToken(baseKey, uv.user.UserId)
	if err != nil {
		return fmt.Errorf("could not LockedBox.ChangePassword: %v", err)
	}

	ck, err := l.derive.DeriveCryptKey(baseKey, nil)
	if err != nil {
		return fmt.Errorf("could not LockedBox.ChangePassword: %v", err)
	}

	// 3.  Add a new BaseKey to the Keyset
	// 3.a Parse the deriver version
	deriverVersion, err := parseVersionToken(argonBlakeDeriverVersion)
	if err != nil {
		return fmt.Errorf("could not LockedBox.ChangePassword: %v", err)
	}

	// 3.b Add a new key with the given deriver version.
	ub.keyset.AddKey(newBaseKey(), deriverVersion)

	// 4.  Save the User and Keyset to the store encrypted with the new keys.
	// 4.a Update our crypter to use the new AuthKey and update the encrypted
	//     User in the database.
	l.crypt.ChangeKey(ak[:])
	err = ub.user.Save(l.store, l.crypt, at)
	if err != nil {
		return fmt.Errorf("could not LockedBox.ChangePassword: %v", err)
	}

	// 4.b Update our crypter to use the new CryptKey and save the encrypted
	//     Keyset to the database.
	l.crypt.ChangeKey(ck[:])
	err = ub.keyset.Save(l.store, l.crypt)
	if err != nil {
		return fmt.Errorf("could not LockedBox.ChangePassword: %v", err)
	}

	// 5.  Store the Metadata encrypted with the MetadataKey derived from the
	//     Keyset.
	// 5.a Derive a new CryptKey to encrypt the Metadata
	key, err := ub.keyset.GetNewMetadataKey(ub.user.MetadataId)
	if err != nil {
		return fmt.Errorf("could not LockedBox.ChangePassword: %v", err)
	}

	// 5.b Update our crypter to use the derived CryptKey and save the
	//     encrypted Metadata to the database.
	l.crypt.ChangeKey(key[:])
	err = ub.metadata.Save(l.store, l.crypt)
	if err != nil {
		return fmt.Errorf("could not LockedBox.ChangePassword: %v", err)
	}

	return nil
}

// NewLockedBox creates a new LockedBox using the given deriver and crypter version
// strings and the given storer.
func NewLockedBox(s storer) (LockedBox, error) {
	var l LockedBox

	// Parse the deriver version and create a new deriver
	deriverVersion, err := parseVersionToken(argonBlakeDeriverVersion)
	if err != nil {
		return l, fmt.Errorf("could not NewLockedBox: %v", err)
	}

	// Parse the crypter version token.
	crypterVersion, err := parseVersionToken(xChaChaCrypterVersion)
	if err != nil {
		return l, fmt.Errorf("could not NewLockedBox: %v", err)
	}

	l.derive = NewDeriver(deriverVersion)
	l.crypt = NewCrypter(crypterVersion)
	l.store = s

	return l, nil
}
