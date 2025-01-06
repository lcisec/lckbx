package vault

import (
	"fmt"
)

type Vault struct {
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
func (v *Vault) Register(username, password string) error {
	// 1. Create a new User, Keyset, and Metadata.
	user := NewUser(username)
	keyset := NewKeyset(user.KeysetId)
	metadata := NewMetadata(user.MetadataId)

	// 2.  Derive the user's keys and tokens.
	baseKey, err := v.derive.DeriveBaseKey(username, password)
	if err != nil {
		return fmt.Errorf("could not Vault.Register: %v", err)
	}

	ak, err := v.derive.DeriveAuthKey(baseKey)
	if err != nil {
		return fmt.Errorf("could not Vault.Register: %v", err)
	}

	at, err := v.derive.DeriveAuthToken(baseKey, user.UserId)
	if err != nil {
		return fmt.Errorf("could not Vault.Register: %v", err)
	}

	ck, err := v.derive.DeriveCryptKey(baseKey, nil)
	if err != nil {
		return fmt.Errorf("could not Vault.Register: %v", err)
	}

	// 3.  Store the User and Keyset encrypted with the user's password.
	// 3.a Update our crypter to use the derived AuthKey and create the new
	//     encrypted user account in the database.
	v.crypt.ChangeKey(ak[:])
	err = user.Create(v.store, v.crypt, at)
	if err != nil {
		return fmt.Errorf("could not Vault.Register: %v", err)
	}

	// 3.b Update our crypter to use the derived CryptKey and save the
	//     encrypted Keyset to the database.
	v.crypt.ChangeKey(ck[:])
	err = keyset.Save(v.store, v.crypt)
	if err != nil {
		return fmt.Errorf("could not Vault.Register: %v", err)
	}

	// 4.  Store the Metadata encrypted with the MetadataKey derived from the
	//     Keyset.
	// 3.a Derive a new CryptKey to encrypt the Metadata
	key, err := keyset.GetNewMetadataKey(user.MetadataId)
	if err != nil {
		return fmt.Errorf("could not Vault.Register: %v", err)
	}

	// 3.b Update our crypter with the derived CryptKey and save the
	//     encrypted Metadata to the database.
	v.crypt.ChangeKey(key[:])
	err = metadata.Save(v.store, v.crypt)
	if err != nil {
		return fmt.Errorf("could not Vault.Register: %v", err)
	}

	return nil
}

// Login
// 1. Get the UserId from the database using the given username.
// 2. Derive an AuthToken, AuthKey, and CryptKey for the user.
// 3. Get the User from the store using the AuthToken and AuthKey
// 4. Get the Keyset from the store using the user's KeysetId
// 5. Get the Metadata from the store using the user's MetadataId.
// 6. Return the UnlockedVault if there are no errors.
func (v *Vault) Login(username, password string) (UnlockedVault, error) {
	var uv UnlockedVault

	// 1.  Get the UserId from the database using the given username.
	userId := v.store.GetUserId(username)

	// 2.  Derive an AuthToken, AuthKey, and CryptKey for the user.
	baseKey, err := v.derive.DeriveBaseKey(username, password)
	if err != nil {
		return uv, fmt.Errorf("could not Vault.Login: %v", err)
	}

	ak, err := v.derive.DeriveAuthKey(baseKey)
	if err != nil {
		return uv, fmt.Errorf("could not Vault.Login: %v", err)
	}

	at, err := v.derive.DeriveAuthToken(baseKey, userId)
	if err != nil {
		return uv, fmt.Errorf("could not Vault.Login: %v", err)
	}

	ck, err := v.derive.DeriveCryptKey(baseKey, nil)
	if err != nil {
		return uv, fmt.Errorf("could not Vault.Login: %v", err)
	}

	// 3.  Get the User from the store using the AuthToken and AuthKey
	// 3.a Update our crypter to use the AuthKey and load the encrypted User
	//     from the store.
	v.crypt.ChangeKey(ak[:])
	u, err := NewUserFromStore(v.store, v.crypt, at, userId)
	if err != nil {
		return uv, fmt.Errorf("could not Vault.Login: %v", err)
	}

	// 4.  Get the Keyset from the store using the user's KeysetId.
	// 4.a Update our crypter to use the derived CryptKey and load the
	//     encrypted Keyset from the store.
	v.crypt.ChangeKey(ck[:])
	ks, err := NewKeysetFromStore(v.store, v.crypt, u.KeysetId)
	if err != nil {
		return uv, fmt.Errorf("could not Vault.Login: %v", err)
	}

	// 5.  Get the Metadata from the store using the user's MetadataId
	// 5.a Derive the CryptKey for the Metadata.
	key, err := ks.GetNewMetadataKey(u.MetadataId)
	if err != nil {
		return uv, fmt.Errorf("could not Vault.Login: %v", err)
	}

	// 5.b Update our crypter to use the derived CryptKey and load the
	//     encrypted Metadata from the store.
	v.crypt.ChangeKey(key[:])
	md, err := NewMetadataFromStore(v.store, v.crypt, u.MetadataId)
	if err != nil {
		return uv, fmt.Errorf("could not Vault.Login: %v", err)
	}

	uv.derive = v.derive
	uv.store = v.store
	uv.user = u
	uv.keyset = ks
	uv.metadata = md

	// 6. Return an UnlockedVault if there are no errors.
	return uv, nil
}

// Change Password
//  1. Login to get an UnlockedVault.
//  2. Derive a new AuthID, AuthKey, and CryptKey from the new password.
//  3. Add a new BaseKey to the Keyset.
//  4. Save the User and Keyset to the store encrypted with the new keys.
//  5. Save the Metadata encrypted with the new Metadata key in the keyset.
func (v *Vault) ChangePassword(username, oldPassword, newPassword string) error {
	// 1.  Login to get an UnlockedVault
	uv, err := v.Login(username, oldPassword)
	if err != nil {
		return fmt.Errorf("could not vault.ChangePassword: %v", err)
	}

	// 2.  Derive a new AuthToken, AuthKey, and CryptKey for the user from the
	//     newPassword.
	baseKey, err := v.derive.DeriveBaseKey(username, newPassword)
	if err != nil {
		return fmt.Errorf("could not Vault.ChangePassword: %v", err)
	}

	ak, err := v.derive.DeriveAuthKey(baseKey)
	if err != nil {
		return fmt.Errorf("could not Vault.ChangePassword: %v", err)
	}

	at, err := v.derive.DeriveAuthToken(baseKey, uv.user.UserId)
	if err != nil {
		return fmt.Errorf("could not Vault.ChangePassword: %v", err)
	}

	ck, err := v.derive.DeriveCryptKey(baseKey, nil)
	if err != nil {
		return fmt.Errorf("could not Vault.ChangePassword: %v", err)
	}

	// 3.  Add a new BaseKey to the Keyset
	// 3.a Parse the deriver version
	deriverVersion, err := parseVersionToken(argonBlakeDeriverVersion)
	if err != nil {
		return fmt.Errorf("could not Vault.ChangePassword: %v", err)
	}

	// 3.b Add a new key with the given deriver version.
	uv.keyset.AddKey(newBaseKey(), deriverVersion)

	// 4.  Save the User and Keyset to the store encrypted with the new keys.
	// 4.a Update our crypter to use the new AuthKey and update the encrypted
	//     User in the database.
	v.crypt.ChangeKey(ak[:])
	err = uv.user.Save(v.store, v.crypt, at)
	if err != nil {
		return fmt.Errorf("could not Vault.ChangePassword: %v", err)
	}

	// 4.b Update our crypter to use the new CryptKey and save the encrypted
	//     Keyset to the database.
	v.crypt.ChangeKey(ck[:])
	err = uv.keyset.Save(v.store, v.crypt)
	if err != nil {
		return fmt.Errorf("could not Vault.ChangePassword: %v", err)
	}

	// 5.  Store the Metadata encrypted with the MetadataKey derived from the
	//     Keyset.
	// 5.a Derive a new CryptKey to encrypt the Metadata
	key, err := uv.keyset.GetNewMetadataKey(uv.user.MetadataId)
	if err != nil {
		return fmt.Errorf("could not Vault.ChangePassword: %v", err)
	}

	// 5.b Update our crypter to use the derived CryptKey and save the
	//     encrypted Metadata to the database.
	v.crypt.ChangeKey(key[:])
	err = uv.metadata.Save(v.store, v.crypt)
	if err != nil {
		return fmt.Errorf("could not Vault.ChangePassword: %v", err)
	}

	return nil
}

// NewVault creates a new Vault using the given deriver and crypter version
// strings and the given storer.
func NewVault(s storer) (Vault, error) {
	var v Vault

	// Parse the deriver version and create a new deriver
	deriverVersion, err := parseVersionToken(argonBlakeDeriverVersion)
	if err != nil {
		return v, fmt.Errorf("could not NewVault: %v", err)
	}

	// Parse the crypter version token.
	crypterVersion, err := parseVersionToken(xChaChaCrypterVersion)
	if err != nil {
		return v, fmt.Errorf("could not NewVault: %v", err)
	}

	v.derive = NewDeriver(deriverVersion)
	v.crypt = NewCrypter(crypterVersion)
	v.store = s

	return v, nil
}
