package vault

import (
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/text/unicode/norm"
)

const (
	minPassphraseLength = 15
)

type argonBlakeDerive struct {
	time      uint32
	memory    uint32
	threads   uint8
	authInfo  []byte
	cryptInfo []byte
}

// Slow takes a username and passphrase and returns a symmetric key Token.
func (a *argonBlakeDerive) DeriveBaseKey(username, passphrase string) (BaseKey, error) {
	var bk BaseKey

	// Normalize our username and password
	username = norm.NFKD.String(username)
	passphrase = norm.NFKD.String(passphrase)

	// Verify password length
	if len(passphrase) < minPassphraseLength {
		return bk, fmt.Errorf("could not DeriveBaseKey: passphrase less than %d character", minPassphraseLength)
	}

	// Hash our username to use it as a salt
	salt := blake2b.Sum256([]byte(username))

	// Derive our key
	key := argon2.IDKey([]byte(passphrase), salt[:], a.time, a.memory, a.threads, keySize)

	copy(bk[:], key)

	return bk, nil
}

// DeriveAuthKey takes a BaseKey and derives an AuthKey.
func (a *argonBlakeDerive) DeriveAuthKey(baseKey BaseKey) (AuthKey, error) {
	var ak AuthKey

	kdf, err := blake2b.NewXOF(keySize, baseKey[:])
	if err != nil {
		return ak, fmt.Errorf("could not DeriveAuthKey: %v", err)
	}

	kdf.Write(a.authInfo)

	_, err = io.ReadFull(kdf, ak[:])
	if err != nil {
		return ak, fmt.Errorf("could not DeriveAuthKey: %v", err)
	}

	return ak, nil
}

// DeriveAuthToken takes a BaseKey and a UserToken and derives an AuthToken
func (a *argonBlakeDerive) DeriveAuthToken(baseKey BaseKey, ut UserToken) (AuthToken, error) {
	var at AuthToken

	kdf, err := blake2b.NewXOF(tokenSize, baseKey[:])
	if err != nil {
		return at, fmt.Errorf("could not DeriveAuthToken: %v", err)
	}

	kdf.Write([]byte(ut.String()))

	_, err = io.ReadFull(kdf, at[:])
	if err != nil {
		return at, fmt.Errorf("could not DeriveAuthToken: %v", err)
	}

	return at, nil
}

// DeriveCryptKey takes a BaseKey and derives a CryptKey.
func (a *argonBlakeDerive) DeriveCryptKey(baseKey BaseKey, salt []byte) (CryptKey, error) {
	var ck CryptKey

	kdf, err := blake2b.NewXOF(keySize, baseKey[:])
	if err != nil {
		return ck, fmt.Errorf("could not DeriveCryptKey: %v", err)
	}

	if salt == nil {
		salt = a.cryptInfo
	}

	kdf.Write(salt)

	_, err = io.ReadFull(kdf, ck[:])
	if err != nil {
		return ck, fmt.Errorf("could not DeriveCryptKey: %v", err)
	}

	return ck, nil
}

// NewV1Deriver returns a deriver based on Argon2 and Blake2.
func NewV1Deriver() argonBlakeDerive {
	return argonBlakeDerive{
		time:      1,
		memory:    2 * 1024 * 1024,
		threads:   4,
		authInfo:  []byte("This key will be used for authentication."),
		cryptInfo: []byte("This key will be used for encryption."),
	}
}
