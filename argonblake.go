package vault

import (
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/text/unicode/norm"
)

// argonBlakeDerive implements the deriver interface using Argon2 and Blake2b.
type argonBlakeDerive struct {
	time      uint32
	memory    uint32
	threads   uint8
	authInfo  []byte
	cryptInfo []byte
}

// DeriveBaseKey takes a username and passphrase and returns a BaseKey.
func (a argonBlakeDerive) DeriveBaseKey(username, passphrase string) (BaseKey, error) {
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
func (a argonBlakeDerive) DeriveAuthKey(baseKey BaseKey) (AuthKey, error) {
	var ak AuthKey

	kdf, err := blake2b.New(keySize, baseKey[:])
	if err != nil {
		return ak, fmt.Errorf("could not DeriveAuthKey: %v", err)
	}

	kdf.Write(a.authInfo)
	copy(ak[:], kdf.Sum(nil))

	return ak, nil
}

// DeriveAuthToken takes a BaseKey and a UserToken and derives an AuthToken
func (a argonBlakeDerive) DeriveAuthToken(baseKey BaseKey, ut UserToken) (AuthToken, error) {
	var at AuthToken

	kdf, err := blake2b.New(tokenSize, baseKey[:])
	if err != nil {
		return at, fmt.Errorf("could not DeriveAuthToken: %v", err)
	}

	kdf.Write([]byte(ut.String()))
	copy(at[:], kdf.Sum(nil))

	return at, nil
}

// DeriveCryptKey takes a BaseKey and derives a CryptKey.
func (a argonBlakeDerive) DeriveCryptKey(baseKey BaseKey, salt []byte) (CryptKey, error) {
	var ck CryptKey

	kdf, err := blake2b.New(keySize, baseKey[:])
	if err != nil {
		return ck, fmt.Errorf("could not DeriveCryptKey: %v", err)
	}

	if salt == nil {
		salt = a.cryptInfo
	}

	kdf.Write(salt)
	copy(ck[:], kdf.Sum(nil))

	return ck, nil
}

func newArgonBlake() argonBlakeDerive {
	return argonBlakeDerive{
		time:      3,
		memory:    64 * 1024,
		threads:   4,
		authInfo:  []byte("This key will be used for authentication."),
		cryptInfo: []byte("This key will be used for encryption."),
	}
}
