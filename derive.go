package vault

const (
	minPassphraseLength = 15
)

// var (
// 	cryptInfo = fmt.Sprintf("This key will be  used to encrypt items.")
// 	metaInfo = fmt.Sprintf("This key will be used to encrypt metadata.")
// )

type argonBlakeDerive struct {
	time int
	memory  uint32
	threads uint8
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
	h, err := blake2b.New256()
	if err != nil {
		return bk, fmt.Errorf("could not DeriveBaseKey: %v", err)
	}

	salt := h.Write(username).Sum(nil)

	// Derive our key
	key := argon2.IDKey([]byte(passphrase), salt, d.time, d.memory, d.threads, keySize)

	copy(bk[:], key)

	return bk, nil
}

// DeriveAuthKey takes a BaseKey and derives an AuthKey.
func (d *argonBlakeDerive) DeriveAuthKey(baseKey BaseKey) (AuthKey, error) {
	var ak AuthKey

	kdf, err := blake2b.NewXOF(keySize, baseKey[:])
	if err != nil {
		return ak, fmt.Errorf("could not DeriveAuthKey: %v", err)
	}

	authInfo = fmt.Sprintf("This key will be used for authentication.")
	kdf.Write([]byte(authInfo))

	_, err = io.ReadFull(kdf, ak[:])
	if err != nil {
		return ak, fmt.Errorf("could not DeriveAuthKey: %v", err)
	}

	return ak, nil
}

// DeriveAuthToken takes a BaseKey and a UserToken and derives an AuthToken
func (d *argonBlakeDerive) DeriveAuthToken(baseKey BaseKey, ut UserToken) (AuthToken, error) {
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
func (d *argonBlakeDerive) DeriveCryptKey(baseKey BaseKey, salt []byte) (CryptKey, error) {
	var ck CryptKey

	kdf, err := blake2b.NewXOF(keySize, baseKey[:])
	if err != nil {
		return ck, fmt.Errorf("could not DeriveCryptKey: %v", err)
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
		time: 1,
		memory: 2 * 1024 * 1024,
		threads: 4,
	}
}
