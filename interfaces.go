package vault

type crypter interface {
	Encrypt(plaintext, additionalData []byte) ([]byte, error)
	Decrypt(ciphertext, additionalData []byte) ([]byte, error)
}

// Deriver is an interface for deriving keys and tokens.
type deriver interface {
	DeriveBaseKey(username, passphrase string) (BaseKey, error)
	DeriveAuthKey(baseKey BaseKey) (AuthKey, error)
	DeriveAuthToken(baseKey BaseKey, uid UserToken) (AuthToken, error)
	DeriveCryptKey(baseKey BaseKey, info []byte) (CryptKey, error)
}

type storer interface {
	SaveUserId(username string, uid UserToken) error
	GetUserId(username string) UserToken
	DeleteUserId(username string) error

	GetUser(aid AuthToken) ([]byte, error)
	SaveUser(aid AuthToken, data []byte) error

	GetKeyset(kid KeysetToken) ([]byte, error)
	SaveKeyset(kid KeysetToken, data []byte) error

	GetMetadata(mid MetadataToken) ([]byte, error)
	SaveMetadata(mid MetadataToken, data []byte) error

	GetItem(iid ItemToken) ([]byte, error)
	SaveItem(iid ItemToken, data []byte) error

	Backup(filename string) error
	Close() error
}
