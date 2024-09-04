package vault

type crypter interface {
	Encrypt(plaintext, additionalData []byte) ([]byte, error)
	Decrypt(ciphertext, additionalData []byte) ([]byte, error)
}


// Deriver is an interface for deriving keys and tokens.
type deriver interface {
	func DeriveBaseKey(username, passphrase string) (BaseKey, error)
	func DeriveAuthKey(baseKey BaseKey) (AuthKey, error)
	func DeriveAuthToken(baseKey BaseKey, uid UserToken) (AuthToken, error)
	func DeriveCryptKey(baseKey BaseKey, info string) (CryptKey, error)
}

type storer interface {
	GetUser(aid AuthToken) ([]byte, error)
	GetUserId(username string) UserToken
	SaveUser(aid AuthToken, data []byte) error

	GetKeyset(kid KeysetToken) ([]byte, error)
	SaveKeyset(kid KeysetToken, data []byte) error

	GetMetadata(mid MetadataToken) ([]byte, error)
	SaveMetadata(mid MetadataToken, data []byte) error

	GetItem(iid ItemToken) ([]byte, error)
	SaveItem(iid ItemToken, data []byte) error

	Backup(filename string) error
	Close()
}