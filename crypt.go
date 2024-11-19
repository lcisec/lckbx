package vault

const (
	xChaChaCrypterVersion = "vt_MMO77C3BEUQLI337JSNV6Y4IFE2I2B6T4YD4JUHFT7OVF3I7XJQA"
)

// NewCrypter creates a new crypter based on the VersionToken passed to it.
func NewCrypter(key []byte, version VersionToken) crypter {
	switch version.String() {
	default:
		return newXChaChaCrypter(key)
	}
}
