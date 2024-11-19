package vault

const (
	minPassphraseLength      = 16
	argonBlakeDeriverVersion = "vt_W5BREZKAIEU4PZEWSZEHYFS53UNZD43ONKWOODRA2L2DZDIS5DYA"
)

// NewDeriver returns a deriver based on the VersionToken provided.
func NewDeriver(version VersionToken) deriver {
	switch version.String() {
	default:
		return newArgonBlake()
	}
}
