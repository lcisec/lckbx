package vault

// Tokens are always randomly generated and only used as identifiers. There is
// no need to ever parse a token. All tokens have the form
// prefix_base32encodedbytes.

import (
	"encoding/base32"
	"fmt"
)

const (
	tokenSize           = 32
	itemTokenPrefix     = "it_"
	userTokenPrefix     = "ut_"
	keysetTokenPrefix   = "kt_"
	metadataTokenPrefix = "mt_"
	versionTokenPrefix  = "vt_"
	authTokenPrefix     = "at_"
)

// tokenEncoder is used to encoded and decode our tokens using a standard
// Base32 encoder with no padding.
var tokenEncoder = base32.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567").WithPadding(base32.NoPadding)

// ItemToken represents an item token.
type ItemToken [tokenSize]byte

// String converts a ItemToken object to a string.
func (i ItemToken) String() string {
	token := tokenEncoder.EncodeToString(i[:])

	return fmt.Sprintf("%s_%s", itemTokenPrefix, token)
}

// NewItemToken generates a random ItemToken.
func NewItemToken() ItemToken {
	var it ItemToken

	bytes := newTokenBytes()
	copy(it[:], bytes[:])

	return it
}

// UserToken represents a user token.
type UserToken [tokenSize]byte

// String converts a UserToken object to a string.
func (u UserToken) String() string {
	token := tokenEncoder.EncodeToString(u[:])

	return fmt.Sprintf("%s_%s", userTokenPrefix, token)
}

// NewUserToken generates a random UserToken.
func NewUserToken() UserToken {
	var ut UserToken

	bytes := newTokenBytes()
	copy(ut[:], bytes[:])

	return ut
}

// KeysetToken represents a keyset token.
type KeysetToken [tokenSize]byte

// String converts a KeysetToken object to a string.
func (k KeysetToken) String() string {
	token := tokenEncoder.EncodeToString(k[:])

	return fmt.Sprintf("%s_%s", keysetTokenPrefix, token)
}

// NewKeysetToken generates a random KeysetToken.
func NewKeysetToken() KeysetToken {
	var kt KeysetToken

	bytes := newTokenBytes()
	copy(kt[:], bytes[:])

	return kt
}

// MetadataToken represents a metadata token.
type MetadataToken [tokenSize]byte

// String converts a MetadataToken object to a string.
func (m MetadataToken) String() string {
	token := tokenEncoder.EncodeToString(m[:])

	return fmt.Sprintf("%s_%s", metadataTokenPrefix, token)
}

// NewMetadataToken generates a random MetadataToken.
func NewMetadataToken() MetadataToken {
	var mt MetadataToken

	bytes := newTokenBytes()
	copy(mt[:], bytes[:])

	return mt
}

// VersionToken represents a version token.
type VersionToken [tokenSize]byte

// String converts a VersionToken object to a string.
func (v VersionToken) String() string {
	token := tokenEncoder.EncodeToString(v[:])

	return fmt.Sprintf("%s_%s", versionTokenPrefix, token)
}

// NewVersionToken generates a random VersionToken.
func NewVersionToken() VersionToken {
	var vt VersionToken

	bytes := newTokenBytes()
	copy(vt[:], bytes[:])

	return vt
}

// AuthToken represents an authentication token.
type AuthToken [tokenSize]byte

// String converts a AuthToken object to a string.
func (i AuthToken) String() string {
	token := tokenEncoder.EncodeToString(i[:])

	return fmt.Sprintf("%s_%s", authTokenPrefix, token)
}
