package vault

// Tokens are always randomly generated and only used as identifiers. There is
// no need to ever parse a token. All tokens have the form
// prefix_base32encodedbytes.

import (
	"encoding/base32"
	"fmt"
	"strings"
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

	return fmt.Sprintf("%s%s", itemTokenPrefix, token)
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

	return fmt.Sprintf("%s%s", userTokenPrefix, token)
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

	return fmt.Sprintf("%s%s", keysetTokenPrefix, token)
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

	return fmt.Sprintf("%s%s", metadataTokenPrefix, token)
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

	return fmt.Sprintf("%s%s", versionTokenPrefix, token)
}

// NewVersionToken generates a random VersionToken.
func NewVersionToken() VersionToken {
	var vt VersionToken

	bytes := newTokenBytes()
	copy(vt[:], bytes[:])

	return vt
}

// parseVersionToken takes a string in the form of vt_base32 and parses it
// into a VersionToken
func parseVersionToken(s string) (VersionToken, error) {
	var vt VersionToken

	if !strings.HasPrefix(s, versionTokenPrefix) {
		return vt, fmt.Errorf("could not parseVersionToken: invalid prefix")
	}

	s = strings.TrimPrefix(s, versionTokenPrefix)

	data, err := tokenEncoder.DecodeString(s)
	if err != nil {
		return vt, fmt.Errorf("could not parseVersionToken: %v", err)
	}

	if len(data) != tokenSize {
		return vt, fmt.Errorf("could not parseVersionToken: invalid length")
	}

	copy(vt[:], data)

	return vt, nil
}

// AuthToken represents an authentication token.
type AuthToken [tokenSize]byte

// String converts a AuthToken object to a string.
func (i AuthToken) String() string {
	token := tokenEncoder.EncodeToString(i[:])

	return fmt.Sprintf("%s%s", authTokenPrefix, token)
}

// NewAuthToken generates a random AuthToken.
func NewAuthToken() AuthToken {
	var at AuthToken

	bytes := newTokenBytes()
	copy(at[:], bytes[:])

	return at
}
