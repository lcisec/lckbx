package vault

// Keys are randomly generated and derived using a deriver. Keys are stored as
// strings and need to be parsed to get their bytes. All keys take the form of
// prefix_base32encodedbytes.

import (
	"encoding/base32"
	"fmt"
	"strings"
)

const (
	keySize        = 32
	baseKeyPrefix  = "bk_"
	cryptKeyPrefix = "ck_"
	authKeyPrefix  = "ak_"
)

// keyEncoder is used to encoded and decode our keys using a standard
// Base32 encoder with no padding.
var keyEncoder = base32.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567").WithPadding(base32.NoPadding)

/*
  Begin BaseKey definition
*/

// BaseKey represents a key used for deriving other keys.
type BaseKey [keySize]byte

// String converts a BaseKey to a string.
func (b BaseKey) String() string {
	key := keyEncoder.EncodeToString(b[:])

	return fmt.Sprintf("%s%s", baseKeyPrefix, key)
}

// parseBaseKey takes a string in the form of prefix_base32 and parses it into
// BaseKey.
func parseBaseKey(s string) (BaseKey, error) {
	var bk BaseKey

	if !strings.HasPrefix(s, baseKeyPrefix) {
		return bk, fmt.Errorf("could not parseBaseKey: invalid prefix")
	}

	s = strings.TrimPrefix(s, baseKeyPrefix)

	data, err := keyEncoder.DecodeString(s)
	if err != nil {
		return bk, fmt.Errorf("could not parseBaseKey: %v", err)
	}

	if len(data) != keySize {
		return bk, fmt.Errorf("could not parseBaseKey: invalid length")
	}

	copy(bk[:], data)

	return bk, nil
}

// newBaseKey generates a random BaseKey
func newBaseKey() BaseKey {
	var bk BaseKey

	bytes := newKeyBytes()
	copy(bk[:], bytes[:])

	return bk
}

/*
  Begin CryptKey definition
*/

// CryptKey represents an encryption key.
type CryptKey [keySize]byte

// String converts a CryptKey to a string.
func (c CryptKey) String() string {
	key := keyEncoder.EncodeToString(c[:])

	return fmt.Sprintf("%s%s", cryptKeyPrefix, key)
}

// parseCryptKey takes a string in the form of prefix_base32 and parses it into
// CryptKey.
func parseCryptKey(s string) (CryptKey, error) {
	var ck CryptKey

	if !strings.HasPrefix(s, cryptKeyPrefix) {
		return ck, fmt.Errorf("could not parseCryptKey: invalid prefix")
	}

	s = strings.TrimPrefix(s, cryptKeyPrefix)

	data, err := keyEncoder.DecodeString(s)
	if err != nil {
		return ck, fmt.Errorf("could not parseCryptKey: %v", err)
	}

	if len(data) != keySize {
		return ck, fmt.Errorf("could not parseCryptKey: invalid length")
	}

	copy(ck[:], data)

	return ck, nil
}

// newCryptKey generates a random CryptKey
func NewCryptKey() CryptKey {
	var ck CryptKey

	bytes := newKeyBytes()
	copy(ck[:], bytes[:])

	return ck
}

/*
  Begin AuthKey definition
*/

// AuthKey represents an authentication key.
type AuthKey [keySize]byte

// String converts an AuthKey to a string.
func (a AuthKey) String() string {
	key := keyEncoder.EncodeToString(a[:])

	return fmt.Sprintf("%s%s", authKeyPrefix, key)
}

// parseAuthKey takes a string in the form of prefix_base32 and parses it into
// AuthKey.
func parseAuthKey(s string) (AuthKey, error) {
	var ak AuthKey

	if !strings.HasPrefix(s, authKeyPrefix) {
		return ak, fmt.Errorf("could not parseAuthKey: invalid prefix")
	}

	s = strings.TrimPrefix(s, authKeyPrefix)

	data, err := keyEncoder.DecodeString(s)
	if err != nil {
		return ak, fmt.Errorf("could not parseAuthKey: %v", err)
	}

	if len(data) != keySize {
		return ak, fmt.Errorf("could not parseAuthKey: invalid length")
	}

	copy(ak[:], data)

	return ak, nil
}
