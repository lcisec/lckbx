package lckbx

import (
	"bytes"
	"fmt"
	"testing"
)

var (
	keyBytesGood          = []byte{31, 34, 182, 210, 19, 183, 200, 6, 8, 41, 125, 107, 196, 122, 143, 6, 30, 149, 213, 230, 89, 18, 54, 64, 40, 113, 179, 235, 141, 23, 109, 79}
	keyBytesBase32Good    = "D4RLNUQTW7EAMCBJPVV4I6UPAYPJLVPGLEJDMQBIOGZ6XDIXNVHQ"
	keyBytesBase32Invalid = "D4RLNUQTW7EAMCBJPVV4I6UPAYPJLVPGLEJDMQBIOGZ6XDIXNVHq"
	keyBytesBase32Short   = "D4RLNUQTW7EAMCBJPVV4I6UPAYPJLVPGLEJDMQBIOGZ6XDIXNV"
	keyBytesBase32Long    = "D4RLNUQTW7EAMCBJPVV4I6UPAYPJLVPGLEJDMQBIOGZ6XDIXNVHQHQ"
)

func TestKeys(t *testing.T) {
	t.Run("Test BaseKey", testBaseKey)
	t.Run("Test CryptKey", testCryptKey)
	t.Run("Test AuthKey", testAuthKey)
}

func testBaseKey(t *testing.T) {
	fmt.Println(t.Name())

	goodKey := fmt.Sprintf("%s%s", baseKeyPrefix, keyBytesBase32Good)
	noPrefixKey := keyBytesBase32Good
	invalidKey := fmt.Sprintf("%s%s", baseKeyPrefix, keyBytesBase32Invalid)
	shortKey := fmt.Sprintf("%s%s", baseKeyPrefix, keyBytesBase32Short)
	longKey := fmt.Sprintf("%s%s", baseKeyPrefix, keyBytesBase32Long)

	// Validate a randomly generated key
	key := newBaseKey()
	parsed, err := parseBaseKey(key.String())
	if err != nil {
		t.Fatal("Unexpected error", err)
	}

	if key.String() != parsed.String() {
		t.Fatal("Expected", key.String(), ", received", parsed.String())
	}

	if !bytes.Equal(key[:], parsed[:]) {
		t.Fatal("Expected equal bytes from parsed random key.")
	}

	// Validate a known key
	parsed, err = parseBaseKey(goodKey)
	if err != nil {
		t.Fatal("Unexpected error", err)
	}

	if goodKey != parsed.String() {
		t.Fatal("Expected", goodKey, ", received", parsed.String())
	}

	if !bytes.Equal(keyBytesGood[:], parsed[:]) {
		t.Fatal("Expected equal bytes from parsed known key.")
	}

	// Validate known bad keys
	_, err = parseBaseKey(noPrefixKey)
	if err == nil {
		t.Fatal("Expected error, received nil")
	}

	_, err = parseBaseKey(invalidKey)
	if err == nil {
		t.Fatal("Expected error, received nil")
	}

	_, err = parseBaseKey(shortKey)
	if err == nil {
		t.Fatal("Expected error, received nil")
	}

	_, err = parseBaseKey(longKey)
	if err == nil {
		t.Fatal("Expected error, received nil")
	}
}

func testCryptKey(t *testing.T) {
	fmt.Println(t.Name())

	goodKey := fmt.Sprintf("%s%s", cryptKeyPrefix, keyBytesBase32Good)
	noPrefixKey := keyBytesBase32Good
	invalidKey := fmt.Sprintf("%s%s", cryptKeyPrefix, keyBytesBase32Invalid)
	shortKey := fmt.Sprintf("%s%s", cryptKeyPrefix, keyBytesBase32Short)
	longKey := fmt.Sprintf("%s%s", cryptKeyPrefix, keyBytesBase32Long)

	// Validate a randomly generated key
	key := NewCryptKey()
	parsed, err := parseCryptKey(key.String())
	if err != nil {
		t.Fatal("Unexpected error", err)
	}

	if key.String() != parsed.String() {
		t.Fatal("Expected", key.String(), ", received", parsed.String())
	}

	if !bytes.Equal(key[:], parsed[:]) {
		t.Fatal("Expected equal bytes from parsed random key.")
	}

	// Validate a known key
	parsed, err = parseCryptKey(goodKey)
	if err != nil {
		t.Fatal("Unexpected error", err)
	}

	if goodKey != parsed.String() {
		t.Fatal("Expected", goodKey, ", received", parsed.String())
	}

	if !bytes.Equal(keyBytesGood[:], parsed[:]) {
		t.Fatal("Expected equal bytes from parsed known key.")
	}

	// Validate known bad keys
	_, err = parseCryptKey(noPrefixKey)
	if err == nil {
		t.Fatal("Expected error, received nil")
	}

	_, err = parseCryptKey(invalidKey)
	if err == nil {
		t.Fatal("Expected error, received nil")
	}

	_, err = parseCryptKey(shortKey)
	if err == nil {
		t.Fatal("Expected error, received nil")
	}

	_, err = parseCryptKey(longKey)
	if err == nil {
		t.Fatal("Expected error, received nil")
	}
}

func testAuthKey(t *testing.T) {
	fmt.Println(t.Name())

	goodKey := fmt.Sprintf("%s%s", authKeyPrefix, keyBytesBase32Good)
	noPrefixKey := keyBytesBase32Good
	invalidKey := fmt.Sprintf("%s%s", authKeyPrefix, keyBytesBase32Invalid)
	shortKey := fmt.Sprintf("%s%s", authKeyPrefix, keyBytesBase32Short)
	longKey := fmt.Sprintf("%s%s", authKeyPrefix, keyBytesBase32Long)

	// Validate a known key
	parsed, err := parseAuthKey(goodKey)
	if err != nil {
		t.Fatal("Unexpected error", err)
	}

	if goodKey != parsed.String() {
		t.Fatal("Expected", goodKey, ", received", parsed.String())
	}

	if !bytes.Equal(keyBytesGood[:], parsed[:]) {
		t.Fatal("Expected equal bytes from parsed known key.")
	}

	// Validate known bad keys
	_, err = parseAuthKey(noPrefixKey)
	if err == nil {
		t.Fatal("Expected error, received nil")
	}

	_, err = parseAuthKey(invalidKey)
	if err == nil {
		t.Fatal("Expected error, received nil")
	}

	_, err = parseAuthKey(shortKey)
	if err == nil {
		t.Fatal("Expected error, received nil")
	}

	_, err = parseAuthKey(longKey)
	if err == nil {
		t.Fatal("Expected error, received nil")
	}
}
