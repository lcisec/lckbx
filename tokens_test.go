package vault

import (
	"fmt"
	"strings"
	"testing"
)

const (
	tokenBase32Size = 52
)

func testTokens(t *testing.T) {
	t.Run("Test ItemToken", testItemToken)
	t.Run("Test UserToken", testUserToken)
	t.Run("Test KeysetToken", testKeysetToken)
	t.Run("Test MetadataToken", testMetadataToken)
	t.Run("Test VersionToken", testVersionToken)
	t.Run("Test AuthToken", testAuthToken)
}

func testTokenBytes(t *testing.T, s string) {
	data, err := tokenEncoder.DecodeString(s)
	if err != nil {
		t.Fatal("Could not parse token bytes:", err)
	}

	if len(data) != tokenSize {
		t.Fatal("Expected", tokenSize, "bytes, received", len(data))
	}
}

func testItemToken(t *testing.T) {
	fmt.Println(t.Name())

	token := NewItemToken().String()

	if !strings.HasPrefix(token, itemTokenPrefix) {
		t.Fatal("ItemToken has incorrect prefix.")
	}

	token = strings.TrimPrefix(token, itemTokenPrefix)
	if len(token) != tokenBase32Size {
		t.Fatal("Expected", tokenBase32Size, "base32 characters, received", len(token))
	}

	testTokenBytes(t, token)
}

func testUserToken(t *testing.T) {
	fmt.Println(t.Name())

	token := NewUserToken().String()

	if !strings.HasPrefix(token, userTokenPrefix) {
		t.Fatal("UserToken has incorrect prefix.")
	}

	token = strings.TrimPrefix(token, userTokenPrefix)
	if len(token) != tokenBase32Size {
		t.Fatal("Expected", tokenBase32Size, "base32 characters, received", len(token))
	}

	testTokenBytes(t, token)
}

func testKeysetToken(t *testing.T) {
	fmt.Println(t.Name())

	token := NewKeysetToken().String()

	if !strings.HasPrefix(token, keysetTokenPrefix) {
		t.Fatal("KeysetToken has incorrect prefix.")
	}

	token = strings.TrimPrefix(token, keysetTokenPrefix)
	if len(token) != tokenBase32Size {
		t.Fatal("Expected", tokenBase32Size, "base32 characters, received", len(token))
	}

	testTokenBytes(t, token)
}

func testMetadataToken(t *testing.T) {
	fmt.Println(t.Name())

	token := NewMetadataToken().String()

	if !strings.HasPrefix(token, metadataTokenPrefix) {
		t.Fatal("MetadataToken has incorrect prefix.")
	}

	token = strings.TrimPrefix(token, metadataTokenPrefix)
	if len(token) != tokenBase32Size {
		t.Fatal("Expected", tokenBase32Size, "base32 characters, received", len(token))
	}

	testTokenBytes(t, token)
}

func testVersionToken(t *testing.T) {
	fmt.Println(t.Name())

	token := NewVersionToken().String()

	if !strings.HasPrefix(token, versionTokenPrefix) {
		t.Fatal("VersionToken has incorrect prefix.")
	}

	parsed, err := parseVersionToken(token)
	if err != nil {
		t.Fatal("Expected no error, recieved", err)
	}

	if parsed.String() != token {
		t.Fatal("Expected", token, ", received", parsed.String())
	}

	token = strings.TrimPrefix(token, versionTokenPrefix)
	if len(token) != tokenBase32Size {
		t.Fatal("Expected", tokenBase32Size, "base32 characters, received", len(token))
	}

	testTokenBytes(t, token)
}

func testAuthToken(t *testing.T) {
	fmt.Println(t.Name())

	token := NewAuthToken().String()

	if !strings.HasPrefix(token, authTokenPrefix) {
		t.Fatal("AuthToken has incorrect prefix.")
	}

	token = strings.TrimPrefix(token, authTokenPrefix)
	if len(token) != tokenBase32Size {
		t.Fatal("Expected", tokenBase32Size, "base32 characters, received", len(token))
	}

	testTokenBytes(t, token)
}
