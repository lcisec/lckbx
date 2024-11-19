package vault

import (
	"fmt"
	"testing"
)

var (
	username       = "user"
	badPassword    = "Thisistooshort."
	goodPassword   = "This is just right."
	userTokenBytes = []byte{31, 34, 182, 210, 19, 183, 200, 6, 8, 41, 125, 107, 196, 122, 143, 6, 30, 149, 213, 230, 89, 18, 54, 64, 40, 113, 179, 235, 141, 23, 109, 79}
	saltBytes      = []byte{31, 34, 182, 210, 19, 183, 200, 6, 8, 41, 125, 107, 196, 122, 143, 6, 30, 149, 213, 230, 89, 18, 54, 64, 40, 113, 179, 235, 141, 23, 109, 79}
)

func testDeriver(t *testing.T) {
	t.Run("Test ArgonBlakeDeriver", testArgonBlakeDeriver)

	// Test NewDeriver after all derivers have been tested.
	t.Run("Test NewDeriver", testNewDeriver)
}

func testNewDeriver(t *testing.T) {
	fmt.Println(t.Name())

	deriverVersion, _ := parseVersionToken(argonBlakeDeriverVersion)
	abd := NewDeriver(deriverVersion)
	bk, _ := abd.DeriveBaseKey(username, goodPassword)

	if bk.String() != argonBlakeBaseKey {
		t.Fatal("Expected", argonBlakeBaseKey, ", received", bk.String())
	}
}
