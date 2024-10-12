package vault

import (
	"fmt"
	"testing"
)

var (
	username       = "user"
	userTokenBytes = []byte{31, 34, 182, 210, 19, 183, 200, 6, 8, 41, 125, 107, 196, 122, 143, 6, 30, 149, 213, 230, 89, 18, 54, 64, 40, 113, 179, 235, 141, 23, 109, 79}
	badPassword    = "Thisistooshort."
	goodPassword   = "This is just right."
	baseKey        = "bk_IQWFPSX2VCCB4ZAI3AEYJNZN2ONKUFMROKKNMH56TBPHI6JII4PA"
	authKey        = "ak_GIG3UGUPV3EVJSAZZ2NQPSHOYRMGP54NHJARXUN67SXNSDXEKLGA"
	authToken      = "at_GIJ7LGGYWCJJ3GPVCQDHXVF7CZDZRDQYSRGLS3OIUKAPS3M7PJAQ"
	cryptKey       = "ck_LIWCI2SX2BYQLU7CATC6MZMOTCT5VLCQ6LAEE6E3EXVAIF5QOVWQ"
	saltBytes      = []byte{31, 34, 182, 210, 19, 183, 200, 6, 8, 41, 125, 107, 196, 122, 143, 6, 30, 149, 213, 230, 89, 18, 54, 64, 40, 113, 179, 235, 141, 23, 109, 79}
	saltedCryptKey = "ck_6M54CRBI3B7EHX565V7OPXHOY7PSCNGRSCBUEAR3E6M36J4HOSHA"
)

func testArgonBlakeDeriver(t *testing.T) {
	t.Run("Test DeriveBaseKey", testDeriveBaseKey)
	t.Run("Test DeriveAuthKey", testDeriveAuthKey)
	t.Run("Test DeriveCryptKey", testDeriveCryptKey)
	t.Run("Test DeriveAuthToken", testDeriveAuthToken)
}

func testDeriveBaseKey(t *testing.T) {
	fmt.Println(t.Name())

	deriver := NewV1Deriver()
	_, err := deriver.DeriveBaseKey(username, badPassword)
	if err == nil {
		t.Fatal("Expected error, received nil")
	}

	bk, err := deriver.DeriveBaseKey(username, goodPassword)
	if err != nil {
		t.Fatal("Expected no error, received", err)
	}

	if bk.String() != baseKey {
		t.Fatal("Expected", baseKey, ", received", bk.String())
	}
}

func testDeriveAuthKey(t *testing.T) {
	fmt.Println(t.Name())

	deriver := NewV1Deriver()
	bk, _ := deriver.DeriveBaseKey(username, goodPassword)

	ak, err := deriver.DeriveAuthKey(bk)
	if err != nil {
		t.Fatal("Expected no error, received", err)
	}

	if ak.String() != authKey {
		t.Fatal("Expected", authKey, ", received", ak.String())
	}
}

func testDeriveCryptKey(t *testing.T) {
	fmt.Println(t.Name())

	deriver := NewV1Deriver()
	bk, _ := deriver.DeriveBaseKey(username, goodPassword)

	ck, err := deriver.DeriveCryptKey(bk, nil)
	if err != nil {
		t.Fatal("Expected no error, received", err)
	}

	if ck.String() != cryptKey {
		t.Fatal("Expected", cryptKey, ", received", ck.String())
	}

	ck, err = deriver.DeriveCryptKey(bk, saltBytes)
	if err != nil {
		t.Fatal("Expected no error, received", err)
	}

	if ck.String() != saltedCryptKey {
		t.Fatal("Expected", saltedCryptKey, ", received", ck.String())
	}
}

func testDeriveAuthToken(t *testing.T) {
	fmt.Println(t.Name())

	deriver := NewV1Deriver()
	bk, _ := deriver.DeriveBaseKey(username, goodPassword)

	uid := NewUserToken()
	copy(uid[:], userTokenBytes)

	at, err := deriver.DeriveAuthToken(bk, uid)
	if err != nil {
		t.Fatal("Expected no error, received", err)
	}

	if at.String() != authToken {
		t.Fatal("Expected", authToken, ", received", at.String())
	}
}
