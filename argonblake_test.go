package vault

import (
	"fmt"
	"testing"
)

var (
	argonBlakeBaseKey        = "bk_IQWFPSX2VCCB4ZAI3AEYJNZN2ONKUFMROKKNMH56TBPHI6JII4PA"
	argonBlakeAuthKey        = "ak_GIG3UGUPV3EVJSAZZ2NQPSHOYRMGP54NHJARXUN67SXNSDXEKLGA"
	argonBlakeAuthToken      = "at_GIJ7LGGYWCJJ3GPVCQDHXVF7CZDZRDQYSRGLS3OIUKAPS3M7PJAQ"
	argonBlakeCryptKey       = "ck_LIWCI2SX2BYQLU7CATC6MZMOTCT5VLCQ6LAEE6E3EXVAIF5QOVWQ"
	argonBlakeSaltedCryptKey = "ck_6M54CRBI3B7EHX565V7OPXHOY7PSCNGRSCBUEAR3E6M36J4HOSHA"
)

func testArgonBlakeDeriver(t *testing.T) {
	t.Run("Test DeriveBaseKey", testArgonBlakeDeriveBaseKey)
	t.Run("Test DeriveAuthKey", testArgonBlakeDeriveAuthKey)
	t.Run("Test DeriveCryptKey", testArgonBlakeDeriveCryptKey)
	t.Run("Test DeriveAuthToken", testArgonBlakeDeriveAuthToken)
}

func testArgonBlakeDeriveBaseKey(t *testing.T) {
	fmt.Println(t.Name())

	deriverVersion, err := parseVersionToken(argonBlakeDeriverVersion)
	if err != nil {
		t.Fatal("Expected no error, received", err)
	}

	deriver := NewDeriver(deriverVersion)
	_, err = deriver.DeriveBaseKey(username, badPassword)
	if err == nil {
		t.Fatal("Expected error, received nil")
	}

	bk, err := deriver.DeriveBaseKey(username, goodPassword)
	if err != nil {
		t.Fatal("Expected no error, received", err)
	}

	if bk.String() != argonBlakeBaseKey {
		t.Fatal("Expected", argonBlakeBaseKey, ", received", bk.String())
	}
}

func testArgonBlakeDeriveAuthKey(t *testing.T) {
	fmt.Println(t.Name())

	deriverVersion, err := parseVersionToken(argonBlakeDeriverVersion)
	if err != nil {
		t.Fatal("Expected no error, received", err)
	}

	deriver := NewDeriver(deriverVersion)
	bk, _ := deriver.DeriveBaseKey(username, goodPassword)

	ak, err := deriver.DeriveAuthKey(bk)
	if err != nil {
		t.Fatal("Expected no error, received", err)
	}

	if ak.String() != argonBlakeAuthKey {
		t.Fatal("Expected", argonBlakeAuthKey, ", received", ak.String())
	}
}

func testArgonBlakeDeriveCryptKey(t *testing.T) {
	fmt.Println(t.Name())

	deriverVersion, err := parseVersionToken(argonBlakeDeriverVersion)
	if err != nil {
		t.Fatal("Expected no error, received", err)
	}

	deriver := NewDeriver(deriverVersion)
	bk, _ := deriver.DeriveBaseKey(username, goodPassword)

	ck, err := deriver.DeriveCryptKey(bk, nil)
	if err != nil {
		t.Fatal("Expected no error, received", err)
	}

	if ck.String() != argonBlakeCryptKey {
		t.Fatal("Expected", argonBlakeCryptKey, ", received", ck.String())
	}

	ck, err = deriver.DeriveCryptKey(bk, saltBytes)
	if err != nil {
		t.Fatal("Expected no error, received", err)
	}

	if ck.String() != argonBlakeSaltedCryptKey {
		t.Fatal("Expected", argonBlakeSaltedCryptKey, ", received", ck.String())
	}
}

func testArgonBlakeDeriveAuthToken(t *testing.T) {
	fmt.Println(t.Name())

	deriverVersion, err := parseVersionToken(argonBlakeDeriverVersion)
	if err != nil {
		t.Fatal("Expected no error, received", err)
	}

	deriver := NewDeriver(deriverVersion)
	bk, _ := deriver.DeriveBaseKey(username, goodPassword)

	uid := NewUserToken()
	copy(uid[:], userTokenBytes)

	at, err := deriver.DeriveAuthToken(bk, uid)
	if err != nil {
		t.Fatal("Expected no error, received", err)
	}

	if at.String() != argonBlakeAuthToken {
		t.Fatal("Expected", argonBlakeAuthToken, ", received", at.String())
	}
}
