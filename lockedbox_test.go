package lckbx

import (
	"fmt"
	"strings"
	"testing"
)

var (
	lockedBoxUser          = "lckbx"
	lockedBoxShortPassword = "0123456789abcd"
	lockedBoxGoodPassword  = "0123456789abcdef"
	lockedBoxBadPassword   = "0123456789abcdee"
)

func TestLockedBox(t *testing.T) {
	t.Run("Test Registration", testRegister)
	t.Run("Test Login", testLogin)
	t.Run("Test Password Change", testChangePassword)
}

func testRegister(t *testing.T) {
	fmt.Println(t.Name())

	store, err := NewStore("register_test.db")
	if err != nil {
		t.Fatalf("Expected no error, received %v", err)
	}

	lb, err := NewLockedBox(&store)
	if err != nil {
		t.Fatalf("Expected no error, received %v", err)
	}

	// Register a new user with a short password
	err = lb.Register(lockedBoxUser, lockedBoxShortPassword)
	if err == nil {
		t.Fatal("Expected error for short password, received nil")
	}

	// Register a new user with a good password
	err = lb.Register(lockedBoxUser, lockedBoxGoodPassword)
	if err != nil {
		t.Fatalf("Expected no error, received %v", err)
	}

	// Register the same user a second time
	err = lb.Register(lockedBoxUser, lockedBoxGoodPassword)
	if err == nil {
		t.Fatalf("Expected error for existing user, received nil")
	}

	// Register the same user with a different case.
	err = lb.Register(strings.ToUpper(lockedBoxUser), lockedBoxGoodPassword)
	if err == nil {
		t.Fatalf("Expected error for existing uppercase user, received nil")
	}
}

func testLogin(t *testing.T) {
	fmt.Println(t.Name())

	store, err := NewStore("login_test.db")
	if err != nil {
		t.Fatalf("Expected no error, received %v", err)
	}

	lb, err := NewLockedBox(&store)
	if err != nil {
		t.Fatalf("Expected no error, received %v", err)
	}

	// Register a user.
	err = lb.Register(lockedBoxUser, lockedBoxGoodPassword)
	if err != nil {
		t.Fatalf("Expected no error, received %v", err)
	}

	// Attempt to login with a bad password.
	_, err = lb.Login(lockedBoxUser, lockedBoxBadPassword)
	if err == nil {
		t.Fatalf("Expected error with bad password, received nil")
	}

	// Attempt to login with a good password.
	unlocked, err := lb.Login(lockedBoxUser, lockedBoxGoodPassword)
	if unlocked.user.UserName != lockedBoxUser {
		t.Fatal("Expected", lockedBoxUser, ", received", unlocked.user.UserName)
	}

	if unlocked.user.KeysetId != unlocked.keyset.KeysetId {
		t.Fatal("Expected", unlocked.keyset.KeysetId, ", received", unlocked.user.KeysetId)
	}

	if unlocked.user.MetadataId != unlocked.metadata.MetadataId {
		t.Fatal("Expected", unlocked.metadata.MetadataId, ", received", unlocked.user.MetadataId)
	}

	// Attempt to login with an uppercase username.
	upper, err := lb.Login(strings.ToUpper(lockedBoxUser), lockedBoxGoodPassword)
	if upper.user.UserName != lockedBoxUser {
		t.Fatal("Expected", lockedBoxUser, ", received", upper.user.UserName)
	}

	if upper.user.KeysetId != upper.keyset.KeysetId {
		t.Fatal("Expected", upper.keyset.KeysetId, ", received", upper.user.KeysetId)
	}

	if upper.user.MetadataId != upper.metadata.MetadataId {
		t.Fatal("Expected", upper.metadata.MetadataId, ", received", upper.user.MetadataId)
	}
}

func testChangePassword(t *testing.T) {
	fmt.Println(t.Name())

	store, err := NewStore("password_test.db")
	if err != nil {
		t.Fatalf("Expected no error, received %v", err)
	}

	lb, err := NewLockedBox(&store)
	if err != nil {
		t.Fatalf("Expected no error, received %v", err)
	}

	// Register a user.
	err = lb.Register(lockedBoxUser, lockedBoxGoodPassword)
	if err != nil {
		t.Fatalf("Expected no error, received %v", err)
	}

	// Login with the good password.
	unlocked1, err := lb.Login(lockedBoxUser, lockedBoxGoodPassword)
	if err != nil {
		t.Fatalf("Expected no error, received %v", err)
	}

	// Change the password.
	err = lb.ChangePassword(lockedBoxUser, lockedBoxGoodPassword, lockedBoxBadPassword)
	if err != nil {
		t.Fatalf("Expected no error, received %v", err)
	}

	// Login with the updated password.
	unlocked2, err := lb.Login(lockedBoxUser, lockedBoxBadPassword)
	if err != nil {
		t.Fatalf("Expected no error, received %v", err)
	}

	// Users should be equal
	if !unlocked1.user.Equal(unlocked2.user) {
		t.Fatalf("Expected users to be equal, received\n%v\n%v", unlocked1.user, unlocked2.user)
	}

	// Keysets will not be equal because a password change adds a new key to
	// the map, which updates the latest value. Check what we can to ensure
	// the Keyset is what we expect.
	if unlocked1.keyset.KeysetId != unlocked2.keyset.KeysetId {
		t.Fatalf("Expected keyset Ids to be equal, received %s %s", unlocked1.keyset.KeysetId, unlocked2.keyset.KeysetId)
	}

	if len(unlocked2.keyset.Keys) != 2 {
		t.Fatalf("Expected two keys in new Keyset, found %d", len(unlocked2.keyset.Keys))
	}

	// The latest key in each keyset should be different since changing the
	// password added a new key.
	ksi1, _ := unlocked1.keyset.GetLatestKey()
	ksi2, _ := unlocked2.keyset.GetLatestKey()

	if ksi1.Equal(ksi2) {
		t.Fatalf("Expected Keyset items to be unequal, received \n%v\n%v", ksi1, ksi2)
	}

	// Metadatas should be equal
	if !unlocked1.metadata.Equal(unlocked2.metadata) {
		t.Fatalf("Expected metadatas to be equal, received\n%v\n%v", unlocked1.metadata, unlocked2.metadata)
	}

	// Change the password for uppercase user.
	err = lb.ChangePassword(strings.ToUpper(lockedBoxUser), lockedBoxBadPassword, lockedBoxGoodPassword)
	if err != nil {
		t.Fatalf("Expected no error, received %v", err)
	}

	// Login with the updated password.
	upper, err := lb.Login(lockedBoxUser, lockedBoxGoodPassword)
	if err != nil {
		t.Fatalf("Expected no error, received %v", err)
	}

	// Users should be equal
	if !unlocked1.user.Equal(upper.user) {
		t.Fatalf("Expected users to be equal, received\n%v\n%v", unlocked1.user, upper.user)
	}

	// Keysets will not be equal because a password change adds a new key to
	// the map, which updates the latest value. Check what we can to ensure
	// the Keyset is what we expect.
	if unlocked1.keyset.KeysetId != upper.keyset.KeysetId {
		t.Fatalf("Expected keyset Ids to be equal, received %s %s", unlocked1.keyset.KeysetId, upper.keyset.KeysetId)
	}

	if len(upper.keyset.Keys) != 3 {
		t.Fatalf("Expected three keys in new Keyset, found %d", len(upper.keyset.Keys))
	}

	// The latest key in each keyset should be different since changing the
	// password added a new key.
	uksi, _ := upper.keyset.GetLatestKey()

	if ksi1.Equal(uksi) {
		t.Fatalf("Expected Keyset items to be unequal, received \n%v\n%v", ksi1, uksi)
	}

	// Metadatas should be equal
	if !unlocked1.metadata.Equal(upper.metadata) {
		t.Fatalf("Expected metadatas to be equal, received\n%v\n%v", unlocked1.metadata, upper.metadata)
	}
}
