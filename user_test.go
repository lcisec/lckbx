package lckbx

import (
	"fmt"
	"testing"
)

var (
	userSaveDatabase   = "user_save_test.db"
	userCreateDatabase = "user_create_test.db"
	username1          = "user1"
	username2          = "user2"
	userTestAuthToken  = "at_6QKWQVVJCMBIOIC3XJFC4WCHHVIJ6FBZ7LK7RWU7Z5LGSMWACKHA"
	userTestAuthToken2 = "at_6QKWQVVJCMBIOIC3XJFC4WCHHVIJ6FBZ7LK7RWU7Z5LGSMWACKHB"
	userEncryptionKey  = []byte{130, 23, 204, 14, 85, 241, 175, 104, 73, 233, 46, 145, 129, 5, 163, 100, 74, 208, 50, 232, 45, 173, 145, 35, 228, 7, 54, 111, 128, 229, 28, 143}
)

func TestUser(t *testing.T) {
	t.Run("Test New User", testNewUser)
	t.Run("Test User Equality", testUserEquality)
	t.Run("Test User Storage", testUserStorage)
	t.Run("Test Create User", testCreateUser)
}

func testNewUser(t *testing.T) {
	fmt.Println(t.Name())

	user := NewUser(username1)
	if user.UserName != username1 {
		t.Fatalf("Expected %s, received %s", username1, user.UserName)
	}
}

func testUserEquality(t *testing.T) {
	uid := NewUserToken()
	kid := NewKeysetToken()
	mid := NewMetadataToken()

	// Create two identical Metadata objects and ensure they are equal.
	user1 := &User{
		UserId:     uid,
		UserName:   username1,
		KeysetId:   kid,
		MetadataId: mid,
	}

	user2 := &User{
		UserId:     uid,
		UserName:   username1,
		KeysetId:   kid,
		MetadataId: mid,
	}

	if !user1.Equal(user2) {
		t.Fatalf("Expected equal User, received \n%+v\n%+v\n", user1, user2)
	}

	// Modify one of the objects and ensure they are unequal.
	user2.UserName = username2

	if user1.Equal(user2) {
		t.Fatalf("Expected unequal User, received \n%+v\n%+v\n", user1, user2)
	}
}

func testUserStorage(t *testing.T) {
	fmt.Println(t.Name())

	crypterVersion, _ := parseVersionToken(xChaChaCrypterVersion)
	crypter := NewCrypter(crypterVersion)
	crypter.ChangeKey(userEncryptionKey)

	storer, _ := NewStore(userSaveDatabase)
	aid, _ := parseAuthToken(userTestAuthToken)

	// Create a new User to work with.
	user := NewUser(username1)

	// Save the User object to the database, retrieve it, verify the retrieved
	// User matches the original.
	err := user.Save(&storer, crypter, aid)
	if err != nil {
		t.Fatal("Expected no error, received", err)
	}

	user2, err := NewUserFromStore(&storer, crypter, aid, user.UserId)
	if err != nil {
		t.Fatal("Expected no error, received", err)
	}

	if !user.Equal(user2) {
		t.Fatal("Expected stored User to equal created User")
	}
}

func testCreateUser(t *testing.T) {
	fmt.Println(t.Name())

	crypterVersion, _ := parseVersionToken(xChaChaCrypterVersion)
	crypter := NewCrypter(crypterVersion)
	crypter.ChangeKey(userEncryptionKey)

	storer, _ := NewStore(userCreateDatabase)
	aid, _ := parseAuthToken(userTestAuthToken)
	aid2, _ := parseAuthToken(userTestAuthToken2)

	// Create a new User to work with
	user := NewUser(username1)

	err := user.Create(&storer, crypter, aid)
	if err != nil {
		t.Fatalf("Expected no error, received %v", err)
	}

	user2, _ := NewUserFromStore(&storer, crypter, aid, user.UserId)
	if !user.Equal(user2) {
		t.Fatal("Expected stored User to equal created User")
	}

	err = user.Create(&storer, crypter, aid2)
	if err == nil {
		t.Fatal("Expected an error received none.")
	}
}
