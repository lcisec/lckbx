package vault

import (
	"bytes"
	"fmt"
	"os"
	"testing"
)

func testNewStore(t *testing.T) {
	fmt.Println(t.Name())

	// Open a database in a path that does not exist.
	_, err := NewStore("bad/path/test.db")
	if err == nil {
		t.Fatal("testNewStore: expected error got nil")
	}

	// Open a database
	s, err := NewStore("test.db")
	if err != nil {
		t.Fatal("testNewStore: unexpected error", err)
	}
	s.Close()
	os.Remove("test.db")
}

func testStoreRWD(t *testing.T) {
	fmt.Println(t.Name())

	s, err := NewStore("test.db")
	if err != nil {
		t.Fatal("testStoreRWD: unexpected error", err)
	}

	defer s.Close()
	defer os.Remove("test.db")

	key := "testkey"
	val := []byte("testvalue")

	for _, bucket := range storeBuckets {
		err := s.write(bucket, key, val)
		if err != nil {
			t.Fatal("testStoreRWD: unexpected error", err)
		}

		data := s.read(bucket, key)
		if !bytes.Equal(data, val) {
			t.Fatal("testStoreRWD: expected", val, ", received", string(data))
		}

		err = s.delete(bucket, key)
		if err != nil {
			t.Fatal("testStoreRWD: unexpected error", err)
		}

		data = s.read(bucket, key)
		if data != nil {
			t.Fatal("testStoreRWD: expected nil, received", string(data))
		}
	}
}

func testStoreBackup(t *testing.T) {
	fmt.Println(t.Name())

	key := "user1"
	val := []byte("value1")

	s, _ := NewStore("test.db")

	s.write(userBucket, key, val)

	err := s.Backup("backup_test.db")
	if err != nil {
		t.Fatal("testStoreRWD: unexpected error", err)
	}

	s.Close()
	os.Remove("test.db")

	s, _ = NewStore("backup_test.db")
	defer s.Close()
	defer os.Remove("backup_test.db")

	data := s.read(userBucket, key)
	if !bytes.Equal(data, val) {
		t.Fatal("testStoreRWD: expected", string(val), ", received", string(data))
	}
}

func testStoreUserId(t *testing.T) {
	fmt.Println(t.Name())

	s, _ := NewStore("test.db")
	defer s.Close()
	defer os.Remove("test.db")

	uid := NewUserToken()
	username := "TestUser"

	err := s.SaveUserId(username, uid)
	if err != nil {
		t.Fatal("Expected no error, received", err)
	}

	data := s.GetUserId(username)
	if string(data) != uid.String() {
		t.Fatal("Expected", uid.String(), ", received", string(data))
	}

	err = s.DeleteUserId(username)
	if err != nil {
		t.Fatal("Expected no error, received", err)
	}

}

func testStoreUser(t *testing.T) {
	fmt.Println(t.Name())

	s, _ := NewStore("test.db")
	defer s.Close()
	defer os.Remove("test.db")

	aid := NewAuthToken()
	userBytes := []byte("test user bytes.")

	err := s.SaveUser(aid, userBytes)
	if err != nil {
		t.Fatal("Expected no error, received", err)
	}

	user, err := s.GetUser(aid)
	if err != nil {
		t.Fatal("Expected no error, received", err)
	}

	if string(user) != string(userBytes) {
		t.Fatal("Expected", string(userBytes), ", received", string(user))
	}
}

func testStoreKeyset(t *testing.T) {
	fmt.Println(t.Name())

	s, _ := NewStore("test.db")
	defer s.Close()
	defer os.Remove("test.db")

	kid := NewKeysetToken()
	keyBytes := []byte("test key bytes.")

	err := s.SaveKeyset(kid, keyBytes)
	if err != nil {
		t.Fatal("Expected no error, received", err)
	}

	key, err := s.GetKeyset(kid)
	if err != nil {
		t.Fatal("Expected no error, received", err)
	}

	if string(key) != string(keyBytes) {
		t.Fatal("Expected", string(keyBytes), ", received", string(key))
	}
}

func testStoreMetadata(t *testing.T) {
	fmt.Println(t.Name())

	s, _ := NewStore("test.db")
	defer s.Close()
	defer os.Remove("test.db")

	mid := NewMetadataToken()
	metaBytes := []byte("test metadata bytes.")

	err := s.SaveMetadata(mid, metaBytes)
	if err != nil {
		t.Fatal("Expected no error, received", err)
	}

	meta, err := s.GetMetadata(mid)
	if err != nil {
		t.Fatal("Expected no error, received", err)
	}

	if string(meta) != string(metaBytes) {
		t.Fatal("Expected", string(metaBytes), ", received", string(meta))
	}
}

func testStoreItem(t *testing.T) {
	fmt.Println(t.Name())

	s, _ := NewStore("test.db")
	defer s.Close()
	defer os.Remove("test.db")

	iid := NewItemToken()
	itemBytes := []byte("test item bytes.")

	err := s.SaveItem(iid, itemBytes)
	if err != nil {
		t.Fatal("Expected no error, received", err)
	}

	item, err := s.GetItem(iid)
	if err != nil {
		t.Fatal("Expected no error, received", err)
	}

	if string(item) != string(itemBytes) {
		t.Fatal("Expected", string(itemBytes), ", received", string(item))
	}
}
