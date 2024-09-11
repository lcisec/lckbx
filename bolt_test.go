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

// func testStoreUser(t *testing.T) {
// 	s, _ := NewStore("test.db")
// 	defer s.Close()
// 	defer os.Remove("test.db")

// 	user, err := GetUser(aid AuthToken) ([]byte, error)
// 	GetUserId(username string) UserToken
// 	SaveUser(aid AuthToken, data []byte) error
// }

// func testStoreKeyset(t *testing.T) {
// 	s, _ := NewStore("test.db")
// 	defer s.Close()
// 	defer os.Remove("test.db")

// 	GetKeyset(kid KeysetToken) ([]byte, error)
// 	SaveKeyset(kid KeysetToken, data []byte) error
// }

// func testStoreMetadata(t *testing.T) {
// 	store, _ := NewStore("test.db")
// 	defer store.Close()
// 	defer os.Remove("test.db")

// 	GetMetadata(mid MetadataToken) ([]byte, error)
// 	SaveMetadata(mid MetadataToken, data []byte) error
// }

// func testStoreItem(t *testing.T) {
// 	store, _ := NewStore("test.db")
// 	defer store.Close()
// 	defer os.Remove("test.db")

// 	GetItem(iid ItemToken) ([]byte, error)
// 	SaveItem(iid ItemToken, data []byte) error
// }
