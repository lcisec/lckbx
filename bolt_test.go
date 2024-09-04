package vault

import (
	"fmt"
	"os"
	"sort"
	"testing"
)

type storeTestCase struct {
	bucket: string
	key:    string
	value:  string
}

func TestStore(t *testing.T) {
	testNewStore(t)
	testStoreRWD(t)
}


func testNewStore(t *testing.T) {
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
	s, _ := NewStore("test.db")
	defer s.Close()
	defer os.Remove("test.db")

	err := s.initialize()
	if err != nil {
		t.Fatal("testStoreRWD: unexpected error", err)
	}

	cases := []storeTestCase{
		{ userBucket, "user1", "value1" },
		{ authBucket, "auth1", "value1" },
		{ keysetBucket, "keyset1", "value1" },
		{ metadataBucket, "metadata1", "value1" },
		{ itemBucket, "item1", "value1" },
	}

	for _, c := range cases {
		err := s.write([]byte(c.bucket), []byte(c.key), []byte(c.value))
		if err != nil {
			t.Fatal("testStoreRWD: unexpected error", err)
		}

		data := s.read([]byte(c.bucket), []byte(c.key))
		if data != []byte(c.value) {
			t.Fatal("testStoreRWD: expected", c.value, ", received", string(data))
		}

		err = s.delete([]byte(c.bucket), []byte(c.key))
		if err != nil {
			t.Fatal("testStoreRWD: unexpected error", err)
		}

		data = s.read([]byte(c.bucket), []byte(c.key))
		if data != nil {
			t.Fatal("testStoreRWD: expected nil, received", string(data))
		}
	}
}

func testStoreBackup(t *testing.T) {
	key := []byte("user1")
	val := []byte("value1")

	s, _ := NewStore("test.db")
	
	s.initialize()
	s.write([]byte(userBucket), key, val)

	err := s.Backup("backup_test.db")
	if err != nil {
		t.Fatal("testStoreRWD: unexpected error", err)
	}

	s.Close()
	os.Remove("test.db")

	s, _ = NewStore("backup_test.db")
	defer s.Close()
	defer os.Remove("backup_test.db")

	data := s.read([]byte(userBucket), key)
	if data != value {
		t.Fatal("testStoreRWD: expected", string(value), ", received", string(data))
	}
}

func testStoreUser(t *testing.T) {
	s, _ := NewStore("test.db")
	defer s.Close()
	defer os.Remove("test.db")

	user, err := GetUser(aid AuthToken) ([]byte, error)
	GetUserId(username string) UserToken
	SaveUser(aid AuthToken, data []byte) error
}

func testStoreKeyset(t *testing.T) {
	s, _ := NewStore("test.db")
	defer s.Close()
	defer os.Remove("test.db")

	GetKeyset(kid KeysetToken) ([]byte, error)
	SaveKeyset(kid KeysetToken, data []byte) error
}

func testStoreMetadata(t *testing.T) {
	store, _ := NewStore("test.db")
	defer store.Close()
	defer os.Remove("test.db")

	GetMetadata(mid MetadataToken) ([]byte, error)
	SaveMetadata(mid MetadataToken, data []byte) error
}

func testStoreItem(t *testing.T) {
	store, _ := NewStore("test.db")
	defer store.Close()
	defer os.Remove("test.db")

	GetItem(iid ItemToken) ([]byte, error)
	SaveItem(iid ItemToken, data []byte) error
}

