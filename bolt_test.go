package vault

import (
	"bytes"
	"os"
	"testing"
)

type storeTestCase struct {
	bucket string
	key    string
	value  []byte
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
		{userBucket, "user1", []byte("value1")},
		{authBucket, "auth1", []byte("value1")},
		{keysetBucket, "keyset1", []byte("value1")},
		{metadataBucket, "metadata1", []byte("value1")},
		{itemBucket, "item1", []byte("value1")},
	}

	for _, c := range cases {
		err := s.write(c.bucket, c.key, c.value)
		if err != nil {
			t.Fatal("testStoreRWD: unexpected error", err)
		}

		data := s.read(c.bucket, c.key)
		if !bytes.Equal(data, c.value) {
			t.Fatal("testStoreRWD: expected", c.value, ", received", string(data))
		}

		err = s.delete(c.bucket, c.key)
		if err != nil {
			t.Fatal("testStoreRWD: unexpected error", err)
		}

		data = s.read(c.bucket, c.key)
		if data != nil {
			t.Fatal("testStoreRWD: expected nil, received", string(data))
		}
	}
}

func testStoreBackup(t *testing.T) {
	key := "user1"
	val := []byte("value1")

	s, _ := NewStore("test.db")

	s.initialize()
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
