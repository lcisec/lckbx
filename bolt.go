package vault

import (
	"fmt"
	"os"
	"time"

	"github.com/boltdb/bolt"
)

const (
	userBucket     = "user"
	authBucket     = "auth"
	keysetBucket   = "keyset"
	metadataBucket = "metadata"
	itemBucket     = "item"
)

var (
	// BucketNotExist = fmt.Errorf("store: bucket does not exist.")
	BucketNotCreated = fmt.Errorf("store: bucket not created.")
)

// Store holds the bolt database
type Store struct {
	db *bolt.DB
}

// initialize configures the Bolt database for use as a Store.
func (s *Store) initialize() error {
	err := s.createBucket(userBucket)
	if err != nil {
		return err
	}

	err = s.createBucket(authBucket)
	if err != nil {
		return err
	}

	err = s.createBucket(keysetBucket)
	if err != nil {
		return err
	}

	err = s.createBucket(metadataBucket)
	if err != nil {
		return err
	}

	err = s.createBucket(itemBucket)
	if err != nil {
		return err
	}

	return nil
}

// createBucket creates a new bucket with the given name at the root of the
// database. An error is returned if the bucket cannot be created.
func (s *Store) createBucket(bucket string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(bucket))
		if err != nil {
			return BucketNotCreated
		}

		return nil
	})
}

// Write stores the given key/value pair in the given bucket.
func (s *Store) write(bucket, key string, value []byte) error {
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))

		return b.Put([]byte(key), []byte(value))
	})

	return err
}

// Read gets the value associated with the given key in the given bucket. If the
// key does not exist, Read returns nil.
func (s *Store) read(bucket, key string) []byte {
	var val []byte

	s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))

		val = b.Get([]byte(key))

		return nil
	})

	return val
}

// Delete removes a key/value pair from the given bucket. An error is returned
// if the key/value pair cannot be deleted.
func (s *Store) delete(bucket, key string) error {
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))

		return b.Delete([]byte(key))
	})

	return err
}

func (s *Store) GetUser(aid AuthToken) ([]byte, error) {
	var user []byte

	user = s.read(authBucket, aid.String())
	if user == nil {
		return user, fmt.Errorf("could not GetUser: user %s not found", aid)
	}

	return user, nil
}

func (s *Store) GetUserId(username string) []byte {
	var uid []byte

	uid = s.read(userBucket, username)
	if uid == nil {
		return []byte("")
	}

	return uid
}

func (s *Store) SaveUser(aid AuthToken, data []byte) error {
	err := s.write(authBucket, aid.String(), data)
	if err != nil {
		return fmt.Errorf("could not SaveUser: %v", err)
	}

	return nil
}

func (s *Store) GetMetadata(mid MetadataToken) ([]byte, error) {
	var md []byte

	md = s.read(metadataBucket, mid.String())
	if md == nil {
		return md, fmt.Errorf("could not GetMetadata: metadata %s not found", mid)
	}

	return md, nil
}

func (s *Store) SaveMetadata(mid MetadataToken, data []byte) error {
	err := s.write(metadataBucket, mid.String(), data)
	if err != nil {
		return fmt.Errorf("could not SaveMetadata: %v", err)
	}

	return nil
}

func (s *Store) GetKeyset(kid KeysetToken) ([]byte, error) {
	var ks []byte

	ks = s.read(keysetBucket, kid.String())
	if ks == nil {
		return ks, fmt.Errorf("could not GetKeyset: keyset %s not found", kid)
	}

	return ks, nil
}

func (s *Store) SaveKeyset(kid KeysetToken, data []byte) error {
	err := s.write(keysetBucket, kid.String(), data)
	if err != nil {
		return fmt.Errorf("could not SaveKeyset: %v", err)
	}

	return nil
}

func (s *Store) GetItem(iid ItemToken) ([]byte, error) {
	var item []byte

	item = s.read(itemBucket, iid.String())
	if item == nil {
		return item, fmt.Errorf("could not GetItem: item %s not found", iid)
	}

	return item, nil

}
func (s *Store) SaveItem(iid ItemToken, data []byte) error {
	err := s.write(itemBucket, iid.String(), data)
	if err != nil {
		return fmt.Errorf("could not SaveItem: %v", err)
	}

	return nil
}

// Backup the database to the given file.
func (s *Store) Backup(filename string) error {
	err := s.db.View(func(tx *bolt.Tx) error {
		file, e := os.Create(filename)
		if e != nil {
			return e
		}

		defer file.Close()

		_, e = tx.WriteTo(file)
		return e
	})

	return err
}

// Close closes the connection to the bolt database.
func (s *Store) Close() error {
	return s.db.Close()
}

// Create a new store object with a bolt database located at filePath.
func NewStore(filePath string) (Store, error) {
	var s Store

	db, err := bolt.Open(filePath, 0640, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return s, fmt.Errorf("could not NewStore: %v", err)
	}

	s.db = db
	err = s.initialize()
	if err != nil {
		return s, fmt.Errorf("could not NewStore: %v", err)
	}

	return s, nil
}
