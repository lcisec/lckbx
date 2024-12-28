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
	storeBuckets = [5]string{
		userBucket,
		authBucket,
		keysetBucket,
		metadataBucket,
		itemBucket,
	}
)

var (
	BucketNotCreated = fmt.Errorf("store: bucket not created.")
)

// Store holds the bolt database
type Store struct {
	db *bolt.DB
}

// initialize configures the Bolt database for use as a Store.
func (s *Store) initialize() error {
	for _, bucket := range storeBuckets {
		err := s.createBucket(bucket)
		if err != nil {
			return err
		}
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

// SaveUserId takes a username and UserToken and stores them in the auth
// bucket. This allows the UserId to be found by username. The UserId is then
// used to derive an AuthToken, which is used to lookup the user in the user
// bucket.
func (s *Store) SaveUserId(username string, uid UserToken) error {
	err := s.write(authBucket, username, []byte(uid.String()))
	if err != nil {
		return fmt.Errorf("could not Store.SaveUserId: %v", err)
	}

	return nil
}

// GetUserId returns the UserToken associated with the given username. If the
// username cannot be found or if there is an error parsing the token, a
// random token is returned.
func (s *Store) GetUserId(username string) UserToken {
	var uid []byte
	var ut UserToken

	uid = s.read(authBucket, username)
	if uid == nil {
		return ut
	}

	token, err := parseUserToken(string(uid))
	if err != nil {
		return ut
	}

	return token
}

// DeleteUserId deletes from the database the bytes for the UserToken
// associated with the username. If the UserToken is deleted, you will not
// be able to derive the AuthToken needed to get the user and you will not
// be able to decrypt the user because the UserToken is used as authenticated
// data during the encryption process.
func (s *Store) DeleteUserId(username string) error {
	return s.delete(authBucket, username)
}

// SaveUser takes an AuthToken and the encrypted user bytes and saves them to
// the user bucket. The AuthToken is derived from the unique UserToken
// associated with the user.
func (s *Store) SaveUser(aid AuthToken, data []byte) error {
	err := s.write(userBucket, aid.String(), data)
	if err != nil {
		return fmt.Errorf("could not SaveUser: %v", err)
	}

	return nil
}

// GetUser takes an AuthToken and returns the encrypted bytes for the user.
func (s *Store) GetUser(aid AuthToken) ([]byte, error) {
	var user []byte

	user = s.read(userBucket, aid.String())
	if user == nil {
		return user, fmt.Errorf("could not GetUser: user %s not found", aid)
	}

	return user, nil
}

// DeleteUser takes an AuthToken and removes the encrypted bytes associated
// with it from the user bucket. The AuthToken is derived from the unique
// UserToken associated with the user.
func (s *Store) DeleteUser(aid AuthToken) error {
	return s.delete(userBucket, aid.String())
}

// SaveMetadata takes a MetadataToken and the encrypted metadata bytes and
// saves them to the metadata bucket.
func (s *Store) SaveMetadata(mid MetadataToken, data []byte) error {
	err := s.write(metadataBucket, mid.String(), data)
	if err != nil {
		return fmt.Errorf("could not SaveMetadata: %v", err)
	}

	return nil
}

// GetMetadata takes a MetadataToken and returns the encrypted bytes for the
// metadata.
func (s *Store) GetMetadata(mid MetadataToken) ([]byte, error) {
	var md []byte

	md = s.read(metadataBucket, mid.String())
	if md == nil {
		return md, fmt.Errorf("could not GetMetadata: metadata %s not found", mid)
	}

	return md, nil
}

// DeleteMetadata takes a MetadataToken and removes the encrypted bytes
// associated with it from the metadata bucket.
func (s *Store) DeleteMetadata(mid MetadataToken) error {
	return s.delete(metadataBucket, mid.String())
}

// SaveKeyset takes a KeysetToken and the encrypted keyset bytes and saves
// them to the keyset bucket.
func (s *Store) SaveKeyset(kid KeysetToken, data []byte) error {
	err := s.write(keysetBucket, kid.String(), data)
	if err != nil {
		return fmt.Errorf("could not SaveKeyset: %v", err)
	}

	return nil
}

// GetKeyset takes a KeysetToken and returns the encrypted bytes for the
// keyset.
func (s *Store) GetKeyset(kid KeysetToken) ([]byte, error) {
	var ks []byte

	ks = s.read(keysetBucket, kid.String())
	if ks == nil {
		return ks, fmt.Errorf("could not GetKeyset: keyset %s not found", kid)
	}

	return ks, nil
}

// DeleteKeyset takes a KeysetToken and removes the encrypted bytes associated
// with it from the keyset bucket.
func (s *Store) DeleteKeyset(kid KeysetToken) error {
	return s.delete(keysetBucket, kid.String())
}

// SaveItem takes an ItemToken and the encrypted Item bytes and saves them
// to the item bucket.
func (s *Store) SaveItem(iid ItemToken, data []byte) error {
	err := s.write(itemBucket, iid.String(), data)
	if err != nil {
		return fmt.Errorf("could not SaveItem: %v", err)
	}

	return nil
}

// GetItem takes an ItemToken and returns the encrypted bytes for the item.
func (s *Store) GetItem(iid ItemToken) ([]byte, error) {
	var item []byte

	item = s.read(itemBucket, iid.String())
	if item == nil {
		return item, fmt.Errorf("could not GetItem: item %s not found", iid)
	}

	return item, nil

}

// Backup creates a backup of the database to the given filename.
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
