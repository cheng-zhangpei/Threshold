package admin

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"time"

	"Threshold/pkg/storage"

	"golang.org/x/crypto/bcrypt"
)

const adminBucket = "admin_credentials"

type Store struct {
	store storage.Store
}

func NewStore(store storage.Store) (*Store, error) {
	return &Store{store: store}, nil
}

// GeneratePasscode 生成一次性口令，写入文件
// 服务端首次启动且无管理员时调用
func GeneratePasscode(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}

	// 生成 32 字节随机口令
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	passcode := hex.EncodeToString(b)

	path := filepath.Join(dir, "admin_passcode.txt")
	if err := os.WriteFile(path, []byte(passcode), 0600); err != nil {
		return "", err
	}

	return passcode, nil
}

// ValidatePasscode 验证口令，成功后删除文件（一次性）
func ValidatePasscode(dir, passcode string) error {
	path := filepath.Join(dir, "admin_passcode.txt")

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("passcode file not found (server may already be initialized)")
	}

	stored := string(data)
	if stored != passcode {
		return fmt.Errorf("invalid passcode")
	}

	// 验证成功，删除口令文件
	os.Remove(path)
	return nil
}
func (s *Store) HasAdmin() bool {
	var exists bool
	s.store.View(func(tx storage.Tx) error {
		v, err := tx.Get(adminBucket, []byte("admin"))
		if err != nil {
			return err
		}
		exists = v != nil
		return nil
	})
	return exists
}

func (s *Store) InitAdmin(username, password string) error {
	if s.HasAdmin() {
		return fmt.Errorf("admin already initialized")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	return s.store.Update(func(tx storage.Tx) error {
		if err := tx.Put(adminBucket, []byte("admin"), []byte(username)); err != nil {
			return err
		}
		if err := tx.Put(adminBucket, []byte("admin:"+username+":hash"), hash); err != nil {
			return err
		}
		return tx.Put(adminBucket, []byte("admin:"+username+":created"), []byte(
			time.Now().Format(time.RFC3339),
		))
	})
}

func (s *Store) Verify(username, password string) error {
	var storedHash []byte
	err := s.store.View(func(tx storage.Tx) error {
		storedUsername, err := tx.Get(adminBucket, []byte("admin"))
		if err != nil {
			return err
		}
		if storedUsername == nil {
			return fmt.Errorf("admin not initialized")
		}
		if string(storedUsername) != username {
			return fmt.Errorf("invalid username")
		}
		hash, err := tx.Get(adminBucket, []byte("admin:"+username+":hash"))
		if err != nil {
			return err
		}
		storedHash = hash
		return nil
	})
	if err != nil {
		return err
	}
	if storedHash == nil {
		return fmt.Errorf("admin credentials not found")
	}
	return bcrypt.CompareHashAndPassword(storedHash, []byte(password))
}
