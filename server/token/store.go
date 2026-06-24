package token

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	_ "crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"Threshold/pkg/storage"

	"github.com/google/uuid"
)

const tokenBucket = "admin_tokens"

type Store struct {
	store storage.Store
	gcm   cipher.AEAD
}

type Entry struct {
	Token     string `json:"token"`
	Username  string `json:"username"`
	CreatedAt int64  `json:"created_at"`
	ExpiresAt int64  `json:"expires_at"`
}

func NewStore(store storage.Store, keyDir string) (*Store, error) {
	if keyDir == "" {
		keyDir = "./data/keys"
	}

	encKey, err := loadOrGenerateKey(keyDir)
	if err != nil {
		return nil, fmt.Errorf("enc_key: %w", err)
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}

	return &Store{store: store, gcm: gcm}, nil
}

func (s *Store) Generate(username string, ttl time.Duration) (string, int64, error) {
	tokenStr := uuid.New().String()
	expiresAt := time.Now().Add(ttl).UnixMilli()

	entry := Entry{
		Token:     tokenStr,
		Username:  username,
		CreatedAt: time.Now().UnixMilli(),
		ExpiresAt: expiresAt,
	}

	plaintext, err := json.Marshal(entry)
	if err != nil {
		return "", 0, err
	}

	nonce := make([]byte, s.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", 0, err
	}
	ciphertext := s.gcm.Seal(nonce, nonce, plaintext, nil)

	err = s.store.Update(func(tx storage.Tx) error {
		return tx.Put(tokenBucket, []byte(tokenStr), ciphertext)
	})
	if err != nil {
		return "", 0, err
	}

	return tokenStr, expiresAt, nil
}

func (s *Store) Validate(tokenStr string) (*Entry, error) {
	var entry Entry

	err := s.store.View(func(tx storage.Tx) error {
		ciphertext, err := tx.Get(tokenBucket, []byte(tokenStr))
		if err != nil {
			return err
		}
		if ciphertext == nil {
			return fmt.Errorf("token not found")
		}

		nonceSize := s.gcm.NonceSize()
		if len(ciphertext) < nonceSize {
			return fmt.Errorf("invalid ciphertext")
		}
		nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
		plaintext, err := s.gcm.Open(nil, nonce, ct, nil)
		if err != nil {
			return fmt.Errorf("decrypt failed: %w", err)
		}

		return json.Unmarshal(plaintext, &entry)
	})
	if err != nil {
		return nil, err
	}

	if time.Now().UnixMilli() > entry.ExpiresAt {
		go s.Revoke(tokenStr)
		return nil, fmt.Errorf("token expired")
	}

	return &entry, nil
}

func (s *Store) Revoke(tokenStr string) error {
	return s.store.Update(func(tx storage.Tx) error {
		return tx.Delete(tokenBucket, []byte(tokenStr))
	})
}

func loadOrGenerateKey(keyDir string) ([]byte, error) {
	keyPath := filepath.Join(keyDir, "enc.key")

	data, err := os.ReadFile(keyPath)
	if err == nil && len(data) >= 32 {
		return data[:32], nil
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}

	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		return nil, err
	}

	return key, nil
}
