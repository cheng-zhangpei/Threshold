package admin

import (
	"os"
	"path/filepath"
	"testing"

	"Threshold/pkg/storage"
)

func setupAdminStore(t *testing.T) (*Store, func()) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	store, err := storage.NewBoltStore(dbPath)
	if err != nil {
		t.Fatalf("NewBoltStore: %v", err)
	}
	adminStore, err := NewStore(store)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	cleanup := func() {
		store.Close()
		os.RemoveAll(dir)
	}
	return adminStore, cleanup
}

func TestAdmin_HasAdmin_BeforeInit(t *testing.T) {
	s, cleanup := setupAdminStore(t)
	defer cleanup()

	if s.HasAdmin() {
		t.Error("expected no admin before init")
	}
}

func TestAdmin_InitAdmin_Success(t *testing.T) {
	s, cleanup := setupAdminStore(t)
	defer cleanup()

	err := s.InitAdmin("admin", "password123")
	if err != nil {
		t.Fatalf("InitAdmin: %v", err)
	}

	if !s.HasAdmin() {
		t.Error("expected HasAdmin=true after init")
	}
}

func TestAdmin_InitAdmin_TwiceFails(t *testing.T) {
	s, cleanup := setupAdminStore(t)
	defer cleanup()

	if err := s.InitAdmin("admin", "password123"); err != nil {
		t.Fatalf("first InitAdmin: %v", err)
	}

	err := s.InitAdmin("admin2", "password456")
	if err == nil {
		t.Fatal("expected error on second init")
	}
}

func TestAdmin_Verify_Success(t *testing.T) {
	s, cleanup := setupAdminStore(t)
	defer cleanup()

	if err := s.InitAdmin("admin", "password123"); err != nil {
		t.Fatalf("InitAdmin: %v", err)
	}

	if err := s.Verify("admin", "password123"); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestAdmin_Verify_WrongPassword(t *testing.T) {
	s, cleanup := setupAdminStore(t)
	defer cleanup()

	if err := s.InitAdmin("admin", "password123"); err != nil {
		t.Fatalf("InitAdmin: %v", err)
	}

	err := s.Verify("admin", "wrongpassword")
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
}

func TestAdmin_Verify_WrongUsername(t *testing.T) {
	s, cleanup := setupAdminStore(t)
	defer cleanup()

	if err := s.InitAdmin("admin", "password123"); err != nil {
		t.Fatalf("InitAdmin: %v", err)
	}

	err := s.Verify("nobody", "password123")
	if err == nil {
		t.Fatal("expected error for wrong username")
	}
}

func TestAdmin_Verify_BeforeInit(t *testing.T) {
	s, cleanup := setupAdminStore(t)
	defer cleanup()

	err := s.Verify("admin", "password123")
	if err == nil {
		t.Fatal("expected error before init")
	}
}
