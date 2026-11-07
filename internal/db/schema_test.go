package db

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestEnsureSchema_FreshDB(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	sqlDb, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("failed to open sqlite db: %v", err)
	}
	defer sqlDb.Close()

	// Run EnsureSchema with fallback
	if err := EnsureSchema(sqlDb, ""); err != nil {
		t.Fatalf("EnsureSchema failed: %v", err)
	}

	// Verify tables exist
	cols, err := getExistingColumns(sqlDb, "users")
	if err != nil {
		t.Fatalf("failed to get columns for users: %v", err)
	}
	for _, expected := range []string{"id", "username", "password", "created_at"} {
		if !cols[expected] {
			t.Errorf("expected column %s missing in users table", expected)
		}
	}

	dockerCols, err := getExistingColumns(sqlDb, "docker_files")
	if err != nil {
		t.Fatalf("failed to get columns for docker_files: %v", err)
	}
	for _, expected := range []string{"id", "path", "created_at"} {
		if !dockerCols[expected] {
			t.Errorf("expected column %s missing in docker_files table", expected)
		}
	}
}

func TestEnsureSchema_WithFile(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_file.db")
	sqlDb, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("failed to open sqlite db: %v", err)
	}
	defer sqlDb.Close()

	schemaFile := filepath.Join(tmpDir, "schema.sql")
	if err := os.WriteFile(schemaFile, []byte(DefaultSchemaSQL), 0644); err != nil {
		t.Fatalf("failed to write schema file: %v", err)
	}

	if err := EnsureSchema(sqlDb, schemaFile); err != nil {
		t.Fatalf("EnsureSchema with file failed: %v", err)
	}

	cols, err := getExistingColumns(sqlDb, "users")
	if err != nil {
		t.Fatalf("failed to get columns: %v", err)
	}
	if !cols["username"] {
		t.Errorf("expected username column")
	}
}

func TestEnsureSchema_AddMissingColumns(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_missing.db")
	sqlDb, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("failed to open sqlite db: %v", err)
	}
	defer sqlDb.Close()

	// Create users table missing 'password' and 'created_at'
	_, err = sqlDb.Exec(`
		CREATE TABLE users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE
		);
	`)
	if err != nil {
		t.Fatalf("failed to create partial users table: %v", err)
	}

	// Verify columns before EnsureSchema
	colsBefore, err := getExistingColumns(sqlDb, "users")
	if err != nil {
		t.Fatalf("failed to get columns before: %v", err)
	}
	if colsBefore["password"] || colsBefore["created_at"] {
		t.Fatalf("columns should not exist initially")
	}

	// Run EnsureSchema
	if err := EnsureSchema(sqlDb, ""); err != nil {
		t.Fatalf("EnsureSchema failed: %v", err)
	}

	// Verify missing columns were added
	colsAfter, err := getExistingColumns(sqlDb, "users")
	if err != nil {
		t.Fatalf("failed to get columns after: %v", err)
	}
	if !colsAfter["password"] {
		t.Errorf("missing column 'password' was not added")
	}
	if !colsAfter["created_at"] {
		t.Errorf("missing column 'created_at' was not added")
	}
}
