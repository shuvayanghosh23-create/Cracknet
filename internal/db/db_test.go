package db

import (
	"testing"
	"time"
)

func TestMigrate_CreatesAllTables(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/test.db"

	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	tables := []string{
		"cracked_hashes",
		"hash_metadata",
		"password_patterns",
		"password_reuse",
		"insight_reports",
	}

	for _, table := range tables {
		var name string
		row := d.conn.QueryRow(
			"SELECT name FROM sqlite_master WHERE type='table' AND name=?", table,
		)
		if err := row.Scan(&name); err != nil {
			t.Errorf("table %q not found: %v", table, err)
		}
	}
}

func TestSaveHashMetadata(t *testing.T) {
	dir := t.TempDir()
	d, err := Open(dir + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	hash := "5f4dcc3b5aa765d61d8327deb882cf99"
	if err := d.SaveHashMetadata(hash, "alice", "alice@example.com", "test.txt"); err != nil {
		t.Fatalf("SaveHashMetadata: %v", err)
	}

	meta, err := d.GetHashMetadata(hash)
	if err != nil {
		t.Fatalf("GetHashMetadata: %v", err)
	}
	if meta == nil {
		t.Fatal("expected metadata, got nil")
	}
	if meta.Username != "alice" {
		t.Errorf("username = %q, want %q", meta.Username, "alice")
	}
	if meta.Email != "alice@example.com" {
		t.Errorf("email = %q, want %q", meta.Email, "alice@example.com")
	}
	if meta.SourceFile != "test.txt" {
		t.Errorf("source_file = %q, want %q", meta.SourceFile, "test.txt")
	}
}

func TestGetHashMetadata_Missing(t *testing.T) {
	dir := t.TempDir()
	d, err := Open(dir + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	meta, err := d.GetHashMetadata("nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if meta != nil {
		t.Error("expected nil for missing hash")
	}
}

func TestSaveInsightReport(t *testing.T) {
	dir := t.TempDir()
	d, err := Open(dir + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	id, err := d.SaveInsightReport(`{"test":true}`, 42)
	if err != nil {
		t.Fatalf("SaveInsightReport: %v", err)
	}
	if id <= 0 {
		t.Errorf("expected positive ID, got %d", id)
	}
}

func TestDetectReuse(t *testing.T) {
	dir := t.TempDir()
	d, err := Open(dir + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	// Save two hashes with the same plaintext.
	_ = d.SaveHash("hash1", "password", "md5")
	_ = d.SaveHash("hash2", "password", "sha1")
	_ = d.SaveHashMetadata("hash1", "alice", "", "file.txt")
	_ = d.SaveHashMetadata("hash2", "bob", "", "file.txt")

	entries, err := d.DetectReuse()
	if err != nil {
		t.Fatalf("DetectReuse: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 reuse entry, got %d", len(entries))
	}
	if len(entries) > 0 && entries[0].Plaintext != "password" {
		t.Errorf("plaintext = %q, want %q", entries[0].Plaintext, "password")
	}
}

func TestSavePasswordPattern(t *testing.T) {
	dir := t.TempDir()
	d, err := Open(dir + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	p := PasswordPattern{
		Plaintext:   "password123",
		PatternType: "word_digits",
		BaseWord:    "password",
		Suffix:      "123",
		Length:      11,
		HasUpper:    false,
		HasDigit:    true,
		HasSpecial:  false,
		EntropyBits: 30.5,
		AnalysedAt:  time.Now().UTC(),
	}
	if err := d.SavePasswordPattern(p); err != nil {
		t.Fatalf("SavePasswordPattern: %v", err)
	}

	patterns, err := d.GetPasswordPatterns()
	if err != nil {
		t.Fatalf("GetPasswordPatterns: %v", err)
	}
	if len(patterns) != 1 {
		t.Errorf("expected 1 pattern, got %d", len(patterns))
	}
}
