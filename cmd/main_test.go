package main

import (
	"os"
	"strings"
	"testing"
)

func TestCrackVerboseFlagHasShortAlias(t *testing.T) {
	cmd := crackCmd()
	flag := cmd.Flags().Lookup("verbose")
	if flag == nil {
		t.Fatal("expected verbose flag to exist")
	}
	if flag.Shorthand != "v" {
		t.Fatalf("expected verbose shorthand to be 'v', got %q", flag.Shorthand)
	}
}

func TestWriteBatchOutputTableIncludesAllRowsAndFullHash(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "batch-out-*.txt")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	f.Close()

	rows := []batchOutputRow{
		{
			Username:  "alice",
			Algo:      "sha256crypt",
			Hash:      "$5$rounds=11858$WH1ABM5sKhxbkgCK$aTQsjPkz0rBsH3lQlJxw9HDTDXPKBxC0LlVeV69P.t1",
			Plaintext: "test",
			Status:    "CRACKED",
		},
		{
			Username: "",
			Algo:     "sha512crypt",
			Hash:     "$6$rounds=11531$G/gkPn17kHYo0gTF$Kq.uZBHlSBXyzsOJXtxJruOOH4yc0Is13uY7yK0PvAvXxbvc1w8DO1RzREMhKsc82K/Jh8OquV8FZUlreYPJk1",
			Status:   "UNCRACKED",
		},
	}

	if err := writeBatchOutputTable(f.Name(), rows); err != nil {
		t.Fatalf("writeBatchOutputTable failed: %v", err)
	}

	data, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	text := string(data)

	for _, col := range []string{"USERNAME", "ALGO", "HASH", "PLAINTEXT", "STATUS"} {
		if !strings.Contains(text, col) {
			t.Fatalf("missing header column %q in output:\n%s", col, text)
		}
	}
	if !strings.Contains(text, rows[0].Hash) || !strings.Contains(text, rows[1].Hash) {
		t.Fatalf("expected full hash values in output:\n%s", text)
	}
	if !strings.Contains(text, "CRACKED") || !strings.Contains(text, "UNCRACKED") {
		t.Fatalf("expected both statuses in output:\n%s", text)
	}
}
