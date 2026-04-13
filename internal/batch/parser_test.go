package batch

import (
	"os"
	"testing"
)

func TestParseLine_BlankAndComment(t *testing.T) {
	if parseLine("") != nil {
		t.Error("blank line should return nil")
	}
	if parseLine("   ") != nil {
		t.Error("whitespace-only line should return nil")
	}
	if parseLine("# this is a comment") != nil {
		t.Error("comment line should return nil")
	}
}

func TestParseLine_HashOnly(t *testing.T) {
	e := parseLine("5f4dcc3b5aa765d61d8327deb882cf99")
	if e == nil {
		t.Fatal("expected entry, got nil")
	}
	if e.Hash != "5f4dcc3b5aa765d61d8327deb882cf99" {
		t.Errorf("wrong hash: %q", e.Hash)
	}
	if e.Algorithm != "" {
		t.Errorf("unexpected algorithm: %q", e.Algorithm)
	}
	if e.Username != "" {
		t.Errorf("unexpected username: %q", e.Username)
	}
}

func TestParseLine_HashColon_Algorithm(t *testing.T) {
	e := parseLine("5f4dcc3b5aa765d61d8327deb882cf99:md5")
	if e == nil {
		t.Fatal("expected entry, got nil")
	}
	if e.Hash != "5f4dcc3b5aa765d61d8327deb882cf99" {
		t.Errorf("wrong hash: %q", e.Hash)
	}
	if e.Algorithm != "md5" {
		t.Errorf("wrong algorithm: %q", e.Algorithm)
	}
}

func TestParseLine_UsernameColon_Hash(t *testing.T) {
	e := parseLine("alice:5f4dcc3b5aa765d61d8327deb882cf99")
	if e == nil {
		t.Fatal("expected entry, got nil")
	}
	if e.Hash != "5f4dcc3b5aa765d61d8327deb882cf99" {
		t.Errorf("wrong hash: %q", e.Hash)
	}
	if e.Username != "alice" {
		t.Errorf("wrong username: %q", e.Username)
	}
}

func TestParseLine_CryptHash(t *testing.T) {
	hash := "$2b$12$WApznUOJfkEGSmYRfnkrPOr466oFDCaj4b6HY3EXGvfxm43seyhgK"
	e := parseLine(hash)
	if e == nil {
		t.Fatal("expected entry, got nil")
	}
	if e.Hash != hash {
		t.Errorf("wrong hash: %q", e.Hash)
	}
}

func TestParseLine_UsernameCryptHash(t *testing.T) {
	hash := "$2b$12$WApznUOJfkEGSmYRfnkrPOr466oFDCaj4b6HY3EXGvfxm43seyhgK"
	e := parseLine("bob:" + hash)
	if e == nil {
		t.Fatal("expected entry, got nil")
	}
	if e.Hash != hash {
		t.Errorf("wrong hash: %q", e.Hash)
	}
	if e.Username != "bob" {
		t.Errorf("wrong username: %q", e.Username)
	}
}

func TestParseLine_CryptHashColonAlgorithm(t *testing.T) {
	hash := "$2b$12$WApznUOJfkEGSmYRfnkrPOr466oFDCaj4b6HY3EXGvfxm43seyhgK"
	e := parseLine(hash + ":bcrypt")
	if e == nil {
		t.Fatal("expected entry, got nil")
	}
	if e.Hash != hash {
		t.Errorf("wrong hash: %q", e.Hash)
	}
	if e.Algorithm != "bcrypt" {
		t.Errorf("wrong algorithm: %q", e.Algorithm)
	}
}

func TestParseFile_Dedup(t *testing.T) {
	content := `# comment
5f4dcc3b5aa765d61d8327deb882cf99
5f4dcc3b5aa765d61d8327deb882cf99
aab3238922bcc25a6f606eb525ffdc56:sha256

`
	f, err := os.CreateTemp(t.TempDir(), "hashes*.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	f.Close()

	entries, err := ParseFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}

	if len(entries) != 2 {
		t.Errorf("expected 2 unique entries, got %d", len(entries))
	}
}

func TestParseFile_MixedFormats(t *testing.T) {
	content := `# batch test
5f4dcc3b5aa765d61d8327deb882cf99
alice:aab3238922bcc25a6f606eb525ffdc56
da39a3ee5e6b4b0d3255bfef95601890afd80709:sha1
$2b$12$WApznUOJfkEGSmYRfnkrPOr466oFDCaj4b6HY3EXGvfxm43seyhgK
`
	f, err := os.CreateTemp(t.TempDir(), "mixed*.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	f.Close()

	entries, err := ParseFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}

	if len(entries) != 4 {
		t.Errorf("expected 4 entries, got %d: %+v", len(entries), entries)
	}

	// Check third entry has sha1 algorithm
	sha1Entry := entries[2]
	if sha1Entry.Algorithm != "sha1" {
		t.Errorf("entry[2] expected algorithm sha1, got %q", sha1Entry.Algorithm)
	}
	// Check fourth entry is a crypt hash
	bcryptEntry := entries[3]
	if bcryptEntry.Hash[0] != '$' {
		t.Errorf("entry[3] expected crypt-style hash, got %q", bcryptEntry.Hash)
	}
}

func TestGroupByAlgorithm_TwoGroups(t *testing.T) {
	entries := []HashEntry{
		{Hash: "5f4dcc3b5aa765d61d8327deb882cf99"},                   // MD5
		{Hash: "da39a3ee5e6b4b0d3255bfef95601890afd80709"},           // SHA1
		{Hash: "aab3238922bcc25a6f606eb525ffdc56", Algorithm: "md5"}, // explicit MD5
	}

	detector := func(hash string) (string, error) {
		switch len(hash) {
		case 32:
			return "md5", nil
		case 40:
			return "sha1", nil
		default:
			return "unknown", nil
		}
	}

	groups, err := GroupByAlgorithm(entries, detector)
	if err != nil {
		t.Fatal(err)
	}

	if len(groups["md5"]) != 2 {
		t.Errorf("expected 2 md5 entries, got %d", len(groups["md5"]))
	}
	if len(groups["sha1"]) != 1 {
		t.Errorf("expected 1 sha1 entry, got %d", len(groups["sha1"]))
	}
}

func TestGroupByAlgorithm_Md5OrNtlm_DefaultsMd5(t *testing.T) {
	entries := []HashEntry{
		{Hash: "5f4dcc3b5aa765d61d8327deb882cf99"},
	}

	detector := func(hash string) (string, error) {
		return "md5_or_ntlm", nil
	}

	groups, err := GroupByAlgorithm(entries, detector)
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := groups["md5"]; !ok {
		t.Error("md5_or_ntlm should default to md5 group")
	}
	if _, ok := groups["md5_or_ntlm"]; ok {
		t.Error("md5_or_ntlm group should not exist; should be folded into md5")
	}
}
