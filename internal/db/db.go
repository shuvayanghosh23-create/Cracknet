package db

import (
	"database/sql"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// CrackedHash represents one entry in the pot file.
type CrackedHash struct {
	Hash      string
	Plaintext string
	Algorithm string
	CrackedAt time.Time
}

// DB wraps the SQLite pot file.
type DB struct {
	conn *sql.DB
}

// Open opens (or creates) the SQLite pot database at the given path.
func Open(path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}

	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}

	if err := migrate(conn); err != nil {
		conn.Close()
		return nil, err
	}

	return &DB{conn: conn}, nil
}

// Close closes the database connection.
func (d *DB) Close() error {
	return d.conn.Close()
}

// migrate creates the schema if it doesn't exist.
func migrate(conn *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS cracked_hashes (
			hash       TEXT PRIMARY KEY,
			plaintext  TEXT NOT NULL,
			algorithm  TEXT NOT NULL,
			cracked_at DATETIME NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS hash_metadata (
			hash        TEXT PRIMARY KEY,
			username    TEXT,
			email       TEXT,
			department  TEXT,
			source_file TEXT,
			import_date DATETIME
		)`,
		`CREATE TABLE IF NOT EXISTS password_patterns (
			plaintext    TEXT PRIMARY KEY,
			pattern_type TEXT,
			base_word    TEXT,
			suffix       TEXT,
			length       INTEGER,
			has_upper    BOOLEAN,
			has_digit    BOOLEAN,
			has_special  BOOLEAN,
			entropy_bits REAL,
			analysed_at  DATETIME
		)`,
		`CREATE TABLE IF NOT EXISTS password_reuse (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			plaintext  TEXT,
			hash1      TEXT,
			hash2      TEXT,
			username1  TEXT,
			username2  TEXT,
			similarity REAL
		)`,
		`CREATE TABLE IF NOT EXISTS insight_reports (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			report_json  TEXT,
			score        INTEGER,
			generated_at DATETIME
		)`,
	}
	for _, stmt := range stmts {
		if _, err := conn.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

// LookupHash returns the cracked hash entry for the given hash, or nil if not found.
func (d *DB) LookupHash(hash string) (*CrackedHash, error) {
	row := d.conn.QueryRow(
		`SELECT hash, plaintext, algorithm, cracked_at FROM cracked_hashes WHERE hash = ?`,
		hash,
	)

	var entry CrackedHash
	var crackedAt string
	err := row.Scan(&entry.Hash, &entry.Plaintext, &entry.Algorithm, &crackedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	entry.CrackedAt, _ = time.Parse(time.RFC3339, crackedAt)
	return &entry, nil
}

// SaveHash inserts or replaces a cracked hash entry.
func (d *DB) SaveHash(hash, plaintext, algorithm string) error {
	_, err := d.conn.Exec(
		`INSERT OR REPLACE INTO cracked_hashes (hash, plaintext, algorithm, cracked_at) VALUES (?, ?, ?, ?)`,
		hash, plaintext, algorithm, time.Now().UTC().Format(time.RFC3339),
	)
	return err
}

// HashMetadata holds contextual metadata for a hash.
type HashMetadata struct {
	Hash       string
	Username   string
	Email      string
	Department string
	SourceFile string
	ImportDate time.Time
}

// PasswordPattern holds the pattern analysis for a plaintext.
type PasswordPattern struct {
	Plaintext   string
	PatternType string
	BaseWord    string
	Suffix      string
	Length      int
	HasUpper    bool
	HasDigit    bool
	HasSpecial  bool
	EntropyBits float64
	AnalysedAt  time.Time
}

// ReuseEntry represents a case where two accounts share the same password.
type ReuseEntry struct {
	Plaintext  string
	Hash1      string
	Hash2      string
	Username1  string
	Username2  string
	Similarity float64
}

// SaveHashMetadata upserts metadata for a hash.
func (d *DB) SaveHashMetadata(hash, username, email, sourceFile string) error {
	_, err := d.conn.Exec(
		`INSERT OR REPLACE INTO hash_metadata (hash, username, email, department, source_file, import_date)
		 VALUES (?, ?, ?, '', ?, ?)`,
		hash, username, email, sourceFile, time.Now().UTC().Format(time.RFC3339),
	)
	return err
}

// GetHashMetadata retrieves metadata for a hash.
func (d *DB) GetHashMetadata(hash string) (*HashMetadata, error) {
	row := d.conn.QueryRow(
		`SELECT hash, username, email, department, source_file, import_date
		 FROM hash_metadata WHERE hash = ?`,
		hash,
	)
	var m HashMetadata
	var importDate string
	err := row.Scan(&m.Hash, &m.Username, &m.Email, &m.Department, &m.SourceFile, &importDate)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	m.ImportDate, _ = time.Parse(time.RFC3339, importDate)
	return &m, nil
}

// GetAllCrackedWithPlaintext returns all cracked hashes with their plaintexts.
func (d *DB) GetAllCrackedWithPlaintext() ([]CrackedHash, error) {
	return d.GetAllHashes()
}

// SavePasswordPattern upserts a pattern analysis for a plaintext.
func (d *DB) SavePasswordPattern(p PasswordPattern) error {
	_, err := d.conn.Exec(
		`INSERT OR REPLACE INTO password_patterns
		 (plaintext, pattern_type, base_word, suffix, length, has_upper, has_digit, has_special, entropy_bits, analysed_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.Plaintext, p.PatternType, p.BaseWord, p.Suffix, p.Length,
		p.HasUpper, p.HasDigit, p.HasSpecial, p.EntropyBits,
		p.AnalysedAt.UTC().Format(time.RFC3339),
	)
	return err
}

// GetPasswordPatterns returns all analyzed password patterns.
func (d *DB) GetPasswordPatterns() ([]PasswordPattern, error) {
	rows, err := d.conn.Query(
		`SELECT plaintext, pattern_type, base_word, suffix, length,
		        has_upper, has_digit, has_special, entropy_bits, analysed_at
		 FROM password_patterns ORDER BY analysed_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []PasswordPattern
	for rows.Next() {
		var p PasswordPattern
		var analysedAt string
		if err := rows.Scan(&p.Plaintext, &p.PatternType, &p.BaseWord, &p.Suffix, &p.Length,
			&p.HasUpper, &p.HasDigit, &p.HasSpecial, &p.EntropyBits, &analysedAt); err != nil {
			return nil, err
		}
		p.AnalysedAt, _ = time.Parse(time.RFC3339, analysedAt)
		results = append(results, p)
	}
	return results, rows.Err()
}

// DetectReuse finds cases where multiple hashes share the same plaintext (exact reuse).
func (d *DB) DetectReuse() ([]ReuseEntry, error) {
	// Find plaintexts that appear in more than one hash entry.
	rows, err := d.conn.Query(`
		SELECT a.plaintext, a.hash, b.hash,
		       COALESCE(ma.username, ''), COALESCE(mb.username, ''), 1.0
		FROM cracked_hashes a
		JOIN cracked_hashes b ON a.plaintext = b.plaintext AND a.hash < b.hash
		LEFT JOIN hash_metadata ma ON a.hash = ma.hash
		LEFT JOIN hash_metadata mb ON b.hash = mb.hash
		ORDER BY a.plaintext
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []ReuseEntry
	for rows.Next() {
		var e ReuseEntry
		if err := rows.Scan(&e.Plaintext, &e.Hash1, &e.Hash2,
			&e.Username1, &e.Username2, &e.Similarity); err != nil {
			return nil, err
		}
		results = append(results, e)
	}
	return results, rows.Err()
}

// SaveInsightReport stores a generated report and returns its ID.
func (d *DB) SaveInsightReport(reportJSON string, score int) (int64, error) {
	res, err := d.conn.Exec(
		`INSERT INTO insight_reports (report_json, score, generated_at) VALUES (?, ?, ?)`,
		reportJSON, score, time.Now().UTC().Format(time.RFC3339),
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// GetAllHashes returns all cracked hash entries.
func (d *DB) GetAllHashes() ([]CrackedHash, error) {
	rows, err := d.conn.Query(
		`SELECT hash, plaintext, algorithm, cracked_at FROM cracked_hashes ORDER BY cracked_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []CrackedHash
	for rows.Next() {
		var entry CrackedHash
		var crackedAt string
		if err := rows.Scan(&entry.Hash, &entry.Plaintext, &entry.Algorithm, &crackedAt); err != nil {
			return nil, err
		}
		entry.CrackedAt, _ = time.Parse(time.RFC3339, crackedAt)
		results = append(results, entry)
	}
	return results, rows.Err()
}
