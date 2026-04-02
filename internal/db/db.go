package db

import (
	"database/sql"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
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

	conn, err := sql.Open("sqlite3", path)
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
	_, err := conn.Exec(`CREATE TABLE IF NOT EXISTS cracked_hashes (
		hash      TEXT PRIMARY KEY,
		plaintext TEXT NOT NULL,
		algorithm TEXT NOT NULL,
		cracked_at DATETIME NOT NULL
	)`)
	return err
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
