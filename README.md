# CrackNet

A high-performance CLI tool for hash analysis and password cracking.
Go orchestrates; Rust does the heavy compute.

## Overview

CrackNet supports:
- **Hash analysis** – auto-detect algorithm and confidence
- **Dictionary attack** – wordlist-based cracking
- **Bruteforce attack** – mask-based keyspace search (Phase 2)
- **Hybrid attack** – wordlist combined with mask (Phase 2)
- **Batch mode** – crack a file of hashes in one run (Phase 2)
- **Pot file** – SQLite cache of previously cracked hashes

## Installation

### Prerequisites

- Go 1.20+
- Rust (install via [rustup](https://rustup.rs/))
- **No system SQLite required** (uses pure-Go `modernc.org/sqlite`)

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

### Build

```bash
make build
```

This produces:
- `./cracknet` – Go CLI binary
- `./target/release/cracknet-cli` – Rust engine (called automatically)

To run from anywhere:
```bash
sudo cp ./cracknet /usr/local/bin/cracknet
```

## Usage

### Analyze a hash

```bash
cracknet analyze --hash 5f4dcc3b5aa765d61d8327deb882cf99
cracknet analyze --hash '$2b$12$...'
```

### Dictionary attack

```bash
cracknet crack --hash 5f4dcc3b5aa765d61d8327deb882cf99 --wordlist /usr/share/wordlists/rockyou.txt
cracknet crack --hash <sha256_hash> --algorithm sha256 --wordlist wordlist.txt --threads 4
```

### Bruteforce attack (mask)

```bash
# Mask syntax: fixed chars + tokens
# Tokens: ?l (lower) ?u (upper) ?d (digit) ?s (special) ?a (all) ?h (hex)
cracknet crack --hash <hash> --mask 'pass?d?d' --mode bruteforce
cracknet crack --hash <hash> --mask '?u?l?l?l?d?d' --mode bruteforce --algorithm sha256
```

### Hybrid attack (wordlist + mask)

```bash
# Appends mask expansion to each word in the wordlist
cracknet crack --hash <hash> --wordlist rockyou.txt --mask '?d?d' --mode hybrid
```

### Batch file mode (Phase 2)

Create a hash file (multiple formats supported per line):

```
# comments start with #
5f4dcc3b5aa765d61d8327deb882cf99
alice:aab3238922bcc25a6f606eb525ffdc56
da39a3ee5e6b4b0d3255bfef95601890afd80709:sha1
$2b$12$WApznUOJfkEGSmYRfnkrPOr466oFDCaj4b6HY3EXGvfxm43seyhgK
```

```bash
# Dictionary batch
cracknet crack --file hashes.txt --wordlist rockyou.txt

# Bruteforce batch
cracknet crack --file hashes.txt --mask 'pass?d?d' --mode bruteforce

# Hybrid batch
cracknet crack --file hashes.txt --wordlist rockyou.txt --mask '?d?d' --mode hybrid
```

Duplicate hashes are automatically deduplicated.
Hashes are grouped by detected algorithm and cracked per group.
Results are written to the pot file as they are found.

Ambiguous 32-hex hashes (MD5 or NTLM) are treated as **MD5** by default.

### Configuration

```bash
cracknet config show
cracknet config set threads 16
cracknet config set default_wordlist /usr/share/wordlists/rockyou.txt
cracknet config set pot_file /path/to/custom.db
```

## Architecture

```
+------------------+    JSON/stdin    +----------------------+
|  Go CLI          | ---------------> |  Rust cracknet-cli   |
|  (orchestration) | <--------------- |  (cracking engine)   |
+------------------+   JSON/stdout   +----------------------+
       |
       | SQLite (modernc.org/sqlite -- pure Go, no CGO)
       v
  ~/.cracknet/pot.db
```

- **Go** (`cmd/`, `internal/`): CLI parsing, config, SQLite pot file, batch parsing, IPC bridge
- **Rust** (`crates/cracknet-core/`): hashing, dictionary/bruteforce/hybrid engines, Rayon threading
- **IPC**: newline-delimited JSON over stdin/stdout

## Development

```bash
make build    # build release binaries
make test     # run all tests (Rust + Go)
make clean    # clean build artifacts
```
