# CrackNet

A high-performance CLI tool for hash analysis and password cracking.
Go orchestrates; Rust does the heavy compute.

## Overview

CrackNet supports:
- **Hash analysis** – auto-detect algorithm, confidence score, and difficulty rating
- **Dictionary attack** – wordlist-based cracking with multi-threading
- **Bruteforce attack** – mask-based keyspace search
- **Hybrid attack** – wordlist combined with mask expansion
- **Batch mode** – crack a file of mixed hashes in one run, grouped by algorithm
- **Pot file** – SQLite cache of previously cracked hashes; instant lookup on repeat runs
- **Intelligence reports** – analyse cracked passwords for DNA patterns, reuse, org risk, and temporal trends

## Supported Algorithms

| Algorithm     | Detection      | Cracking |
|---------------|---------------|----------|
| MD5           | ✓              | ✓        |
| NTLM          | ✓              | ✓        |
| MD5 / NTLM*   | ✓ (ambiguous)  | ✓ (as MD5)|
| SHA-1         | ✓              | ✓        |
| SHA-256       | ✓              | ✓        |
| SHA-512       | ✓              | ✓        |
| bcrypt        | ✓              | ✓        |
| md5crypt ($1$)| ✓              | ✓        |
| sha256crypt ($5$) | ✓          | ✓        |
| sha512crypt ($6$) | ✓          | ✓        |

\* Ambiguous 32-hex hashes are treated as **MD5** by default.

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

Auto-detect the algorithm, print confidence score and difficulty rating:

```bash
cracknet analyze --hash 5f4dcc3b5aa765d61d8327deb882cf99
cracknet analyze --hash '$2b$12$...'
```

### Crack a single hash

#### Dictionary attack

```bash
cracknet crack --hash 5f4dcc3b5aa765d61d8327deb882cf99 --wordlist /usr/share/wordlists/rockyou.txt
cracknet crack --hash <sha256_hash> --algorithm sha256 --wordlist wordlist.txt --threads 4
```

#### Bruteforce attack (mask)

```bash
# Mask tokens: ?l (lowercase) ?u (uppercase) ?d (digit) ?s (special) ?a (all printable) ?h (hex)
cracknet crack --hash <hash> --mask 'pass?d?d' --mode bruteforce
cracknet crack --hash <hash> --mask '?u?l?l?l?d?d' --mode bruteforce --algorithm sha256
```

#### Hybrid attack (wordlist + mask)

Appends every mask expansion to each word in the wordlist:

```bash
cracknet crack --hash <hash> --wordlist rockyou.txt --mask '?d?d' --mode hybrid
```

### Batch file mode

Process an entire file of hashes in one run.  Hashes are deduplicated, grouped by auto-detected algorithm, and cracked per group.

#### Batch file format

Multiple formats are supported on the same line and can be mixed freely:

```
# lines starting with # are ignored
5f4dcc3b5aa765d61d8327deb882cf99
alice:aab3238922bcc25a6f606eb525ffdc56
da39a3ee5e6b4b0d3255bfef95601890afd80709:sha1
$2b$12$WApznUOJfkEGSmYRfnkrPOr466oFDCaj4b6HY3EXGvfxm43seyhgK
```

| Line format          | Meaning                                      |
|----------------------|----------------------------------------------|
| `hash`               | bare hash; algorithm auto-detected           |
| `hash:algorithm`     | hash with explicit algorithm hint            |
| `username:hash`      | username/email paired with hash              |
| `email@domain:hash`  | email stored in metadata for org analysis    |

#### Batch examples

```bash
# Dictionary batch
cracknet crack --file hashes.txt --wordlist rockyou.txt

# Verbose – print each cracked result as it is found
cracknet crack --file hashes.txt --wordlist rockyou.txt -v

# Bruteforce batch
cracknet crack --file hashes.txt --mask 'pass?d?d' --mode bruteforce

# Hybrid batch
cracknet crack --file hashes.txt --wordlist rockyou.txt --mask '?d?d' --mode hybrid

# Only crack MD5 and SHA-1 groups; skip everything else
cracknet crack --file hashes.txt --wordlist rockyou.txt --only md5,sha1

# Skip bcrypt (slow) and sha512crypt groups
cracknet crack --file hashes.txt --wordlist rockyou.txt --skip bcrypt,sha512crypt

# Write all rows (cracked + uncracked) to a human-readable table file
cracknet crack --file hashes.txt --wordlist rockyou.txt --out results.txt

# Attempt cracking even for algorithm groups not natively supported
cracknet crack --file hashes.txt --wordlist rockyou.txt --force
```

**Batch behaviour notes:**
- Duplicate hashes are automatically deduplicated (first occurrence wins).
- Hashes are grouped by detected algorithm and cracked per group in sorted order.
- Results are written to the pot file as they are found (instant cache on re-run).
- By default, batch mode shows a quiet in-place progress bar; use `-v` for per-hash output.
- `--out` writes a formatted table with columns USERNAME, ALGO, HASH, PLAINTEXT, STATUS.
- `--only` and `--skip` are mutually exclusive.

### `crack` flag reference

| Flag              | Description                                                        |
|-------------------|--------------------------------------------------------------------|
| `--hash`          | Single hash to crack                                               |
| `--file`          | Batch file of hashes (one per line)                                |
| `--wordlist`      | Path to wordlist file                                              |
| `--mask`          | Mask pattern for bruteforce/hybrid (e.g. `pass?d?d`)               |
| `--mode`          | Attack mode: `dictionary` \| `bruteforce` \| `hybrid` \| `auto`   |
| `--algorithm`     | Algorithm override (auto-detected when omitted)                    |
| `--threads`       | Number of threads (default from config, typically 8)               |
| `--only`          | Comma-separated list of algorithm groups to crack (batch only)     |
| `--skip`          | Comma-separated list of algorithm groups to skip (batch only)      |
| `-v` / `--verbose`| Print each cracked result as it is found (batch only)              |
| `--out`           | Write all batch entries to a human-readable output table           |
| `--force`         | Attempt unsupported algorithm groups instead of skipping           |

### Configuration

Settings are stored in `~/.cracknet/config.toml` and can be viewed or changed at any time:

```bash
cracknet config show
cracknet config set threads 16
cracknet config set default_wordlist /usr/share/wordlists/rockyou.txt
cracknet config set pot_file /path/to/custom.db
cracknet config set gpu true
```

| Key               | Default               | Description                            |
|-------------------|-----------------------|----------------------------------------|
| `threads`         | `8`                   | Default number of cracking threads     |
| `gpu`             | `false`               | Reserved for future GPU acceleration   |
| `default_wordlist`| *(empty)*             | Wordlist used when `--wordlist` is omitted |
| `pot_file`        | `~/.cracknet/pot.db`  | Path to the SQLite pot file            |

### Intelligence reports (`insight`)

After cracking, the `insight` command analyses the cracked plaintexts stored in the pot file and produces password intelligence reports.

```bash
# Run all modules, print text summary
cracknet insight --db

# Run specific modules only
cracknet insight --db --module dna,reuse

# Generate a combined report as JSON
cracknet insight --db --report --format json -o report.json

# Generate an HTML report
cracknet insight --db --report --format html -o report.html

# Temporal comparison with custom date ranges
cracknet insight --db --module temporal \
  --from 2024-01-01 --to 2024-06-30 \
  --compare-from 2024-07-01 --compare-to 2024-12-31
```

#### Available modules

| Module     | What it does                                                                 |
|------------|------------------------------------------------------------------------------|
| `dna`      | Classifies cracked passwords by character composition (digits-only, mixed case, special chars, etc.) and highlights key findings |
| `reuse`    | Detects exact password reuse across different accounts/usernames              |
| `temporal` | Compares the number of passwords cracked across two configurable date windows |
| `org`      | Groups cracked hashes by email domain and calculates a per-domain risk score  |

#### `insight` flag reference

| Flag             | Description                                                        |
|------------------|--------------------------------------------------------------------|
| `--db`           | Analyse everything stored in the SQLite pot file                   |
| `--file`         | Hash file to import metadata from                                  |
| `--module`       | Comma-separated modules to run: `dna,reuse,temporal,org` or `all` |
| `--report`       | Generate a full combined report instead of a quick summary         |
| `--format`       | Report format: `text` (default) \| `json` \| `html`               |
| `-o` / `--output`| Write report to a file (default: stdout)                           |
| `--from`         | Start date for temporal period 1 (YYYY-MM-DD)                      |
| `--to`           | End date for temporal period 1 (YYYY-MM-DD)                        |
| `--compare-from` | Start date for temporal period 2 (YYYY-MM-DD)                      |
| `--compare-to`   | End date for temporal period 2 (YYYY-MM-DD)                        |

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
  ├── cracked_hashes     (hash, plaintext, algorithm, cracked_at)
  ├── hash_metadata      (username, email, department, source_file)
  ├── password_patterns  (composition analysis, entropy, base word)
  └── password_reuse     (exact-reuse pairs across accounts)
```

### Go layer (`cmd/`, `internal/`)

| Package              | Responsibility                                                      |
|----------------------|---------------------------------------------------------------------|
| `cmd/`               | Root CLI, `analyze`, `crack`, `config`, `insight` commands (Cobra) |
| `internal/bridge`    | IPC bridge – spawns the Rust binary, speaks newline-delimited JSON  |
| `internal/batch`     | Batch file parser, deduplication, algorithm grouping, filters       |
| `internal/config`    | Load/save `~/.cracknet/config.toml` (TOML via BurntSushi)          |
| `internal/db`        | SQLite pot file – open, migrate schema, save/lookup hashes          |
| `internal/display`   | Formatted terminal output (tables, progress bars, colour)           |
| `internal/insight`   | DNA, reuse, temporal, org analysis modules; report generation       |

### Rust layer (`crates/`)

| Crate / Module              | Responsibility                                                 |
|-----------------------------|----------------------------------------------------------------|
| `cracknet-cli`              | Binary entry point – reads JSON commands from stdin            |
| `cracknet-core/analyze`     | Hash type detection (prefix + length + charset heuristics)     |
| `cracknet-core/attack/dictionary` | Wordlist attack with Rayon parallel hashing             |
| `cracknet-core/attack/bruteforce` | Mask-based keyspace expansion and parallel hashing      |
| `cracknet-core/attack/hybrid`     | Wordlist × mask combinator                              |
| `cracknet-core/algorithms`  | MD5, SHA-1/256/512, NTLM, bcrypt, md5crypt, sha*crypt backends |
| `cracknet-core/dna`         | Password composition classification for the insight engine     |
| `cracknet-core/progress`    | Streaming progress events sent back to Go over stdout          |

### IPC protocol

All communication between Go and the Rust engine uses **newline-delimited JSON** over stdin/stdout.  Go writes one JSON command object and reads streamed response objects (progress events, result, or error) until the final message arrives.

## Development

```bash
make build    # build release binaries (cargo build --release + go build)
make test     # run all tests (cargo test + go test ./...)
make clean    # clean build artifacts
```
