package main

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"cracknet/internal/batch"
	"cracknet/internal/bridge"
	"cracknet/internal/config"
	"cracknet/internal/db"
	"cracknet/internal/display"
	"cracknet/internal/insight"
)

func main() {
	root := buildRootCmd()
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func buildRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "cracknet",
		Short: "CrackNet - distributed password cracking and hash analysis",
		Long: `CrackNet is a CLI tool for hash analysis and dictionary-based password cracking.
It uses a high-performance Rust engine for hashing and a Go shell for orchestration.`,
	}

	root.AddCommand(analyzeCmd())
	root.AddCommand(crackCmd())
	root.AddCommand(configCmd())
	root.AddCommand(insightCmd())
	return root
}

// ──────────────────────────────────────────────
// analyze subcommand
// ──────────────────────────────────────────────

func analyzeCmd() *cobra.Command {
	var hashFlag string

	cmd := &cobra.Command{
		Use:   "analyze",
		Short: "Detect hash type and show confidence score",
		Example: `  cracknet analyze --hash 5f4dcc3b5aa765d61d8327deb882cf99
  cracknet analyze --hash '$2b$12$...'`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if hashFlag == "" && len(args) > 0 {
				hashFlag = args[0]
			}
			if hashFlag == "" {
				return fmt.Errorf("--hash is required")
			}

			msg, err := bridge.RunAnalyze(hashFlag)
			if err != nil {
				display.PrintError(err.Error())
				return err
			}

			if msg.Type == "error" {
				display.PrintError(msg.Msg)
				return fmt.Errorf("%s", msg.Msg)
			}

			display.PrintHashInfo(display.HashInfo{
				Hash:       hashFlag,
				Algorithm:  msg.Algorithm,
				Confidence: msg.Confidence,
				Difficulty: msg.Difficulty,
			})
			return nil
		},
	}

	cmd.Flags().StringVar(&hashFlag, "hash", "", "Hash string to analyze")
	return cmd
}

// ──────────────────────────────────────────────
// crack subcommand
// ──────────────────────────────────────────────

func crackCmd() *cobra.Command {
	var (
		hashFlag      string
		fileFlag      string
		wordlistFlag  string
		maskFlag      string
		modeFlag      string
		threadsFlag   int
		algorithmFlag string
		onlyFlag      string
		skipFlag      string
		verboseFlag   bool
		outFlag       string
		forceFlag     bool
	)

	cmd := &cobra.Command{
		Use:   "crack",
		Short: "Crack hashes using dictionary, bruteforce, or hybrid attacks",
		Long: `Crack one hash (--hash) or a batch file (--file) using one of:
  dictionary  – wordlist attack (default when --wordlist is set)
  bruteforce  – mask-based attack (requires --mask)
  hybrid      – wordlist + mask combinator (requires both)
  auto        – pick mode based on provided flags (default)

Mask token reference:
  ?l  lowercase a-z      ?u  uppercase A-Z
  ?d  digits 0-9         ?s  special chars
  ?a  all printable       ?h  hex digits 0-9a-f

Ambiguous 32-hex hashes (MD5 or NTLM) are treated as MD5 by default.

When using --file, you can filter which algorithm groups to process:
  --only md5,sha1     only crack those groups (comma-separated)
  --skip bcrypt       skip those groups (comma-separated)
(--only and --skip are mutually exclusive)

Batch output:
  default       quiet in-place progress (no per-hash cracked output)
  --verbose, -v print every cracked line (✓ hash => plaintext)
  --out FILE    write all batch entries to one human-readable table
  --force       attempt unsupported algorithm groups instead of skipping`,
		Example: `  cracknet crack --hash 5f4dcc3b5aa765d61d8327deb882cf99 --wordlist rockyou.txt
  cracknet crack --file hashes.txt --wordlist rockyou.txt
  cracknet crack --file hashes.txt --wordlist rockyou.txt --only md5,sha1
  cracknet crack --file hashes.txt --wordlist rockyou.txt --skip bcrypt
  cracknet crack --hash 5f4dcc3b5aa765d61d8327deb882cf99 --mask 'pass?d?d' --mode bruteforce
  cracknet crack --file hashes.txt --wordlist rockyou.txt --mask '?d?d' --mode hybrid
  cracknet crack --hash <sha256> --algorithm sha256 --wordlist wordlist.txt --threads 4`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if hashFlag == "" && fileFlag == "" {
				return fmt.Errorf("either --hash or --file is required")
			}
			if hashFlag != "" && fileFlag != "" {
				return fmt.Errorf("--hash and --file are mutually exclusive")
			}
			if onlyFlag != "" && skipFlag != "" {
				return fmt.Errorf("--only and --skip are mutually exclusive")
			}

			cfg, err := config.Load()
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}

			// Resolve wordlist
			if wordlistFlag == "" {
				wordlistFlag = cfg.DefaultWordlist
			}

			// Resolve threads
			if threadsFlag == 0 {
				threadsFlag = cfg.Threads
			}

			// Resolve mode
			if modeFlag == "" {
				modeFlag = "auto"
			}

			// Validate mode
			switch modeFlag {
			case "dictionary", "bruteforce", "hybrid", "auto":
			default:
				return fmt.Errorf("unknown --mode %q; choose: dictionary|bruteforce|hybrid|auto", modeFlag)
			}

			// Validate required flags per mode
			switch modeFlag {
			case "dictionary":
				if wordlistFlag == "" {
					return fmt.Errorf("dictionary mode requires --wordlist")
				}
			case "bruteforce":
				if maskFlag == "" {
					return fmt.Errorf("bruteforce mode requires --mask")
				}
			case "hybrid":
				if wordlistFlag == "" || maskFlag == "" {
					return fmt.Errorf("hybrid mode requires both --wordlist and --mask")
				}
			case "auto":
				if wordlistFlag == "" && maskFlag == "" {
					return fmt.Errorf("--wordlist or --mask (or both) is required")
				}
			}

			// Open pot DB
			potDB, dbErr := db.Open(cfg.PotFile)
			if dbErr == nil {
				defer potDB.Close()
			}

			if fileFlag != "" {
				return runBatchCrack(
					fileFlag,
					wordlistFlag,
					maskFlag,
					modeFlag,
					algorithmFlag,
					threadsFlag,
					onlyFlag,
					skipFlag,
					verboseFlag,
					outFlag,
					forceFlag,
					potDB,
					cfg,
				)
			}
			return runSingleCrack(hashFlag, wordlistFlag, maskFlag, modeFlag, algorithmFlag, threadsFlag, potDB)
		},
	}

	cmd.Flags().StringVar(&hashFlag, "hash", "", "Single hash to crack")
	cmd.Flags().StringVar(&fileFlag, "file", "", "Batch file of hashes (one per line)")
	cmd.Flags().StringVar(&wordlistFlag, "wordlist", "", "Path to wordlist file")
	cmd.Flags().StringVar(&maskFlag, "mask", "", "Mask for bruteforce/hybrid (e.g. pass?d?d)")
	cmd.Flags().StringVar(&modeFlag, "mode", "", "Attack mode: dictionary|bruteforce|hybrid|auto (default auto)")
	cmd.Flags().IntVar(&threadsFlag, "threads", 0, "Number of threads (default from config)")
	cmd.Flags().StringVar(&algorithmFlag, "algorithm", "", "Hash algorithm override (auto-detect if omitted)")
	cmd.Flags().StringVar(&onlyFlag, "only", "", "Comma-separated list of algorithms to crack (e.g. md5,sha1)")
	cmd.Flags().StringVar(&skipFlag, "skip", "", "Comma-separated list of algorithms to skip (e.g. bcrypt,sha512crypt)")
	cmd.Flags().BoolVarP(&verboseFlag, "verbose", "v", false, "Verbose batch output (print every cracked hash line)")
	cmd.Flags().StringVar(&outFlag, "out", "", "Write all batch entries (cracked + uncracked) to a human-readable output file")
	cmd.Flags().BoolVar(&forceFlag, "force", false, "Attempt unsupported algorithm groups instead of skipping")
	return cmd
}

// runSingleCrack handles cracking a single hash.
func runSingleCrack(
	hashFlag, wordlistFlag, maskFlag, modeFlag, algorithmFlag string,
	threadsFlag int,
	potDB *db.DB,
) error {
	// Resolve algorithm via auto-detect if not provided
	if algorithmFlag == "" {
		msg, err := bridge.RunAnalyze(hashFlag)
		if err == nil && msg.Type != "error" {
			algorithmFlag = msg.Algorithm
			fmt.Printf("  Auto-detected algorithm: %s (confidence: %.0f%%)\n",
				msg.Algorithm, msg.Confidence)
		} else {
			algorithmFlag = "md5"
		}
		// Treat md5_or_ntlm as md5 by default
		if algorithmFlag == "md5_or_ntlm" {
			algorithmFlag = "md5"
		}
	}

	// Check pot file cache first
	if potDB != nil {
		if entry, err := potDB.LookupHash(hashFlag); err == nil && entry != nil {
			display.PrintResult(display.Result{
				Hash:      hashFlag,
				Plaintext: entry.Plaintext,
				Algorithm: entry.Algorithm,
				Cracked:   true,
			})
			fmt.Println("  (retrieved from pot file cache)")
			return nil
		}
	}

	effectiveMode := resolveMode(modeFlag, wordlistFlag, maskFlag)
	fmt.Printf("  Cracking %s using %s [%s] with %d thread(s)...\n",
		hashFlag, algorithmFlag, effectiveMode, threadsFlag)

	progressFn := func(tried uint64, speed float64, elapsedMs uint64) {
		display.PrintProgress(display.Progress{
			Tried:     tried,
			Speed:     speed,
			ElapsedMs: elapsedMs,
		})
	}

	msg, err := callCrack(hashFlag, wordlistFlag, maskFlag, algorithmFlag, effectiveMode, threadsFlag, progressFn)
	if err != nil {
		display.PrintError(err.Error())
		return err
	}

	if msg.Type == "error" {
		display.PrintError(msg.Msg)
		return fmt.Errorf("%s", msg.Msg)
	}

	result := display.Result{
		Hash:      hashFlag,
		Algorithm: algorithmFlag,
		ElapsedMs: msg.ElapsedMs,
		Cracked:   msg.Cracked,
	}
	if msg.Plaintext != nil {
		result.Plaintext = *msg.Plaintext
	}

	display.PrintResult(result)

	// Save to pot file
	if msg.Cracked && msg.Plaintext != nil && potDB != nil {
		_ = potDB.SaveHash(hashFlag, *msg.Plaintext, algorithmFlag)
	}

	return nil
}

// runBatchCrack handles cracking a file of hashes.
func runBatchCrack(
	fileFlag, wordlistFlag, maskFlag, modeFlag, algorithmFlag string,
	threadsFlag int,
	onlyFlag, skipFlag string,
	verbose bool,
	outFlag string,
	force bool,
	potDB *db.DB,
	cfg config.Config,
) error {
	entries, err := batch.ParseFile(fileFlag)
	if err != nil {
		return fmt.Errorf("parse batch file: %w", err)
	}
	if len(entries) == 0 {
		return fmt.Errorf("no hashes found in %q", fileFlag)
	}

	fmt.Printf("  Loaded %d unique hash(es) from %s\n", len(entries), fileFlag)

	// Save metadata for each entry when a pot DB is available.
	if potDB != nil {
		for _, e := range entries {
			email := ""
			username := e.Username
			if strings.Contains(e.Username, "@") {
				email = e.Username
				username = strings.SplitN(e.Username, "@", 2)[0]
			}
			_ = potDB.SaveHashMetadata(e.Hash, username, email, fileFlag)
		}
	}

	// Group by algorithm using the Rust analyzer for detection.
	detect := func(hash string) (string, error) {
		if algorithmFlag != "" {
			return algorithmFlag, nil
		}
		msg, err := bridge.RunAnalyze(hash)
		if err != nil {
			return "md5", nil // fallback
		}
		if msg.Type == "error" {
			return "md5", nil
		}
		return msg.Algorithm, nil
	}

	groups, err := batch.GroupByAlgorithm(entries, detect)
	if err != nil {
		return fmt.Errorf("group hashes: %w", err)
	}

	// Apply --only / --skip filters.
	groups, warns := batch.FilterGroups(groups, onlyFlag, skipFlag)
	for _, w := range warns {
		fmt.Printf("  ⚠ --only: algorithm %q not found in file\n", w)
	}
	if len(groups) == 0 {
		return fmt.Errorf("no algorithm groups match the given --only/--skip filters")
	}

	effectiveMode := resolveMode(modeFlag, wordlistFlag, maskFlag)
	fmt.Printf("  Attack mode: %s | Threads: %d\n", effectiveMode, threadsFlag)

	crackedCount := 0
	total := 0

	algorithms := make([]string, 0, len(groups))
	for algo := range groups {
		algorithms = append(algorithms, algo)
		total += len(groups[algo])
	}
	sort.Strings(algorithms)
	outRows := make([]batchOutputRow, 0, total)

	wordlistSize := -1
	if wordlistFlag != "" && (effectiveMode == "dictionary" || effectiveMode == "hybrid") {
		wordlistSize = countWordlistLines(wordlistFlag)
	}

	for _, algo := range algorithms {
		group := groups[algo]
		if !isCrackSupportedAlgorithm(algo) && !force {
			fmt.Printf("\n  [%s] detected but not supported for cracking; skipping (use --force to attempt)\n", algo)
			for _, entry := range group {
				outRows = append(outRows, batchOutputRow{
					Username: entry.Username,
					Algo:     algo,
					Hash:     entry.Hash,
					Status:   "UNCRACKED",
				})
			}
			continue
		}
		if !isCrackSupportedAlgorithm(algo) && force {
			fmt.Printf("\n  [%s] unsupported algorithm group; attempting due to --force\n", algo)
		}

		groupStart := time.Now()
		groupCracked := 0
		groupLineActive := false
		cachedProcessed := 0
		toCrack := make([]string, 0, len(group))
		crackedByHash := make(map[string]string, len(group))

		for _, entry := range group {
			h := entry.Hash
			if potDB != nil {
				if cached, err := potDB.LookupHash(h); err == nil && cached != nil {
					cachedProcessed++
					groupCracked++
					crackedCount++
					crackedByHash[normalizeHashKey(h)] = cached.Plaintext
					continue
				}
			}
			toCrack = append(toCrack, h)
		}

		workers := threadsFlag
		if algo == "bcrypt" {
			workers = minInt(len(group), minInt(threadsFlag, runtime.NumCPU()))
		}
		fmt.Printf("\n  Batch session: algo=%s | total=%d | mode=%s | wordlist=%s | threads=%d | workers=%d\n",
			algo, len(group), effectiveMode, formatWordlistSize(wordlistSize), threadsFlag, workers)

		if cachedProcessed > 0 {
			fmt.Printf("  Cached cracked: %d\n", cachedProcessed)
		}

		lastProcessed := cachedProcessed
		lastTried := uint64(0)
		lastSpeed := 0.0
		lastElapsed := uint64(0)
		displayCracked := groupCracked
		lastRendered := ""
		lastRenderedLen := 0
		renderProgress := func() {
			remaining := len(group) - lastProcessed
			if remaining < 0 {
				remaining = 0
			}
			bar := progressBar(lastProcessed, len(group), 30)
			elapsed := (time.Duration(lastElapsed) * time.Millisecond).Round(time.Second)
			line := fmt.Sprintf("\r  %s %3d%% | processed %d/%d | cracked %d | remaining %d | tried %d | %s | elapsed %s",
				bar,
				percent(lastProcessed, len(group)),
				lastProcessed,
				len(group),
				displayCracked,
				remaining,
				lastTried,
				formatSpeed(lastSpeed),
				elapsed,
			)
			if line == lastRendered {
				return
			}
			padding := ""
			if lastRenderedLen > len(line) {
				padding = strings.Repeat(" ", lastRenderedLen-len(line))
			}
			fmt.Printf("%s%s", line, padding)
			groupLineActive = true
			lastRendered = line
			lastRenderedLen = len(line)
		}
		renderProgress()

		progressCb := func(msg bridge.Message) {
			lastProcessed = cachedProcessed + msg.ProcessedHashes
			if msg.CrackedHashes > 0 {
				displayCracked = maxInt(groupCracked, cachedProcessed+msg.CrackedHashes)
			} else {
				displayCracked = groupCracked
			}
			lastTried = msg.Tried
			lastSpeed = msg.Speed
			lastElapsed = msg.ElapsedMs
			renderProgress()
		}

		resultCb := func(msg bridge.Message) {
			if !msg.Cracked {
				return
			}
			groupCracked++
			crackedCount++
			plain := ""
			if msg.Plaintext != nil {
				plain = *msg.Plaintext
			}
			if potDB != nil && plain != "" {
				_ = potDB.SaveHash(msg.Hash, plain, algo)
			}
			entry := fmt.Sprintf("%s => %s", shortHash(msg.Hash), plain)
			crackedByHash[normalizeHashKey(msg.Hash)] = plain
			displayCracked = groupCracked
			if verbose {
				if groupLineActive {
					fmt.Println()
					groupLineActive = false
				}
				fmt.Printf("  ✓ %s\n", entry)
			}
			renderProgress()
		}

		if len(toCrack) > 0 {
			msg, err := bridge.RunCrackBatch(toCrack, wordlistFlag, maskFlag, algo, effectiveMode, threadsFlag, progressCb, resultCb)
			if err != nil {
				if groupLineActive {
					fmt.Println()
					groupLineActive = false
				}
				display.PrintError(fmt.Sprintf("[%s] batch crack failed: %v", algo, err))
				continue
			}
			if msg.Type == "error" {
				if groupLineActive {
					fmt.Println()
					groupLineActive = false
				}
				display.PrintError(fmt.Sprintf("[%s] %s", algo, msg.Msg))
				continue
			}
		}

		if groupLineActive {
			fmt.Println()
		}

		for _, entry := range group {
			plaintext, cracked := crackedByHash[normalizeHashKey(entry.Hash)]
			status := "UNCRACKED"
			if cracked {
				status = "CRACKED"
			} else {
				plaintext = ""
			}
			outRows = append(outRows, batchOutputRow{
				Username:  entry.Username,
				Algo:      algo,
				Hash:      entry.Hash,
				Plaintext: plaintext,
				Status:    status,
			})
		}
		fmt.Printf("  [%s] summary: %d/%d cracked in %s\n",
			algo,
			groupCracked,
			len(group),
			time.Since(groupStart).Round(time.Millisecond),
		)
	}

	if outFlag != "" {
		if err := writeBatchOutputTable(outFlag, outRows); err != nil {
			return fmt.Errorf("write output file %q: %w", outFlag, err)
		}
		fmt.Printf("  Wrote %d result row(s) to %s\n", len(outRows), outFlag)
	}

	fmt.Printf("\n  Batch complete: %d/%d cracked.\n", crackedCount, total)
	return nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

const (
	gigaHashThreshold = 1_000_000_000
	megaHashThreshold = 1_000_000
	kiloHashThreshold = 1_000
)

var supportedCrackAlgorithms = map[string]bool{
	"md5":         true,
	"md5_or_ntlm": true,
	"sha1":        true,
	"sha256":      true,
	"sha512":      true,
	"ntlm":        true,
	"bcrypt":      true,
	"md5crypt":    true,
	"sha256crypt": true,
	"sha512crypt": true,
}

func isCrackSupportedAlgorithm(algo string) bool {
	return supportedCrackAlgorithms[strings.ToLower(strings.TrimSpace(algo))]
}

type batchOutputRow struct {
	Username  string
	Algo      string
	Hash      string
	Plaintext string
	Status    string
}

func normalizeHashKey(hash string) string {
	return strings.ToLower(strings.TrimSpace(hash))
}

func writeBatchOutputTable(path string, rows []batchOutputRow) error {
	header := []string{"USERNAME", "ALGO", "HASH", "PLAINTEXT", "STATUS"}
	widths := []int{
		len(header[0]),
		len(header[1]),
		len(header[2]),
		len(header[3]),
		len(header[4]),
	}
	for _, row := range rows {
		if len(row.Username) > widths[0] {
			widths[0] = len(row.Username)
		}
		if len(row.Algo) > widths[1] {
			widths[1] = len(row.Algo)
		}
		if len(row.Hash) > widths[2] {
			widths[2] = len(row.Hash)
		}
		if len(row.Plaintext) > widths[3] {
			widths[3] = len(row.Plaintext)
		}
		if len(row.Status) > widths[4] {
			widths[4] = len(row.Status)
		}
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	writeLine := func(cols ...string) error {
		_, err := fmt.Fprintf(
			f,
			"%-*s | %-*s | %-*s | %-*s | %-*s\n",
			widths[0], cols[0],
			widths[1], cols[1],
			widths[2], cols[2],
			widths[3], cols[3],
			widths[4], cols[4],
		)
		return err
	}

	if err := writeLine(header...); err != nil {
		return err
	}
	sep := fmt.Sprintf(
		"%s-+-%s-+-%s-+-%s-+-%s\n",
		strings.Repeat("-", widths[0]),
		strings.Repeat("-", widths[1]),
		strings.Repeat("-", widths[2]),
		strings.Repeat("-", widths[3]),
		strings.Repeat("-", widths[4]),
	)
	if _, err := f.WriteString(sep); err != nil {
		return err
	}
	for _, row := range rows {
		if err := writeLine(row.Username, row.Algo, row.Hash, row.Plaintext, row.Status); err != nil {
			return err
		}
	}
	return nil
}

func formatSpeed(speed float64) string {
	unit := "H/s"
	switch {
	case speed >= gigaHashThreshold:
		speed /= gigaHashThreshold
		unit = "GH/s"
	case speed >= megaHashThreshold:
		speed /= megaHashThreshold
		unit = "MH/s"
	case speed >= kiloHashThreshold:
		speed /= kiloHashThreshold
		unit = "KH/s"
	}
	return fmt.Sprintf("%.2f %s", speed, unit)
}

func shortHash(hash string) string {
	if len(hash) <= 18 {
		return hash
	}
	return hash[:8] + "…" + hash[len(hash)-8:]
}

func progressBar(done, total, width int) string {
	if total <= 0 {
		return "[" + strings.Repeat("░", width) + "]"
	}
	if done < 0 {
		done = 0
	}
	if done > total {
		done = total
	}
	filled := int(float64(done) / float64(total) * float64(width))
	return "[" + strings.Repeat("█", filled) + strings.Repeat("░", width-filled) + "]"
}

func percent(done, total int) int {
	if total <= 0 {
		return 0
	}
	if done < 0 {
		done = 0
	}
	if done > total {
		done = total
	}
	return int(float64(done) * 100 / float64(total))
}

func countWordlistLines(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return -1
	}
	defer f.Close()

	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		count++
	}
	if err := scanner.Err(); err != nil {
		return -1
	}
	return count
}

func formatWordlistSize(n int) string {
	if n < 0 {
		return "unknown"
	}
	return fmt.Sprintf("%d entries", n)
}

// resolveMode determines the effective attack mode from user flags.
func resolveMode(mode, wordlist, mask string) string {
	switch mode {
	case "dictionary", "bruteforce", "hybrid":
		return mode
	default: // "auto" or empty
		switch {
		case wordlist != "" && mask != "":
			return "hybrid"
		case mask != "":
			return "bruteforce"
		default:
			return "dictionary"
		}
	}
}

// callCrack dispatches to the correct bridge function based on effective mode.
func callCrack(
	hash, wordlist, mask, algorithm, mode string,
	threads int,
	progress bridge.ProgressCallback,
) (*bridge.Message, error) {
	switch mode {
	case "bruteforce":
		return bridge.RunBruteforce(hash, mask, algorithm, threads, progress)
	case "hybrid":
		return bridge.RunHybrid(hash, wordlist, mask, algorithm, threads, progress)
	default: // "dictionary"
		return bridge.RunCrack(hash, wordlist, algorithm, threads, progress)
	}
}

// ──────────────────────────────────────────────
// config subcommand
// ──────────────────────────────────────────────

func configCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage CrackNet configuration",
	}

	cmd.AddCommand(configShowCmd())
	cmd.AddCommand(configSetCmd())
	return cmd
}

func configShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Show current configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}

			headers := []string{"Key", "Value"}
			rows := [][]string{
				{"threads", strconv.Itoa(cfg.Threads)},
				{"gpu", strconv.FormatBool(cfg.GPU)},
				{"default_wordlist", cfg.DefaultWordlist},
				{"pot_file", cfg.PotFile},
				{"config_dir", cfg.ConfigDir},
			}
			display.PrintTable(headers, rows)
			return nil
		},
	}
}

func configSetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set <key> <value>",
		Short: "Set a configuration value",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			key := args[0]
			value := args[1]

			cfg, err := config.Load()
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}

			switch strings.ToLower(key) {
			case "threads":
				n, err := strconv.Atoi(value)
				if err != nil || n < 1 {
					return fmt.Errorf("threads must be a positive integer")
				}
				cfg.Threads = n
			case "gpu":
				b, err := strconv.ParseBool(value)
				if err != nil {
					return fmt.Errorf("gpu must be true or false")
				}
				cfg.GPU = b
			case "default_wordlist":
				cfg.DefaultWordlist = value
			case "pot_file":
				cfg.PotFile = value
			default:
				return fmt.Errorf("unknown config key: %q", key)
			}

			if err := config.Save(cfg); err != nil {
				return fmt.Errorf("save config: %w", err)
			}

			fmt.Printf("  Set %s = %s\n", key, value)
			return nil
		},
	}
}

// ──────────────────────────────────────────────
// insight subcommand
// ──────────────────────────────────────────────

func insightCmd() *cobra.Command {
	var (
		fileFlag   string
		dbFlag     bool
		moduleFlag string
		reportFlag bool
		formatFlag string
		outputFlag string
		fromFlag   string
		toFlag     string
		from2Flag  string
		to2Flag    string
	)

	cmd := &cobra.Command{
		Use:   "insight",
		Short: "Analyse cracked passwords and generate intelligence reports",
		Long: `cracknet insight – password intelligence engine

Analyse crack results stored in the pot file DB or a hash file directly.
Modules: dna, reuse, policy, temporal, org, predict (comma-separated or 'all').

Examples:
  cracknet insight --db
  cracknet insight --db --module dna,reuse
  cracknet insight --db --report --format json -o report.json
  cracknet insight --file hashes.txt`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !dbFlag && fileFlag == "" {
				return fmt.Errorf("either --db or --file is required")
			}

			cfg, err := config.Load()
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}

			potDB, err := db.Open(cfg.PotFile)
			if err != nil {
				return fmt.Errorf("open pot DB: %w", err)
			}
			defer potDB.Close()

			modules := parseModuleList(moduleFlag)
			report := insight.FullReport{}

			for _, mod := range modules {
				switch mod {
				case "dna":
					fmt.Println("  Running DNA analysis...")
					dnaReport, err := insight.RunDNA(potDB)
					if err != nil {
						fmt.Printf("  ⚠ dna: %v\n", err)
					} else {
						report.DNA = dnaReport
					}

				case "reuse":
					fmt.Println("  Running reuse detection...")
					reuseReport, err := insight.RunReuse(potDB)
					if err != nil {
						fmt.Printf("  ⚠ reuse: %v\n", err)
					} else {
						report.Reuse = reuseReport
					}

				case "temporal":
					from1, to1, from2Parsed, to2Parsed, parseErr := parseTemporalFlags(fromFlag, toFlag, from2Flag, to2Flag)
					if parseErr != nil {
						fmt.Printf("  ⚠ temporal: %v\n", parseErr)
						break
					}
					fmt.Println("  Running temporal analysis...")
					tempReport, err := insight.RunTemporal(potDB, from1, to1, from2Parsed, to2Parsed)
					if err != nil {
						fmt.Printf("  ⚠ temporal: %v\n", err)
					} else {
						report.Temporal = tempReport
					}

				case "org":
					fmt.Println("  Running org analysis...")
					orgGroups, err := insight.RunOrg(potDB)
					if err != nil {
						fmt.Printf("  ⚠ org: %v\n", err)
					} else {
						report.Org = orgGroups
					}
				}
			}

			if !reportFlag {
				// Print summary to stdout using text format.
				out, err := insight.GenerateReport(report, "text")
				if err != nil {
					return fmt.Errorf("generate report: %w", err)
				}
				fmt.Print(out)
				return nil
			}

			out, err := insight.GenerateReport(report, formatFlag)
			if err != nil {
				return fmt.Errorf("generate report: %w", err)
			}

			if outputFlag != "" {
				if err := os.WriteFile(outputFlag, []byte(out), 0o644); err != nil {
					return fmt.Errorf("write report: %w", err)
				}
				fmt.Printf("  Report written to %s\n", outputFlag)
				return nil
			}
			fmt.Print(out)
			return nil
		},
	}

	cmd.Flags().StringVar(&fileFlag, "file", "", "Hash file to analyse (imports metadata)")
	cmd.Flags().BoolVar(&dbFlag, "db", false, "Analyse everything in the SQLite pot DB")
	cmd.Flags().StringVar(&moduleFlag, "module", "all", "Modules to run: dna|reuse|temporal|org|all")
	cmd.Flags().BoolVar(&reportFlag, "report", false, "Generate a full combined report")
	cmd.Flags().StringVar(&formatFlag, "format", "text", "Report format: text|json|html")
	cmd.Flags().StringVarP(&outputFlag, "output", "o", "", "Output file path (default stdout)")
	cmd.Flags().StringVar(&fromFlag, "from", "", "Start date for temporal analysis (YYYY-MM-DD)")
	cmd.Flags().StringVar(&toFlag, "to", "", "End date for temporal analysis (YYYY-MM-DD)")
	cmd.Flags().StringVar(&from2Flag, "compare-from", "", "Start of comparison period for temporal")
	cmd.Flags().StringVar(&to2Flag, "compare-to", "", "End of comparison period for temporal")
	return cmd
}

// parseModuleList parses the --module flag value into a deduplicated list.
func parseModuleList(s string) []string {
	all := []string{"dna", "reuse", "temporal", "org"}
	if s == "" || s == "all" {
		return all
	}
	seen := make(map[string]bool)
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(strings.ToLower(p))
		if p == "all" {
			return all
		}
		if p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// parseTemporalFlags parses the four date strings for temporal analysis.
func parseTemporalFlags(from1Str, to1Str, from2Str, to2Str string) (time.Time, time.Time, time.Time, time.Time, error) {
	const layout = "2006-01-02"
	parse := func(s, def string) (time.Time, error) {
		if s == "" {
			s = def
		}
		return time.Parse(layout, s)
	}
	now := time.Now().UTC()
	weekAgo := now.AddDate(0, 0, -7).Format(layout)
	twoWeeksAgo := now.AddDate(0, 0, -14).Format(layout)

	from1, err := parse(from1Str, twoWeeksAgo)
	if err != nil {
		return time.Time{}, time.Time{}, time.Time{}, time.Time{}, fmt.Errorf("invalid --from: %w", err)
	}
	to1, err := parse(to1Str, weekAgo)
	if err != nil {
		return time.Time{}, time.Time{}, time.Time{}, time.Time{}, fmt.Errorf("invalid --to: %w", err)
	}
	from2, err := parse(from2Str, weekAgo)
	if err != nil {
		return time.Time{}, time.Time{}, time.Time{}, time.Time{}, fmt.Errorf("invalid --compare-from: %w", err)
	}
	to2, err := parse(to2Str, now.Format(layout))
	if err != nil {
		return time.Time{}, time.Time{}, time.Time{}, time.Time{}, fmt.Errorf("invalid --compare-to: %w", err)
	}
	return from1, to1, from2, to2, nil
}
