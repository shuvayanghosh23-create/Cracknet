package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"cracknet/internal/batch"
	"cracknet/internal/bridge"
	"cracknet/internal/config"
	"cracknet/internal/db"
	"cracknet/internal/display"
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

Ambiguous 32-hex hashes (MD5 or NTLM) are treated as MD5 by default.`,
		Example: `  cracknet crack --hash 5f4dcc3b5aa765d61d8327deb882cf99 --wordlist rockyou.txt
  cracknet crack --file hashes.txt --wordlist rockyou.txt
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
				return runBatchCrack(fileFlag, wordlistFlag, maskFlag, modeFlag, algorithmFlag, threadsFlag, potDB, cfg)
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

	effectiveMode := resolveMode(modeFlag, wordlistFlag, maskFlag)
	fmt.Printf("  Attack mode: %s | Threads: %d\n", effectiveMode, threadsFlag)

	crackedCount := 0
	total := len(entries)

	for algo, group := range groups {
		fmt.Printf("\n  [%s] %d hash(es)\n", algo, len(group))
		groupStart := time.Now()
		groupCracked := 0
		groupLineActive := false

		for idx, entry := range group {
			h := entry.Hash

			// Check pot file cache first
			if potDB != nil {
				if cached, err := potDB.LookupHash(h); err == nil && cached != nil {
					if groupLineActive {
						fmt.Println()
						groupLineActive = false
					}
					display.PrintResult(display.Result{
						Hash:      h,
						Plaintext: cached.Plaintext,
						Algorithm: cached.Algorithm,
						Cracked:   true,
					})
					fmt.Println("  (from cache)")
					crackedCount++
					groupCracked++
					continue
				}
			}

			progressFn := func(tried uint64, speed float64, elapsedMs uint64) {
				elapsed := (time.Duration(elapsedMs) * time.Millisecond).Round(time.Second)
				fmt.Printf("\r  [%s] %d/%d processed | current tried: %d | %.2f H/s | elapsed: %s   ",
					algo, idx+1, len(group), tried, speed, elapsed)
				groupLineActive = true
			}

			msg, err := callCrack(h, wordlistFlag, maskFlag, algo, effectiveMode, threadsFlag, progressFn)
			if err != nil {
				if groupLineActive {
					fmt.Println()
					groupLineActive = false
				}
				display.PrintError(fmt.Sprintf("%s: %v", h, err))
				continue
			}

			if msg.Cracked && msg.Plaintext != nil && potDB != nil {
				_ = potDB.SaveHash(h, *msg.Plaintext, algo)
			}

			if msg.Cracked {
				if groupLineActive {
					fmt.Println()
					groupLineActive = false
				}
				result := display.Result{
					Hash:      h,
					Algorithm: algo,
					ElapsedMs: msg.ElapsedMs,
					Cracked:   true,
				}
				if msg.Plaintext != nil {
					result.Plaintext = *msg.Plaintext
				}
				display.PrintResult(result)
				crackedCount++
				groupCracked++
			}
		}

		if groupLineActive {
			fmt.Println()
		}
		fmt.Printf("  [%s] summary: %d/%d cracked in %s\n",
			algo,
			groupCracked,
			len(group),
			time.Since(groupStart).Round(time.Millisecond),
		)
	}

	fmt.Printf("\n  Batch complete: %d/%d cracked.\n", crackedCount, total)
	return nil
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
