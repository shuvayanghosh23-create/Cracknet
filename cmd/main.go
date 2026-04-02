package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

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
		wordlistFlag  string
		threadsFlag   int
		algorithmFlag string
	)

	cmd := &cobra.Command{
		Use:   "crack",
		Short: "Crack a hash using a dictionary attack",
		Example: `  cracknet crack --hash 5f4dcc3b5aa765d61d8327deb882cf99 --wordlist /usr/share/wordlists/rockyou.txt
  cracknet crack --hash <sha256> --algorithm sha256 --wordlist wordlist.txt --threads 4`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if hashFlag == "" {
				return fmt.Errorf("--hash is required")
			}

			cfg, err := config.Load()
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}

			// Resolve wordlist
			if wordlistFlag == "" {
				wordlistFlag = cfg.DefaultWordlist
			}
			if wordlistFlag == "" {
				return fmt.Errorf("--wordlist is required (or set default_wordlist in config)")
			}

			// Resolve threads
			if threadsFlag == 0 {
				threadsFlag = cfg.Threads
			}

			// Resolve algorithm
			if algorithmFlag == "" {
				// Auto-detect
				msg, err := bridge.RunAnalyze(hashFlag)
				if err == nil && msg.Type != "error" {
					algorithmFlag = msg.Algorithm
					fmt.Printf("  Auto-detected algorithm: %s (confidence: %.0f%%)\n",
						msg.Algorithm, msg.Confidence)
				} else {
					algorithmFlag = "md5"
				}
			}

			// Check pot file cache first
			potDB, dbErr := db.Open(cfg.PotFile)
			if dbErr == nil {
				defer potDB.Close()
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

			fmt.Printf("  Cracking %s using %s with %d thread(s)...\n",
				hashFlag, algorithmFlag, threadsFlag)

			progressFn := func(tried uint64, speed float64, elapsedMs uint64) {
				display.PrintProgress(display.Progress{
					Tried:     tried,
					Speed:     speed,
					ElapsedMs: elapsedMs,
				})
			}

			msg, err := bridge.RunCrack(hashFlag, wordlistFlag, algorithmFlag, threadsFlag, progressFn)
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
		},
	}

	cmd.Flags().StringVar(&hashFlag, "hash", "", "Hash to crack (required)")
	cmd.Flags().StringVar(&wordlistFlag, "wordlist", "", "Path to wordlist file")
	cmd.Flags().IntVar(&threadsFlag, "threads", 0, "Number of threads (default from config)")
	cmd.Flags().StringVar(&algorithmFlag, "algorithm", "", "Hash algorithm (auto-detect if omitted)")
	return cmd
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
