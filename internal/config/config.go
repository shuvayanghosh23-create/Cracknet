package config

import (
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// Config holds all CrackNet configuration.
type Config struct {
	Threads         int    `toml:"threads"`
	GPU             bool   `toml:"gpu"`
	DefaultWordlist string `toml:"default_wordlist"`
	PotFile         string `toml:"pot_file"`
	ConfigDir       string `toml:"config_dir"`
}

// DefaultConfig returns the default configuration.
func DefaultConfig() Config {
	home, _ := os.UserHomeDir()
	configDir := filepath.Join(home, ".cracknet")
	return Config{
		Threads:         8,
		GPU:             false,
		DefaultWordlist: "",
		PotFile:         filepath.Join(configDir, "pot.db"),
		ConfigDir:       configDir,
	}
}

// configPath returns the path to the user config file.
func configPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".cracknet", "config.toml"), nil
}

// Load reads the config from ~/.cracknet/config.toml.
// Falls back to defaults if the file does not exist.
func Load() (Config, error) {
	cfg := DefaultConfig()

	path, err := configPath()
	if err != nil {
		return cfg, err
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return cfg, nil
	}

	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// Save writes the configuration to ~/.cracknet/config.toml.
func Save(cfg Config) error {
	path, err := configPath()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return toml.NewEncoder(f).Encode(cfg)
}
