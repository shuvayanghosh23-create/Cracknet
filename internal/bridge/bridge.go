package bridge

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
)

// JobRequest is the message sent to the Rust binary.
type JobRequest struct {
	Type      string `json:"type"`
	Hash      string `json:"hash"`
	Wordlist  string `json:"wordlist,omitempty"`
	Algorithm string `json:"algorithm,omitempty"`
	Threads   int    `json:"threads,omitempty"`
}

// Message is a generic JSON message received from the Rust binary.
type Message struct {
	Type       string  `json:"type"`
	Algorithm  string  `json:"algorithm,omitempty"`
	Confidence float32 `json:"confidence,omitempty"`
	Difficulty string  `json:"difficulty,omitempty"`
	Cracked    bool    `json:"cracked,omitempty"`
	Plaintext  *string `json:"plaintext,omitempty"`
	ElapsedMs  uint64  `json:"elapsed_ms,omitempty"`
	Tried      uint64  `json:"tried,omitempty"`
	Speed      float64 `json:"speed,omitempty"`
	Msg        string  `json:"message,omitempty"`
}

// ProgressCallback is called when a progress update is received.
type ProgressCallback func(tried uint64, speed float64, elapsedMs uint64)

// RunAnalyze asks the Rust binary to detect the hash type.
func RunAnalyze(hash string) (*Message, error) {
	req := JobRequest{
		Type: "analyze",
		Hash: hash,
	}
	return call(req, nil)
}

// RunCrack asks the Rust binary to run a dictionary attack.
func RunCrack(hash, wordlist, algorithm string, threads int, progress ProgressCallback) (*Message, error) {
	req := JobRequest{
		Type:      "crack",
		Hash:      hash,
		Wordlist:  wordlist,
		Algorithm: algorithm,
		Threads:   threads,
	}
	return call(req, progress)
}

// call spawns the Rust binary, sends req as JSON, and reads responses.
func call(req JobRequest, progress ProgressCallback) (*Message, error) {
	binary := findBinary()

	input, err := pipeInput(req)
	if err != nil {
		return nil, err
	}

	cmd := exec.Command(binary)
	cmd.Stdin = input

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start cracknet-cli: %w", err)
	}

	// Drain stderr in background
	go func() {
		io.Copy(io.Discard, stderr)
	}()

	var result *Message
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		var msg Message
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			continue
		}

		switch msg.Type {
		case "progress":
			if progress != nil {
				progress(msg.Tried, msg.Speed, msg.ElapsedMs)
			}
		default:
			result = &msg
		}
	}

	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("cracknet-cli exited with error: %w", err)
	}

	if result == nil {
		return nil, fmt.Errorf("no response from cracknet-cli")
	}
	return result, nil
}

// pipeInput creates an io.Reader that writes req as JSON followed by a newline.
func pipeInput(req JobRequest) (io.Reader, error) {
	data, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	r, w := io.Pipe()
	go func() {
		w.Write(data)
		w.Write([]byte("\n"))
		w.Close()
	}()
	return r, nil
}

// findBinary locates the cracknet-cli binary.
func findBinary() string {
	// Check PATH first
	if path, err := exec.LookPath("cracknet-cli"); err == nil {
		return path
	}
	// Fall back to development build path
	return "crates/target/release/cracknet-cli"
}
