package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

const (
	defaultOutput = "redis-users.json"
	tokenBytes    = 32
	privateFile   = 0o600
)

type writeMode uint8

const (
	writeNew writeMode = iota
	writeReplace
)

type user struct {
	Role string `json:"role"`
	Hash string `json:"tokenSHA"`
}

func main() {
	output := flag.String("output", defaultOutput, "output token file")
	force := flag.Bool("force", false, "replace the output file")
	flag.Parse()

	if flag.NArg() != 0 {
		fail(fmt.Errorf("unexpected arguments: %v", flag.Args()))
	}

	standard, err := newToken()
	if err != nil {
		fail(err)
	}

	readOnly, err := newToken()
	if err != nil {
		fail(err)
	}

	users := map[string]user{
		"standard": {
			Role: "rw",
			Hash: hashToken(standard),
		},
		"readonly": {
			Role: "ro",
			Hash: hashToken(readOnly),
		},
	}

	body, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		fail(err)
	}
	body = append(body, '\n')

	mode := writeNew
	if *force {
		mode = writeReplace
	}

	if err := writeFile(*output, body, mode); err != nil {
		fail(err)
	}

	_, _ = fmt.Fprintf(os.Stdout, "standard:%s\nreadonly:%s\n", standard, readOnly)
}

func newToken() (string, error) {
	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}

	return hex.EncodeToString(raw), nil
}

func hashToken(raw string) string {
	hash := sha256.Sum256([]byte(raw))

	return hex.EncodeToString(hash[:])
}

func writeFile(path string, body []byte, mode writeMode) error {
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if mode == writeReplace {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}

	file, err := os.OpenFile(path, flags, privateFile) // #nosec G304 -- The CLI user selects this output.
	if err != nil {
		return fmt.Errorf("open token file: %w", err)
	}

	if _, err := file.Write(body); err != nil {
		_ = file.Close()

		return fmt.Errorf("write token file: %w", err)
	}

	if err := file.Close(); err != nil {
		return fmt.Errorf("close token file: %w", err)
	}

	return nil
}

func fail(err error) {
	_, _ = fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
