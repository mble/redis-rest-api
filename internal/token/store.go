package token

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync/atomic"

	"github.com/mble/redis-rest-api/internal/domain"
)

const (
	sha256HexLen      = sha256.Size * 2
	defaultTokenKinds = 2
	maxTokenBytes     = 4096
	maxTokenFileBytes = 1 << 20
	maxTokenEntries   = 10_000
	maxTokenIDBytes   = 128
	standardID        = "standard"
	readOnlyID        = "readonly"
)

type diskEntry struct {
	Role string `json:"role"`
	Hash string `json:"tokenSHA"`
}

type entry struct {
	principal domain.Principal
	hash      [sha256.Size]byte
}

type Store struct {
	path    string
	static  []entry
	current atomic.Pointer[snapshot]
}

type snapshot struct {
	principals map[[sha256.Size]byte]domain.Principal
}

func Load(path, standard, readOnly string) (*Store, error) {
	static := make([]entry, 0, defaultTokenKinds)

	if standard != "" {
		if err := validateRaw(standard); err != nil {
			return nil, fmt.Errorf("standard token: %w", err)
		}

		static = append(static, makeEntry(standardID, domain.RoleReadWrite, standard))
	}

	if readOnly != "" {
		if err := validateRaw(readOnly); err != nil {
			return nil, fmt.Errorf("read-only token: %w", err)
		}

		static = append(static, makeEntry(readOnlyID, domain.RoleReadOnly, readOnly))
	}

	current, err := loadSnapshot(path, static)
	if err != nil {
		return nil, err
	}

	store := &Store{path: path, static: static}
	store.current.Store(current)

	return store, nil
}

func loadSnapshot(path string, static []entry) (*snapshot, error) {
	entries := make([]entry, 0, len(static)+defaultTokenKinds)
	entries = append(entries, static...)

	if path != "" {
		fileEntries, err := loadFile(path)
		if err != nil {
			return nil, err
		}

		entries = append(entries, fileEntries...)
	}
	if len(entries) == 0 {
		return nil, errors.New("no REST tokens configured")
	}
	if len(entries) > maxTokenEntries {
		return nil, fmt.Errorf("REST tokens exceed limit of %d", maxTokenEntries)
	}

	principals := make(map[[sha256.Size]byte]domain.Principal, len(entries))
	for _, candidate := range entries {
		if _, exists := principals[candidate.hash]; exists {
			return nil, errors.New("duplicate REST token")
		}

		principals[candidate.hash] = candidate.principal
	}

	return &snapshot{principals: principals}, nil
}

func (s *Store) Verify(raw string) (domain.Principal, bool) {
	if len(raw) > maxTokenBytes {
		return domain.Principal{}, false
	}

	hash := sha256.Sum256([]byte(raw))
	principal, found := s.current.Load().principals[hash]

	return principal, found
}

func (s *Store) Reload() error {
	// Publish only a complete, validated replacement.
	next, err := loadSnapshot(s.path, s.static)
	if err != nil {
		return err
	}

	s.current.Store(next)

	return nil
}

func validateRaw(raw string) error {
	if len(raw) > maxTokenBytes {
		return fmt.Errorf("must not exceed %d bytes", maxTokenBytes)
	}

	return nil
}

func loadFile(path string) ([]entry, error) {
	file, err := os.Open(path) // #nosec G304 -- The operator configures this path.
	if err != nil {
		return nil, fmt.Errorf("read token file: %w", err)
	}
	defer file.Close()

	raw, err := io.ReadAll(io.LimitReader(file, maxTokenFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read token file: %w", err)
	}
	if len(raw) > maxTokenFileBytes {
		return nil, fmt.Errorf("token file exceeds %d bytes", maxTokenFileBytes)
	}

	disk := map[string]diskEntry{}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&disk); err != nil {
		return nil, fmt.Errorf("decode token file: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("decode token file: trailing JSON value")
	}
	if len(disk) > maxTokenEntries {
		return nil, fmt.Errorf("token file entries exceed limit of %d", maxTokenEntries)
	}

	entries := make([]entry, 0, len(disk))
	for name, value := range disk {
		parsed, err := parseEntry(name, value)
		if err != nil {
			return nil, fmt.Errorf("token %q: %w", name, err)
		}

		entries = append(entries, parsed)
	}

	return entries, nil
}

func parseEntry(id string, value diskEntry) (entry, error) {
	if strings.TrimSpace(id) == "" {
		return entry{}, errors.New("token name must not be blank")
	}
	if len(id) > maxTokenIDBytes {
		return entry{}, fmt.Errorf("token name must not exceed %d bytes", maxTokenIDBytes)
	}

	role, err := parseRole(value.Role)
	if err != nil {
		return entry{}, err
	}

	if len(value.Hash) != sha256HexLen {
		return entry{}, fmt.Errorf("tokenSHA must contain %d hex characters", sha256HexLen)
	}

	decoded, err := hex.DecodeString(value.Hash)
	if err != nil {
		return entry{}, errors.New("tokenSHA must be hexadecimal")
	}

	parsed := entry{principal: domain.Principal{ID: id, Role: role}}
	copy(parsed.hash[:], decoded)

	return parsed, nil
}

func parseRole(raw string) (domain.Role, error) {
	switch raw {
	case "rw":
		return domain.RoleReadWrite, nil
	case "ro":
		return domain.RoleReadOnly, nil
	default:
		return 0, fmt.Errorf("invalid role %q", raw)
	}
}

func makeEntry(id string, role domain.Role, raw string) entry {
	return entry{
		principal: domain.Principal{ID: id, Role: role},
		hash:      sha256.Sum256([]byte(raw)),
	}
}
