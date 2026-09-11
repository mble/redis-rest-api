package token

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/mble/redis-rest-api/internal/domain"
)

const (
	sha256HexLen      = sha256.Size * 2
	defaultTokenKinds = 2
	maxTokenBytes     = 4096
)

type diskEntry struct {
	Role string `json:"role"`
	Hash string `json:"tokenSHA"`
}

type entry struct {
	role domain.Role
	hash [sha256.Size]byte
}

type Store struct {
	roles map[[sha256.Size]byte]domain.Role
}

func Load(path, standard, readOnly string) (*Store, error) {
	entries := make([]entry, 0, defaultTokenKinds)

	if path != "" {
		fileEntries, err := loadFile(path)
		if err != nil {
			return nil, err
		}

		entries = append(entries, fileEntries...)
	}

	if standard != "" {
		if err := validateRaw(standard); err != nil {
			return nil, fmt.Errorf("standard token: %w", err)
		}

		entries = append(entries, makeEntry(domain.RoleReadWrite, standard))
	}

	if readOnly != "" {
		if err := validateRaw(readOnly); err != nil {
			return nil, fmt.Errorf("read-only token: %w", err)
		}

		entries = append(entries, makeEntry(domain.RoleReadOnly, readOnly))
	}

	if len(entries) == 0 {
		return nil, errors.New("no REST tokens configured")
	}

	roles := make(map[[sha256.Size]byte]domain.Role, len(entries))
	for _, candidate := range entries {
		if _, exists := roles[candidate.hash]; exists {
			return nil, errors.New("duplicate REST token")
		}

		roles[candidate.hash] = candidate.role
	}

	return &Store{roles: roles}, nil
}

func (s *Store) Verify(raw string) (domain.Role, bool) {
	if len(raw) > maxTokenBytes {
		return 0, false
	}

	hash := sha256.Sum256([]byte(raw))
	role, found := s.roles[hash]

	return role, found
}

func validateRaw(raw string) error {
	if len(raw) > maxTokenBytes {
		return fmt.Errorf("must not exceed %d bytes", maxTokenBytes)
	}

	return nil
}

func loadFile(path string) ([]entry, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- The operator configures this path.
	if err != nil {
		return nil, fmt.Errorf("read token file: %w", err)
	}

	disk := map[string]diskEntry{}
	if err := json.Unmarshal(raw, &disk); err != nil {
		return nil, fmt.Errorf("decode token file: %w", err)
	}

	entries := make([]entry, 0, len(disk))
	for name, value := range disk {
		parsed, err := parseEntry(value)
		if err != nil {
			return nil, fmt.Errorf("token %q: %w", name, err)
		}

		entries = append(entries, parsed)
	}

	return entries, nil
}

func parseEntry(value diskEntry) (entry, error) {
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

	parsed := entry{role: role}
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

func makeEntry(role domain.Role, raw string) entry {
	return entry{
		role: role,
		hash: sha256.Sum256([]byte(raw)),
	}
}
