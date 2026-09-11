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
	principals map[[sha256.Size]byte]domain.Principal
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

		entries = append(entries, makeEntry(standardID, domain.RoleReadWrite, standard))
	}

	if readOnly != "" {
		if err := validateRaw(readOnly); err != nil {
			return nil, fmt.Errorf("read-only token: %w", err)
		}

		entries = append(entries, makeEntry(readOnlyID, domain.RoleReadOnly, readOnly))
	}

	if len(entries) == 0 {
		return nil, errors.New("no REST tokens configured")
	}

	principals := make(map[[sha256.Size]byte]domain.Principal, len(entries))
	for _, candidate := range entries {
		if _, exists := principals[candidate.hash]; exists {
			return nil, errors.New("duplicate REST token")
		}

		principals[candidate.hash] = candidate.principal
	}

	return &Store{principals: principals}, nil
}

func (s *Store) Verify(raw string) (domain.Principal, bool) {
	if len(raw) > maxTokenBytes {
		return domain.Principal{}, false
	}

	hash := sha256.Sum256([]byte(raw))
	principal, found := s.principals[hash]

	return principal, found
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
		parsed, err := parseEntry(name, value)
		if err != nil {
			return nil, fmt.Errorf("token %q: %w", name, err)
		}

		entries = append(entries, parsed)
	}

	return entries, nil
}

func parseEntry(id string, value diskEntry) (entry, error) {
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
