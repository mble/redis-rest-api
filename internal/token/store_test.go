package token

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/mble/redis-rest-api/internal/domain"
)

const testMaxTokenBytes = 4096

func TestRawTokens(t *testing.T) {
	store, err := Load("", "write", "read")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		token string
		role  domain.Role
		ok    bool
	}{
		{token: "write", role: domain.RoleReadWrite, ok: true},
		{token: "read", role: domain.RoleReadOnly, ok: true},
		{token: "wrong", ok: false},
		{token: "", ok: false},
	}

	for _, test := range tests {
		principal, ok := store.Verify(test.token)
		if ok != test.ok || (ok && principal.Role != test.role) {
			t.Fatalf("token %q: expected (%d, %t), got (%#v, %t)", test.token, test.role, test.ok, principal, ok)
		}
	}
}

func TestTokenFile(t *testing.T) {
	hash := sha256.Sum256([]byte("secret"))
	body := []byte(`{"standard":{"role":"rw","tokenSHA":"` + hex.EncodeToString(hash[:]) + `"}}`)
	path := filepath.Join(t.TempDir(), "tokens.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}

	store, err := Load(path, "", "")
	if err != nil {
		t.Fatal(err)
	}

	principal, ok := store.Verify("secret")
	if !ok || principal.Role != domain.RoleReadWrite || principal.ID != "standard" {
		t.Fatalf("unexpected principal: (%#v, %t)", principal, ok)
	}
}

func TestInvalidTokenFile(t *testing.T) {
	tests := []string{
		`{"user":{"role":"admin","tokenSHA":"00"}}`,
		`{"user":{"role":"rw","tokenSHA":"00"}}`,
		`{"user":{"role":"rw","tokenSHA":"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"}}`,
	}

	for _, body := range tests {
		path := filepath.Join(t.TempDir(), "tokens.json")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}

		if _, err := Load(path, "", ""); err == nil {
			t.Fatalf("expected %s to fail", body)
		}
	}
}

func TestNoTokens(t *testing.T) {
	if _, err := Load("", "", ""); err == nil {
		t.Fatal("expected missing token error")
	}
}

func TestDuplicateTokens(t *testing.T) {
	if _, err := Load("", "same", "same"); err == nil {
		t.Fatal("expected duplicate token error")
	}
}

func TestRejectsOversizedRawToken(t *testing.T) {
	token := string(make([]byte, testMaxTokenBytes+1))
	if _, err := Load("", token, ""); err == nil {
		t.Fatal("expected oversized token error")
	}
}

func BenchmarkVerify(b *testing.B) {
	for _, size := range []int{2, 100, 1000, 10000} {
		b.Run(fmt.Sprintf("tokens_%d", size), func(b *testing.B) {
			store := benchmarkStore(b, size)
			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				store.Verify("missing-token")
			}
		})
	}
}

func benchmarkStore(b *testing.B, size int) *Store {
	b.Helper()

	disk := make(map[string]diskEntry, size)
	for index := range size {
		raw := fmt.Sprintf("token-%d", index)
		hash := sha256.Sum256([]byte(raw))
		disk[raw] = diskEntry{Role: "rw", Hash: hex.EncodeToString(hash[:])}
	}

	body, err := json.Marshal(disk)
	if err != nil {
		b.Fatal(err)
	}
	path := filepath.Join(b.TempDir(), "tokens.json")
	if writeErr := os.WriteFile(path, body, 0o600); writeErr != nil {
		b.Fatal(writeErr)
	}

	store, err := Load(path, "", "")
	if err != nil {
		b.Fatal(err)
	}

	return store
}
