package token

import (
	"crypto/sha256"
	"encoding/hex"
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
		role, ok := store.Verify(test.token)
		if ok != test.ok || (ok && role != test.role) {
			t.Fatalf("token %q: expected (%d, %t), got (%d, %t)", test.token, test.role, test.ok, role, ok)
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

	role, ok := store.Verify("secret")
	if !ok || role != domain.RoleReadWrite {
		t.Fatalf("expected write token, got (%d, %t)", role, ok)
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
