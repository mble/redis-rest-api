package service

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/mble/redis-rest-api/internal/domain"
	"github.com/mble/redis-rest-api/internal/token"
)

const (
	writeToken = "write-token-for-tests-0123456789abcdef"
	readToken  = "read-token-for-tests-0123456789abcdef"
)

type fakeStore struct {
	executed  []domain.Command
	batchMode domain.BatchMode
	batchCall int
	replies   []domain.Reply
}

func (f *fakeStore) Exec(_ context.Context, command domain.Command) (any, error) {
	f.executed = append(f.executed, command)

	return "OK", nil
}

func (f *fakeStore) ExecRaw(_ context.Context, command domain.Command) ([]byte, error) {
	f.executed = append(f.executed, command)

	return []byte("+OK\r\n"), nil
}

func (f *fakeStore) Batch(
	_ context.Context,
	commands []domain.Command,
	mode domain.BatchMode,
) ([]domain.Reply, error) {
	f.executed = append(f.executed, commands...)
	f.batchMode = mode
	f.batchCall++

	if f.replies != nil {
		return f.replies, nil
	}

	replies := make([]domain.Reply, len(commands))
	for index, command := range commands {
		replies[index].Value = command[0]
	}

	return replies, nil
}

func (f *fakeStore) BatchRaw(_ context.Context, commands []domain.Command) ([]domain.Reply, error) {
	f.executed = append(f.executed, commands...)
	f.batchCall++

	replies := make([]domain.Reply, len(commands))
	for index := range commands {
		replies[index].Value = []byte("+OK\r\n")
	}

	return replies, nil
}

func (f *fakeStore) Catalog(context.Context) (map[string]domain.CommandInfo, error) {
	return nil, nil
}

func (f *fakeStore) Ping(context.Context) error {
	return nil
}

func (f *fakeStore) Subscribe(
	context.Context,
	[]string,
	domain.SubscriptionMode,
) (domain.Subscription, error) {
	return nil, errors.New("not implemented")
}

func (f *fakeStore) Monitor(context.Context) (domain.Monitor, error) {
	return nil, errors.New("not implemented")
}

func (f *fakeStore) Close() error {
	return nil
}

func TestExecPolicy(t *testing.T) {
	tests := []struct {
		name      string
		token     string
		command   domain.Command
		wantError string
	}{
		{name: "write", token: writeToken, command: domain.Command{"SET", "key", "value"}},
		{name: "read", token: readToken, command: domain.Command{"GET", "key"}},
		{name: "read denies write", token: readToken, command: domain.Command{"SET", "key", "value"}, wantError: "NOPERM"},
		{name: "read denies scan", token: readToken, command: domain.Command{"SCAN", 0}, wantError: "NOPERM"},
		{name: "unsupported connection", token: writeToken, command: domain.Command{"AUTH", "secret"}, wantError: "not supported"},
		{name: "command exception", token: writeToken, command: domain.Command{"COMMAND"}},
		{name: "unsafe server command", token: writeToken, command: domain.Command{"SHUTDOWN"}, wantError: "not supported"},
		{name: "future admin command", token: writeToken, command: domain.Command{"FUTUREADMIN"}, wantError: "not supported"},
		{name: "admin command", token: writeToken, command: domain.Command{"CONFIG", "GET", "*"}, wantError: "not supported"},
		{name: "server inspection", token: writeToken, command: domain.Command{"INFO"}},
		{name: "ping exception", token: readToken, command: domain.Command{"PING"}},
		{name: "echo exception", token: readToken, command: domain.Command{"ECHO", "value"}},
		{name: "unknown", token: writeToken, command: domain.Command{"NOPE"}, wantError: "not supported"},
		{name: "missing token", command: domain.Command{"GET", "key"}, wantError: domain.ErrUnauthorized.Error()},
		{name: "empty", token: writeToken, command: nil, wantError: "command is empty"},
		{name: "non-string name", token: writeToken, command: domain.Command{1}, wantError: "command name"},
		{name: "nonblocking xread", token: readToken, command: domain.Command{"XREAD", "STREAMS", "events", "0"}},
		{name: "blocking xread", token: readToken, command: domain.Command{"XREAD", "BLOCK", 1, "STREAMS", "events", "$"}, wantError: "not supported"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &fakeStore{}
			service := newTestService(t, store)

			principal, err := service.Auth(test.token)
			if err == nil {
				_, err = service.Exec(t.Context(), principal, test.command)
			}
			if test.wantError == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if test.wantError != "" && (err == nil || !strings.Contains(err.Error(), test.wantError)) {
				t.Fatalf("expected error containing %q, got %v", test.wantError, err)
			}
		})
	}
}

func TestAuthIdentity(t *testing.T) {
	service := newTestService(t, &fakeStore{})
	principal, err := service.Auth(writeToken)
	if err != nil {
		t.Fatal(err)
	}
	if principal.ID != "standard" || principal.Role != domain.RoleReadWrite {
		t.Fatalf("unexpected principal: %#v", principal)
	}
}

func TestPipelineSkipsRejectedCommands(t *testing.T) {
	store := &fakeStore{
		replies: []domain.Reply{
			{Value: "value"},
			{Value: int64(1)},
		},
	}
	service := newTestService(t, store)
	principal := mustAuth(t, service, writeToken)
	commands := []domain.Command{
		{"GET", "key"},
		{"AUTH", "secret"},
		{"SET", "key", "value"},
	}

	replies, err := service.Batch(t.Context(), principal, commands, domain.BatchPipeline)
	if err != nil {
		t.Fatal(err)
	}

	if len(replies) != len(commands) {
		t.Fatalf("expected %d replies, got %d", len(commands), len(replies))
	}
	if replies[1].Err == nil || !strings.Contains(replies[1].Err.Error(), "not supported") {
		t.Fatalf("expected rejected middle command, got %#v", replies[1])
	}

	wantExecuted := []domain.Command{commands[0], commands[2]}
	if !reflect.DeepEqual(store.executed, wantExecuted) {
		t.Fatalf("expected commands %#v, got %#v", wantExecuted, store.executed)
	}
}

func TestTransactionRejectsBeforeRedis(t *testing.T) {
	store := &fakeStore{}
	service := newTestService(t, store)
	principal := mustAuth(t, service, writeToken)
	commands := []domain.Command{
		{"SET", "key", "value"},
		{"AUTH", "secret"},
	}

	_, err := service.Batch(t.Context(), principal, commands, domain.BatchTransaction)
	if err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("expected unsupported error, got %v", err)
	}
	if store.batchCall != 0 {
		t.Fatalf("expected no Redis batch, got %d", store.batchCall)
	}
}

func newTestService(t *testing.T, store domain.Store) *Service {
	t.Helper()

	tokens, err := token.Load("", writeToken, readToken)
	if err != nil {
		t.Fatal(err)
	}

	catalog := map[string]domain.CommandInfo{
		"auth":        {},
		"command":     {ACL: []string{"@connection"}},
		"config":      {ACL: []string{"@admin"}},
		"echo":        {ACL: []string{"@connection"}},
		"futureadmin": {ACL: []string{"@admin"}},
		"get":         {ReadOnly: true},
		"info":        {ReadOnly: true, ACL: []string{"@admin"}},
		"ping":        {ACL: []string{"@connection"}},
		"scan":        {ReadOnly: true},
		"set":         {ReadOnly: false},
		"shutdown":    {ACL: []string{"@dangerous"}},
		"xread":       {ReadOnly: true, Flags: []string{"readonly", "blocking"}},
	}

	return New(store, tokens, catalog)
}

func mustAuth(t *testing.T, service *Service, raw string) domain.Principal {
	t.Helper()

	principal, err := service.Auth(raw)
	if err != nil {
		t.Fatal(err)
	}

	return principal
}
