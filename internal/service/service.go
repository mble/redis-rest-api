package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/mble/redis-rest-api/internal/domain"
	"github.com/mble/redis-rest-api/internal/token"
)

const (
	maxCommandArgs = 1024
	monitorName    = "monitor"
	psubscribeName = "psubscribe"
	subscribeName  = "subscribe"
)

var unsupported = map[string]struct{}{
	"asking":       {},
	"auth":         {},
	"client":       {},
	"cluster":      {},
	"discard":      {},
	"exec":         {},
	"hello":        {},
	"multi":        {},
	psubscribeName: {},
	"punsubscribe": {},
	"quit":         {},
	"readonly":     {},
	"readwrite":    {},
	"reset":        {},
	"select":       {},
	"ssubscribe":   {},
	subscribeName:  {},
	"sunsubscribe": {},
	"unsubscribe":  {},
	"unwatch":      {},
	"watch":        {},
	monitorName:    {},
}

var costlyReads = map[string]struct{}{
	"keys": {},
	"scan": {},
}

var supportedConnection = map[string]struct{}{
	"command": {},
	"echo":    {},
	"ping":    {},
}

var readOnlyConnection = map[string]struct{}{
	"echo": {},
	"ping": {},
}

// Permit read-oriented server inspection without exposing administration.
var supportedAdmin = map[string]struct{}{
	"command":  {},
	"dbsize":   {},
	"info":     {},
	"lastsave": {},
	"memory":   {},
	"role":     {},
	"time":     {},
}

// These commands control the backing Redis process, not REST data.
var unsafeServer = map[string]struct{}{
	"bgrewriteaof": {},
	"bgsave":       {},
	"debug":        {},
	"failover":     {},
	"migrate":      {},
	"module":       {},
	"psync":        {},
	"replconf":     {},
	"replicaof":    {},
	"save":         {},
	"shutdown":     {},
	"slaveof":      {},
	"swapdb":       {},
	"sync":         {},
}

type Service struct {
	store   domain.Store
	tokens  *token.Store
	catalog map[string]domain.CommandInfo
}

func New(store domain.Store, tokens *token.Store, catalog map[string]domain.CommandInfo) *Service {
	return &Service{
		store:   store,
		tokens:  tokens,
		catalog: catalog,
	}
}

func (s *Service) Exec(ctx context.Context, rawToken string, cmd domain.Command) (any, error) {
	role, err := s.role(rawToken)
	if err != nil {
		return nil, err
	}

	if allowErr := s.allow(role, cmd); allowErr != nil {
		return nil, allowErr
	}

	return s.store.Exec(ctx, cmd)
}

func (s *Service) ExecRaw(ctx context.Context, rawToken string, cmd domain.Command) ([]byte, error) {
	role, err := s.role(rawToken)
	if err != nil {
		return nil, err
	}

	if allowErr := s.allow(role, cmd); allowErr != nil {
		return nil, allowErr
	}

	return s.store.ExecRaw(ctx, cmd)
}

func (s *Service) Batch(
	ctx context.Context,
	rawToken string,
	commands []domain.Command,
	mode domain.BatchMode,
) ([]domain.Reply, error) {
	role, err := s.role(rawToken)
	if err != nil {
		return nil, err
	}

	if len(commands) == 0 {
		return nil, fmt.Errorf("%w: command list is empty", domain.ErrInvalid)
	}

	if mode == domain.BatchTransaction {
		return s.transaction(ctx, role, commands)
	}

	return s.pipeline(ctx, role, commands)
}

func (s *Service) BatchRaw(
	ctx context.Context,
	rawToken string,
	commands []domain.Command,
) ([]domain.Reply, error) {
	role, err := s.role(rawToken)
	if err != nil {
		return nil, err
	}

	if len(commands) == 0 {
		return nil, fmt.Errorf("%w: command list is empty", domain.ErrInvalid)
	}

	replies := make([]domain.Reply, len(commands))
	valid := make([]domain.Command, 0, len(commands))
	indices := make([]int, 0, len(commands))

	for index, cmd := range commands {
		if allowErr := s.allow(role, cmd); allowErr != nil {
			replies[index].Err = allowErr
			continue
		}

		valid = append(valid, cmd)
		indices = append(indices, index)
	}

	if len(valid) == 0 {
		return replies, nil
	}

	results, err := s.store.BatchRaw(ctx, valid)
	if err != nil {
		return nil, err
	}

	if len(results) != len(valid) {
		return nil, fmt.Errorf("%w: pipeline returned %d of %d replies", domain.ErrUnavailable, len(results), len(valid))
	}

	for index, result := range results {
		replies[indices[index]] = result
	}

	return replies, nil
}

func (s *Service) Ping(ctx context.Context) error {
	return s.store.Ping(ctx)
}

func (s *Service) Subscribe(
	ctx context.Context,
	rawToken string,
	channels []string,
	mode domain.SubscriptionMode,
) (domain.Subscription, error) {
	role, err := s.role(rawToken)
	if err != nil {
		return nil, err
	}

	if len(channels) == 0 {
		return nil, fmt.Errorf("%w: SUBSCRIBE requires a channel", domain.ErrInvalid)
	}

	name, err := subscriptionName(mode)
	if err != nil {
		return nil, err
	}

	if _, err := s.require(role, name); err != nil {
		return nil, err
	}

	return s.store.Subscribe(ctx, channels, mode)
}

func (s *Service) Monitor(ctx context.Context, rawToken string) (domain.Monitor, error) {
	role, err := s.role(rawToken)
	if err != nil {
		return nil, err
	}

	if role != domain.RoleReadWrite {
		return nil, permissionError(monitorName)
	}

	if _, err := s.require(role, monitorName); err != nil {
		return nil, err
	}

	return s.store.Monitor(ctx)
}

func (s *Service) pipeline(
	ctx context.Context,
	role domain.Role,
	commands []domain.Command,
) ([]domain.Reply, error) {
	replies := make([]domain.Reply, len(commands))
	valid := make([]domain.Command, 0, len(commands))
	indices := make([]int, 0, len(commands))

	for index, cmd := range commands {
		if allowErr := s.allow(role, cmd); allowErr != nil {
			replies[index].Err = allowErr
			continue
		}

		valid = append(valid, cmd)
		indices = append(indices, index)
	}

	if len(valid) == 0 {
		return replies, nil
	}

	results, err := s.store.Batch(ctx, valid, domain.BatchPipeline)
	if err != nil {
		return nil, err
	}

	if len(results) != len(valid) {
		return nil, fmt.Errorf("%w: pipeline returned %d of %d replies", domain.ErrUnavailable, len(results), len(valid))
	}

	for index, result := range results {
		replies[indices[index]] = result
	}

	return replies, nil
}

func (s *Service) transaction(
	ctx context.Context,
	role domain.Role,
	commands []domain.Command,
) ([]domain.Reply, error) {
	for _, cmd := range commands {
		if allowErr := s.allow(role, cmd); allowErr != nil {
			return nil, allowErr
		}
	}

	return s.store.Batch(ctx, commands, domain.BatchTransaction)
}

func (s *Service) role(rawToken string) (domain.Role, error) {
	role, ok := s.tokens.Verify(rawToken)
	if !ok {
		return 0, domain.ErrUnauthorized
	}

	return role, nil
}

func (s *Service) allow(role domain.Role, cmd domain.Command) error {
	name, err := commandName(cmd)
	if err != nil {
		return err
	}

	info, err := s.require(role, name)
	if err != nil {
		return err
	}

	if _, blocked := unsupported[name]; blocked {
		return unsupportedError(name)
	}
	if _, blocked := unsafeServer[name]; blocked {
		return unsupportedError(name)
	}

	if unsupportedCategory(name, info.ACL) {
		return unsupportedError(name)
	}

	if hasFlag(info.Flags, "blocking") && blocks(cmd) {
		return unsupportedError(name)
	}

	if role != domain.RoleReadOnly {
		return nil
	}

	if _, allowed := readOnlyConnection[name]; allowed {
		return nil
	}

	if !info.ReadOnly {
		return permissionError(name)
	}

	if _, costly := costlyReads[name]; costly {
		return permissionError(name)
	}

	return nil
}

func (s *Service) require(role domain.Role, name string) (domain.CommandInfo, error) {
	info, ok := s.catalog[name]
	if ok {
		return info, nil
	}

	if name == subscribeName || name == psubscribeName || name == monitorName {
		return domain.CommandInfo{ReadOnly: name != monitorName}, nil
	}

	if role == domain.RoleReadOnly {
		return domain.CommandInfo{}, permissionError(name)
	}

	return domain.CommandInfo{}, unsupportedError(name)
}

func subscriptionName(mode domain.SubscriptionMode) (string, error) {
	switch mode {
	case domain.SubscriptionChannel:
		return subscribeName, nil
	case domain.SubscriptionPattern:
		return psubscribeName, nil
	default:
		return "", fmt.Errorf("%w: unknown subscription mode", domain.ErrInvalid)
	}
}

func commandName(cmd domain.Command) (string, error) {
	if len(cmd) == 0 {
		return "", fmt.Errorf("%w: command is empty", domain.ErrInvalid)
	}

	if len(cmd) > maxCommandArgs {
		return "", fmt.Errorf("%w: command exceeds %d arguments", domain.ErrInvalid, maxCommandArgs)
	}

	raw, ok := cmd[0].(string)
	if !ok || strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("%w: command name must be a string", domain.ErrInvalid)
	}

	return strings.ToLower(raw), nil
}

func blocks(cmd domain.Command) bool {
	name, err := commandName(cmd)
	if err != nil {
		return true
	}

	if name != "xread" && name != "xreadgroup" {
		return true
	}

	for _, arg := range cmd[1:] {
		value, ok := arg.(string)
		if ok && strings.EqualFold(value, "block") {
			return true
		}
	}

	return false
}

func hasFlag(flags []string, target string) bool {
	for _, flag := range flags {
		if strings.EqualFold(flag, target) {
			return true
		}
	}

	return false
}

func unsupportedCategory(name string, categories []string) bool {
	for _, category := range categories {
		switch strings.ToLower(category) {
		case "@cluster", "@transaction":
			return true
		case "@connection":
			_, allowed := supportedConnection[name]
			if !allowed {
				return true
			}
		case "@admin":
			_, allowed := supportedAdmin[name]
			if !allowed {
				return true
			}
		}
	}

	return false
}

func permissionError(name string) error {
	return fmt.Errorf("NOPERM this user has no permissions to run the '%s' command", name)
}

func unsupportedError(name string) error {
	return fmt.Errorf("ERR command '%s' is not supported", name)
}
