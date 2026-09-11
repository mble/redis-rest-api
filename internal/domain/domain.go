package domain

import (
	"context"
	"errors"
)

var (
	ErrInvalid      = errors.New("invalid request")
	ErrUnauthorized = errors.New("unauthorized")
	ErrUnavailable  = errors.New("redis unavailable")
)

type Role uint8

const (
	RoleReadWrite Role = iota
	RoleReadOnly
)

type Principal struct {
	ID   string
	Role Role
}

type BatchMode uint8

const (
	BatchPipeline BatchMode = iota
	BatchTransaction
)

type SubscriptionMode uint8

const (
	SubscriptionChannel SubscriptionMode = iota
	SubscriptionPattern
)

type Command []any

type Reply struct {
	Value any
	Err   error
}

type CommandInfo struct {
	ReadOnly bool
	Flags    []string
	ACL      []string
}

type Event struct {
	Kind    string
	Channel string
	Pattern string
	Payload string
	Count   int
}

type Subscription interface {
	Events() <-chan Event
	Errors() <-chan error
	Close() error
}

type Monitor interface {
	Lines() <-chan string
	Errors() <-chan error
	Close() error
}

type Store interface {
	Exec(context.Context, Command) (any, error)
	ExecRaw(context.Context, Command) ([]byte, error)
	Batch(context.Context, []Command, BatchMode) ([]Reply, error)
	BatchRaw(context.Context, []Command) ([]Reply, error)
	Catalog(context.Context) (map[string]CommandInfo, error)
	Ping(context.Context) error
	Subscribe(context.Context, []string, SubscriptionMode) (Subscription, error)
	Monitor(context.Context) (Monitor, error)
	Close() error
}
