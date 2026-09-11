package redisdb

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mble/redis-rest-api/internal/domain"
	"github.com/redis/go-redis/v9"
)

const (
	defaultHandshakeTimeout = 3 * time.Second
	streamBuffer            = 16
)

type Client struct {
	redis *redis.Client
	opts  *redis.Options
}

func New(opts *redis.Options) *Client {
	cloned := *opts
	cloned.Protocol = 2
	if opts.TLSConfig != nil {
		cloned.TLSConfig = opts.TLSConfig.Clone()
	}

	return &Client{
		redis: redis.NewClient(&cloned),
		opts:  &cloned,
	}
}

func (c *Client) Exec(ctx context.Context, command domain.Command) (any, error) {
	value, err := c.redis.Do(ctx, command...).Result()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}

	return value, classify(err)
}

func (c *Client) ExecRaw(ctx context.Context, command domain.Command) ([]byte, error) {
	value, err := c.redis.DoRaw(ctx, command...).Result()

	return value, classify(err)
}

func (c *Client) Batch(
	ctx context.Context,
	commands []domain.Command,
	mode domain.BatchMode,
) ([]domain.Reply, error) {
	queue := func(pipe redis.Pipeliner) error {
		for _, command := range commands {
			pipe.Do(ctx, command...)
		}

		return nil
	}

	var (
		results []redis.Cmder
		err     error
	)

	switch mode {
	case domain.BatchPipeline:
		results, err = c.redis.Pipelined(ctx, queue)
	case domain.BatchTransaction:
		results, err = c.redis.TxPipelined(ctx, queue)
	default:
		return nil, fmt.Errorf("%w: unknown batch mode", domain.ErrInvalid)
	}

	if err != nil && !isCommandError(err) {
		return nil, classify(err)
	}

	if len(results) != len(commands) {
		return nil, fmt.Errorf("%w: Redis returned %d of %d replies", domain.ErrUnavailable, len(results), len(commands))
	}

	replies := make([]domain.Reply, len(results))
	for index, result := range results {
		command, ok := result.(*redis.Cmd)
		if !ok {
			return nil, fmt.Errorf("%w: unexpected parsed reply %T", domain.ErrUnavailable, result)
		}

		value, resultErr := command.Result()
		if errors.Is(resultErr, redis.Nil) {
			resultErr = nil
			value = nil
		}

		replies[index] = domain.Reply{
			Value: value,
			Err:   classify(resultErr),
		}
	}

	return replies, nil
}

func (c *Client) BatchRaw(ctx context.Context, commands []domain.Command) ([]domain.Reply, error) {
	results, err := c.redis.Pipelined(ctx, func(pipe redis.Pipeliner) error {
		for _, command := range commands {
			raw := redis.NewRawCmd(ctx, command...)
			if err := pipe.Process(ctx, raw); err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil && !isCommandError(err) {
		return nil, classify(err)
	}

	if len(results) != len(commands) {
		return nil, fmt.Errorf("%w: Redis returned %d of %d replies", domain.ErrUnavailable, len(results), len(commands))
	}

	replies := make([]domain.Reply, len(results))
	for index, result := range results {
		command, ok := result.(*redis.RawCmd)
		if !ok {
			return nil, fmt.Errorf("%w: unexpected raw reply %T", domain.ErrUnavailable, result)
		}

		value, resultErr := command.Result()
		replies[index] = domain.Reply{
			Value: value,
			Err:   classify(resultErr),
		}
	}

	return replies, nil
}

func (c *Client) Catalog(ctx context.Context) (map[string]domain.CommandInfo, error) {
	commands, err := c.redis.Command(ctx).Result()
	if err != nil {
		return nil, classify(err)
	}

	catalog := make(map[string]domain.CommandInfo, len(commands))
	for name, info := range commands {
		catalog[strings.ToLower(name)] = domain.CommandInfo{
			ReadOnly: info.ReadOnly,
			Flags:    append([]string(nil), info.Flags...),
			ACL:      append([]string(nil), info.ACLFlags...),
		}
	}

	return catalog, nil
}

func (c *Client) Ping(ctx context.Context) error {
	return classify(c.redis.Ping(ctx).Err())
}

func (c *Client) Subscribe(
	ctx context.Context,
	channels []string,
	mode domain.SubscriptionMode,
) (domain.Subscription, error) {
	var pubsub *redis.PubSub

	switch mode {
	case domain.SubscriptionChannel:
		pubsub = c.redis.Subscribe(ctx, channels...)
	case domain.SubscriptionPattern:
		pubsub = c.redis.PSubscribe(ctx, channels...)
	default:
		return nil, fmt.Errorf("%w: unknown subscription mode", domain.ErrInvalid)
	}

	streamCtx, cancel := context.WithCancel(ctx)
	stream := &subscription{
		pubsub: pubsub,
		events: make(chan domain.Event, streamBuffer),
		errors: make(chan error, 1),
		cancel: cancel,
	}

	go stream.receive(streamCtx)

	return stream, nil
}

func (c *Client) Monitor(ctx context.Context) (domain.Monitor, error) {
	conn, reader, err := c.monitorConn(ctx)
	if err != nil {
		return nil, err
	}

	streamCtx, cancel := context.WithCancel(ctx)
	stream := &monitor{
		conn:   conn,
		reader: reader,
		lines:  make(chan string, streamBuffer),
		errors: make(chan error, 1),
		cancel: cancel,
	}

	go stream.receive(streamCtx)

	return stream, nil
}

func (c *Client) Close() error {
	return c.redis.Close()
}

func classify(err error) error {
	if err == nil {
		return nil
	}

	if isCommandError(err) {
		return err
	}

	return fmt.Errorf("%w: %w", domain.ErrUnavailable, err)
}

func isCommandError(err error) bool {
	var redisErr redis.Error

	return errors.As(err, &redisErr)
}

type subscription struct {
	pubsub *redis.PubSub
	events chan domain.Event
	errors chan error
	cancel context.CancelFunc
	once   sync.Once
}

func (s *subscription) Events() <-chan domain.Event {
	return s.events
}

func (s *subscription) Errors() <-chan error {
	return s.errors
}

func (s *subscription) Close() error {
	var err error

	s.once.Do(func() {
		s.cancel()
		err = s.pubsub.Close()
	})

	return err
}

func (s *subscription) receive(ctx context.Context) {
	defer close(s.events)

	for {
		message, err := s.pubsub.Receive(ctx)
		if err != nil {
			if ctx.Err() == nil {
				s.sendError(classify(err))
			}

			return
		}

		event, ok := pubsubEvent(message)
		if !ok {
			continue
		}

		select {
		case s.events <- event:
		case <-ctx.Done():
			return
		}
	}
}

func (s *subscription) sendError(err error) {
	select {
	case s.errors <- err:
	default:
	}
}

func pubsubEvent(message any) (domain.Event, bool) {
	switch value := message.(type) {
	case *redis.Subscription:
		return domain.Event{
			Kind:    value.Kind,
			Channel: value.Channel,
			Count:   value.Count,
		}, true
	case *redis.Message:
		kind := "message"
		if value.Pattern != "" {
			kind = "pmessage"
		}

		return domain.Event{
			Kind:    kind,
			Channel: value.Channel,
			Pattern: value.Pattern,
			Payload: value.Payload,
		}, true
	default:
		return domain.Event{}, false
	}
}

type monitor struct {
	conn   net.Conn
	reader *bufio.Reader
	lines  chan string
	errors chan error
	cancel context.CancelFunc
	once   sync.Once
}

func (m *monitor) Lines() <-chan string {
	return m.lines
}

func (m *monitor) Errors() <-chan error {
	return m.errors
}

func (m *monitor) Close() error {
	var err error

	m.once.Do(func() {
		m.cancel()
		err = m.conn.Close()
	})

	return err
}

func (m *monitor) receive(ctx context.Context) {
	defer close(m.lines)

	for {
		line, err := readSimple(m.reader)
		if err != nil {
			if ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				m.sendError(classify(err))
			}

			return
		}

		select {
		case m.lines <- line:
		case <-ctx.Done():
			return
		}
	}
}

func (m *monitor) sendError(err error) {
	select {
	case m.errors <- err:
	default:
	}
}

func (c *Client) monitorConn(ctx context.Context) (net.Conn, *bufio.Reader, error) {
	conn, err := dial(ctx, c.opts)
	if err != nil {
		return nil, nil, classify(err)
	}

	fail := func(err error) (net.Conn, *bufio.Reader, error) {
		_ = conn.Close()

		return nil, nil, classify(err)
	}

	if err := setDeadline(ctx, conn, handshakeTimeout(c.opts)); err != nil {
		return fail(err)
	}

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	if c.opts.Password != "" {
		auth := []string{"AUTH", c.opts.Password}
		if c.opts.Username != "" && c.opts.Username != "default" {
			auth = []string{"AUTH", c.opts.Username, c.opts.Password}
		}

		if err := roundTrip(writer, reader, auth); err != nil {
			return fail(err)
		}
	}

	if c.opts.ClientName != "" {
		if err := roundTrip(writer, reader, []string{"CLIENT", "SETNAME", c.opts.ClientName + "-monitor"}); err != nil {
			return fail(err)
		}
	}

	if err := roundTrip(writer, reader, []string{"MONITOR"}); err != nil {
		return fail(err)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return fail(err)
	}

	return conn, reader, nil
}

func handshakeTimeout(opts *redis.Options) time.Duration {
	timeout := opts.ReadTimeout
	if timeout <= 0 {
		timeout = opts.WriteTimeout
	}
	if timeout <= 0 {
		timeout = opts.DialTimeout
	}
	if timeout <= 0 {
		timeout = defaultHandshakeTimeout
	}

	return timeout
}

func setDeadline(ctx context.Context, conn net.Conn, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}

	return conn.SetDeadline(deadline)
}

func dial(ctx context.Context, opts *redis.Options) (net.Conn, error) {
	network := opts.Network
	if network == "" {
		network = "tcp"
	}

	dialer := opts.Dialer
	if dialer == nil {
		dialer = redis.NewDialer(opts)
	}

	return dialer(ctx, network, opts.Addr)
}

func roundTrip(writer *bufio.Writer, reader *bufio.Reader, args []string) error {
	if err := writeCommand(writer, args); err != nil {
		return err
	}

	if err := writer.Flush(); err != nil {
		return err
	}

	_, err := readSimple(reader)

	return err
}

func writeCommand(writer *bufio.Writer, args []string) error {
	if _, err := fmt.Fprintf(writer, "*%d\r\n", len(args)); err != nil {
		return err
	}

	for _, arg := range args {
		if _, err := fmt.Fprintf(writer, "$%d\r\n", len(arg)); err != nil {
			return err
		}

		if _, err := writer.WriteString(arg); err != nil {
			return err
		}

		if _, err := writer.WriteString("\r\n"); err != nil {
			return err
		}
	}

	return nil
}

func readSimple(reader *bufio.Reader) (string, error) {
	prefix, err := reader.ReadByte()
	if err != nil {
		return "", err
	}

	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}

	line = strings.TrimSuffix(line, "\r\n")
	if prefix == '-' {
		return "", errors.New(line)
	}

	if prefix != '+' {
		return "", fmt.Errorf("unexpected RESP prefix %s", strconv.QuoteRune(rune(prefix)))
	}

	return line, nil
}

var _ io.Closer = (*monitor)(nil)
