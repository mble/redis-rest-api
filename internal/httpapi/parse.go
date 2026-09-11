package httpapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/mble/redis-rest-api/internal/domain"
)

const (
	maxBatchCommands = 1000
	queryArgParts    = 2
	queryArgBase     = 2
)

func parseCommand(request *http.Request, maxBody int64) (domain.Command, error) {
	switch request.Method {
	case http.MethodGet, http.MethodHead:
		return parsePath(request.URL.EscapedPath())
	case http.MethodPost, http.MethodPut:
		if request.URL.Path == "/" || request.URL.Path == "" {
			return decodeCommand(request.Body, maxBody)
		}

		return parseBodyValue(request, maxBody)
	default:
		return nil, fmt.Errorf("%w: method not allowed", domain.ErrInvalid)
	}
}

func parseBodyValue(request *http.Request, maxBody int64) (domain.Command, error) {
	command, err := parsePath(request.URL.EscapedPath())
	if err != nil {
		return nil, err
	}

	body, err := readBody(request.Body, maxBody)
	if err != nil {
		return nil, err
	}

	command = append(command, body)
	queryArgs, err := parseQueryArgs(request.URL.RawQuery)
	if err != nil {
		return nil, err
	}

	return append(command, queryArgs...), nil
}

func parsePath(escapedPath string) (domain.Command, error) {
	trimmed := strings.TrimPrefix(escapedPath, "/")
	if trimmed == "" {
		return nil, fmt.Errorf("%w: command is empty", domain.ErrInvalid)
	}

	parts := strings.Split(trimmed, "/")
	command := make(domain.Command, len(parts))
	for index, part := range parts {
		value, err := url.PathUnescape(part)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid path escape", domain.ErrInvalid)
		}

		command[index] = value
	}

	return command, nil
}

func parseQueryArgs(rawQuery string) (domain.Command, error) {
	if rawQuery == "" {
		return nil, nil
	}

	args := make(domain.Command, 0, strings.Count(rawQuery, "&")*queryArgParts+queryArgBase)
	for _, field := range strings.Split(rawQuery, "&") {
		key, value, hasValue := strings.Cut(field, "=")
		key, err := url.QueryUnescape(key)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid query escape", domain.ErrInvalid)
		}

		if key == "_token" {
			continue
		}

		args = append(args, key)
		if !hasValue {
			continue
		}

		value, err = url.QueryUnescape(value)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid query escape", domain.ErrInvalid)
		}

		args = append(args, value)
	}

	return args, nil
}

func decodeCommand(reader io.Reader, maxBody int64) (domain.Command, error) {
	var raw []any
	if err := decodeJSON(reader, maxBody, &raw); err != nil {
		return nil, err
	}

	return normalizeCommand(raw)
}

func parseCommands(reader io.Reader, maxBody int64) ([]domain.Command, error) {
	var raw [][]any
	if err := decodeJSON(reader, maxBody, &raw); err != nil {
		return nil, err
	}

	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: command list is empty", domain.ErrInvalid)
	}

	if len(raw) > maxBatchCommands {
		return nil, fmt.Errorf("%w: command list exceeds %d commands", domain.ErrInvalid, maxBatchCommands)
	}

	commands := make([]domain.Command, len(raw))
	for index, array := range raw {
		if array == nil {
			return nil, fmt.Errorf("%w: command %d must be an array", domain.ErrInvalid, index)
		}

		command, err := normalizeCommand(array)
		if err != nil {
			return nil, fmt.Errorf("%w: command %d: %v", domain.ErrInvalid, index, cleanError(err))
		}

		commands[index] = command
	}

	return commands, nil
}

func decodeJSON(reader io.Reader, maxBody int64, target any) error {
	limited := &io.LimitedReader{R: reader, N: maxBody + 1}
	decoder := json.NewDecoder(limited)
	decoder.UseNumber()

	if err := decoder.Decode(target); err != nil {
		if limited.N == 0 {
			return fmt.Errorf("%w: request body exceeds %d bytes", domain.ErrInvalid, maxBody)
		}

		return fmt.Errorf("%w: invalid JSON: %w", domain.ErrInvalid, err)
	}

	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("%w: request body must contain one JSON value", domain.ErrInvalid)
	}
	if limited.N == 0 {
		return fmt.Errorf("%w: request body exceeds %d bytes", domain.ErrInvalid, maxBody)
	}

	return nil
}

func normalizeCommand(raw []any) (domain.Command, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: command is empty", domain.ErrInvalid)
	}

	command := domain.Command(raw)
	for index, value := range raw {
		normalized, err := normalizeArg(value)
		if err != nil {
			return nil, fmt.Errorf("%w: argument %d: %w", domain.ErrInvalid, index, err)
		}

		command[index] = normalized
	}

	if _, ok := command[0].(string); !ok {
		return nil, fmt.Errorf("%w: command name must be a string", domain.ErrInvalid)
	}

	return command, nil
}

func normalizeArg(value any) (any, error) {
	switch typed := value.(type) {
	case nil, string, bool:
		return typed, nil
	case json.Number:
		integer, err := typed.Int64()
		if err == nil {
			return integer, nil
		}

		decimal, err := typed.Float64()
		if err != nil {
			return nil, fmt.Errorf("invalid number %q", typed)
		}

		return decimal, nil
	default:
		return nil, fmt.Errorf("objects and arrays are not Redis arguments")
	}
}

func readBody(reader io.Reader, maxBody int64) ([]byte, error) {
	limited := io.LimitReader(reader, maxBody+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("%w: read request body: %w", domain.ErrInvalid, err)
	}

	if int64(len(body)) > maxBody {
		return nil, fmt.Errorf("%w: request body exceeds %d bytes", domain.ErrInvalid, maxBody)
	}

	return body, nil
}

type queryAuth uint8

const (
	queryAuthDenied queryAuth = iota
	queryAuthAllowed
)

type tokenSource uint8

const (
	tokenSourceNone tokenSource = iota
	tokenSourceHeader
	tokenSourceQuery
)

func requestToken(request *http.Request, queryMode queryAuth) (string, tokenSource) {
	header := strings.TrimSpace(request.Header.Get("Authorization"))
	if header != "" {
		scheme, value, ok := strings.Cut(header, " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") {
			return "", tokenSourceNone
		}

		return strings.TrimSpace(value), tokenSourceHeader
	}
	if queryMode != queryAuthAllowed {
		return "", tokenSourceNone
	}

	value := request.URL.Query().Get("_token")
	if value == "" {
		return "", tokenSourceNone
	}

	return value, tokenSourceQuery
}
