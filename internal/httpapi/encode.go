package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/mble/redis-rest-api/internal/domain"
)

type responseFormat uint8

const (
	formatJSON responseFormat = iota
	formatRESP2
)

type stringEncoding uint8

const (
	encodingPlain stringEncoding = iota
	encodingBase64
)

type responseOptions struct {
	format   responseFormat
	encoding stringEncoding
}

type resultResponse struct {
	Result any `json:"result"`
}

type errorResponse struct {
	Error string `json:"error"`
}

type statusResponse struct {
	Status string `json:"status"`
}

const (
	maxResponseDepth    = 128
	encodedNumberBytes  = 32
	respErrorFrameBytes = len("-\r\n")
	defaultJSONCapacity = 256
)

const (
	jsonResultPrefix    = `{"result":`
	jsonErrorPrefix     = `{"error":`
	jsonReplacementRune = `\ufffd`
)

var errResponseLimit = errors.New("response exceeds maximum size")

func parseOptions(request *http.Request) (responseOptions, error) {
	options := responseOptions{}

	switch strings.ToLower(strings.TrimSpace(request.Header.Get(headerFormat))) {
	case "", "json":
		options.format = formatJSON
	case "resp2":
		options.format = formatRESP2
	default:
		return responseOptions{}, fmt.Errorf("invalid %s header", headerFormat)
	}

	switch strings.ToLower(strings.TrimSpace(request.Header.Get(headerEncoding))) {
	case "":
		options.encoding = encodingPlain
	case "base64":
		options.encoding = encodingBase64
	default:
		return responseOptions{}, fmt.Errorf("invalid %s header", headerEncoding)
	}

	if options.format == formatRESP2 && options.encoding == encodingBase64 {
		return responseOptions{}, fmt.Errorf("%s cannot be combined with RESP2", headerEncoding)
	}

	return options, nil
}

func normalize(value any, encoding stringEncoding, limit int64) (any, error) {
	budget := responseBudget{remaining: limit}

	return normalizeBudget(value, encoding, &budget)
}

func normalizeBudget(value any, encoding stringEncoding, budget *responseBudget) (any, error) {
	return normalizeValue(value, encoding, budget, 0)
}

type responseBudget struct {
	remaining int64
}

func (b *responseBudget) use(size int) error {
	if size < 0 || int64(size) > b.remaining {
		return errResponseLimit
	}

	b.remaining -= int64(size)

	return nil
}

func normalizeValue(value any, encoding stringEncoding, budget *responseBudget, depth int) (any, error) {
	if depth > maxResponseDepth {
		return nil, errors.New("redis response nesting is too deep")
	}

	switch typed := value.(type) {
	case nil:
		return keepValue(nil, len("null"), budget)
	case string:
		return normalizeString(typed, encoding, budget)
	case []byte:
		return normalizeBytes(typed, encoding, budget)
	case int, int8, int16, int32, int64:
		return keepValue(typed, encodedNumberBytes, budget)
	case uint, uint8, uint16, uint32, uint64:
		return keepValue(typed, encodedNumberBytes, budget)
	case float32, float64, bool:
		return keepValue(typed, encodedNumberBytes, budget)
	case []string:
		return normalizeStrings(typed, encoding, budget, depth+1)
	case []any:
		return normalizeSlice(typed, encoding, budget, depth+1)
	case map[string]any:
		values := make(map[string]any, len(typed))
		for key, item := range typed {
			if err := budget.use(len(key)); err != nil {
				return nil, err
			}

			normalized, err := normalizeValue(item, encoding, budget, depth+1)
			if err != nil {
				return nil, err
			}

			values[key] = normalized
		}

		return values, nil
	default:
		return nil, fmt.Errorf("unsupported Redis response type %T", value)
	}
}

func normalizeString(value string, encoding stringEncoding, budget *responseBudget) (any, error) {
	if encoding != encodingBase64 || value == "OK" {
		return keepValue(value, len(value), budget)
	}

	size := base64.StdEncoding.EncodedLen(len(value))
	if err := budget.use(size); err != nil {
		return nil, err
	}

	return base64.StdEncoding.EncodeToString([]byte(value)), nil
}

func normalizeBytes(value []byte, encoding stringEncoding, budget *responseBudget) (any, error) {
	if encoding != encodingBase64 {
		if err := budget.use(len(value)); err != nil {
			return nil, err
		}

		return string(value), nil
	}

	size := base64.StdEncoding.EncodedLen(len(value))
	if err := budget.use(size); err != nil {
		return nil, err
	}

	return base64.StdEncoding.EncodeToString(value), nil
}

func keepValue(value any, size int, budget *responseBudget) (any, error) {
	if err := budget.use(size); err != nil {
		return nil, err
	}

	return value, nil
}

func normalizeStrings(
	values []string,
	encoding stringEncoding,
	budget *responseBudget,
	depth int,
) ([]any, error) {
	normalized := make([]any, len(values))
	for index, value := range values {
		item, err := normalizeValue(value, encoding, budget, depth)
		if err != nil {
			return nil, err
		}

		normalized[index] = item
	}

	return normalized, nil
}

func normalizeSlice(
	values []any,
	encoding stringEncoding,
	budget *responseBudget,
	depth int,
) ([]any, error) {
	normalized := make([]any, len(values))
	for index, value := range values {
		item, err := normalizeValue(value, encoding, budget, depth)
		if err != nil {
			return nil, err
		}

		normalized[index] = item
	}

	return normalized, nil
}

func writeJSON(writer http.ResponseWriter, request *http.Request, status int, value any) {
	body, err := json.Marshal(value)
	if err != nil {
		status = http.StatusInternalServerError
		body = []byte(`{"error":"encode response"}`)
	}

	writeBody(writer, request, status, "application/json", body)
}

type jsonBuffer struct {
	body   []byte
	budget responseBudget
}

func marshalBoundJSON(value any, limit int64) ([]byte, error) {
	buffer := jsonBuffer{
		body:   make([]byte, 0, min(int(limit), defaultJSONCapacity)),
		budget: responseBudget{remaining: limit},
	}
	if err := appendJSONValue(value, &buffer, 0); err != nil {
		return nil, err
	}

	return buffer.body, nil
}

func (b *jsonBuffer) write(value string) error {
	if err := b.budget.use(len(value)); err != nil {
		return err
	}

	b.body = append(b.body, value...)

	return nil
}

func (b *jsonBuffer) writeByte(value byte) error {
	if err := b.budget.use(1); err != nil {
		return err
	}

	b.body = append(b.body, value)

	return nil
}

func appendJSONValue(value any, buffer *jsonBuffer, depth int) error {
	if depth > maxResponseDepth {
		return errors.New("redis response nesting is too deep")
	}

	switch typed := value.(type) {
	case nil:
		return buffer.write("null")
	case string:
		return appendJSONString(typed, buffer)
	case int, int8, int16, int32, int64:
		return buffer.write(formatInt(typed))
	case uint, uint8, uint16, uint32, uint64:
		return buffer.write(formatUint(typed))
	case float32, float64:
		return appendJSONFloat(typed, buffer)
	case bool:
		return buffer.write(strconv.FormatBool(typed))
	case resultResponse:
		return appendJSONObject(jsonResultPrefix, typed.Result, buffer, depth)
	case errorResponse:
		return appendJSONObject(jsonErrorPrefix, typed.Error, buffer, depth)
	case []any:
		return appendJSONArray(typed, buffer, depth)
	case []string:
		return appendJSONStrings(typed, buffer, depth)
	case map[string]any:
		return appendJSONMap(typed, buffer, depth)
	default:
		return fmt.Errorf("unsupported JSON response type %T", value)
	}
}

func appendJSONObject(
	prefix string,
	value any,
	buffer *jsonBuffer,
	depth int,
) error {
	if err := buffer.write(prefix); err != nil {
		return err
	}
	if err := appendJSONValue(value, buffer, depth+1); err != nil {
		return err
	}

	return buffer.write("}")
}

func appendJSONArray(values []any, buffer *jsonBuffer, depth int) error {
	if err := buffer.write("["); err != nil {
		return err
	}

	for index, value := range values {
		if index > 0 {
			if err := buffer.write(","); err != nil {
				return err
			}
		}
		if err := appendJSONValue(value, buffer, depth+1); err != nil {
			return err
		}
	}

	return buffer.write("]")
}

func appendJSONStrings(values []string, buffer *jsonBuffer, depth int) error {
	if err := buffer.write("["); err != nil {
		return err
	}

	for index, value := range values {
		if index > 0 {
			if err := buffer.write(","); err != nil {
				return err
			}
		}
		if err := appendJSONValue(value, buffer, depth+1); err != nil {
			return err
		}
	}

	return buffer.write("]")
}

func appendJSONMap(values map[string]any, buffer *jsonBuffer, depth int) error {
	if err := buffer.write("{"); err != nil {
		return err
	}

	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for index, key := range keys {
		if index > 0 {
			if err := buffer.write(","); err != nil {
				return err
			}
		}
		if err := appendJSONString(key, buffer); err != nil {
			return err
		}
		if err := buffer.write(":"); err != nil {
			return err
		}
		if err := appendJSONValue(values[key], buffer, depth+1); err != nil {
			return err
		}
	}

	return buffer.write("}")
}

func appendJSONString(value string, buffer *jsonBuffer) error {
	if err := buffer.write("\""); err != nil {
		return err
	}

	for index := 0; index < len(value); {
		char := value[index]
		if char < utf8.RuneSelf {
			start := index
			for index < len(value) && jsonASCIISafe(value[index]) {
				index++
			}
			if index > start {
				if err := buffer.write(value[start:index]); err != nil {
					return err
				}

				continue
			}

			if err := appendJSONASCII(char, buffer); err != nil {
				return err
			}

			index++
			continue
		}

		runeValue, decodedSize := utf8.DecodeRuneInString(value[index:])
		if runeValue == utf8.RuneError && decodedSize == 1 {
			if err := buffer.write(jsonReplacementRune); err != nil {
				return err
			}

			index++
			continue
		}

		if runeValue == '\u2028' || runeValue == '\u2029' {
			escape := "\\u2028"
			if runeValue == '\u2029' {
				escape = "\\u2029"
			}
			if err := buffer.write(escape); err != nil {
				return err
			}
		} else if err := buffer.write(value[index : index+decodedSize]); err != nil {
			return err
		}

		index += decodedSize
	}

	return buffer.write("\"")
}

func jsonASCIISafe(char byte) bool {
	return char >= 0x20 && char < utf8.RuneSelf &&
		char != '\\' && char != '"' && char != '<' && char != '>' && char != '&'
}

func appendJSONASCII(char byte, buffer *jsonBuffer) error {
	if jsonASCIISafe(char) {
		return buffer.writeByte(char)
	}

	switch char {
	case '\\':
		return buffer.write(`\\`)
	case '"':
		return buffer.write(`\"`)
	case '\n':
		return buffer.write(`\n`)
	case '\r':
		return buffer.write(`\r`)
	case '\t':
		return buffer.write(`\t`)
	case '\b':
		return buffer.write(`\b`)
	case '\f':
		return buffer.write(`\f`)
	default:
		const hex = "0123456789abcdef"
		if err := buffer.write(`\u00`); err != nil {
			return err
		}
		if err := buffer.writeByte(hex[char>>4]); err != nil {
			return err
		}

		return buffer.writeByte(hex[char&0x0f])
	}
}

func formatInt(value any) string {
	switch typed := value.(type) {
	case int:
		return strconv.FormatInt(int64(typed), 10)
	case int8:
		return strconv.FormatInt(int64(typed), 10)
	case int16:
		return strconv.FormatInt(int64(typed), 10)
	case int32:
		return strconv.FormatInt(int64(typed), 10)
	case int64:
		return strconv.FormatInt(typed, 10)
	default:
		return ""
	}
}

func formatUint(value any) string {
	switch typed := value.(type) {
	case uint:
		return strconv.FormatUint(uint64(typed), 10)
	case uint8:
		return strconv.FormatUint(uint64(typed), 10)
	case uint16:
		return strconv.FormatUint(uint64(typed), 10)
	case uint32:
		return strconv.FormatUint(uint64(typed), 10)
	case uint64:
		return strconv.FormatUint(typed, 10)
	default:
		return ""
	}
}

func appendJSONFloat(value any, buffer *jsonBuffer) error {
	body, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode Redis number: %w", err)
	}

	return buffer.write(string(body))
}

func writeBoundJSON(
	writer http.ResponseWriter,
	request *http.Request,
	status int,
	value any,
	limit int64,
) {
	body, err := marshalBoundJSON(value, limit)
	if err != nil {
		writeEncodeError(writer, request, err)

		return
	}

	writeBody(writer, request, status, "application/json", body)
}

func writeBody(
	writer http.ResponseWriter,
	request *http.Request,
	status int,
	contentType string,
	body []byte,
) {
	writer.Header().Set("Content-Type", contentType)
	writer.Header().Set("Content-Length", strconv.Itoa(len(body)))
	writer.WriteHeader(status)

	if request.Method == http.MethodHead {
		return
	}

	_, _ = writer.Write(body)
}

func writeError(writer http.ResponseWriter, request *http.Request, status int, message string) {
	writeJSON(writer, request, status, errorResponse{Error: message})
}

func writeRawRESP2(
	writer http.ResponseWriter,
	request *http.Request,
	status int,
	replies []domain.Reply,
	limit int64,
) {
	size, err := rawSize(replies, limit)
	if err != nil {
		writeEncodeError(writer, request, err)

		return
	}

	writer.Header().Set("Content-Type", "application/octet-stream")
	writer.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	writer.WriteHeader(status)

	if request.Method == http.MethodHead {
		return
	}

	for _, reply := range replies {
		if reply.Err != nil {
			_, _ = fmt.Fprintf(writer, "-%s\r\n", respError(cleanError(reply.Err)))
			continue
		}

		raw, _ := reply.Value.([]byte)
		_, _ = writer.Write(raw)
	}
}

func rawSize(replies []domain.Reply, limit int64) (int64, error) {
	budget := responseBudget{remaining: limit}
	for _, reply := range replies {
		if reply.Err != nil {
			size := len(respError(cleanError(reply.Err))) + respErrorFrameBytes
			if err := budget.use(size); err != nil {
				return 0, err
			}

			continue
		}

		raw, ok := reply.Value.([]byte)
		if !ok {
			return 0, errors.New("invalid raw Redis response")
		}
		if err := budget.use(len(raw)); err != nil {
			return 0, err
		}
	}

	return limit - budget.remaining, nil
}

func writeEncodeError(writer http.ResponseWriter, request *http.Request, err error) {
	status := http.StatusInternalServerError
	if errors.Is(err, errResponseLimit) {
		status = http.StatusBadGateway
	}

	writeError(writer, request, status, err.Error())
}

func respError(message string) string {
	message = strings.ReplaceAll(message, "\r", "")
	message = strings.ReplaceAll(message, "\n", "")

	return message
}

func writeSSE(writer io.Writer, value string) error {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")

	for _, line := range strings.Split(value, "\n") {
		if _, err := fmt.Fprintf(writer, "data: %s\n", line); err != nil {
			return err
		}
	}

	_, err := io.WriteString(writer, "\n")

	return err
}

func openStream(writer http.ResponseWriter) error {
	controller := http.NewResponseController(writer)
	if err := controller.Flush(); err != nil {
		return err
	}

	return setDeadline(controller, time.Time{})
}

func writeStream(writer http.ResponseWriter, value string, timeout time.Duration) error {
	controller := http.NewResponseController(writer)
	if err := setDeadline(controller, time.Now().Add(timeout)); err != nil {
		return err
	}
	defer func() {
		_ = setDeadline(controller, time.Time{})
	}()

	if err := writeSSE(writer, value); err != nil {
		return err
	}

	return controller.Flush()
}

func setDeadline(controller *http.ResponseController, deadline time.Time) error {
	err := controller.SetWriteDeadline(deadline)
	if errors.Is(err, http.ErrNotSupported) {
		return nil
	}

	return err
}
