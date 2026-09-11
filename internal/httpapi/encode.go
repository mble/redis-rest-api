package httpapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

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

func normalize(value any, encoding stringEncoding) (any, error) {
	switch typed := value.(type) {
	case nil:
		return nil, nil
	case string:
		if encoding == encodingBase64 && typed != "OK" {
			return base64.StdEncoding.EncodeToString([]byte(typed)), nil
		}

		return typed, nil
	case []byte:
		if encoding == encodingBase64 {
			return base64.StdEncoding.EncodeToString(typed), nil
		}

		return string(typed), nil
	case int, int8, int16, int32, int64:
		return typed, nil
	case uint, uint8, uint16, uint32, uint64:
		return typed, nil
	case float32, float64, bool:
		return typed, nil
	case []string:
		values := make([]any, len(typed))
		for index, item := range typed {
			values[index] = item
		}

		return normalizeSlice(values, encoding)
	case []any:
		return normalizeSlice(typed, encoding)
	case map[string]any:
		values := make(map[string]any, len(typed))
		for key, item := range typed {
			normalized, err := normalize(item, encoding)
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

func normalizeSlice(values []any, encoding stringEncoding) ([]any, error) {
	normalized := make([]any, len(values))
	for index, value := range values {
		item, err := normalize(value, encoding)
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

	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Content-Length", strconv.Itoa(len(body)))
	writer.WriteHeader(status)

	if request.Method == http.MethodHead {
		return
	}

	_, _ = writer.Write(body)
}

func writeError(writer http.ResponseWriter, request *http.Request, status int, message string) {
	writeJSON(writer, request, status, map[string]string{"error": message})
}

func writeRawRESP2(writer http.ResponseWriter, request *http.Request, status int, replies []domain.Reply) {
	var body bytes.Buffer

	for _, reply := range replies {
		if reply.Err != nil {
			body.WriteByte('-')
			body.WriteString(respError(cleanError(reply.Err)))
			body.WriteString("\r\n")
			continue
		}

		raw, ok := reply.Value.([]byte)
		if !ok {
			writeError(writer, request, http.StatusInternalServerError, "invalid raw Redis response")

			return
		}

		body.Write(raw)
	}

	writer.Header().Set("Content-Type", "application/octet-stream")
	writer.Header().Set("Content-Length", strconv.Itoa(body.Len()))
	writer.WriteHeader(status)

	if request.Method == http.MethodHead {
		return
	}

	_, _ = writer.Write(body.Bytes())
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
