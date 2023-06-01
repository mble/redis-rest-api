package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-redis/redismock/v9"
)

func authenticateMatcher(tb testing.TB, ok bool, passError string, statusCode, expectedStatusCode int, codeError string) {
	tb.Helper()

	if ok {
		tb.Error(passError)
	}

	if statusCode != expectedStatusCode {
		tb.Error(codeError)
	}
}

func TestAuthenticate(t *testing.T) {
	log.SetOutput(io.Discard)

	um := UserMap{}

	t.Run("unsupported method", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/", http.NoBody)
		res := httptest.NewRecorder()
		_, ok := authenticate(res, req, um)

		authenticateMatcher(
			t,
			ok,
			"authenticate should return false for wrong method",
			res.Code,
			http.StatusMethodNotAllowed,
			"authenticate should return 405 for wrong method",
		)
	})

	t.Run("no auth header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		res := httptest.NewRecorder()
		_, ok := authenticate(res, req, um)
		authenticateMatcher(
			t,
			ok,
			"authenticate should return false for no auth header",
			res.Code,
			http.StatusUnauthorized,
			"authenticate should return 401 for no auth header",
		)
	})

	t.Run("no matching user", func(t *testing.T) {
		um = UserMap{
			"readwrite": UserDetails{
				Role:     "rw",
				TokenSHA: "a883dafc480d466ee04e0d6da986bd78eb1fdd2178d04693723da3a8f95d42f4",
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		req.Header.Add("Authorization", "Bearer 1234")
		req.Header.Add("X-Redis-User", "test")

		res := httptest.NewRecorder()
		_, ok := authenticate(res, req, um)

		authenticateMatcher(
			t,
			ok,
			"authenticate should return false for no matching user",
			res.Code,
			http.StatusUnauthorized,
			"authenticate should return 401 for no matching user",
		)
	})

	t.Run("no user map", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		req.Header.Add("Authorization", "Bearer 1234")
		req.Header.Add("X-Redis-User", "test")

		res := httptest.NewRecorder()
		_, ok := authenticate(res, req, um)

		authenticateMatcher(
			t,
			ok,
			"authenticate should return false for no user map",
			res.Code,
			http.StatusUnauthorized,
			"authenticate should return 401 for no user map",
		)
	})

	t.Run("no matching pass", func(t *testing.T) {
		um = UserMap{
			"readwrite": UserDetails{
				Role:     "rw",
				TokenSHA: "a883dafc480d466ee04e0d6da986bd78eb1fdd2178d04693723da3a8f95d42f4",
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		req.Header.Add("Authorization", "Bearer 3456")
		req.Header.Add("X-Redis-User", "readwrite")

		res := httptest.NewRecorder()
		_, ok := authenticate(res, req, um)

		authenticateMatcher(
			t,
			ok,
			"authenticate should return false for no matching pass",
			res.Code,
			http.StatusUnauthorized,
			"authenticate should return 401 for no matching pass",
		)
	})

	t.Run("everything is as expected", func(t *testing.T) {
		um = UserMap{
			"readwrite": UserDetails{
				Role:     "rw",
				TokenSHA: "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4",
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		req.Header.Add("Authorization", "Bearer 1234")
		req.Header.Add("X-Redis-User", "readwrite")
		res := httptest.NewRecorder()

		role, ok := authenticate(res, req, um)
		if !ok {
			t.Errorf("expected auth to pass")
		}

		expectedRole := "rw"
		if role != Role(expectedRole) {
			t.Errorf("expected %s, got %s", expectedRole, role)
		}
	})
}

func TestHandleErr(t *testing.T) {
	log.SetOutput(io.Discard)

	err := fmt.Errorf("oh noes")
	res := httptest.NewRecorder()
	handleErr(res, err)

	if res.Code != http.StatusBadRequest {
		t.Error("response did not have 400 bad request set")
	}

	expected := `{"error":"oh noes"}`
	bodyStr := res.Body.String()

	if bodyStr != expected {
		t.Errorf("expected %s, got %s", expected, bodyStr)
	}
}

func TestValidateCommand(t *testing.T) {
	log.SetOutput(io.Discard)

	const errPrefix = "NOPERM"

	allowedCmds := map[string]int{
		"set": 0,
		"get": 1,
		"del": 2,
	}

	t.Run("command not allowed", func(t *testing.T) {
		cmd := "incr"

		err := validateCommand(cmd, allowedCmds)
		if err == nil {
			t.Fatal("expected error, got nil")
		}

		errMsg := err.Error()
		if !strings.HasPrefix(errMsg, errPrefix) {
			t.Errorf("expected %s to have prefix %s", errMsg, errPrefix)
		}
	})

	t.Run("command allowed", func(t *testing.T) {
		cmd := "get"

		err := validateCommand(cmd, allowedCmds)
		if err != nil {
			t.Errorf("expected nil, got %s", err)
		}
	})

	t.Run("accepts different case", func(t *testing.T) {
		cmd := "GeT"

		err := validateCommand(cmd, allowedCmds)
		if err != nil {
			t.Errorf("expected nil, got %s", err)
		}
	})
}

func mockAuthenticatePass(_ http.ResponseWriter, _ *http.Request, _ UserMap) (role Role, ok bool) {
	return Role("rw"), true
}

func mockAuthenticateFail(w http.ResponseWriter, _ *http.Request, _ UserMap) (role Role, ok bool) {
	w.WriteHeader(http.StatusUnauthorized)
	return "", false
}

func TestRootHandler(t *testing.T) {
	log.SetOutput(io.Discard)

	db, _ := redismock.NewClientMock()
	ctx := context.Background()

	um := UserMap{
		"readwrite": UserDetails{
			Role:     "rw",
			TokenSHA: "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4",
		},
	}

	t.Run("auth failed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		res := httptest.NewRecorder()

		fn := rootHandler(ctx, db, um, mockAuthenticateFail)
		fn(res, req)

		if res.Code < http.StatusBadRequest {
			t.Errorf("expected status < %d, got %d", http.StatusBadRequest, res.Code)
		}
	})

	t.Run("POST", func(t *testing.T) {
		method := http.MethodPost
		t.Run("invalid path", func(t *testing.T) {
			req := httptest.NewRequest(method, "/foobar", http.NoBody)
			res := httptest.NewRecorder()

			fn := rootHandler(ctx, db, um, mockAuthenticatePass)
			fn(res, req)

			if res.Code < http.StatusBadRequest {
				t.Errorf("expected status < %d, got %d", http.StatusBadRequest, res.Code)
			}
		})

		t.Run("empty body", func(t *testing.T) {
			req := httptest.NewRequest(method, "/", http.NoBody)
			res := httptest.NewRecorder()

			fn := rootHandler(ctx, db, um, mockAuthenticatePass)
			fn(res, req)

			if res.Code < http.StatusBadRequest {
				t.Errorf("expected status < %d, got %d", http.StatusBadRequest, res.Code)
			}
		})

		t.Run("garbled body", func(t *testing.T) {
			body := strings.NewReader(`{"foo:[bar]}`)

			req := httptest.NewRequest(method, "/", body)
			res := httptest.NewRecorder()

			fn := rootHandler(ctx, db, um, mockAuthenticatePass)
			fn(res, req)

			if res.Code < http.StatusBadRequest {
				t.Errorf("expected status < %d, got %d", http.StatusBadRequest, res.Code)
			}
		})
	})

	t.Run("GET", func(t *testing.T) {
		method := http.MethodGet

		t.Run("no cmd", func(t *testing.T) {
			path := "/"

			req := httptest.NewRequest(method, path, http.NoBody)
			res := httptest.NewRecorder()

			fn := rootHandler(ctx, db, um, mockAuthenticatePass)
			fn(res, req)

			if res.Code < http.StatusBadRequest {
				t.Errorf("expected status < %d, got %d", http.StatusBadRequest, res.Code)
			}
		})

		t.Run("multi cmd", func(t *testing.T) {
			db2, mock := redismock.NewClientMock()
			path := "/set/foo/1"

			req := httptest.NewRequest(method, path, http.NoBody)
			res := httptest.NewRecorder()

			mock.ExpectDo("set", "foo", "1").RedisNil()

			fn := rootHandler(ctx, db2, um, mockAuthenticatePass)
			fn(res, req)

			if res.Code != http.StatusOK {
				t.Errorf("expected status < %d, got %d", http.StatusOK, res.Code)
				t.Log(res.Body)
			}
		})
	})

	t.Run("command exec", func(t *testing.T) {
		t.Run("parse fail", func(t *testing.T) {
			var buf bytes.Buffer
			log.SetOutput(&buf)
			defer func() {
				log.SetOutput(io.Discard)
			}()

			body := strings.NewReader(`[{"foo":1}]`)
			req := httptest.NewRequest(http.MethodPost, "/", body)
			res := httptest.NewRecorder()

			fn := rootHandler(ctx, db, um, mockAuthenticatePass)
			fn(res, req)

			if res.Code < http.StatusBadRequest {
				t.Errorf("expected status < %d, got %d", http.StatusBadRequest, res.Code)
			}

			if !strings.Contains(buf.String(), "failed to parse") {
				t.Errorf("expected %s to contain 'failed to parse'", buf.String())
			}
		})

		t.Run("invalid command", func(t *testing.T) {
			body := strings.NewReader(`["INFO"]`)
			req := httptest.NewRequest(http.MethodPost, "/", body)
			res := httptest.NewRecorder()

			fn := rootHandler(ctx, db, um, mockAuthenticatePass)
			fn(res, req)

			if res.Code < http.StatusBadRequest {
				t.Errorf("expected status < %d, got %d", http.StatusBadRequest, res.Code)
			}
		})

		t.Run("valid command", func(t *testing.T) {
			db, mock := redismock.NewClientMock()

			body := strings.NewReader(`["GET", "foo"]`)
			req := httptest.NewRequest(http.MethodPost, "/", body)
			res := httptest.NewRecorder()

			mock.ExpectDo("GET", "foo").RedisNil()

			fn := rootHandler(ctx, db, um, mockAuthenticatePass)
			fn(res, req)

			if res.Code != http.StatusOK {
				t.Errorf("expected status < %d, got %d", http.StatusOK, res.Code)
				t.Log(res.Body)
			}
		})
	})
}

func TestPipelineHandler(t *testing.T) {
	log.SetOutput(io.Discard)

	db, _ := redismock.NewClientMock()
	ctx := context.Background()

	um := UserMap{
		"readwrite": UserDetails{
			Role:     "rw",
			TokenSHA: "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4",
		},
	}

	t.Run("auth failed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/pipeline", http.NoBody)
		res := httptest.NewRecorder()

		fn := pipelineHandler(ctx, db, um, mockAuthenticateFail)
		fn(res, req)

		if res.Code != http.StatusUnauthorized {
			t.Errorf("expected: %d, got: %d", http.StatusUnauthorized, res.Code)
		}
	})

	t.Run("invalid method", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/pipeline", http.NoBody)
		res := httptest.NewRecorder()

		fn := pipelineHandler(ctx, db, um, mockAuthenticatePass)
		fn(res, req)

		if res.Code < http.StatusBadRequest {
			t.Errorf("expected: %d, got: %d", http.StatusBadRequest, res.Code)
		}
	})

	t.Run("POST", func(t *testing.T) {
		t.Run("empty body", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/pipeline", http.NoBody)
			res := httptest.NewRecorder()

			fn := pipelineHandler(ctx, db, um, mockAuthenticatePass)
			fn(res, req)

			if res.Code < http.StatusBadRequest {
				t.Errorf("expected: %d, got: %d", http.StatusBadRequest, res.Code)
			}
		})

		t.Run("garbled body", func(t *testing.T) {
			body := strings.NewReader(`[["GET", "foo]`)
			req := httptest.NewRequest(http.MethodPost, "/pipeline", body)
			res := httptest.NewRecorder()

			fn := pipelineHandler(ctx, db, um, mockAuthenticatePass)
			fn(res, req)

			if res.Code < http.StatusBadRequest {
				t.Errorf("expected: %d, got: %d", http.StatusBadRequest, res.Code)
			}
		})

		t.Run("parse fail", func(t *testing.T) {
			var buf bytes.Buffer
			log.SetOutput(&buf)
			defer func() {
				log.SetOutput(io.Discard)
			}()

			body := strings.NewReader(`[[[{"1":"foo"}]]]`)
			req := httptest.NewRequest(http.MethodPost, "/pipeline", body)
			res := httptest.NewRecorder()

			fn := pipelineHandler(ctx, db, um, mockAuthenticatePass)
			fn(res, req)

			if !strings.Contains(buf.String(), "internal parsing err") {
				t.Errorf("expected %s to contain 'internal parsing err'", buf.String())
			}
		})

		t.Run("invalid command", func(t *testing.T) {
			db, mock := redismock.NewClientMock()
			body := strings.NewReader(`[["INFO"]]`)
			req := httptest.NewRequest(http.MethodPost, "/pipeline", body)
			res := httptest.NewRecorder()
			expectedBody := `[{"error":"NOPERM this user has no permissions to run the 'info' command"}]`

			mock.ExpectDo("PING")

			fn := pipelineHandler(ctx, db, um, mockAuthenticatePass)
			fn(res, req)

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Error(err)
			}

			if res.Code != http.StatusOK {
				t.Errorf("expected status < %d, got %d", http.StatusOK, res.Code)
				t.Log(res.Body)
			}

			bdy, _ := io.ReadAll(res.Body)
			if string(bdy) != expectedBody {
				t.Errorf("expected: %s, got %s", expectedBody, bdy)
			}
		})

		t.Run("invalid command in the middle", func(t *testing.T) {
			db, mock := redismock.NewClientMock()
			body := strings.NewReader(`[["GET", "foo"], ["INFO"], ["DEL", "foo"]]`)
			expectedBody := `[{"result":1},{"error":"NOPERM this user has no permissions to run the 'info' command"},{"result":1}]`
			req := httptest.NewRequest(http.MethodPost, "/pipeline", body)
			res := httptest.NewRecorder()

			mock.ExpectDo("GET", "foo").SetVal(1)
			mock.ExpectDo("PING").SetVal("PONG")
			mock.ExpectDo("DEL", "foo").SetVal(1)

			fn := pipelineHandler(ctx, db, um, mockAuthenticatePass)
			fn(res, req)

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Error(err)
			}

			if res.Code != http.StatusOK {
				t.Errorf("expected status < %d, got %d", http.StatusOK, res.Code)
				t.Log(res.Body)
			}

			bdy, _ := io.ReadAll(res.Body)
			if string(bdy) != expectedBody {
				t.Errorf("expected: %s, got %s", expectedBody, bdy)
			}
		})

		t.Run("err command in the middle", func(t *testing.T) {
			t.Skip("skip: mock currently does not handle this case, but works in practice")
			// $ curl -s -X POST https://localhost:8081/pipeline -H "Authorization: Bearer [token]" -d '    [
			// 		["SET", "key1", "valuex"],
			// 		["SETEX", "key2", 13, "valuez"],
			// 		["INCR", "key1"],
			//		["ZADD", "myset", 11, "item1", 22, "item2"]
			//  ]'
			// [{"result":"OK"},{"result":"OK"},{"error":"ERR value is not an integer or out of range"},{"result":2}]

			db, mock := redismock.NewClientMock()
			body := strings.NewReader(`[["GET", "foo"], ["SET", "foo", "mykey"], ["DEL", "foo"]]`)
			expectedBody := `[{"result":1},{"error":"oh noes"},{"result":1}]`
			req := httptest.NewRequest(http.MethodPost, "/pipeline", body)
			res := httptest.NewRecorder()

			mock.ExpectDo("GET", "foo").SetVal(1)
			mock.ExpectDo("SET", "foo", "mykey").SetErr(fmt.Errorf("oh noes"))
			mock.ExpectDo("DEL", "foo").SetVal(1)

			fn := pipelineHandler(ctx, db, um, mockAuthenticatePass)
			fn(res, req)

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Error(err)
			}

			if res.Code != http.StatusOK {
				t.Errorf("expected status < %d, got %d", http.StatusOK, res.Code)
				t.Log(res.Body)
			}

			bdy, _ := io.ReadAll(res.Body)
			if string(bdy) != expectedBody {
				t.Errorf("expected: %s, got %s", expectedBody, bdy)
			}
		})

		t.Run("all valid", func(t *testing.T) {
			db, mock := redismock.NewClientMock()
			body := strings.NewReader(`[["GET", "foo"], ["SET", "foo", "mykey"], ["DEL", "foo"]]`)
			expectedBody := `[{"result":1},{"result":"OK"},{"result":1}]`
			req := httptest.NewRequest(http.MethodPost, "/pipeline", body)
			res := httptest.NewRecorder()

			mock.ExpectDo("GET", "foo").SetVal(1)
			mock.ExpectDo("SET", "foo", "mykey").SetVal("OK")
			mock.ExpectDo("DEL", "foo").SetVal(1)

			fn := pipelineHandler(ctx, db, um, mockAuthenticatePass)
			fn(res, req)

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Error(err)
			}

			if res.Code != http.StatusOK {
				t.Errorf("expected status < %d, got %d", http.StatusOK, res.Code)
				t.Log(res.Body)
			}

			bdy, _ := io.ReadAll(res.Body)
			if string(bdy) != expectedBody {
				t.Errorf("expected: %s, got %s", expectedBody, bdy)
			}
		})
	})
}

func TestTxHandler(t *testing.T) {
	log.SetOutput(io.Discard)

	db, _ := redismock.NewClientMock()
	ctx := context.Background()

	um := UserMap{
		"readwrite": UserDetails{
			Role:     "rw",
			TokenSHA: "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4",
		},
	}

	t.Run("auth failed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/multi-exec", http.NoBody)
		res := httptest.NewRecorder()

		fn := txHandler(ctx, db, um, mockAuthenticateFail)
		fn(res, req)

		if res.Code != http.StatusUnauthorized {
			t.Errorf("expected: %d, got: %d", http.StatusUnauthorized, res.Code)
		}
	})

	t.Run("invalid method", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodHead, "/multi-exec", http.NoBody)
		res := httptest.NewRecorder()

		fn := txHandler(ctx, db, um, mockAuthenticatePass)
		fn(res, req)

		if res.Code != http.StatusBadRequest {
			t.Errorf("expected: %d, got: %d", http.StatusBadRequest, res.Code)
		}
	})

	t.Run("POST", func(t *testing.T) {
		t.Run("empty body", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/multi-exe", http.NoBody)
			res := httptest.NewRecorder()

			fn := txHandler(ctx, db, um, mockAuthenticatePass)
			fn(res, req)

			if res.Code < http.StatusBadRequest {
				t.Errorf("expected: %d, got: %d", http.StatusBadRequest, res.Code)
			}
		})

		t.Run("garbled body", func(t *testing.T) {
			body := strings.NewReader(`[["GET", "foo]`)
			req := httptest.NewRequest(http.MethodPost, "/multi-exe", body)
			res := httptest.NewRecorder()

			fn := txHandler(ctx, db, um, mockAuthenticatePass)
			fn(res, req)

			if res.Code < http.StatusBadRequest {
				t.Errorf("expected: %d, got: %d", http.StatusBadRequest, res.Code)
			}
		})

		t.Run("parse fail", func(t *testing.T) {
			var buf bytes.Buffer
			log.SetOutput(&buf)
			defer func() {
				log.SetOutput(io.Discard)
			}()

			body := strings.NewReader(`[[[{"1":"foo"}]]]`)
			req := httptest.NewRequest(http.MethodPost, "/multi-exe", body)
			res := httptest.NewRecorder()

			fn := txHandler(ctx, db, um, mockAuthenticatePass)
			fn(res, req)

			if res.Code < http.StatusBadRequest {
				t.Errorf("expected: %d, got: %d", http.StatusBadRequest, res.Code)
			}

			if !strings.Contains(buf.String(), "internal parsing err") {
				t.Errorf("expected %s to contain 'internal parsing err'", buf.String())
			}
		})

		t.Run("invalid command", func(t *testing.T) {
			db, mock := redismock.NewClientMock()
			body := strings.NewReader(`[["INFO"]]`)
			req := httptest.NewRequest(http.MethodPost, "/multi-exe", body)
			res := httptest.NewRecorder()
			expectedBody := `{"error":"NOPERM this user has no permissions to run the 'info' command"}`

			fn := txHandler(ctx, db, um, mockAuthenticatePass)
			fn(res, req)

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Error(err)
			}

			if res.Code != http.StatusBadRequest {
				t.Errorf("expected status < %d, got %d", http.StatusOK, res.Code)
				t.Log(res.Body)
			}

			bdy, _ := io.ReadAll(res.Body)
			if string(bdy) != expectedBody {
				t.Errorf("expected: %s, got %s", expectedBody, bdy)
			}
		})

		t.Run("invalid command in the middle", func(t *testing.T) {
			db, mock := redismock.NewClientMock()
			body := strings.NewReader(`[["GET", "foo"], ["INFO"], ["DEL", "foo"]]`)
			expectedBody := `{"error":"NOPERM this user has no permissions to run the 'info' command"}`
			req := httptest.NewRequest(http.MethodPost, "/multi-exe", body)
			res := httptest.NewRecorder()

			fn := txHandler(ctx, db, um, mockAuthenticatePass)
			fn(res, req)

			// No expectations due to DISCARD, which is not mocked

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Error(err)
			}

			if res.Code != http.StatusBadRequest {
				t.Errorf("expected status < %d, got %d", http.StatusOK, res.Code)
				t.Log(res.Body)
			}

			bdy, _ := io.ReadAll(res.Body)
			if string(bdy) != expectedBody {
				t.Errorf("expected: %s, got %s", expectedBody, bdy)
			}
		})

		t.Run("err command in the middle", func(t *testing.T) {
			t.Skip("skip: mock currently does not handle this case, but works in practice")
			// $ curl -s -X POST https://localhost:8081/multi-exec -H "Authorization: Bearer [token]" -d '    [
			// 		["SET", "key1", "valuex"],
			// 		["SETEX", "key2", 13, "valuez"],
			// 		["INCR", "key1"],
			//		["ZADD", "myset", 11, "item1", 22, "item2"]
			//  ]'
			// [{"result":"OK"},{"result":"OK"},{"error":"ERR value is not an integer or out of range"},{"result":2}]

			db, mock := redismock.NewClientMock()
			body := strings.NewReader(`[["GET", "foo"], ["SET", "foo", "mykey"], ["DEL", "foo"]]`)
			expectedBody := `[{"result":1},{"error":"oh noes"},{"result":1}]`
			req := httptest.NewRequest(http.MethodPost, "/multi-exe", body)
			res := httptest.NewRecorder()

			mock.ExpectTxPipeline()
			mock.ExpectDo("GET", "foo").SetVal(1)
			mock.ExpectDo("SET", "foo", "mykey").SetErr(fmt.Errorf("oh noes"))
			mock.ExpectDo("DEL", "foo").SetVal(1)
			mock.ExpectTxPipelineExec()

			fn := txHandler(ctx, db, um, mockAuthenticatePass)
			fn(res, req)

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Error(err)
			}

			if res.Code != http.StatusOK {
				t.Errorf("expected status < %d, got %d", http.StatusOK, res.Code)
				t.Log(res.Body)
			}

			bdy, _ := io.ReadAll(res.Body)
			if string(bdy) != expectedBody {
				t.Errorf("expected: %s, got %s", expectedBody, bdy)
			}
		})

		t.Run("all valid", func(t *testing.T) {
			db, mock := redismock.NewClientMock()
			body := strings.NewReader(`[["GET", "foo"], ["SET", "foo", "mykey"], ["DEL", "foo"]]`)
			expectedBody := `[{"result":1},{"result":"OK"},{"result":1}]`
			req := httptest.NewRequest(http.MethodPost, "/multi-exec", body)
			res := httptest.NewRecorder()

			mock.ExpectTxPipeline()
			mock.ExpectDo("GET", "foo").SetVal(1)
			mock.ExpectDo("SET", "foo", "mykey").SetVal("OK")
			mock.ExpectDo("DEL", "foo").SetVal(1)
			mock.ExpectTxPipelineExec()

			fn := txHandler(ctx, db, um, mockAuthenticatePass)
			fn(res, req)

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Error(err)
			}

			if res.Code != http.StatusOK {
				t.Errorf("expected status < %d, got %d", http.StatusOK, res.Code)
				t.Log(res.Body)
			}

			bdy, _ := io.ReadAll(res.Body)
			if string(bdy) != expectedBody {
				t.Errorf("expected: %s, got %s", expectedBody, bdy)
			}
		})
	})
}
