package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/redis/go-redis/v9"
)

type Result struct {
	Res any `json:"result"`
}

type Error struct {
	Err string `json:"error"`
}

type authFunc func(w http.ResponseWriter, r *http.Request, um UserMap) (role Role, ok bool)

func authenticate(w http.ResponseWriter, r *http.Request, um UserMap) (role Role, ok bool) {
	ValidMethods := []string{
		http.MethodGet,
		http.MethodPost,
		http.MethodPut,
		http.MethodHead,
	}

	const (
		BearerSchema = "Bearer "
		UserHeader   = "X-Redis-User"
		AuthHeader   = "Authorization"
	)

	methodFound := false

	for _, v := range ValidMethods {
		if v == r.Method {
			methodFound = true

			break
		}
	}

	if !methodFound {
		w.WriteHeader(http.StatusMethodNotAllowed)

		return "", false
	}

	userHeader := r.Header.Get(UserHeader)
	user := "readwrite"

	if userHeader != "" {
		user = userHeader
	}

	authHeader := r.Header.Get(AuthHeader)
	if authHeader == "" {
		w.WriteHeader(http.StatusUnauthorized)

		return "", false
	}

	userDetails, err := lookupUser(user, um)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)

		return "", false
	}

	givenPass := strings.TrimPrefix(authHeader, BearerSchema)
	h := sha256.New()
	h.Write([]byte(givenPass))
	hashedPass := fmt.Sprintf("%x", h.Sum(nil))

	if subtle.ConstantTimeCompare([]byte(hashedPass), []byte(userDetails.TokenSHA)) != 1 {
		w.WriteHeader(http.StatusUnauthorized)

		return "", false
	}

	return userDetails.Role, true
}

func handleErr(w http.ResponseWriter, err error) {
	errText := err.Error()
	errText = strings.TrimPrefix(errText, "http: ")

	resp := Error{errText}

	log.Println(err)

	w.WriteHeader(http.StatusBadRequest)

	jsonresp, jerr := json.Marshal(resp)
	if jerr != nil {
		log.Println(jerr)
	}

	_, werr := w.Write(jsonresp)
	if werr != nil {
		log.Println(werr)
	}
}

func validateCommand(cmd string, allowedCmds map[string]int) error {
	lowerCmd := strings.ToLower(cmd)

	_, ok := allowedCmds[lowerCmd]
	if !ok {
		return fmt.Errorf("NOPERM this user has no permissions to run the '%s' command", lowerCmd)
	}

	return nil
}

func rootHandler(ctx context.Context, redisClient *redis.Client, um UserMap, auth authFunc) func(w http.ResponseWriter, r *http.Request) {
	splitter := func(c rune) bool {
		return c == '/'
	}

	return func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		role, ok := auth(w, r, um)
		if !ok {
			return
		}

		path := r.URL.Path
		icmd := []interface{}{}

		validJSONMethod := r.Method == http.MethodPost || r.Method == http.MethodPut

		switch {
		case validJSONMethod && (path == "/" || path == ""):
			body, err := io.ReadAll(r.Body)
			if err != nil {
				handleErr(w, err)

				return
			}

			err = json.Unmarshal(body, &icmd)
			if err != nil {
				handleErr(w, err)

				return
			}
		case r.Method == http.MethodGet:
			cmd := strings.FieldsFunc(path, splitter)
			if len(cmd) < 1 {
				w.WriteHeader(http.StatusBadRequest)

				return
			}

			for _, v := range cmd {
				icmd = append(icmd, v)
			}
		default:
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		cmd := icmd[0]
		strCmd, ok := cmd.(string)

		if !ok {
			handleErr(w, fmt.Errorf("%v failed to parse", cmd))

			return
		}

		err := validateCommand(strCmd, role.AllowedCommands())
		if err != nil {
			handleErr(w, err)

			return
		}

		res, err := redisClient.Do(ctx, icmd...).Result()
		if err != nil && !errors.Is(err, redis.Nil) {
			handleErr(w, err)

			return
		}

		resp := Result{res}
		jsonresp, _ := json.Marshal(resp)

		w.Header().Add("content-type", "application/json")
		w.Header().Add("content-length", fmt.Sprintf("%d", (len(jsonresp))))
		w.WriteHeader(http.StatusOK)

		_, werr := w.Write(jsonresp)
		if werr != nil {
			log.Println(werr)
		}
	}
}

func pipelineHandler(ctx context.Context, redisClient *redis.Client, um UserMap, auth authFunc) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		role, ok := auth(w, r, um)
		if !ok {
			return
		}

		validJSONMethod := r.Method == http.MethodPost || r.Method == http.MethodPut

		if !validJSONMethod {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		icmd := []interface{}{}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			handleErr(w, err)

			return
		}

		err = json.Unmarshal(body, &icmd)
		if err != nil {
			handleErr(w, err)

			return
		}

		errMap := map[int]error{}
		cmdIndicies := []int{}

		results, _ := redisClient.Pipelined(ctx, func(pipe redis.Pipeliner) error {
			for idx, cmd := range icmd {
				cmdIndicies = append(cmdIndicies, idx)

				c, ok := cmd.([]interface{})
				if !ok {
					log.Printf("internal parsing err for: %v", cmd)
					continue
				}

				strCmd, ok := c[0].(string)
				if !ok {
					log.Printf("internal parsing err for %v", c[0])
					continue
				}

				err := validateCommand(strCmd, role.AllowedCommands())
				if err != nil {
					errMap[idx] = err
					pipe.Do(ctx, "PING") // FIXME(matt): we'll replace these with errors
					continue
				}

				pipe.Do(ctx, c...)
			}

			return nil
		})

		pipelineResults := make([]interface{}, 0, len(results))

		for _, idx := range cmdIndicies {
			if errMap[idx] != nil {
				pipelineResults = append(pipelineResults, Error{errMap[idx].Error()})
				continue
			}

			if idx+1 <= len(results) {
				if results[idx] != nil {
					r, err := results[idx].(*redis.Cmd).Result()
					if err != nil && !errors.Is(err, redis.Nil) {
						pipelineResults = append(pipelineResults, Error{fmt.Sprintf("%v", err)})
						continue
					}

					pipelineResults = append(pipelineResults, Result{r})
				}
			}
		}

		jsonresp, _ := json.Marshal(pipelineResults)

		w.Header().Add("content-type", "application/json")
		w.Header().Add("content-length", fmt.Sprintf("%d", (len(jsonresp))))
		w.WriteHeader(http.StatusOK)

		_, werr := w.Write(jsonresp)
		if werr != nil {
			log.Println(werr)
		}
	}
}

func txHandler(ctx context.Context, redisClient *redis.Client, um UserMap, auth authFunc) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		role, ok := auth(w, r, um)
		if !ok {
			return
		}

		validJSONMethod := r.Method == http.MethodPost || r.Method == http.MethodPut

		if !validJSONMethod {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		icmd := []interface{}{}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			handleErr(w, err)

			return
		}

		err = json.Unmarshal(body, &icmd)
		if err != nil {
			handleErr(w, err)

			return
		}

		results, txErr := redisClient.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			for _, cmd := range icmd {
				c, ok := cmd.([]interface{})
				if !ok {
					pipe.Discard()
					return fmt.Errorf("EXECABORT: internal parsing err for: %v", cmd)
				}

				strCmd, ok := c[0].(string)
				if !ok {
					pipe.Discard()
					return fmt.Errorf("EXECABORT: internal parsing err for %v", c[0])
				}

				err := validateCommand(strCmd, role.AllowedCommands())
				if err != nil {
					pipe.Discard()
					return err
				}

				pipe.Do(ctx, c...)
			}

			return nil
		})

		// Our internal EXECABORTs aren't considered "redis errors"
		if txErr != nil && (redis.HasErrorPrefix(txErr, "EXECABORT") || strings.HasPrefix(txErr.Error(), "EXECABORT") || strings.HasPrefix(txErr.Error(), "NOPERM")) {
			handleErr(w, txErr)

			return
		}

		pipelineResults := make([]interface{}, 0, len(results))

		for _, result := range results {
			r, err := result.(*redis.Cmd).Result()
			if err != nil && !errors.Is(err, redis.Nil) {
				pipelineResults = append(pipelineResults, Error{fmt.Sprintf("%v", err)})
			} else {
				pipelineResults = append(pipelineResults, Result{r})
			}
		}

		jsonresp, _ := json.Marshal(pipelineResults)

		w.Header().Add("content-type", "application/json")
		w.Header().Add("content-length", fmt.Sprintf("%d", (len(jsonresp))))
		w.WriteHeader(http.StatusOK)

		_, werr := w.Write(jsonresp)
		if werr != nil {
			log.Println(werr)
		}
	}
}
