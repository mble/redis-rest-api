package main

import (
	"bytes"
	"io"
	"log"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestAllowedCommands(t *testing.T) {
	testCases := []struct {
		expectedCommands map[string]int
		desc             string
		role             Role
	}{
		{
			desc:             "rw",
			role:             "rw",
			expectedCommands: AllowedRWCommands,
		},
		{
			desc:             "ro",
			role:             "ro",
			expectedCommands: AllowedROCommands,
		},
		{
			desc:             "missing_role",
			role:             "gg",
			expectedCommands: nil,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			if !reflect.DeepEqual(tC.expectedCommands, tC.role.AllowedCommands()) {
				t.Errorf("expected: %+v, got: %+v", tC.expectedCommands, tC.role.AllowedCommands())
			}
		})
	}
}

func TestLoadUsers(t *testing.T) {
	log.SetOutput(io.Discard)
	t.Run("empty filepath", func(t *testing.T) {
		const mapFilename = ""

		_, err := loadUsers(mapFilename)
		if err == nil {
			t.Errorf("expected err != nil")
		}
	})

	t.Run("unmarshal fail", func(t *testing.T) {
		file, err := os.CreateTemp("", "oops-test.json")
		if err != nil {
			t.Fatal(err)
		}
		file.Close()

		_, err = loadUsers(file.Name())
		if err == nil {
			t.Errorf("expected err != nil")
		}
	})

	t.Run("handles invalid roles", func(t *testing.T) {
		var buf bytes.Buffer
		log.SetOutput(&buf)
		defer func() {
			log.SetOutput(io.Discard)
		}()

		const mapFilename = "testdata/redis-users-test.json"

		um, err := loadUsers(mapFilename)
		if err != nil {
			t.Fatalf("expected err == nil, got %v", err)
		}

		expectedUsers := []string{"readonly", "readwrite"}
		users := make([]string, len(um))

		i := 0
		for k := range um {
			users[i] = k
			i++
		}

		if !strings.Contains(buf.String(), "garbo has invalid role: gg") {
			t.Error("expected ignore message to be logged")
			t.Log(buf.String())
		}

		sort.Strings(expectedUsers)
		sort.Strings(users)

		if !reflect.DeepEqual(expectedUsers, users) {
			t.Errorf("expected: %+v, got: %+v", expectedUsers, users)
		}
	})
}

func TestLookupUser(t *testing.T) {
	t.Run("nil usermap", func(t *testing.T) {
		user := "foo"
		expectedErr := "user map is nil"

		_, err := lookupUser(user, nil)
		if err == nil {
			t.Fatal("expected: err, got: nil")
		}

		if err.Error() != expectedErr {
			t.Errorf("expected: %s, got: %s", expectedErr, err.Error())
		}
	})

	t.Run("user not found", func(t *testing.T) {
		user := "foo"
		expectedErr := "user not found"
		um := UserMap{
			"readwrite": UserDetails{},
		}

		_, err := lookupUser(user, um)
		if err == nil {
			t.Error("expected: err, got: nil")
		}

		if err.Error() != expectedErr {
			t.Errorf("expected: %s, got: %s", expectedErr, err.Error())
		}
	})

	t.Run("user found", func(t *testing.T) {
		user := "readwrite"
		expectedDetails := UserDetails{
			Role:     "rw",
			TokenSHA: "foobar",
		}
		um := UserMap{
			"readwrite": expectedDetails,
		}

		details, err := lookupUser(user, um)
		if err != nil {
			t.Fatalf("expected: err == nil, got: %s", err)
		}

		if !reflect.DeepEqual(expectedDetails, details) {
			t.Errorf("expected: %+v, got: %+v", expectedDetails, details)
		}
	})
}
