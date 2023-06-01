package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
)

type Role string

func (r Role) AllowedCommands() map[string]int {
	switch r {
	case readOnly:
		return AllowedROCommands
	case readWrite:
		return AllowedRWCommands
	default:
		return nil
	}
}

const (
	readWrite Role = "rw"
	readOnly  Role = "ro"
)

type UserMap map[string]UserDetails
type UserDetails struct {
	Role     Role   `json:"role"`
	TokenSHA string `json:"tokenSHA"`
}

func loadUsers(mapFilename string) (UserMap, error) {
	f, err := os.Open(mapFilename)
	if err != nil {
		return UserMap{}, err
	}
	defer f.Close()

	um := UserMap{}

	raw, err := io.ReadAll(f)
	if err != nil {
		return UserMap{}, err
	}

	err = json.Unmarshal(raw, &um)
	if err != nil {
		return UserMap{}, err
	}

	for u, d := range um {
		if d.Role != readWrite && d.Role != readOnly {
			log.Printf("mapfile %s: %s has invalid role: %s, ignoring", mapFilename, u, d.Role)
			delete(um, u)
		}
	}

	return um, nil
}

func lookupUser(user string, userMap UserMap) (UserDetails, error) {
	if userMap == nil {
		return UserDetails{}, fmt.Errorf("user map is nil")
	}

	details, ok := userMap[user]
	if !ok {
		return UserDetails{}, fmt.Errorf("user not found")
	}

	return details, nil
}
