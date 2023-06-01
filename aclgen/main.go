package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

type UserDetails struct {
	Role  string `json:"role"`
	Token string `json:"tokenSHA"`
}

func token() (string, error) {
	var bytes [32]byte

	_, err := rand.Read(bytes[:])
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(bytes[:]), nil
}

func main() {
	fmt.Println("[!] Generating tokens these will not be shown again!")

	users := map[string]UserDetails{
		"readwrite": {
			Role: "rw",
		},
		"readonly": {
			Role: "ro",
		},
	}

	for username, details := range users {
		token, err := token()
		if err != nil {
			panic(err)
		}

		fmt.Printf("%s:%s\n", username, token)

		details.Token = token

		h := sha256.New()
		h.Write([]byte(token))

		hashedToken := fmt.Sprintf("%x", h.Sum(nil))
		details.Token = hashedToken
		users[username] = details
	}

	fmt.Println("[!] Rendering redis-users.json")

	m, err := os.Create("redis-users.json")
	if err != nil {
		panic(err)
	}
	defer m.Close()

	jsonUsers, err := json.Marshal(users)
	if err != nil {
		panic(err)
	}

	_, err = fmt.Fprintf(m, "%s\n", jsonUsers)
	if err != nil {
		panic(err)
	}
}
