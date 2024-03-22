package main

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/petrkamnev/password-compromise-check-server/pkg/PasswordCompromiseCheckClientLib"
)

func main() {
	serverURL := "http://localhost:8080"
	for i := 0; i < 100; i++ {
		password := generateRandomPassword()

		if rand.Intn(2) == 0 {
			_, err := PasswordCompromiseCheckClientLib.CheckSHA1Password(password, serverURL, i)
			if err != nil {
				fmt.Println("Error checking SHA1 password:", err)
				continue
			}
		} else {
			_, err := PasswordCompromiseCheckClientLib.CheckSHA1PSIPassword(password, serverURL, i)
			if err != nil {
				fmt.Println("Error checking SHA1 PSI password:", err)
				continue
			}
		}
	}
}

func generateRandomPassword() string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	passwordLength := 6
	rand.Seed(time.Now().UnixNano())
	b := make([]rune, passwordLength)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
