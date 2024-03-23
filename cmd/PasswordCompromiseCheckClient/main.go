package main

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/petrkamnev/password-compromise-check-server/pkg/PasswordCompromiseCheckClientLib"

	"github.com/schollz/progressbar/v3"
)

func main() {
	serverURL := "http://localhost:8080"
	bar := progressbar.Default(10001)
	for i := 0; i < 10001; i++ {
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

		bar.Add(1) // Increment the progress bar by 1 for each password processed
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
