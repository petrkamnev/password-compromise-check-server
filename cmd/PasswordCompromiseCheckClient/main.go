package main

import (
	"flag"
	"fmt"

	"github.com/petrkamnev/password-compromise-check-server/pkg/PasswordCompromiseCheckClientLib"
)

func main() {
	mode := flag.String("mode", "SHA-1", "The mode of the server (\"SHA-1\", \"NTLM\", \"PSI\")")
	password := flag.String("password", "", "The password to check")
	url := flag.String("url", "", "The password compromise check server url")
	flag.Parse()
	if *mode == "SHA-1" {
		result, err := PasswordCompromiseCheckClientLib.CheckSHA1Password(*password, *url)
		if err != nil {
			fmt.Println("Error checking password:", err)
			return
		}
		fmt.Println(result)
	} else if *mode == "NTLM" {
	} else if *mode == "PSI" {
		result, err := PasswordCompromiseCheckClientLib.CheckSHA1PSIPassword(*password, *url)
		if err != nil {
			fmt.Println("Error checking password:", err)
			return
		}
		fmt.Println(result)
	} else {
		flag.Usage()
		return
	}

}
