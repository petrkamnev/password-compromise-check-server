package main

import (
	"flag"
	"fmt"

	"github.com/petrkamnev/password-compromise-check-server/pkg/PasswordCompromiseCheckClientLib"
)

func main() {
	mode := flag.String("mode", "sha1", "The mode of the server (\"sha1\", \"ntlm\", \"psi\")")
	password := flag.String("password", "", "The password to check")
	url := flag.String("url", "", "The password compromise check server url")
	flag.Parse()
	if *mode == "sha1" {
		result, err := PasswordCompromiseCheckClientLib.CheckSHA1Password(*password, *url)
		if err != nil {
			fmt.Println("Error checking password:", err)
			return
		}
		fmt.Println(result)
	} else if *mode == "ntlm" {
	} else if *mode == "psi" {
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
