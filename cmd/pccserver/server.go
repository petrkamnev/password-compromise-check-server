package main

import (
	"fmt"
	"net/http"

	"github.com/spf13/cobra"
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run the server",
	Long:  `Run the server with specified options.`,
	Run: func(cmd *cobra.Command, args []string) {
		port, _ := cmd.Flags().GetInt("port")
		host, _ := cmd.Flags().GetString("host")
		addr := fmt.Sprintf("%s:%d", host, port)
		mode, _ := cmd.Flags().GetString("mode")
		//TODO: state checks (sha1, ntlm)
		if mode == "psi" {
			http.HandleFunc("/psi/", handlePSI)
		} else if mode == "hash" {
			http.HandleFunc("/range/", handleRange)
			http.HandleFunc("/pwnedpassword/", handlePwnedPassword)
		} else {
			fmt.Println("Error: ")
		}

		fmt.Printf("Starting server on %s\n", addr)
		if err := http.ListenAndServe(addr, nil); err != nil {
			fmt.Println("Error starting server:", err)
		} else {
			fmt.Println("Server started successfully")
		}

	},
}

func init() {
	serverCmd.Flags().IntP("port", "p", 8080, "Port to run the server on")
	serverCmd.Flags().String("host", "localhost", "Host address")
	serverCmd.Flags().StringP("mode", "m", "hash", "Password checking mode (protocol): \"hash\", \"psi\"")
	rootCmd.AddCommand(serverCmd)
}
