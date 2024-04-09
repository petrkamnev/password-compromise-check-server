package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "pccserver",
	Short: "pccserver is an application for deploying a HIBP-like server for checking password compromise",
	Long:  `examples:`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func getStoragePath() string {
	storagePath := os.Getenv("STORAGE_PATH")
	if storagePath == "" {
		// Default value if not set
		storagePath = "./"
	}
	return storagePath
}
