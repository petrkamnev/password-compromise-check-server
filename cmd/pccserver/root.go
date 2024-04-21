package main

import (
	"fmt"
	"os"

	"path/filepath"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "pccserver",
	Short: "pccserver is an application for deploying a HIBP-like server for checking password compromise",
	Long:  `examples:`,
}

func init() {
	initServerCmd()
	initImportCmd()
	rootCmd.AddCommand(serverCmd)
	rootCmd.AddCommand(importCmd)
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
		configDir, err := os.UserConfigDir()
		if err != nil {
			storagePath = "./storage/"
		} else {
			storagePath = filepath.Join(configDir, "pccserver", "storage")
		}
	}

	return storagePath
}
