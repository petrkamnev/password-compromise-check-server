package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var outputStateCmd = &cobra.Command{
	Use:   "output-state",
	Short: "Outputs information about the current state of the compromised passwords storage",
	Run: func(cmd *cobra.Command, args []string) {
		jsonMode, _ := cmd.Flags().GetBool("json")
		outputState(jsonMode)
	},
}

func initOutputStateCmd() {
	outputStateCmd.Flags().Bool("json", false, "Output in JSON format")
}

func outputState(jsonMode bool) {
	state, err := getState()
	if err != nil {
		fmt.Println(err)
		return
	}

	if jsonMode {
		data, err := json.Marshal(state)
		if err != nil {
			fmt.Println("Error marshalling state:", err)
			return
		}
		fmt.Println(string(data))
	} else {
		fmt.Printf("Supported Hash Functions: %v\n", state.SupportedHashFunctions)
	}
}

func getState() (*State, error) {
	state, err := readStateFile()
	if err != nil {
		return nil, fmt.Errorf("Error retrieving state: %v", err)
	}
	return state, nil
}

type State struct {
	SupportedHashFunctions []string `json:"supported_hash_functions"`
}

func readStateFile() (*State, error) {
	path := filepath.Join(getStoragePath(), "state.json")
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &State{SupportedHashFunctions: []string{}}, nil
		}
		return nil, err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	state := &State{}
	err = decoder.Decode(state)
	if err != nil {
		return nil, err
	}
	return state, nil
}

func updateStateFile(newFunc string) error {
	state, err := readStateFile()
	if err != nil {
		return fmt.Errorf("failed to read state file: %v", err)
	}
	found := false
	for _, funcName := range state.SupportedHashFunctions {
		if funcName == newFunc {
			found = true
			break
		}
	}
	if !found {
		state.SupportedHashFunctions = append(state.SupportedHashFunctions, newFunc)
	}

	path := filepath.Join(getStoragePath(), "state.json")
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create state file: %v", err)
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(state)
	if err != nil {
		return fmt.Errorf("failed to encode state: %v", err)
	}
	return nil
}

func getSupportedHashFunctions() ([]string, error) {
	path := filepath.Join(getStoragePath(), "state.json")
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open state file: %v", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	state := &State{}
	if err = decoder.Decode(state); err != nil {
		return nil, fmt.Errorf("failed to decode state file: %v", err)
	}

	return state.SupportedHashFunctions, nil
}
