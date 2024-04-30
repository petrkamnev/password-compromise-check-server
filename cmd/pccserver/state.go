package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

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
