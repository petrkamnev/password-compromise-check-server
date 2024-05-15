package main

import (
	"bufio"
	"fmt"
	"math/rand"
	"net/http"
	"path/filepath"
	"strconv"

	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	psi_ds "github.com/openmined/psi/datastructure"
	psi_proto "github.com/openmined/psi/pb"
	psi_server "github.com/openmined/psi/server"
	"github.com/pkg/xattr"
	"google.golang.org/protobuf/proto"
)

var serverCmd = &cobra.Command{
	Use:   "run-server",
	Short: "Run the server",
	Long:  `Run the server with specified options.`,
	Run: func(cmd *cobra.Command, args []string) {
		port, _ := cmd.Flags().GetInt("port")
		addr := fmt.Sprintf(":%d", port)
		mode, _ := cmd.Flags().GetString("mode")
		if mode == "psi" {
			http.HandleFunc("/psi/", handlePSI)
		} else if mode == "hash" {
			http.HandleFunc("/range/", handleRange)
			http.HandleFunc("/pwnedpassword/", handlePwnedPassword)
		} else {
			fmt.Println("Error: incorrect \"mode\" option value")
			return
		}

		supportedHashFunctions, err := getSupportedHashFunctions()
		if err != nil || len(supportedHashFunctions) == 0 {
			fmt.Printf("Error: No hash functions are imported or unable to read state: %v\n", err)
			return
		}

		if !quietFlag {
			fmt.Printf("Server started on localhost%s\nSupported hash functions: %v\n", addr, supportedHashFunctions)
		}
		if err := http.ListenAndServe(addr, nil); err != nil {
			fmt.Println("Error starting server:", err)
		}
	},
}

func initServerCmd() {
	serverCmd.Flags().IntP("port", "p", 8080, "Port to run the server on")
	serverCmd.Flags().StringP("mode", "m", "hash", "Password checking mode (protocol): \"hash\", \"psi\"")
}

func handleRange(w http.ResponseWriter, r *http.Request) {
	prefix := strings.ToUpper(strings.TrimPrefix(r.URL.Path, "/range/"))
	mode := r.URL.Query().Get("mode")
	if mode != "ntlm" {
		mode = "sha1"
	}

	// Check if the requested mode is supported
	supportedHashFunctions, err := getSupportedHashFunctions()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Error checking supported hash functions"))
		return
	}

	isSupported := false
	for _, m := range supportedHashFunctions {
		if m == mode {
			isSupported = true
			break
		}
	}

	if !isSupported {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("Requested hash function '%s' is not supported", mode)))
		return
	}

	folderPath := mode

	// Construct the filename based on the given prefix
	filename := filepath.Join(getStoragePath(), folderPath, prefix+".txt")

	// Check if the file exists
	_, err = os.Stat(filename)
	if os.IsNotExist(err) {
		// If the file doesn't exist, set the response code to 400 and write the error message to the response body
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("The hash prefix was not in a valid format"))
		return
	}

	// Open the file
	file, err := os.Open(filename)
	if err != nil {
		// If there is an error opening the file, handle it (you may choose to log the error or handle it differently)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal Server Error"))
		return
	}
	defer file.Close()

	// Get file information
	fileInfo, err := file.Stat()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal Server Error"))
		return
	}

	// Caching
	modified := true
	ifModifiedSince := r.Header.Get("If-Modified-Since")
	ifNoneMatch := r.Header.Get("If-None-Match")
	etag, err := xattr.Get(filename, "user.etag")
	if (ifModifiedSince != "" && !fileInfo.ModTime().IsZero()) || (err == nil && ifNoneMatch != "") {
		modified = false
	}

	if ifModifiedSince != "" && !fileInfo.ModTime().IsZero() && fileInfo.ModTime().After(parseTime(ifModifiedSince)) {
		modified = true
	}
	if err == nil && ifNoneMatch != "" && ifNoneMatch != string(etag) {
		modified = true
	}
	if !modified {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	// Set Last-Modified header using the file's modification date, if it exists
	if !fileInfo.ModTime().IsZero() {
		w.Header().Set("Last-Modified", fileInfo.ModTime().UTC().Format(http.TimeFormat))
	}

	// Set ETag header, if the ETag exists
	if err == nil {
		w.Header().Set("ETag", string(etag))
	}

	// Handle Add-Padding header
	addPadding := r.Header.Get("Add-Padding") == "true"
	var responseContent string

	if !addPadding {
		fileSize := fileInfo.Size()
		fileContent := make([]byte, fileSize)
		_, err = file.Read(fileContent)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Internal Server Error"))
			return
		}
		responseContent = string(fileContent)
	} else {
		scanner := bufio.NewScanner(file)
		lineCount := 0
		for scanner.Scan() {
			lineCount++
		}
		if err := scanner.Err(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Internal Server Error"))
			return
		}

		// Generate dummy lines if necessary
		if lineCount < 1300 {
			numDummyLines := 1300 + rand.Intn(201) - lineCount
			dummyLines := make([]string, numDummyLines)
			for i := 0; i < numDummyLines; i++ {
				var dummySuffix string
				if mode == "ntlm" {
					dummySuffix = fmt.Sprintf("%027d", 0)
				} else {
					dummySuffix = fmt.Sprintf("%035d", 0)
				}
				dummyLines[i] = dummySuffix + ":0"
			}

			// Read the file content again and append dummy lines
			file.Seek(0, 0)
			fileContent, err := io.ReadAll(file)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("Internal Server Error"))
				return
			}
			responseContent = string(fileContent) + "\n" + strings.Join(dummyLines, "\n")
		} else {
			// Read the file content directly if no padding is needed
			file.Seek(0, 0)
			fileContent, err := io.ReadAll(file)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("Internal Server Error"))
				return
			}
			responseContent = string(fileContent)
		}
	}

	// Set the response code to 200
	w.WriteHeader(http.StatusOK)

	// Write the response content to the response body
	w.Write([]byte(responseContent))
}

func parseTime(value string) time.Time {
	if value == "" {
		return time.Time{}
	}
	parsedTime, err := time.Parse(http.TimeFormat, value)
	if err != nil {
		return time.Time{}
	}
	return parsedTime
}

func handlePwnedPassword(w http.ResponseWriter, r *http.Request) {
	mode := r.URL.Query().Get("mode")
	if mode != "ntlm" {
		mode = "sha1"
	}

	// Check if the requested mode is supported
	supportedHashFunctions, err := getSupportedHashFunctions()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Error checking supported hash functions"))
		return
	}

	isSupported := false
	for _, m := range supportedHashFunctions {
		if m == mode {
			isSupported = true
			break
		}
	}

	if !isSupported {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("Requested hash function '%s' is not supported", mode)))
		return
	}

	// Extract the hash value from the URL
	hashValue := strings.ToUpper(strings.TrimPrefix(r.URL.Path, "/pwnedpassword/"))

	// Validate the hash format
	if (mode == "sha1" && len(hashValue) != 40) || (mode == "ntlm" && len(hashValue) != 32) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("The hash was not in a valid format"))
		return
	}

	// Extract prefix and suffix
	prefix := hashValue[:5]
	suffix := hashValue[5:]

	// Construct the filename based on the given prefix
	filename := filepath.Join(getStoragePath(), mode, prefix+".txt")

	// Check if the file exists
	_, err = os.Stat(filename)
	if os.IsNotExist(err) {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Open the file
	file, err := os.Open(filename)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal Server Error"))
		return
	}
	defer file.Close()

	// Read the file line by line and check for the suffix
	var count int
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, suffix) {
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				count, err = strconv.Atoi(parts[1])
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte("Internal Server Error"))
					return
				}
				break
			}
		}
	}

	if err := scanner.Err(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal Server Error"))
		return
	}

	if count == 0 {
		w.WriteHeader(http.StatusNotFound)
	} else {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, count)
	}
}

func handlePSI(w http.ResponseWriter, r *http.Request) {
	prefix := strings.ToUpper(strings.TrimPrefix(r.URL.Path, "/psi/"))
	mode := r.URL.Query().Get("mode")
	if mode != "ntlm" {
		mode = "sha1"
	}

	// Check if the requested mode is supported
	supportedHashFunctions, err := getSupportedHashFunctions()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Error checking supported hash functions"))
		return
	}

	isSupported := false
	for _, m := range supportedHashFunctions {
		if m == mode {
			isSupported = true
			break
		}
	}

	if !isSupported {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("Requested hash function '%s' is not supported", mode)))
		return
	}
	folderPath := mode

	// Determine the storage subdirectory based on the mode parameter
	if mode == "ntlm" {
		folderPath = "ntlm"
	} else {
		folderPath = "sha1"
	}

	// Construct the filename based on the given prefix
	filename := filepath.Join(getStoragePath(), folderPath, prefix+".txt")

	// Read the request body
	requestBody, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}

	psiRequest := &psi_proto.Request{}
	err = proto.Unmarshal(requestBody, psiRequest)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to deserialize request: %v", err), http.StatusBadRequest)
		return
	}

	// Check if the file exists
	_, err = os.Stat(filename)
	if os.IsNotExist(err) {
		http.Error(w, "The hash prefix was not in a valid format", http.StatusBadRequest)
		return
	}

	// Open the file
	file, err := os.Open(filename)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	// Get file information
	fileInfo, err := file.Stat()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	fileSize := fileInfo.Size()
	fileContent := make([]byte, fileSize)
	_, err = file.Read(fileContent)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Split file content into lines
	lines := strings.Split(string(fileContent), "\n")

	// Extract values from lines
	var values []string
	for _, line := range lines {
		parts := strings.Split(line, ":")
		if len(parts) == 2 {
			values = append(values, strings.TrimSpace(parts[0]))
		}
	}

	server, err := psi_server.CreateWithNewKey(true)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create a PSI server: %v", err), http.StatusInternalServerError)
		return
	}

	serverSetup, err := server.CreateSetupMessage(0, 1, values, psi_ds.Raw)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create serverSetup: %v", err), http.StatusInternalServerError)
		return
	}
	serializedServerSetup, err := proto.Marshal(serverSetup)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to serialize serverSetup: %v", err), http.StatusInternalServerError)
		return
	}

	response, err := server.ProcessRequest(psiRequest)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to process request: %v", err), http.StatusInternalServerError)
		return
	}
	serializedResponse, err := proto.Marshal(response)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to serialize response: %v", err), http.StatusInternalServerError)
		return
	}

	// Send the serialized response back to the client
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("PSI-Response-Length", fmt.Sprint(len(serializedResponse)))
	w.Header().Set("PSI-Setup-Length", fmt.Sprint(len(serializedServerSetup)))
	w.WriteHeader(http.StatusOK)
	w.Write(serializedResponse)
	w.Write(serializedServerSetup)
}
