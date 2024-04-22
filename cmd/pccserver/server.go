package main

import (
	"fmt"
	"net/http"
	"path/filepath"

	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	psi_ds "github.com/openmined/psi/datastructure"
	psi_proto "github.com/openmined/psi/pb"
	psi_server "github.com/openmined/psi/server"
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
		//TODO: state checks (sha1, ntlm)
		if mode == "psi" {
			http.HandleFunc("/psi/", handlePSI)
		} else if mode == "hash" {
			http.HandleFunc("/range/", handleRange)
			http.HandleFunc("/pwnedpassword/", handlePwnedPassword)
		} else {
			fmt.Println("Error: ")
		}

		fmt.Printf("Server started on localhost%s\n", addr)
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
	var folderPath string

	// Determine the storage subdirectory based on the mode parameter
	if mode == "ntlm" {
		folderPath = "ntlm"
	} else {
		folderPath = "sha1"
	}

	// Construct the filename based on the given prefix
	filename := filepath.Join(getStoragePath(), folderPath, prefix+".txt")

	// Check if the file exists
	_, err := os.Stat(filename)
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

	// Check if the file creation date is later than If-Modified-Since
	ifModifiedSince := r.Header.Get("If-Modified-Since")
	if ifModifiedSince != "" && !fileInfo.ModTime().IsZero() && !fileInfo.ModTime().Before(parseTime(ifModifiedSince)) {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	fileSize := fileInfo.Size()
	fileContent := make([]byte, fileSize)
	_, err = file.Read(fileContent)
	if err != nil {
		// If there is an error reading the file, handle it (you may choose to log the error or handle it differently)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal Server Error"))
		return
	}

	// Set Last-Modified header using the file creation date
	w.Header().Set("Last-Modified", fileInfo.ModTime().UTC().Format(http.TimeFormat))

	// Set the response code to 200
	w.WriteHeader(http.StatusOK)

	// Write the file content to the response body
	w.Write(fileContent)
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
	//hashValue := strings.TrimPrefix(r.URL.Path, "/pwnedpassword/")
	//count, err := getCount(hashValue)
	//if err != nil {
	//	http.Error(w, err.Error(), http.StatusInternalServerError)
	//	return
	//}

	//if count == 0 {
	//	http.NotFound(w, r)
	//	return
	//}

	//fmt.Fprint(w, count)
	//w.WriteHeader(http.StatusOK)
}

func handlePSI(w http.ResponseWriter, r *http.Request) {
	prefix := strings.ToUpper(strings.TrimPrefix(r.URL.Path, "/psi/"))
	mode := r.URL.Query().Get("mode")
	var folderPath string

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
		fmt.Errorf("Failed to deserialize request: %v", err)
	}

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

	fileSize := fileInfo.Size()
	fileContent := make([]byte, fileSize)
	_, err = file.Read(fileContent)
	if err != nil {
		// If there is an error reading the file, handle it (you may choose to log the error or handle it differently)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal Server Error"))
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
		fmt.Errorf("Failed to create a PSI server %v", err)
	}

	// Create the setup
	serverSetup, err := server.CreateSetupMessage(0, 1, values, psi_ds.Raw)
	if err != nil {
		fmt.Errorf("Failed to create serverSetup: %v", err)
	}
	serializedServerSetup, err := proto.Marshal(serverSetup)
	if err != nil {
		fmt.Errorf("Failed to serialize serverSetup: %v", err)
	}

	// Get the response
	response, err := server.ProcessRequest(psiRequest)
	if err != nil {
		fmt.Errorf("Failed to process request: %v", err)
	}
	serializedResponse, err := proto.Marshal(response)
	if err != nil {
		fmt.Errorf("Failed to serialize response: %v", err)
	}

	// Send the serialized response back to the client
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("PSI-Response-Length", fmt.Sprint(len(serializedResponse)))
	w.Header().Set("PSI-Setup-Length", fmt.Sprint(len(serializedServerSetup)))
	w.WriteHeader(http.StatusOK) // Set the response code before writing the body
	w.Write(serializedResponse)
	w.Write(serializedServerSetup)
}
