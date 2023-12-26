package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

var storagePath = "./storage"

func main() {
	http.HandleFunc("/range/", handleRange)
	http.HandleFunc("/pwnedpassword/", handlePwnedPassword)

	port := ":8080"
	fmt.Printf("Server listening on port %s...\n", port)
	http.ListenAndServe(port, nil)
}

func handleRange(w http.ResponseWriter, r *http.Request) {
	prefix := strings.ToUpper(strings.TrimPrefix(r.URL.Path, "/range/"))
	mode := r.URL.Query().Get("mode")
	//addPadding := r.Header.Get("Add-Padding") == "true"
	ifModifiedSince := r.Header.Get("If-Modified-Since")
	if mode != "ntlm" {
		// Construct the filename based on the given prefix
		filename := "./storage/" + prefix + ".txt"

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
