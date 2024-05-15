package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/pkg/xattr"

	"github.com/avast/retry-go"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

var importCmd = &cobra.Command{
	Use:   "import-values",
	Short: "Import the values of compromised passwords",
	Long:  `Import or update the password compromise checking server storage.`,
	Run: func(cmd *cobra.Command, args []string) {
		hashFunction, _ := cmd.Flags().GetString("hash-function")
		if hashFunction != "sha1" && hashFunction != "ntlm" {
			fmt.Printf("Error: incorrect \"hash-function\" parameter value. Allowed values: \"sha1\", \"ntlm\"\n")
			return
		}
		url, _ := cmd.Flags().GetString("url")
		importFilePath, _ := cmd.Flags().GetString("file")
		forceRewrite, _ := cmd.Flags().GetBool("force-rewrite")
		//TODO: state checks (sha1, ntlm)
		if *&importFilePath == "" {
			var cpd CompromisedPasswordsAPIImporter
			cpd.url = url
			cpd.client = &http.Client{}
			cpd.mode = hashFunction
			cpd.forceRewrite = forceRewrite
			err := cpd.downloadAllPrefixes()
			if err != nil {
				fmt.Printf("Error downloading prefixes: %v\n", err)
			} else {
				updateStateFile(hashFunction)
			}
		} else {
			var cpi CompromisedPasswordsFileImporter
			cpi.filename = importFilePath
			cpi.mode = hashFunction
			err := cpi.importAllPrefixes()
			if err != nil {
				fmt.Printf("Error downloading prefixes: %v\n", err)
			} else {
				updateStateFile(hashFunction)
			}
		}
	},
}

func initImportCmd() {
	importCmd.Flags().String("hash-function", "sha1", "Hash function for password checking: \"sha1\", \"ntlm\"")
	importCmd.Flags().StringP("url", "u", "https://api.pwnedpasswords.com/range/", "External password compromise checking API URL for import")
	importCmd.Flags().StringP("file", "f", "", "File with compromised password hashes for import. If this parameter is given, the \"url\" parameter is ignored")
	importCmd.Flags().Bool("force-rewrite", false, "Do not use caching headers for storage update optimization")
}

const HIBPPrefixesCount = 1 << 20

type CompromisedPasswordsAPIImporter struct {
	client       *http.Client
	url          string
	mode         string
	forceRewrite bool
}

func (downloader *CompromisedPasswordsAPIImporter) downloadAllPrefixes() error {
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, min(runtime.NumCPU()*8, 64))
	var bar *progressbar.ProgressBar
	if !quietFlag {
		bar = progressbar.Default(HIBPPrefixesCount)
	}
	directory := filepath.Join(getStoragePath(), downloader.mode)
	if err := os.MkdirAll(directory, 0755); err != nil {
		return fmt.Errorf("Failed to create directory: %v", err)
	}
	// Use a channel to communicate errors from goroutines
	errCh := make(chan error, (HIBPPrefixesCount))

	// Iterate from 0 to 2^20 - 1
	for i := 0; i < (HIBPPrefixesCount); i++ {
		wg.Add(1)
		semaphore <- struct{}{} // Acquire semaphore
		go func(prefix int) {
			defer func() {
				<-semaphore // Release semaphore
				wg.Done()
			}()
			err := downloader.downloadByPrefix(prefix)
			if err != nil {
				fmt.Printf("Error downloading for prefix %d: %v\n", prefix, err)
				errCh <- err
			}
			if bar != nil {
				bar.Add(1)
			}
		}(i)
	}

	go func() {
		wg.Wait()
		close(errCh)
	}()

	// Check for errors from goroutines
	for err := range errCh {
		if err != nil {
			return err
		}
	}

	return nil
}

func (downloader *CompromisedPasswordsAPIImporter) downloadByPrefix(prefix int) error {
	prefixHex := strings.ToUpper(fmt.Sprintf("%05x", prefix))
	filename := filepath.Join(getStoragePath(), downloader.mode+"/"+prefixHex+".txt")
	url := downloader.url + prefixHex
	if downloader.mode == "ntlm" {
		url += "?mode=ntlm"
	}
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	request.Header.Set("User-Agent", "CompromisedPasswordsImporter")
	localETag, err := xattr.Get(filename, "user.etag")
	if err == nil && !downloader.forceRewrite {
		request.Header.Set("If-None-Match", string(localETag))
	}
	var response *http.Response
	err = retry.Do(
		func() error {
			var err error
			response, err = downloader.client.Do(request)
			return err
		},
		retry.Attempts(10),
		retry.OnRetry(func(n uint, err error) {
			log.Printf("Retrying request: %v", err)
		}),
	)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotModified {
		// No update needed; local file is up-to-date
		return nil
	}
	lastModifiedHeader := response.Header.Get("Last-Modified")
	lastModifiedDate, err := time.Parse(time.RFC1123, lastModifiedHeader)
	if err != nil {
		lastModifiedDate = time.Now().Local()
	}

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	// Copy the response body to the file
	_, err = io.Copy(file, response.Body)
	if err != nil {
		return err
	}
	err = os.Chtimes(filename, lastModifiedDate, lastModifiedDate)
	if err != nil {
		return err
	}

	if etag := response.Header.Get("ETag"); etag != "" {
		if err := xattr.Set(filename, "user.etag", []byte(etag)); err != nil {
			return err
		}
	}

	return nil
}

type CompromisedPasswordsFileImporter struct {
	filename string
	mode     string
}

func (importer *CompromisedPasswordsFileImporter) importAllPrefixes() error {
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, min(runtime.NumCPU()*8, 64))
	var bar *progressbar.ProgressBar
	if !quietFlag {
		bar = progressbar.Default(HIBPPrefixesCount)
	}
	directory := filepath.Join(getStoragePath(), importer.mode)
	if err := os.MkdirAll(directory, 0755); err != nil {
		return fmt.Errorf("Failed to create directory: %v", err)
	}

	// Use a channel to communicate errors from goroutines
	errCh := make(chan error, (HIBPPrefixesCount))

	// Iterate from 0 to 2^20 - 1
	for i := 0; i < (HIBPPrefixesCount); i++ {
		wg.Add(1)
		semaphore <- struct{}{} // Acquire semaphore
		go func(prefix int) {
			defer func() {
				<-semaphore // Release semaphore
				wg.Done()
			}()
			err := importer.importByPrefix(prefix)
			if err != nil {
				fmt.Printf("Error importing for prefix %d: %v\n", prefix, err)
				errCh <- err
			}
			bar.Add(1)
		}(i)
	}

	go func() {
		wg.Wait()
		close(errCh)
	}()

	// Check for errors from goroutines
	for err := range errCh {
		if err != nil {
			return err
		}
	}

	return nil
}

func (importer *CompromisedPasswordsFileImporter) importByPrefix(prefix int) error {
	prefixHex := strings.ToUpper(fmt.Sprintf("%05x", prefix))
	filename := filepath.Join(getStoragePath(), importer.mode+"/"+prefixHex+".txt")
	data, err := importer.readDataForPrefix(prefixHex)
	if err != nil {
		return err
	}

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(data)
	if err != nil {
		return err
	}

	currentDate := time.Now()
	err = os.Chtimes(filename, currentDate, currentDate)
	if err != nil {
		return err
	}

	return nil
}

// getRange retrieves the Pwned password leak record range from the data file.
func (importer *CompromisedPasswordsFileImporter) readDataForPrefix(prefix string) (string, error) {
	// Helper function to find the offset
	findOffset := func(start, end int64, dataFile *os.File) int64 {
		var mid int64
		for start+1 < end {
			mid = (start + end) / 2
			dataFile.Seek(mid, 0)
			reader := bufio.NewReader(dataFile)
			reader.ReadString('\n') // Skip possibly partial line
			line, err := reader.ReadString('\n')
			if err != nil {
				break // EOF
			}
			linePrefix := line[:5]
			if linePrefix < prefix {
				start = mid
			} else {
				end = mid
			}
		}
		if start != 0 {
			return end
		}
		return start
	}

	// Open the data file
	file, err := os.Open(importer.filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// Find start offset of the prefix
	var startOffset int64
	file.Seek(0, 2) // Move to end of file to get size
	endOffset, _ := file.Seek(0, 1)
	startOffset = findOffset(0, endOffset, file)
	// Read and process the lines between the found offsets
	file.Seek(startOffset, 0)

	results := []string{}
	scanner := bufio.NewScanner(file)
	if startOffset != 0 {
		scanner.Scan()
	}
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, prefix) {
			break
		}
		results = append(results, strings.TrimSpace(line[5:]))
	}
	return strings.Join(results, "\n"), nil
}

var exportCmd = &cobra.Command{
	Use:   "export-values",
	Short: "Export compromised passwords",
	Long:  `Export compromised passwords to a file.`,
	Run: func(cmd *cobra.Command, args []string) {
		mode, _ := cmd.Flags().GetString("mode")
		if mode != "sha1" && mode != "ntlm" {
			fmt.Printf("Error: incorrect \"mode\" parameter value. Allowed values: \"sha1\", \"ntlm\"\n")
			return
		}
		filePath, _ := cmd.Flags().GetString("file")
		if filePath == "" {
			fmt.Println("Error: file path must be specified with -f or --file")
			return
		}
		err := exportHashValues(mode, filePath)
		if err != nil {
			fmt.Printf("Error exporting hash values: %v\n", err)
			return
		}
	},
}

func initExportCmd() {
	exportCmd.Flags().StringP("mode", "m", "sha1", "Hash function to validate (SHA-1 or NTLM)")
	exportCmd.Flags().StringP("file", "f", "", "Path to the file for saving hash values")
}

func exportHashValues(mode, filePath string) error {
	// Check if the requested mode is supported
	supportedHashFunctions, err := getSupportedHashFunctions()
	if err != nil {
		return fmt.Errorf("error checking supported hash functions: %w", err)
	}

	isSupported := false
	for _, m := range supportedHashFunctions {
		if m == mode {
			isSupported = true
			break
		}
	}

	if !isSupported {
		return fmt.Errorf("unsupported hash function: %s", mode)
	}

	// Open the file to write the hash values
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer file.Close()

	var bar *progressbar.ProgressBar
	if !quietFlag {
		bar = progressbar.Default(HIBPPrefixesCount)
	}

	// Iterate over all possible prefixes
	for i := 0; i <= 0xFFFFF; i++ { // Hexadecimal range from 0x00000 to 0xFFFFF
		prefix := fmt.Sprintf("%05X", i)
		data, err := fetchHashData(prefix, mode)
		if err != nil {
			return err
		}
		_, err = file.WriteString(data + "\n")
		if err != nil {
			return fmt.Errorf("failed to write to file: %v", err)
		}
		if bar != nil {
			bar.Add(1)
		}
	}

	return nil
}

func fetchHashData(prefix, mode string) (string, error) {
	folderPath := mode
	filename := filepath.Join(getStoragePath(), folderPath, prefix+".txt")

	file, err := os.Open(filename)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var result strings.Builder
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			// Append the prefix and the line content
			result.WriteString(fmt.Sprintf("%s%s\n", prefix, line))
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("error reading file: %v", err)
	}

	return result.String(), nil
}
