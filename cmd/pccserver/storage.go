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
		if *&importFilePath != "" {
			var cpd CompromisedPasswordsAPIImporter
			cpd.url = url
			cpd.client = &http.Client{}
			cpd.mode = hashFunction
			cpd.forceRewrite = forceRewrite
			err := cpd.downloadAllPrefixes()
			if err != nil {
				fmt.Printf("Error downloading prefixes: %v\n", err)
			}
		}
	},
}

func initImportCmd() {
	serverCmd.Flags().String("hash-function", "sha1", "Hash function for password checking: \"sha1\", \"ntlm\"")
	serverCmd.Flags().StringP("url", "u", "https://api.pwnedpasswords.com/range/", "External password compromise checking API URL for import")
	serverCmd.Flags().StringP("file", "f", "", "File with compromised password hashes for import. If this parameter is given, the \"url\" parameter is ignored")
	serverCmd.Flags().Bool("force-rewrite", false, "Do not use caching headers for storage update optimization")
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
	bar := progressbar.Default(HIBPPrefixesCount)

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

	return nil
}

type CompromisedPasswordsFileImporter struct {
	filename     string
	mode         string
	forceRewrite bool
}

func (importer *CompromisedPasswordsFileImporter) importAllPrefixes() error {
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, min(runtime.NumCPU()*8, 64))
	bar := progressbar.Default(HIBPPrefixesCount)

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

func (importer *CompromisedPasswordsFileImporter) readDataForPrefix(prefixHex string) (string, error) {
	masterFile, err := os.Open(importer.filename)
	if err != nil {
		return "", err
	}
	defer masterFile.Close()

	reader := bufio.NewReader(masterFile)
	start, end := int64(0), int64(0)
	masterFile.Seek(0, io.SeekEnd)
	end, _ = masterFile.Seek(0, io.SeekCurrent)

	for start < end {
		mid := (start + end) / 2
		masterFile.Seek(mid, io.SeekStart)
		reader.ReadString('\n') // Skip possibly partial line
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		linePrefix := line[:5]
		if linePrefix < prefixHex {
			start = mid + 1
		} else {
			end = mid
		}
	}

	results := ""
	masterFile.Seek(start, io.SeekStart)
	reader.ReadString('\n') // Skip possibly partial line if not at the beginning
	for {
		line, err := reader.ReadString('\n')
		if err != nil || !strings.HasPrefix(line, prefixHex) {
			break
		}
		if !strings.Contains(line, ":") {
			line = line[:len(line)-1] + ":1\n"
		}
		results += line[5:]
	}

	return results, nil
}
