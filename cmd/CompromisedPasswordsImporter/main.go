package main

import (
	"flag"
	"fmt"
	"github.com/avast/retry-go"
	"github.com/schollz/progressbar/v3"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const HIBPPrefixesCount = 1 << 20

type CompromisedPasswordsDownloader struct {
	client *http.Client
	url    string
}

func main() {
	mode := flag.String("mode", "URL", "The mode for importing the values (\"URL\" or \"file\")")
	source := flag.String("source", "https://api.pwnedpasswords.com/range/", "The source of the "+
		"values (a URL or a path to the hashes file)")
	flag.Parse()

	if *mode == "URL" {
		var cpd CompromisedPasswordsDownloader
		cpd.url = *source
		cpd.client = &http.Client{}
		err := cpd.downloadAllPrefixes()
		if err != nil {
			fmt.Printf("Error downloading prefixes: %v\n", err)
		}
	}
	fmt.Println("Username:", *mode)
	fmt.Println("Username:", *source)

}

func (downloader *CompromisedPasswordsDownloader) downloadAllPrefixes() error {
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

func (downloader *CompromisedPasswordsDownloader) downloadByPrefix(prefix int) error {
	prefixHex := strings.ToUpper(fmt.Sprintf("%05x", prefix))
	filename := filepath.Join("./storage", prefixHex+".txt")
	request, err := http.NewRequest(http.MethodGet, downloader.url+prefixHex, nil)
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
