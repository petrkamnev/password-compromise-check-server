package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"strings"

	"net/http"
	"strconv"

	psi_client "github.com/openmined/psi/client"
	psi_proto "github.com/openmined/psi/pb"
	"google.golang.org/protobuf/proto"
)

func main() {
	mode := flag.String("mode", "SHA-1", "The mode of the server (\"SHA-1\", \"NTLM\", \"PSI\")")
	password := flag.String("password", "", "The password to check")
	url := flag.String("url", "", "The password compromise check server url")
	flag.Parse()
	if *mode == "SHA-1" {
		hash := sha1.New()
		hash.Write([]byte(*password))
		hashBytes := hash.Sum(nil)

		// Convert hash to hexadecimal string
		hashString := hex.EncodeToString(hashBytes)

		// Extract prefix and suffix
		prefix := hashString[:5]
		suffix := strings.ToUpper(hashString[5:])
		response, err := http.Get(*url + "/range/" + prefix)
		if err != nil {
			fmt.Println("Error sending data to server:", err)
			return
		}
		defer response.Body.Close()

		// Read the response body
		body, err := io.ReadAll(response.Body)
		if err != nil {
			fmt.Println("Error reading response body:", err)
			return
		}

		// Check if the response contains the suffix of the hash
		fmt.Println(strings.Contains(string(body), suffix))

	} else if *mode == "NTLM" {

	} else if *mode == "PSI" {
		hash := sha1.New()
		hash.Write([]byte(*password))
		hashBytes := hash.Sum(nil)

		// Convert hash to hexadecimal string
		hashString := hex.EncodeToString(hashBytes)

		// Extract prefix and suffix
		prefix := hashString[:5]
		suffix := strings.ToUpper(hashString[5:])
		client, err := psi_client.CreateWithNewKey(true)
		if err != nil {
			fmt.Errorf("Failed to create a PSI client %v", err)
		}
		clientInputs := []string{suffix}
		// Create client request
		request, err := client.CreateRequest(clientInputs)
		if err != nil {
			fmt.Errorf("Failed to create request %v", err)
		}
		serializedRequest, err := proto.Marshal(request)
		if err != nil {
			fmt.Errorf("Failed to serialize request: %v", err)
		}

		response, err := http.Post(*url+"/psi/"+prefix, "application/octet-stream", bytes.NewBuffer(serializedRequest))
		if err != nil {
			fmt.Println("Error sending data to server:", err)
			return
		}
		// Read the response headers
		psiResponseLengthHeader := response.Header.Get("PSI-Response-Length")
		psiSetupLengthHeader := response.Header.Get("PSI-Setup-Length")

		// Convert the lengths to integers
		psiResponseLength, err1 := strconv.Atoi(psiResponseLengthHeader)
		psiSetupLength, err2 := strconv.Atoi(psiSetupLengthHeader)
		if err1 != nil || err2 != nil {
			fmt.Println("Error converting message lengths to integers:", err1, err2)
			return
		}

		// Read the serialized messages from the response body
		psiResponseSerialized, err1 := io.ReadAll(io.LimitReader(response.Body, int64(psiResponseLength)))
		psiSetupSerialized, err2 := io.ReadAll(io.LimitReader(response.Body, int64(psiSetupLength)))
		if err1 != nil || err2 != nil {
			fmt.Println("Error reading psi data:", err1, err2)
			return
		}
		psiResponse := &psi_proto.Response{}
		err = proto.Unmarshal(psiResponseSerialized, psiResponse)
		if err != nil {
			fmt.Errorf("Failed to deserialize response: %v", err)
		}
		psiSetup := &psi_proto.ServerSetup{}
		err = proto.Unmarshal(psiSetupSerialized, psiSetup)
		if err != nil {
			fmt.Errorf("Failed to deserialize serverSetup: %v", err)
		}

		intersectionSize, err := client.GetIntersectionSize(psiSetup, psiResponse)
		if err != nil {
			fmt.Errorf("failed to compute intersection size %v", err)
		}
		fmt.Println(intersectionSize != 0)

	} else {
		flag.Usage()
		return
	}

}
