package PasswordCompromiseCheckClientLib

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"net/http"
	"strconv"

	psi_client "github.com/openmined/psi/client"
	psi_proto "github.com/openmined/psi/pb"
	"google.golang.org/protobuf/proto"
)

func CheckNTLMPassword(password string, url string) (bool, error) {
	hash := sha1.New()
	hash.Write([]byte(password))
	hashBytes := hash.Sum(nil)
	hashString := hex.EncodeToString(hashBytes)
	prefix := hashString[:5]
	suffix := strings.ToUpper(hashString[5:])
	response, err := http.Get(url + "/range/" + prefix)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return false, err
	}
	return strings.Contains(string(body), suffix), nil
}

func CheckNTLMPSIPassword(password string, url string) (bool, error) {
	hash := sha1.New()
	hash.Write([]byte(password))
	hashBytes := hash.Sum(nil)
	hashString := hex.EncodeToString(hashBytes)
	prefix := hashString[:5]
	suffix := strings.ToUpper(hashString[5:])
	client, err := psi_client.CreateWithNewKey(true)
	if err != nil {
		return false, fmt.Errorf("Failed to create a PSI client: %v", err)
	}
	clientInputs := []string{suffix}
	request, err := client.CreateRequest(clientInputs)
	if err != nil {
		return false, fmt.Errorf("Failed to create request: %v", err)
	}
	serializedRequest, err := proto.Marshal(request)
	if err != nil {
		return false, fmt.Errorf("Failed to serialize request: %v", err)
	}

	response, err := http.Post(url+"/psi/"+prefix, "application/octet-stream", bytes.NewBuffer(serializedRequest))
	if err != nil {
		return false, fmt.Errorf("Error sending data to server: %v", err)
	}
	defer response.Body.Close()

	psiResponseLengthHeader := response.Header.Get("PSI-Response-Length")
	psiSetupLengthHeader := response.Header.Get("PSI-Setup-Length")

	// Convert the lengths to integers
	psiResponseLength, err1 := strconv.Atoi(psiResponseLengthHeader)
	psiSetupLength, err2 := strconv.Atoi(psiSetupLengthHeader)
	if err1 != nil || err2 != nil {
		return false, fmt.Errorf("Error converting message lengths to integers:", err1, err2)
	}

	// Read the serialized messages from the response body
	psiResponseSerialized, err1 := io.ReadAll(io.LimitReader(response.Body, int64(psiResponseLength)))
	psiSetupSerialized, err2 := io.ReadAll(io.LimitReader(response.Body, int64(psiSetupLength)))
	if err1 != nil || err2 != nil {
		return false, fmt.Errorf("Error reading psi data:", err1, err2)
	}
	psiResponse := &psi_proto.Response{}
	err = proto.Unmarshal(psiResponseSerialized, psiResponse)
	if err != nil {
		return false, fmt.Errorf("Failed to deserialize response: %v", err)
	}
	psiSetup := &psi_proto.ServerSetup{}
	err = proto.Unmarshal(psiSetupSerialized, psiSetup)
	if err != nil {
		return false, fmt.Errorf("Failed to deserialize serverSetup: %v", err)
	}

	intersectionSize, err := client.GetIntersectionSize(psiSetup, psiResponse)
	if err != nil {
		return false, fmt.Errorf("failed to compute intersection size %v", err)
	}
	return intersectionSize != 0, nil
}
