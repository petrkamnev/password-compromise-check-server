package PasswordCompromiseCheckClientLib

import (
	"bytes"
	"crypto/sha1"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"net/http"
	"strconv"

	psi_client "github.com/openmined/psi/client"
	psi_proto "github.com/openmined/psi/pb"
	"google.golang.org/protobuf/proto"
)

func CheckSHA1Password(password string, url string, id int) (bool, error) {
	p0 := time.Now()
	hash := sha1.New()
	hash.Write([]byte(password))
	hashBytes := hash.Sum(nil)
	hashString := hex.EncodeToString(hashBytes)
	prefix := hashString[:5]
	suffix := strings.ToUpper(hashString[5:])
	p1 := time.Now()
	response, err := http.Get(url + "/range/" + prefix)
	p2 := time.Now()
	if err != nil {
		return false, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return false, err
	}
	p3 := time.Now()
	result := strings.Contains(string(body), suffix)
	if _, err := os.Stat("client_performance.csv"); os.IsNotExist(err) {
		file, err := os.Create("client_performance.csv")
		if err != nil {
			return false, err
		}
		defer file.Close()
		writer := csv.NewWriter(file)
		defer writer.Flush()
		if err := writer.Write([]string{"id", "p0p1", "p1p2", "p2p3", "mode"}); err != nil {
			return false, err
		}
	}
	file, err := os.OpenFile("client_performance.csv", os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return false, err
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	p0p1 := p1.Sub(p0).Nanoseconds()
	p1p2 := p2.Sub(p1).Nanoseconds()
	p2p3 := p3.Sub(p2).Nanoseconds()

	if err := writer.Write([]string{fmt.Sprintf("%d", id), fmt.Sprintf("%d", p0p1), fmt.Sprintf("%d", p1p2), fmt.Sprintf("%d", p2p3), "sha1"}); err != nil {
		return false, err
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return false, err
	}
	return result, nil
}

func CheckSHA1PSIPassword(password string, url string, id int) (bool, error) {
	p0 := time.Now()
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

	p1 := time.Now()
	response, err := http.Post(url+"/psi/"+prefix, "application/octet-stream", bytes.NewBuffer(serializedRequest))
	p2 := time.Now()
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
	p3 := time.Now()
	if _, err := os.Stat("client_performance.csv"); os.IsNotExist(err) {
		file, err := os.Create("client_performance.csv")
		if err != nil {
			return false, err
		}
		defer file.Close()
		writer := csv.NewWriter(file)
		defer writer.Flush()
		if err := writer.Write([]string{"id", "p0p1", "p1p2", "p2p3", "mode"}); err != nil {
			return false, err
		}
	}
	file, err := os.OpenFile("client_performance.csv", os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return false, err
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	p0p1 := p1.Sub(p0).Nanoseconds()
	p1p2 := p2.Sub(p1).Nanoseconds()
	p2p3 := p3.Sub(p2).Nanoseconds()

	if err := writer.Write([]string{fmt.Sprintf("%d", id), fmt.Sprintf("%d", p0p1), fmt.Sprintf("%d", p1p2), fmt.Sprintf("%d", p2p3), "psi"}); err != nil {
		return false, err
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return false, err
	}
	return intersectionSize != 0, nil
}
