package evervault_test

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"testing"

	"github.com/evervault/evervault-go"
	"github.com/stretchr/testify/assert"
)

const testCage = "go-sdk-hello-cage.app_869a0605f7c3.cages.evervault.com"

func makeTestClient(t *testing.T) (*evervault.Client, error) {
	t.Helper()

	apiKey := os.Getenv("EV_API_KEY")
	if apiKey == "" {
		t.Skip("Skipping testing when no API key provided")
	}

	appUUID := os.Getenv("EV_APP_UUID")
	if appUUID == "" {
		t.Skip("Skipping testing when no app uuid provided")
	}

	return evervault.MakeClient(apiKey, appUUID)
}

func buildCageRequest() *http.Request {
	body := []byte(`{"test": true}`)
	req, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("https://%s/echo", testCage), bytes.NewBuffer(body))
	req.Close = true
	req.Header.Set("API-KEY", os.Getenv("EV_API_KEY"))
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	return req
}

func TestCageClient(t *testing.T) {
	t.Parallel()

	assert := assert.New(t)

	testClient, err := makeTestClient(t)
	if err != nil {
		t.Errorf("Error creating evervault client: %s", err)
		return
	}

	expectedPCRs := evervault.PCRs{
		PCR0: "f039c31c536749ac6b2a9344fcb36881dd1cf066ca44afcaf9369a9877e2d3c85fa738c427d502e01e35994da7458e2d",
		PCR1: "bcdf05fefccaa8e55bf2c8d6dee9e79bbff31e34bf28a99aa19e6b29c37ee80b214a414b7607236edf26fcb78654e63f",
		PCR2: "71c478711438fe252fbd9b1da56218bea5d630da55aa56431257df77bd42f65a434601bf53be9a1901fcd61680e425c7",
		PCR8: "1650274b27bf44fba6f1779602399763af9e4567927d771b1b37aeb1ac502c84fbd6a7ab7b05600656a257247529fbb8",
	}

	cageClient, err := testClient.CageClient(testCage, []evervault.PCRs{expectedPCRs})
	if err != nil {
		t.Errorf("Error creating cage client: %s", err)
		return
	}

	req := buildCageRequest()

	t.Log("making request", testCage)

	resp, err := cageClient.Do(req)
	if err != nil {
		t.Errorf("Error making request: %s", err)
		return
	}

	defer resp.Body.Close()

	assert.Equal("200 OK", resp.Status)
	assert.Contains(resp.Header, "X-Evervault-Cage-Ctx")

	respBody, _ := io.ReadAll(resp.Body)
	assert.Equal(`{"message":"Hello! I'm writing to you from within an enclave","body":{"test":true}}`, string(respBody))
}

func TestCagePartialPCR(t *testing.T) {
	t.Parallel()

	assert := assert.New(t)

	testClient, err := makeTestClient(t)
	if err != nil {
		t.Errorf("Error creating evervault client: %s", err)
		return
	}

	expectedPCRs := evervault.PCRs{
		PCR8: "1650274b27bf44fba6f1779602399763af9e4567927d771b1b37aeb1ac502c84fbd6a7ab7b05600656a257247529fbb8",
	}

	cageClient, err := testClient.CageClient(testCage, []evervault.PCRs{expectedPCRs})
	if err != nil {
		t.Errorf("Error creating cage client: %s", err)
		return
	}

	req := buildCageRequest()

	t.Log("making request", testCage)

	resp, err := cageClient.Do(req)
	if err != nil {
		t.Errorf("Error making request: %s", err)
		return
	}

	defer resp.Body.Close()

	assert.Equal("200 OK", resp.Status)
	assert.Contains(resp.Header, "X-Evervault-Cage-Ctx")

	respBody, _ := io.ReadAll(resp.Body)
	assert.Equal(`{"message":"Hello! I'm writing to you from within an enclave","body":{"test":true}}`, string(respBody))
}

func TestCageFailsOnPartialIncorrectPCR(t *testing.T) {
	t.Parallel()

	assert := assert.New(t)

	testClient, err := makeTestClient(t)
	if err != nil {
		t.Errorf("Error creating evervault client: %s", err)
		return
	}

	expectedPCRs := evervault.PCRs{
		PCR0: "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
		PCR8: "1650274b27bf44fba6f1779602399763af9e4567927d771b1b37aeb1ac502c84fbd6a7ab7b05600656a257247529fbb8",
	}

	cageClient, err := testClient.CageClient(testCage, []evervault.PCRs{expectedPCRs})
	if err != nil {
		t.Errorf("Error creating cage client: %s", err)
		return
	}

	req := buildCageRequest()

	t.Log("making request", testCage)

	resp, err := cageClient.Do(req)
	if resp != nil {
		resp.Body.Close()
	}

	assert.ErrorIs(err, evervault.ErrAttestionFailure)
}

func TestCageRequiresPCR(t *testing.T) {
	t.Parallel()

	assert := assert.New(t)

	testClient, err := makeTestClient(t)
	if err != nil {
		t.Errorf("Error creating evervault client: %s", err)
		return
	}

	emptyPCRs := evervault.PCRs{}

	_, err = testClient.CageClient(testCage, []evervault.PCRs{emptyPCRs})
	assert.ErrorIs(err, evervault.ErrNoPCRs)
}

func TestCageFailsOnIncorrectPCRs(t *testing.T) {
	t.Parallel()

	assert := assert.New(t)

	testClient, err := makeTestClient(t)
	if err != nil {
		t.Errorf("Error creating evervault client: %s", err)
		return
	}

	expectedPCRs := evervault.PCRs{
		PCR0: "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
		PCR1: "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
		PCR2: "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
		PCR8: "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
	}

	cageClient, err := testClient.CageClient(testCage, []evervault.PCRs{expectedPCRs})
	if err != nil {
		t.Errorf("Error creating cage client: %s", err)
		return
	}

	req := buildCageRequest()

	t.Log("making request", testCage)

	resp, err := cageClient.Do(req)
	if resp != nil {
		resp.Body.Close()
	}

	assert.ErrorIs(err, evervault.ErrAttestionFailure)
}

func ExampleClient_CageClient() {
	apiKey := os.Getenv("EV_API_KEY")
	appUUID := os.Getenv("EV_APP_UUID")

	evClient, err := evervault.MakeClient(apiKey, appUUID)
	if err != nil {
		log.Fatal(err)
	}

	expectedPCRs := evervault.PCRs{
		PCR0: "f039c31c536749ac6b2a9344fcb36881dd1cf066ca44afcaf9369a9877e2d3c85fa738c427d502e01e35994da7458e2d",
		PCR1: "bcdf05fefccaa8e55bf2c8d6dee9e79bbff31e34bf28a99aa19e6b29c37ee80b214a414b7607236edf26fcb78654e63f",
		PCR2: "71c478711438fe252fbd9b1da56218bea5d630da55aa56431257df77bd42f65a434601bf53be9a1901fcd61680e425c7",
		PCR8: "1650274b27bf44fba6f1779602399763af9e4567927d771b1b37aeb1ac502c84fbd6a7ab7b05600656a257247529fbb8",
	}

	cageClient, err := evClient.CageClient(testCage, []evervault.PCRs{expectedPCRs})
	if err != nil {
		log.Fatal(err)
	}

	body := []byte(`{"test": true}`)
	req, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("https://%s/", testCage), bytes.NewBuffer(body))
	req.Close = true
	req.Header.Set("API-KEY", apiKey)
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	log.Printf("making request: %s", testCage)

	resp, err := cageClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	fmt.Println(string(respBody))
	// Output: {"message":"Hello! I'm writing to you from within an enclave","body":{"test":true}}
}
