//go:build unit_test
// +build unit_test

package evervault_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/evervault/evervault-go"
	"github.com/evervault/evervault-go/models"
	"github.com/stretchr/testify/assert"
)

const cage = "synthetic-cage.app-f5f084041a7e.cage.evervault.com"

type CageEcho struct {
	ReqID string `json:"reqId"`
	Body  Body   `json:"body"`
}

type Body struct {
	Test    bool   `json:"test"`
	Message string `json:"message,omitempty"`
}

func (b Body) String() string {
	return fmt.Sprintf(`{"message":"%s","test":%t}`, b.Message, b.Test)
}

func makeTestClient(t *testing.T) (*evervault.Client, error) {
	t.Helper()

	appUUID := os.Getenv("EV_APP_UUID")
	if appUUID == "" {
		t.Skip("Skipping testing when no app uuid provided")
	}

	apiKey := os.Getenv("EV_API_KEY")
	if apiKey == "" {
		t.Skip("Skipping testing when no API key provided")
	}

	return evervault.MakeClient(appUUID, apiKey)
}

func buildCageRequest(t *testing.T, testCage string) *http.Request {
	t.Helper()

	ctx := context.Background()
	body := bytes.NewBufferString(`{"test": true}`)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("https://%s/echo", testCage), body)
	if err != nil {
		t.Fatal("Couldnt build cage request: %w", err)
		return nil
	}

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

	expectedPCRs := models.PCRs{
		PCR0: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		PCR1: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		PCR2: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		PCR8: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	}

	cageClient, err := testClient.CagesClient(cage, []models.PCRs{expectedPCRs})
	if err != nil {
		t.Errorf("Error creating cage client: %s", err)
		return
	}

	req := buildCageRequest(t, cage)

	t.Log("making request", cage)

	resp, err := cageClient.Do(req)
	if err != nil {
		t.Errorf("Error making request: %s", err)
		return
	}

	defer resp.Body.Close()

	assert.Equal("200 OK", resp.Status)
	assert.Contains(resp.Header, "X-Evervault-Cage-Ctx")

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("failed to read response body: %s", err)
		return
	}

	var jsonResp CageEcho
	if err = json.Unmarshal(respBody, &jsonResp); err != nil {
		t.Errorf("failed to unmarshal response body: %s", err)
		return
	}

	assert.Equal(jsonResp.Body.Test, true)
}

func TestCagePartialPCR(t *testing.T) {
	t.Parallel()

	assert := assert.New(t)

	testClient, err := makeTestClient(t)
	if err != nil {
		t.Errorf("Error creating evervault client: %s", err)
		return
	}

	expectedPCRs := models.PCRs{
		PCR8: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	}

	cageClient, err := testClient.CagesClient(cage, []models.PCRs{expectedPCRs})
	if err != nil {
		t.Errorf("Error creating cage client: %s", err)
		return
	}

	req := buildCageRequest(t, cage)

	t.Log("making request", cage)

	resp, err := cageClient.Do(req)
	if err != nil {
		t.Errorf("Error making request: %s", err)
		return
	}

	defer resp.Body.Close()

	assert.Equal("200 OK", resp.Status)
	assert.Contains(resp.Header, "X-Evervault-Cage-Ctx")

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("failed to read response body: %s", err)
		return
	}

	var jsonResp CageEcho
	if err = json.Unmarshal(respBody, &jsonResp); err != nil {
		t.Errorf("failed to unmarshal response body: %s", err)
		return
	}

	assert.Equal(jsonResp.Body.Test, true)
}

func GetPCRData() ([]models.PCRs, error) {
	var pcrs []models.PCRs
	expectedPCRs := models.PCRs{
		PCR0: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		PCR8: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	}
	pcrs = append(pcrs, expectedPCRs)
	return pcrs, nil
}

func GetInvalidPCRData() ([]models.PCRs, error) {
	var pcrs []models.PCRs
	expectedPCRs := models.PCRs{
		PCR0: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		PCR8: "INVALID00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	}
	pcrs = append(pcrs, expectedPCRs)
	return pcrs, nil
}

func TestCagePartialPCRProvider(t *testing.T) {
	t.Parallel()

	assert := assert.New(t)

	testClient, err := makeTestClient(t)
	if err != nil {
		t.Errorf("Error creating evervault client: %s", err)
		return
	}

	cageClient, err := testClient.CagesClient(cage, GetPCRData)
	if err != nil {
		t.Errorf("Error creating cage client: %s", err)
		return
	}

	req := buildCageRequest(t, cage)

	t.Log("making request", cage)

	resp, err := cageClient.Do(req)
	if err != nil {
		t.Errorf("Error making request: %s", err)
		return
	}

	defer resp.Body.Close()

	assert.Equal("200 OK", resp.Status)
	assert.Contains(resp.Header, "X-Evervault-Cage-Ctx")

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("failed to read response body: %s", err)
		return
	}

	var jsonResp CageEcho
	if err = json.Unmarshal(respBody, &jsonResp); err != nil {
		t.Errorf("failed to unmarshal response body: %s", err)
		return
	}

	assert.Equal(jsonResp.Body.Test, true)
}

func TestCageFailsOnPartialIncorrectPCRProvider(t *testing.T) {
	t.Parallel()

	assert := assert.New(t)

	testClient, err := makeTestClient(t)
	if err != nil {
		t.Errorf("Error creating evervault client: %s", err)
		return
	}

	cageClient, err := testClient.CagesClient(cage, GetInvalidPCRData)
	if err != nil {
		t.Errorf("Error creating cage client: %s", err)
		return
	}

	req := buildCageRequest(t, cage)

	t.Log("making request", cage)

	resp, err := cageClient.Do(req)
	if resp != nil {
		resp.Body.Close()
	}

	assert.ErrorIs(err, evervault.ErrAttestionFailure)
}

func TestCageFailsOnPartialIncorrectPCR(t *testing.T) {
	t.Parallel()

	assert := assert.New(t)

	testClient, err := makeTestClient(t)
	if err != nil {
		t.Errorf("Error creating evervault client: %s", err)
		return
	}

	expectedPCRs := models.PCRs{
		PCR0: "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
		PCR8: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	}

	cageClient, err := testClient.CagesClient(cage, []models.PCRs{expectedPCRs})
	if err != nil {
		t.Errorf("Error creating cage client: %s", err)
		return
	}

	req := buildCageRequest(t, cage)

	t.Log("making request", cage)

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

	_, err = testClient.CagesClient(cage, []models.PCRs{})
	assert.ErrorIs(err, evervault.ErrNoPCRs)
}
