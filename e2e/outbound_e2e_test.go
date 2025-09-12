package e2e_test

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"testing"

	"github.com/evervault/evervault-go/internal/testhelper"
	"github.com/stretchr/testify/require"
)

func TestE2EOutboundRelay(t *testing.T) {
	t.Parallel()

	client := GetClient(t)
	syntheticEndpointUrl := testhelper.LoadRequiredEnv(t, "EV_SYNTHETIC_ENDPOINT_URL")

	encryptedString, err := client.EncryptString("some_string")
	require.NoError(t, err)

	encryptedNumber, err := client.EncryptInt(1234567890)
	require.NoError(t, err)

	encryptedBool, err := client.EncryptBool(true)
	require.NoError(t, err)

	outboundRelayClient, err := client.OutboundRelayClient()
	require.NoError(t, err)

	data := map[string]string{"string": encryptedString, "number": encryptedNumber, "boolean": encryptedBool}

	payload, err := json.Marshal(data)
	require.NoError(t, err)

	resp, err := outboundRelayClient.Post(syntheticEndpointUrl, "application/json", bytes.NewReader(payload))
	require.NoError(t, err)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// close response body
	err = resp.Body.Close()
	if err != nil {
		log.Printf("Failed to close response body: %s", err)
	}

	responseData := make(map[string]map[string]bool)

	//nolint:errcheck
	_ = json.Unmarshal(body, &responseData)

	if responseData["request"]["string"] != false {
		t.Errorf("Expected false as response %t", responseData["request"]["string"])
		return
	}

	if responseData["request"]["number"] != false {
		t.Errorf("Expected false as response %t", responseData["request"]["number"])
		return
	}

	if responseData["request"]["boolean"] != false {
		t.Errorf("Expected false as response %t", responseData["request"]["boolean"])
		return
	}
}
