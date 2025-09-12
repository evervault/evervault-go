//go:build e2e
// +build e2e

package e2e_test

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

var syntheticEndpointUrl string = os.Getenv("EV_SYNTHETIC_ENDPOINT_URL")

func TestE2EOutboundRelay(t *testing.T) {
	t.Parallel()

	client := GetClient(t)

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

	body, err := ioutil.ReadAll(resp.Body)
	require.NoError(t, err)

	// close response body
	resp.Body.Close()

	responseData := make(map[string]map[string]bool)

	json.Unmarshal(body, &responseData)

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
