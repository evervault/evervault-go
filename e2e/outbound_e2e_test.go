package e2e_test

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/evervault/evervault-go/internal/testhelper"
	"github.com/stretchr/testify/require"
)

func TestE2EOutboundRelay(t *testing.T) {
	t.Parallel()

	client := GetClient(t)
	syntheticEndpointUrl := testhelper.LoadRequiredEnvVar("EV_RELAY_TARGET", t)

	encryptedString, err := client.EncryptString("some_string")
	require.NoError(t, err, "error encrypting string")

	encryptedNumber, err := client.EncryptInt(1234567890)
	require.NoError(t, err, "error encrypting number")

	encryptedBool, err := client.EncryptBool(true)
	require.NoError(t, err, "error encrypting bool")

	outboundRelayClient, err := client.OutboundRelayClient()
	require.NoError(t, err, "error getting outbound client")

	data := map[string]string{"string": encryptedString, "number": encryptedNumber, "boolean": encryptedBool}

	payload, err := json.Marshal(data)
	require.NoError(t, err, "error Marshalling payload")

	resp, err := outboundRelayClient.Post(syntheticEndpointUrl, "application/json", bytes.NewReader(payload))
	require.NoError(t, err, "error posting with outbound client")
	
	body, err := ioutil.ReadAll(resp.Body)
	require.NoError(t, err, "error posting with outbound client")

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
