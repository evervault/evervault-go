package e2e_test

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/evervault/evervault-go/internal/testhelper"
)

func TestE2EOutboundRelay(t *testing.T) {
	t.Parallel()

	client := GetClient(t)
	syntheticEndpointUrl := testhelper.LoadRequiredEnvVar("EV_RELAY_TARGET", t)

	if t.Failed() {
		return
	}

	encryptedString, err := client.EncryptString("some_string")
	if err != nil {
		t.Errorf("error encrypting string %s", err)
		return
	}

	encryptedNumber, err := client.EncryptInt(1234567890)
	if err != nil {
		t.Errorf("error encrypting number %s", err)
		return
	}

	encryptedBool, err := client.EncryptBool(true)
	if err != nil {
		t.Errorf("error encrypting bool %s", err)
		return
	}

	outboundRelayClient, err := client.OutboundRelayClient()
	if err != nil {
		t.Errorf("Error getting outbound client %s", err)
		return
	}

	data := map[string]string{"string": encryptedString, "number": encryptedNumber, "boolean": encryptedBool}

	payload, err := json.Marshal(data)
	if err != nil {
		t.Errorf("error Marshalling payload %s", err)
		return
	}

	resp, err := outboundRelayClient.Post(syntheticEndpointUrl, "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Errorf("error posting with outbound client %s", err)
		return
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("error posting with outbound client %s", err)
		return
	}

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
