package evervault_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/evervault/evervault-go"
)

// Full Example encrypting data and using outbound relay to talk to a third party.
func Example() {
	evClient, err := evervault.MakeClient(os.Getenv("EV_API_KEY"), os.Getenv("EV_APP_UUID"))
	if err != nil {
		panic(err)
	}

	encrypted, err := evClient.Encrypt("Hello, world!")
	if err != nil {
		panic(err)
	}

	fmt.Println(encrypted)

	// Send the decrypted data to a third-party API
	outboundRelayClient, err := evClient.OutboundRelayClient()
	if err != nil {
		panic(err)
	}

	payload, err := json.Marshal(fmt.Sprintf(`{"encrypted": "%s"}`, encrypted))
	if err != nil {
		panic(err)
	}

	resp, err := outboundRelayClient.Post("https://example.com/", "application/json", bytes.NewBuffer(payload))
	if err != nil {
		panic(err)
	}

	defer resp.Body.Close()
	fmt.Println(resp.StatusCode)
	// Output: 200 OK
}

// Example encrypting data locally.
func Example_encrypt() {
	evClient, err := evervault.MakeClient(os.Getenv("EV_API_KEY"), os.Getenv("EV_APP_UUID"))
	if err != nil {
		panic(err)
	}

	encrypted, err := evClient.Encrypt("Hello, world!")
	if err != nil {
		panic(err)
	}

	fmt.Println(encrypted)
	// Output: ev:
}
