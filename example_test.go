package evervault_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/evervault/evervault-go"
)

// Full Example encrypting data and using outbound relay to talk to a third party.
func Example() {
	syntheticEndpointUrl := os.Getenv("EV_SYNTHETIC_ENDPOINT_URL")
	evClient, err := evervault.MakeClient(os.Getenv("EV_APP_UUID"), os.Getenv("EV_API_KEY"))
	if err != nil {
		log.Fatal(err)
	}

	encrypted, err := evClient.EncryptString("Hello, world!")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(encrypted[0:3]) // Only print start of string to indicate its encrypted

	// Send the decrypted data to a third-party API
	outboundRelayClient, err := evClient.OutboundRelayClient()
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()

	data := map[string]string{"string": "value"}

	payload, err := json.Marshal(data)
	if err != nil {
		log.Fatalf("Encountered unexpected error: %s", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, syntheticEndpointUrl, bytes.NewReader(payload))
	if err != nil {
		log.Fatal(err)
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	resp, err := outboundRelayClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	defer func() {
		bodyCloseErr := resp.Body.Close()
		if bodyCloseErr != nil {
			log.Printf("Failed to close response body: %s", bodyCloseErr)
		}
	}()
	fmt.Println(resp.Status)
	// Output: ev:
	// 200 OK
}

// Example encrypting data locally.
func ExampleClient_EncryptString() {
	evClient, err := evervault.MakeClient(os.Getenv("EV_APP_UUID"), os.Getenv("EV_API_KEY"))
	if err != nil {
		log.Fatal(err)
	}

	encrypted, err := evClient.EncryptString("Hello, world!")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(encrypted[0:3]) // Only print start of string to indicate its encrypted
	// Output: ev:
}
