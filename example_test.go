package evervault_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/evervault/evervault-go"
)

// Full Example encrypting data and using outbound relay to talk to a third party.
func Example() {
	evClient, err := evervault.MakeClient(os.Getenv("EV_API_KEY"), os.Getenv("EV_APP_UUID"))
	if err != nil {
		log.Fatal(err)
	}

	encrypted, err := evClient.Encrypt("Hello, world!")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(encrypted[0:3]) // Only print start of string to indicate its encrypted

	// Send the decrypted data to a third-party API
	outboundRelayClient, err := evClient.OutboundRelayClient()
	if err != nil {
		log.Fatal(err)
	}

	payload, err := json.Marshal(fmt.Sprintf(`{"encrypted": "%s"}`, encrypted))
	if err != nil {
		log.Fatal(err)
	}

	resp, err := outboundRelayClient.Post("https://example.com/", "application/json", bytes.NewBuffer(payload))
	if err != nil {
		log.Fatal(err)
	}

	defer resp.Body.Close()
	fmt.Println(resp.Status)
	// Output: ev:
	// 200 OK
}

// Example encrypting data locally.
func ExampleClient_Encrypt() {
	evClient, err := evervault.MakeClient(os.Getenv("EV_API_KEY"), os.Getenv("EV_APP_UUID"))
	if err != nil {
		log.Fatal(err)
	}

	encrypted, err := evClient.Encrypt("Hello, world!")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(encrypted[0:3]) // Only print start of string to indicate its encrypted
	// Output: ev:
}
