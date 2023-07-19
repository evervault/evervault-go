package evervault

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Evervault Client.
// Client will connect to Evervault API and retrieve public key.
// The Client can be used to:
//   - perform encryptions
//   - Create Outbound relay client
//   - Create Cage clients
//   - run evervault Functions.
type Client struct {
	Config                    Config
	apiKey                    string
	appUUID                  string
	p256PublicKeyUncompressed []byte
	p256PublicKeyCompressed   []byte
	expectedPCRs              []PCRs
}

type KeysResponse struct {
	TeamUUID                string `json:"teamUuid"`
	Key                     string `json:"key"`
	EcdhKey                 string `json:"ecdhKey"`
	EcdhP256Key             string `json:"ecdhP256Key"`
	EcdhP256KeyUncompressed string `json:"ecdhP256KeyUncompressed"`
}

type clientRequest struct {
	url      string
	method   string
	body     []byte
	apiKey   string
	appUUID  string
	runToken string
}

func (c *Client) initClient() error {
	keysResponse, err := c.getPublicKey()
	if err != nil {
		return err
	}

	decodedPublicKeyUncompressed, err := base64.StdEncoding.DecodeString(keysResponse.EcdhP256KeyUncompressed)
	if err != nil {
		return fmt.Errorf("error decoding uncompressed public key %w", err)
	}

	decodedPublicKeyCompressed, err := base64.StdEncoding.DecodeString(keysResponse.EcdhP256Key)
	if err != nil {
		return fmt.Errorf("error decoding compressed public key %w", err)
	}

	c.p256PublicKeyUncompressed = decodedPublicKeyUncompressed
	c.p256PublicKeyCompressed = decodedPublicKeyCompressed
	c.expectedPCRs = []PCRs{}

	return nil
}

func (c *Client) getPublicKey() (KeysResponse, error) {
	publicKeyURL := fmt.Sprintf("%s/cages/key", c.Config.EvAPIURL)

	keys, err := c.makeRequest(publicKeyURL, http.MethodGet, nil, "")
	if err != nil {
		return KeysResponse{}, err
	}

	res := KeysResponse{}
	if err := json.Unmarshal(keys, &res); err != nil {
		return KeysResponse{}, fmt.Errorf("Error parsing JSON response %w", err)
	}

	return res, nil
}

func (c *Client) decrypt(encryptedData any) (map[string]any, error) {
	pBytes, err := json.Marshal(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("Error marshalling payload to json %w", err)
	}

	decryptURL := fmt.Sprintf("%s/decrypt", c.Config.EvAPIURL)

	decryptedData, err := c.makeRequest(decryptURL, "POST", pBytes, "")
	if err != nil {
		return nil, err
	}

	var res map[string]any
	if err := json.Unmarshal(decryptedData, &res); err != nil {
		return nil, fmt.Errorf("Error parsing JSON response %w", err)
	}

	return res, nil
}

func (c *Client) makeRequest(url string, method string, body []byte, runToken string) ([]byte, error) {
	req, err := c.buildRequestContext(clientRequest{
		url:      url,
		method:   method,
		body:     body,
		apiKey:   c.apiKey,
		appUUID:  c.appUUID,
		runToken: runToken,
	})
	if err != nil {
		return nil, fmt.Errorf("Error creating request %w", err)
	}

	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Error making request %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, APIError{StatusCode: resp.StatusCode, Message: "Error making HTTP request"}
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Error serialising body %w", err)
	}

	return respBody, nil
}

func (c *Client) buildRequestContext(clientRequest clientRequest) (*http.Request, error) {
	ctx := context.Background()
	if clientRequest.method == http.MethodGet {
		req, err := http.NewRequestWithContext(ctx, clientRequest.method, clientRequest.url, nil)
		if err != nil {
			return nil, fmt.Errorf("Error creating request %w", err)
		}

		setRequestHeaders(req, clientRequest.apiKey, clientRequest.appUUID, clientRequest.runToken)

		return req, nil
	}

	bodyReader := bytes.NewReader(clientRequest.body)

	req, err := http.NewRequestWithContext(ctx, clientRequest.method, clientRequest.url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("Error creating request %w", err)
	}

	setRequestHeaders(req, clientRequest.apiKey, clientRequest.appUUID, clientRequest.runToken)

	return req, nil
}

func setRequestHeaders(req *http.Request, apiKey string, appUUID string, runToken string) {
	if runToken != "" {
		req.Header = http.Header{
			"Authorization": {fmt.Sprintf("Bearer %s", runToken)},
			"Content-Type":  {"application/json"},
			"user-agent":    {fmt.Sprintf("evervault-go/%s", ClientVersion)},
		}
	} else {
		req.Header = http.Header{
			"Authorization": {fmt.Sprintf(
				"Bearer %s",
				base64.StdEncoding.EncodeToString(
					[]byte(
						fmt.Sprintf("%s:%s", apiKey, appUUID)
					)
				)
			)},
			"API-KEY":      {apiKey},
			"Content-Type": {"application/json"},
			"user-agent":   {fmt.Sprintf("evervault-go/%s", ClientVersion)},
		}
	}
}
