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
	appUUID                   string
	apiKey                    string
	p256PublicKeyUncompressed []byte
	p256PublicKeyCompressed   []byte
}

type KeysResponse struct {
	TeamUUID                string `json:"teamUuid"`
	Key                     string `json:"key"`
	EcdhKey                 string `json:"ecdhKey"`
	EcdhP256Key             string `json:"ecdhP256Key"`
	EcdhP256KeyUncompressed string `json:"ecdhP256KeyUncompressed"`
}

type clientRequest struct {
	url          string
	method       string
	body         []byte
	appUUID      string
	apiKey       string
	useBasicAuth bool
}

type clientResponse struct {
	body        []byte
	contentType string
	statusCode  int
}

type TokenResponse struct {
	Token  string `json:"token"`
	Expiry int64  `json:"expiry"`
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

	return nil
}

func (c *Client) getPublicKey() (KeysResponse, error) {
	publicKeyURL := c.Config.EvAPIURL + "/cages/key"

	response, err := c.makeRequest(publicKeyURL, http.MethodGet, nil, false)

	if response.statusCode != http.StatusOK {
		return KeysResponse{}, APIError{Message: "error making HTTP request"}
	}

	if err != nil {
		return KeysResponse{}, err
	}

	res := KeysResponse{}
	if err := json.Unmarshal(response.body, &res); err != nil {
		return KeysResponse{}, fmt.Errorf("error parsing JSON response %w", err)
	}

	return res, nil
}

func (c *Client) decrypt(encryptedData string) (any, error) {
	pBytes, err := json.Marshal(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("error marshalling payload to json %w", err)
	}

	decryptURL := c.Config.EvAPIURL + "/decrypt"

	response, err := c.makeRequest(decryptURL, http.MethodPost, pBytes, true)

	if response.statusCode != http.StatusOK {
		return TokenResponse{}, ExtractAPIError(response.body)
	}

	if err != nil {
		return nil, err
	}

	var res any
	if response.contentType == "application/json" {
		if err := json.Unmarshal(response.body, &res); err != nil {
			return nil, fmt.Errorf("error parsing JSON response %w", err)
		}

		return res, nil
	}

	decryptedString := string(response.body)

	return decryptedString, nil
}

func (c *Client) createToken(action string, payload any, expiry int64) (TokenResponse, error) {
	body := map[string]any{
		"action":  action,
		"payload": payload,
		"expiry":  expiry,
	}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("error marshalling payload to json %w", err)
	}

	tokenURL := c.Config.EvAPIURL + "/client-side-tokens"

	response, err := c.makeRequest(tokenURL, http.MethodPost, bodyBytes, false)

	if response.statusCode != http.StatusOK {
		return TokenResponse{}, ExtractAPIError(response.body)
	}

	if err != nil {
		return TokenResponse{}, err
	}

	res := TokenResponse{}
	if err := json.Unmarshal(response.body, &res); err != nil {
		return TokenResponse{}, fmt.Errorf("error parsing JSON response %w", err)
	}

	return res, nil
}

func (c *Client) makeRequest(url, method string, body []byte, useBasicAuth bool) (clientResponse, error) {
	req, err := c.buildRequestContext(clientRequest{
		url:          url,
		method:       method,
		body:         body,
		appUUID:      c.appUUID,
		apiKey:       c.apiKey,
		useBasicAuth: useBasicAuth,
	})
	if err != nil {
		return clientResponse{}, fmt.Errorf("error creating request %w", err)
	}

	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		return clientResponse{}, fmt.Errorf("error making request %w", err)
	}

	defer resp.Body.Close()

	statusCode := resp.StatusCode

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return clientResponse{}, fmt.Errorf("error serialising body %w", err)
	}

	contentType := resp.Header.Get("Content-Type")

	return clientResponse{respBody, contentType, statusCode}, nil
}

func (c *Client) buildRequestContext(clientRequest clientRequest) (*http.Request, error) {
	ctx := context.Background()
	if clientRequest.method == http.MethodGet {
		req, err := http.NewRequestWithContext(ctx, clientRequest.method, clientRequest.url, nil)
		if err != nil {
			return nil, fmt.Errorf("error creating request %w", err)
		}

		setRequestHeaders(req, clientRequest.appUUID, clientRequest.apiKey, clientRequest.useBasicAuth)

		return req, nil
	}

	bodyReader := bytes.NewReader(clientRequest.body)

	req, err := http.NewRequestWithContext(ctx, clientRequest.method, clientRequest.url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("error creating request %w", err)
	}

	setRequestHeaders(req, clientRequest.appUUID, clientRequest.apiKey, clientRequest.useBasicAuth)

	return req, nil
}

func setRequestHeaders(req *http.Request, appUUID, apiKey string, useBasicAuth bool) {
	if useBasicAuth {
		stringBytes := []byte(fmt.Sprintf("%s:%s", appUUID, apiKey))
		base64EncodedHeaderValue := base64.StdEncoding.EncodeToString(stringBytes)
		req.Header = http.Header{
			"Authorization": {"Basic " + base64EncodedHeaderValue},
			"Content-Type":  {"application/json"},
			"user-agent":    {"evervault-go/" + ClientVersion},
		}
	} else {
		req.Header = http.Header{
			"API-KEY":      {apiKey},
			"Content-Type": {"application/json"},
			"user-agent":   {"evervault-go/" + ClientVersion},
		}
	}
}
