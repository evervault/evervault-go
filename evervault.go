package evervault

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/evervault/evervault-go/internal/crypto"
	"github.com/evervault/evervault-go/internal/datatypes"
)

const clientVersion = "0.1.3"

var ClientVersion = clientVersion

var (
	ErrClientNotInitilization          = errors.New("evervault client unable to initialize")
	ErrAppCredentialsRequired          = errors.New("evervault client requires an api key and app uuid")
	ErrCryptoKeyImportError            = errors.New("unable to import crypto key")
	ErrCryptoUnableToPerformEncryption = errors.New("unable to perform encryption")
	ErrInvalidDataType                 = errors.New("Error: Invalid datatype")
)

type PCRs struct {
	PCR0 string
	PCR1 string
	PCR2 string
	PCR8 string
}

// MakeClient creates a new Client instance if an API key and Evervault App UUID is provided. The client
// will connect to Evervaults API to retrieve the public keys from your Evervault App.
//
// If an apiKey is not passed then ErrAppCredentialsRequired is returned. If the client cannot
// be created then nil will be returned.
func MakeClient(apiKey string, appUUID string) (*Client, error) {
	config := MakeConfig()
	return MakeCustomClient(apiKey, appUUID, config)
}

// MakeCustomClient creates a new Client instance but can be specified with a Config. The client
// will connect to Evervaults API to retrieve the public keys from your Evervault App.
//
// If an apiKey or appUUID is not passed then ErrAppCredentialsRequired is returned. If the client cannot
// be created then nil will be returned.
func MakeCustomClient(apiKey string, appUUID string, config Config) (*Client, error) {
	if apiKey == "" || appUUID == "" {
		return nil, ErrAppCredentialsRequired
	}

	client := &Client{
		apiKey:  apiKey,
		appUUID: appUUID,
		Config:  config,
	}

	err := client.initClient()
	if err != nil {
		return nil, err
	}

	return client, nil
}

// Encrypt encrypts the value passed to it using the Evervault Encryption Scheme.
// The encrypted value is returned as an Evervault formated encrypted string.
//
// If an error occurs then nil is returned. If the error is due a problem with Key creation then
// ErrCryptoKeyImportError is returned. For anyother error ErrCryptoUnableToPerformEncryption is returned.
func (c *Client) Encrypt(value interface{}) (string, error) {
	ephemeralECDHCurve := ecdh.P256()

	ephemeralECDHKey, err := ephemeralECDHCurve.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("error generating ephemeral curve %w", err)
	}

	appPublicKeyCurve := ecdh.P256()

	appPubKey, err := appPublicKeyCurve.NewPublicKey(c.p256PublicKeyUncompressed)
	if err != nil {
		return "", ErrCryptoKeyImportError
	}

	shared, err := ephemeralECDHKey.ECDH(appPubKey)
	if err != nil {
		return "", fmt.Errorf("Error generating ephermeral key %w", err)
	}

	ephemeralPublicECDHKeyBytes := ephemeralECDHKey.PublicKey().Bytes()
	compressedEphemeralPublicKey := crypto.CompressPublicKey(ephemeralPublicECDHKeyBytes)

	aesKey, err := crypto.DeriveKDFAESKey(ephemeralPublicECDHKeyBytes, shared)
	if err != nil {
		return "", err
	}

	return c.encryptValue(value, aesKey, compressedEphemeralPublicKey)
}

func (c *Client) encryptValue(value interface{}, aesKey []byte, ephemeralPublicKey []byte) (string, error) {
	switch valueType := value.(type) {
	case string:
		return crypto.EncryptValue(aesKey, ephemeralPublicKey, c.p256PublicKeyCompressed, valueType, datatypes.String)
	case int:
		val := strconv.Itoa(valueType)
		return crypto.EncryptValue(aesKey, ephemeralPublicKey, c.p256PublicKeyCompressed, val, datatypes.Number)
	case float64:
		val := strconv.FormatFloat(valueType, 'f', -1, 64)
		return crypto.EncryptValue(aesKey, ephemeralPublicKey, c.p256PublicKeyCompressed, val, datatypes.Number)
	case bool:
		val := strconv.FormatBool(valueType)
		return crypto.EncryptValue(aesKey, ephemeralPublicKey, c.p256PublicKeyCompressed, val, datatypes.Boolean)
	case []byte:
		val := string(valueType)
		return crypto.EncryptValue(aesKey, ephemeralPublicKey, c.p256PublicKeyCompressed, val, datatypes.String)
	default:
		return "", ErrInvalidDataType
	}
}

// Will return a http.Client that is configured to use the Evervault Relay as a proxy.
func (c *Client) OutboundRelayClient() (*http.Client, error) {
	caCertResponse, err := c.makeRequest(c.Config.EvervaultCaURL, "GET", nil, "")
	if err != nil {
		return nil, err
	}

	return c.relayClient(caCertResponse)
}

// Passing the name of your Evervault Function along with the data to be sent to that function will
// return a RunTokenResponse. This response contains a token that can be returned to your
// client for Function invocation.
func (c *Client) CreateFunctionRunToken(functionName string, payload interface{}) (RunTokenResponse, error) {
	tokenResponse, err := c.createRunToken(functionName, payload)
	if err != nil {
		return RunTokenResponse{}, err
	}

	return tokenResponse, nil
}

// Passing the name of your Evervault Function along with the data to be sent to that
// function will invoke a function in your Evervault App. The response from the function
// will be returned as a FunctionRunResponse.
func (c *Client) RunFunction(functionName string, payload interface{}, runToken string) (FunctionRunResponse, error) {
	functionResponse, err := c.runFunction(functionName, payload, runToken)
	if err != nil {
		return FunctionRunResponse{}, err
	}

	return functionResponse, nil
}

func (c *Client) CageClient(cageHostname string, expectedPCRs []PCRs) (*http.Client, error) {
	c.expectedPCRs = expectedPCRs
	caCertResponse, err := c.makeRequest(c.Config.EvervaultCagesCaUrl, "GET", nil, "")

	if err != nil {
		return nil, err
	}

	cagesClient, err := c.cagesClient(caCertResponse)
	if err != nil {
		return nil, err
	}

	return cagesClient, nil
}
