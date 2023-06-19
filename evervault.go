package evervault

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"log"
	"net/http"
	"strconv"

	"github.com/evervault/evervault-go/internal/crypto"
	"github.com/evervault/evervault-go/internal/datatypes"
)

const clientVersion = "0.0.1"

var ClientVersion = clientVersion

var (
	ErrClientNotInitilization          = errors.New("evervault client unable to initialize")
	ErrAPIKeyRequired                  = errors.New("evervault client requires an api key")
	ErrCryptoKeyImportError            = errors.New("unable to import crypto key")
	ErrCryptoUnableToPerformEncryption = errors.New("unable to perform encryption")
	ErrInvalidDataType                 = errors.New("Error: Invalid datatype")
)

// InitClient creates a new Client instance if an API key is provided. The client
// will connect to Evervaults API to retrieve the public keys from your Evervault App.
//
// If an apiKey is not passed then ErrAPIKeyRequired is returned. If the client cannot
// be created then nil will be returned.
func (c *Client) InitClient(apiKey string) (*Client, error) {
	config, err := MakeConfig(apiKey)
	if err != nil {
		return nil, err
	}

	c.Config = config

	return c.makeClient()
}

// Encrypt encrypts the value passed to it using the Evervault Encryption Scheme.
// The encrypted value is returned as an Evervault formated encrypted string.
//
// If an error occurs then nil is returned. If the error is due a problem with Key creation then
// ErrCryptoKeyImportError is returned. For anyother error ErrCryptoUnableToPerformEncryption is returned.
func (c *Client) Encrypt(value interface{}) (string, error) {
	ephemeralECDHCurve := ecdh.P256()
	ephemeralECDHKey, _ := ephemeralECDHCurve.GenerateKey(rand.Reader)

	appPublicKeyCurve := ecdh.P256()

	appPubKey, err := appPublicKeyCurve.NewPublicKey(c.p256PublicKeyUncompressed)
	if err != nil {
		log.Fatalf("App PublicKey parse error: %v", err)
		return "", ErrCryptoKeyImportError
	}

	shared, err := ephemeralECDHKey.ECDH(appPubKey)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	ephemeralPublicECDHKeyBytes := ephemeralECDHKey.PublicKey().Bytes()
	compressedEpemeralPublicKey := crypto.CompressPublicKey(ephemeralPublicECDHKeyBytes)
	aesKey := crypto.DeriveKDFAESKey(ephemeralPublicECDHKeyBytes, shared)

	switch valueType := value.(type) {
	case string:
		return crypto.EncryptValue(aesKey, compressedEpemeralPublicKey, c.p256PublicKeyCompressed, valueType, datatypes.String), nil
	case int:
		val := strconv.Itoa(valueType)
		return crypto.EncryptValue(aesKey, compressedEpemeralPublicKey, c.p256PublicKeyCompressed, val, datatypes.Number), nil
	case float64:
		val := strconv.FormatFloat(valueType, 'f', -1, 64)
		return crypto.EncryptValue(aesKey, compressedEpemeralPublicKey, c.p256PublicKeyCompressed, val, datatypes.Number), nil
	case bool:
		val := strconv.FormatBool(valueType)
		return crypto.EncryptValue(aesKey, compressedEpemeralPublicKey, c.p256PublicKeyCompressed, val, datatypes.Boolean), nil
	case []byte:
		val := string(valueType)
		return crypto.EncryptValue(aesKey, compressedEpemeralPublicKey, c.p256PublicKeyCompressed, val, datatypes.String), nil
	default:
		log.Fatalf("Error: %v", valueType)
		return "", ErrInvalidDataType
	}
}

// Will return a http.Client that is configured to use the Evervault Relay as a proxy.
func (c *Client) OutboundRelayClient() (*http.Client, error) {
	caCertResponse, err := c.makeRequest(c.Config.evervaultCaURL, "GET", nil, "")
	if err != nil {
		log.Fatalf("Error: %v", err)
		return nil, err
	}

	return c.relayClient(caCertResponse), nil
}

// Passing the name of your Evervault Function along with the data to be sent to that function will
// return a RunTokenResponse. This response contains a token that can be returned to your
// client for Function invocation.
func (c *Client) CreateFunctionRunToken(functionName string, payload interface{}) (RunTokenResponse, error) {
	tokenResponse, err := c.createRunToken(functionName, payload)
	if err != nil {
		log.Fatalf("Error: %v", err)
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
		log.Fatalf("Error: %v", err)
		return FunctionRunResponse{}, err
	}

	return functionResponse, nil
}
