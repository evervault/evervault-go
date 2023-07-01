// Evervault Go SDK.
// Supported functions are:
//   - Encrypt data server-side including files
//   - Invoke Functions
//   - Invoke Cages
//   - Proxy requests through Outbound Relay
//
// For up to date usage docs please refer to [Evervault docs](https://docs.evervault.com/sdks/go)
package evervault

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"strconv"

	"github.com/evervault/evervault-go/internal/crypto"
	"github.com/evervault/evervault-go/internal/datatypes"
)

// Current version of the evervault SDK.
const ClientVersion = "0.2.0"

// MakeClient creates a new Client instance if an API key and Evervault App UUID is provided. The client
// will connect to Evervaults API to retrieve the public keys from your Evervault App.
//
//	import "github.com/evervault/evervault-go"
//	evClient, err := evervault.MakeClient("<API_KEY>", "<APP_UUID>")
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
//	encrypted := evClient.Encrypt("Hello, world!");
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
