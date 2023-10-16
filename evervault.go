// Evervault Go SDK.
// Supported functions are:
//   - Encrypt data server-side including files
//   - Invoke Functions
//   - Invoke Cages
//   - Proxy requests through Outbound Relay
//
// For up to date usage docs please refer to [Evervault docs]
//
// [Evervault docs]: https://docs.evervault.com/sdks/go
package evervault

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"reflect"
	"strconv"
	"time"

	"github.com/evervault/evervault-go/internal/crypto"
	"github.com/evervault/evervault-go/internal/datatypes"
)

// MakeClient creates a new Client instance if an API key and Evervault App ID is provided. The client
// will connect to Evervaults API to retrieve the public keys from your Evervault App.
//
//	import "github.com/evervault/evervault-go"
//	evClient, err := evervault.MakeClient("<API_KEY>", "<APP_UUID>")
//
// If an apiKey is not passed then ErrAppCredentialsRequired is returned. If the client cannot
// be created then nil will be returned.
func MakeClient(appUUID, apiKey string) (*Client, error) {
	config := MakeConfig()
	return MakeCustomClient(appUUID, apiKey, config)
}

// MakeCustomClient creates a new Client instance but can be specified with a Config. The client
// will connect to Evervaults API to retrieve the public keys from your Evervault App.
//
// If an apiKey or appUUID is not passed then ErrAppCredentialsRequired is returned. If the client cannot
// be created then nil will be returned.
func MakeCustomClient(appUUID, apiKey string, config Config) (*Client, error) {
	if apiKey == "" || appUUID == "" {
		return nil, ErrAppCredentialsRequired
	}

	client := &Client{appUUID: appUUID, apiKey: apiKey, Config: config}
	if err := client.initClient(); err != nil {
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
func (c *Client) Encrypt(value any) (string, error) {
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

func (c *Client) encryptValue(value any, aesKey, ephemeralPublicKey []byte) (string, error) {
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

// Decrypt decrypts data previously encrypted with Encrypt or through Relay
//
//	decrypted := evClient.Decrypt(encrypted);
func (c *Client) Decrypt(encryptedData any) (any, error) {
	// Used to check whether encryptedData is the zero value for its type
	if reflect.ValueOf(encryptedData).IsZero() {
		return nil, ErrInvalidDataType
	}

	decryptResponse, err := c.decrypt(encryptedData)
	if err != nil {
		return nil, err
	}

	return decryptResponse, nil
}

// CreateClientSideDecryptToken creates a time bound token that can be used to perform decrypts.
// The payload is required and ensures the token can only be used to decrypt that specific payload.
//
// The expiry is the time the token should expire.
// The max time is 10 minutes in the future and defaults to 5 minutes if not provided.
//
// # It returns a TokenResponse or an error
//
// token, err := CreateClientSideDecryptToken(payload, timeInFiveMinutes).
func (c *Client) CreateClientSideDecryptToken(payload any, expiry ...time.Time) (TokenResponse, error) {
	// Used to check whether payload is the zero value for its type
	if payload == nil {
		return TokenResponse{}, ErrInvalidDataType
	}

	var epochTime int64
	if expiry != nil {
		epochTime = expiry[0].UnixMilli()
	}

	token, err := c.createToken("api:decrypt", payload, epochTime)
	if err != nil {
		return TokenResponse{}, err
	}

	return token, nil
}
