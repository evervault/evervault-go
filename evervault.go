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
	"strconv"
	"time"

	"github.com/evervault/evervault-go/internal/crypto"
	"github.com/evervault/evervault-go/internal/datatypes"
)

// Current version of the evervault SDK.
const ClientVersion = "0.5.0"

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

func (c *Client) getAesKeyAndCompressedEphemeralPublicKey() ([]byte, []byte, error) {
	ephemeralECDHCurve := ecdh.P256()

	ephemeralECDHKey, err := ephemeralECDHCurve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating ephemeral curve %w", err)
	}

	appPublicKeyCurve := ecdh.P256()

	appPubKey, err := appPublicKeyCurve.NewPublicKey(c.p256PublicKeyUncompressed)
	if err != nil {
		return nil, nil, ErrCryptoKeyImportError
	}

	shared, err := ephemeralECDHKey.ECDH(appPubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("Error generating ephermeral key %w", err)
	}

	ephemeralPublicECDHKeyBytes := ephemeralECDHKey.PublicKey().Bytes()
	compressedEphemeralPublicKey := crypto.CompressPublicKey(ephemeralPublicECDHKeyBytes)

	aesKey, err := crypto.DeriveKDFAESKey(ephemeralPublicECDHKeyBytes, shared)
	if err != nil {
		return nil, nil, err
	}

	return aesKey, compressedEphemeralPublicKey, nil
}

// EncryptString encrypts the value passed to it using the Evervault Encryption Scheme.
// The encrypted value is returned as an Evervault formatted encrypted string.
//
//	encrypted := evClient.EncryptString("Hello, world!");
//
// If an error occurs then nil is returned. If the error is due a problem with Key creation then
// ErrCryptoKeyImportError is returned. For anyother error ErrCryptoUnableToPerformEncryption is returned.
func (c *Client) EncryptString(value string) (string, error) {
	aesKey, compressedEphemeralPublicKey, err := c.getAesKeyAndCompressedEphemeralPublicKey()
	if err != nil {
		return "", err
	}

	return c.encryptString(value, aesKey, compressedEphemeralPublicKey)
}

// EncryptInt encrypts the value passed to it using the Evervault Encryption Scheme.
// The encrypted value is returned as an Evervault formatted encrypted string.
//
//	encrypted := evClient.EncryptInt(100);
//
// If an error occurs then nil is returned. If the error is due a problem with Key creation then
// ErrCryptoKeyImportError is returned. For anyother error ErrCryptoUnableToPerformEncryption is returned.
func (c *Client) EncryptInt(value int) (string, error) {
	aesKey, compressedEphemeralPublicKey, err := c.getAesKeyAndCompressedEphemeralPublicKey()
	if err != nil {
		return "", err
	}

	return c.encryptInt(value, aesKey, compressedEphemeralPublicKey)
}

// EncryptFloat64 encrypts the value passed to it using the Evervault Encryption Scheme.
// The encrypted value is returned as an Evervault formatted encrypted string.
//
//	encrypted := evClient.EncryptInt(100.1);
//
// If an error occurs then nil is returned. If the error is due a problem with Key creation then
// ErrCryptoKeyImportError is returned. For anyother error ErrCryptoUnableToPerformEncryption is returned.
func (c *Client) EncryptFloat64(value float64) (string, error) {
	aesKey, compressedEphemeralPublicKey, err := c.getAesKeyAndCompressedEphemeralPublicKey()
	if err != nil {
		return "", err
	}

	return c.encryptFloat64(value, aesKey, compressedEphemeralPublicKey)
}

// EncryptBool encrypts the value passed to it using the Evervault Encryption Scheme.
// The encrypted value is returned as an Evervault formatted encrypted string.
//
//	encrypted := evClient.EncryptBool(true);
//
// If an error occurs then nil is returned. If the error is due a problem with Key creation then
// ErrCryptoKeyImportError is returned. For anyother error ErrCryptoUnableToPerformEncryption is returned.
func (c *Client) EncryptBool(value bool) (string, error) {
	aesKey, compressedEphemeralPublicKey, err := c.getAesKeyAndCompressedEphemeralPublicKey()
	if err != nil {
		return "", err
	}

	return c.encryptBool(value, aesKey, compressedEphemeralPublicKey)
}

// EncryptByteArray encrypts the value passed to it using the Evervault Encryption Scheme.
// The encrypted value is returned as an Evervault formatted encrypted string.
//
//	encrypted := evClient.EncryptByteArray([]byte("Hello, world!"));
//
// If an error occurs then nil is returned. If the error is due a problem with Key creation then
// ErrCryptoKeyImportError is returned. For anyother error ErrCryptoUnableToPerformEncryption is returned.
func (c *Client) EncryptByteArray(value []byte) (string, error) {
	aesKey, compressedEphemeralPublicKey, err := c.getAesKeyAndCompressedEphemeralPublicKey()
	if err != nil {
		return "", err
	}

	return c.encryptByteArray(value, aesKey, compressedEphemeralPublicKey)
}

func (c *Client) encryptString(value string, aesKey, ephemeralPublicKey []byte) (string, error) {
	return crypto.EncryptValue(aesKey, ephemeralPublicKey, c.p256PublicKeyCompressed, value, datatypes.String)
}

func (c *Client) encryptInt(value int, aesKey, ephemeralPublicKey []byte) (string, error) {
	val := strconv.Itoa(value)
	return crypto.EncryptValue(aesKey, ephemeralPublicKey, c.p256PublicKeyCompressed, val, datatypes.Number)
}

func (c *Client) encryptFloat64(value float64, aesKey, ephemeralPublicKey []byte) (string, error) {
	val := strconv.FormatFloat(value, 'f', -1, 64)
	return crypto.EncryptValue(aesKey, ephemeralPublicKey, c.p256PublicKeyCompressed, val, datatypes.Number)
}

func (c *Client) encryptBool(value bool, aesKey, ephemeralPublicKey []byte) (string, error) {
	val := strconv.FormatBool(value)
	return crypto.EncryptValue(aesKey, ephemeralPublicKey, c.p256PublicKeyCompressed, val, datatypes.Boolean)
}

func (c *Client) encryptByteArray(value []byte, aesKey, ephemeralPublicKey []byte) (string, error) {
	val := string(value)
	return crypto.EncryptValue(aesKey, ephemeralPublicKey, c.p256PublicKeyCompressed, val, datatypes.String)
}

// DecryptString decrypts data previously encrypted with Encrypt or through Relay
//
//	decrypted := evClient.Decrypt(encrypted);
func (c *Client) DecryptString(encryptedData string) (string, error) {
	decryptResponse, err := c.decrypt(encryptedData)
	if err != nil {
		return "", err
	}

	return decryptResponse.(string), nil
}

// DecryptInt decrypts data previously encrypted with Encrypt or through Relay
//
//	decrypted := evClient.DecryptInt(encrypted);
func (c *Client) DecryptInt(encryptedData string) (int, error) {
	decryptResponse, err := c.decrypt(encryptedData)
	if err != nil {
		return 0, err
	}

	// decryptedToFloat, err := strconv.ParseFloat(decryptResponse, 64)
	// if err != nil {
	// 	return 0, err
	// }
	
	return int(decryptResponse.(float64)), nil
}

// DecryptFloat64 decrypts data previously encrypted with Encrypt or through Relay
//
//	decrypted := evClient.DecryptInt(encrypted);
func (c *Client) DecryptFloat64(encryptedData string) (float64, error) {
	decryptResponse, err := c.decrypt(encryptedData)
	if err != nil {
		return 0, err
	}
	return decryptResponse.(float64), nil
}

// DecryptBool decrypts data previously encrypted with Encrypt or through Relay
//
//	decrypted := evClient.DecryptBool(encrypted);
func (c *Client) DecryptBool(encryptedData string) (bool, error) {
	decryptResponse, err := c.decrypt(encryptedData)
	if err != nil {
		return false, err
	}
	return decryptResponse.(bool), nil
}

// DecryptByteArray decrypts data previously encrypted with Encrypt or through Relay
//
//	decrypted := evClient.DecryptByteArray(encrypted);
func (c *Client) DecryptByteArray(encryptedData string) ([]byte, error) {
	decryptResponse, err := c.decrypt(encryptedData)
	if err != nil {
		return nil, err
	}
	return []byte(decryptResponse.(string)), nil
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
