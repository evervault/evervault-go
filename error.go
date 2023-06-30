package evervault

import (
	"errors"
	"strconv"
)

// ErrAttestionFailure is retuned when a connection to a cage cannot be attested.
var ErrAttestionFailure = errors.New("attestation failed")

// ErrClientNotInitilization is returned when Evervault client has not been initialized.
var ErrClientNotInitilization = errors.New("evervault client unable to initialize")

// ErrAppCredentialsRequired is returned when the required application credentials for initialisation are missing.
var ErrAppCredentialsRequired = errors.New("evervault client requires an api key and app uuid")

// ErrCryptoKeyImportError is returned when the client is unable to the import Keys for crypto.
var ErrCryptoKeyImportError = errors.New("unable to import crypto key")

// ErrCryptoUnableToPerformEncryption is reutrned when the encryption function is unable to encrypt data.
var ErrCryptoUnableToPerformEncryption = errors.New("unable to perform encryption")

// ErrInvalidDataType is returned when an unsupported data type was specified for encryption.
var ErrInvalidDataType = errors.New("Error: Invalid datatype")

// Evervault API Error. Returned from evervault servers when an error is encountered.
type APIError struct {
	StatusCode int
	Message    string
	Details    map[string]interface{}
}

func (e APIError) Error() string {
	return "Status code received " + strconv.Itoa(e.StatusCode) + ", " + e.Message
}
