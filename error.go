package evervault

import (
	"errors"
	"strconv"
)

var (
	// An Error with attesting the connection to a cage.
	ErrAttestionFailure = errors.New("attestation failed")
	// Evervault client has not been initialized.
	ErrClientNotInitilization = errors.New("evervault client unable to initialize")
	// Missing required application credentials for initialisation.
	ErrAppCredentialsRequired = errors.New("evervault client requires an api key and app uuid")
	// Unable the import Keys for crypto.
	ErrCryptoKeyImportError = errors.New("unable to import crypto key")
	// Unable to encrypt data.
	ErrCryptoUnableToPerformEncryption = errors.New("unable to perform encryption")
	// An unsupported data type was specified for encryption.
	ErrInvalidDataType = errors.New("Error: Invalid datatype")
)

// Evervault API Error. Returned from evervault servers when an erro is encountered.
type APIError struct {
	StatusCode int
	Message    string
	Details    map[string]interface{}
}

func (e APIError) Error() string {
	return "Status code received " + strconv.Itoa(e.StatusCode) + ", " + e.Message
}
