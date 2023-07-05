package evervault

import (
	"errors"
	"fmt"
)

// ErrUnVerifiedSignature is returned when a attestation docs signature cant be verified.
var ErrUnVerifiedSignature = errors.New("unable to verify certificate signature")

// ErrNoPCRs is returned when a PCRs is created without any PCR in it to attest with.
var ErrNoPCRs = errors.New("Error: no PCRs where provided to attest with")

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

// APIError represents an error returned from the Evervault API servers.
type APIError struct {
	StatusCode int
	Message    string
	Details    map[string]any
}

func (e APIError) Error() string {
	return fmt.Sprintf("Status code received %d, %s", e.StatusCode, e.Message)
}
