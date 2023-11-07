package types

import (
	"encoding/json"
	"errors"
	"fmt"
)

// ErrUnVerifiedSignature is returned when a attestation docs signature cant be verified.
var ErrUnVerifiedSignature = errors.New("unable to verify certificate signature")

// ErrNoPCRs is returned when a PCRs is created without any PCR in it to attest with.
var ErrNoPCRs = errors.New("Error: no PCRs where provided to attest with")

// ErrInvalidPCRProvider is returned when an invalid PCR provider type is passed to CagesClient.
var ErrInvalidPCRProvider = errors.New("unsupported type, must be array or callback: func() ([]types.PCRs, error)")

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

func ExtractAPIError(resp []byte) error {
	evervaultError := APIError{}
	if err := json.Unmarshal(resp, &evervaultError); err != nil {
		return fmt.Errorf("Error parsing JSON response %w", err)
	}

	if evervaultError.Code == "functions/function-not-ready" {
		functionNotReadyError := FunctionNotReadyError{Message: evervaultError.Message}
		return functionNotReadyError
	}

	if evervaultError.Code == "functions/request-timeout" {
		functionTimeoutError := FunctionTimeoutError{Message: evervaultError.Message}
		return functionTimeoutError
	}

	return evervaultError
}

// APIError represents an error returned from the Evervault API servers.
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"detail"`
}

func (e APIError) Error() string {
	return e.Message
}

// FunctionTimeoutError is returned when a function invocation times out.
type FunctionTimeoutError struct {
	Message string
}

func (e FunctionTimeoutError) Error() string {
	return e.Message
}

// FunctionNotReadyError is returned when the Function is not ready to be invoked yet.
// This can occur when it hasn't been executed in a while.
// Retrying to run the Function after a short time should resolve this.
type FunctionNotReadyError struct {
	Message string
}

func (e FunctionNotReadyError) Error() string {
	return e.Message
}

// FunctionRuntimeError is returned when an error is thrown during the function invocation.
type FunctionRuntimeError struct {
	Status    string `json:"status"`
	ErrorBody struct {
		Message string `json:"message"`
		Stack   string `json:"stack"`
	} `json:"error"`
	ID string `json:"id"`
}

func (e FunctionRuntimeError) Error() string {
	return fmt.Sprintf("Error in Function run %s: %s", e.ID, e.ErrorBody.Message)
}
