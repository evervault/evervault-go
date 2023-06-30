package evervault

import (
	"errors"
	"strconv"
)

var (
	ErrClientNotInitilization          = errors.New("evervault client unable to initialize")
	ErrAppCredentialsRequired          = errors.New("evervault client requires an api key and app uuid")
	ErrCryptoKeyImportError            = errors.New("unable to import crypto key")
	ErrCryptoUnableToPerformEncryption = errors.New("unable to perform encryption")
	ErrInvalidDataType                 = errors.New("Error: Invalid datatype")
)

type APIError struct {
	StatusCode int
	Message    string
	Details    map[string]interface{}
}

func (e APIError) Error() string {
	return "Status code received " + strconv.Itoa(e.StatusCode) + ", " + e.Message
}
