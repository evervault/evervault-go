//go:build unit_test
// +build unit_test

package evervault_test

import (
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"github.com/evervault/evervault-go"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
)

func TestAttestationDocCacheInit(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	assert := assert.New(t)

	httpmock.RegisterResponder("GET", "https://test.app-133.cage.evervault.com/.well-known/attestation",
		httpmock.NewStringResponder(200, `{"attestation_doc": "1aGVsbG8gd29ybGQ"}`))

	cache, _ := evervault.NewAttestationCache("test.app-133.cage.evervault.com", 2700)
	doc := cache.Get()

	decodedDoc, _ := base64.StdEncoding.DecodeString("1aGVsbG8gd29ybGQ")
	assert.Contains(string(doc), string(decodedDoc))
	cache.StopPolling()
}

func TestAttestationDocCachePoll(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	assert := assert.New(t)

	callCount := 0

	responder := httpmock.Responder(func(req *http.Request) (*http.Response, error) {
		callCount++
		if callCount == 1 {
			return httpmock.NewStringResponse(200, `{"attestation_doc": "ZnJpZGF5"}`), nil
		}
		return httpmock.NewStringResponse(200, `{"attestation_doc": "bW9uZGF5"}`), nil
	})

	httpmock.RegisterResponder("GET", "https://test.app-133.cage.evervault.com/.well-known/attestation", responder)

	duration := 500 * time.Millisecond
	cache, _ := evervault.NewAttestationCache("test.app-133.cage.evervault.com", duration)

	doc := cache.Get()
	decodedDoc, _ := base64.StdEncoding.DecodeString("ZnJpZGF5") 
	assert.Contains(string(doc), string(decodedDoc))

	time.Sleep(1 * time.Second)

	newDoc := cache.Get()
	newDecodedDoc, _ := base64.StdEncoding.DecodeString("bW9uZGF5")

	assert.Contains(string(newDoc), string(newDecodedDoc))
	cache.StopPolling()
}
