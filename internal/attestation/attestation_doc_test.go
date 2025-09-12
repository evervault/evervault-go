package attestation_test

import (
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"github.com/evervault/evervault-go/internal/attestation"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAttestationDocCacheInit(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	assert := assert.New(t)

	httpmock.RegisterResponder("GET", "https://test.app-133.cage.evervault.com/.well-known/attestation",
		httpmock.NewStringResponder(200, `{"attestation_doc": "1aGVsbG8gd29ybGQ"}`))

	cache, err := attestation.NewAttestationCache("test.app-133.cage.evervault.com", 2700)
	require.NoError(t, err)
	doc := cache.Get()

	decodedDoc, err := base64.StdEncoding.DecodeString("1aGVsbG8gd29ybGQ")
	require.NoError(t, err)
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
	cache, err := attestation.NewAttestationCache("test.app-133.cage.evervault.com", duration)
	require.NoError(t, err)

	doc := cache.Get()
	decodedDoc, err := base64.StdEncoding.DecodeString("ZnJpZGF5")
	require.NoError(t, err) 
	assert.Contains(string(doc), string(decodedDoc))

	time.Sleep(1 * time.Second)

	newDoc := cache.Get()
	newDecodedDoc, err := base64.StdEncoding.DecodeString("bW9uZGF5")
	require.NoError(t, err)

	assert.Contains(string(newDoc), string(newDecodedDoc))
	cache.StopPolling()
}
