//go:build unit_test
// +build unit_test

package evervault_test

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
)

func TestAttestationDocCacheInit(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	assert := assert.New(t)

	httpmock.RegisterResponder("GET", "https://test.app-133.cage.evervault.com/.well-known/attestation",
		httpmock.NewStringResponder(200, `{"attestation_doc": "1aGVsbG8gd29ybGQ"}`))

	cache, _ := evervault.newAttestationCache("test.app-133.cage.evervault.com", 2700)
	doc := cache.Get()

	decodedDoc, _ := base64.StdEncoding.DecodeString("1aGVsbG8gd29ybGQ")
	assert.Contains(string(doc), string(decodedDoc))
}

func TestAttestationDocCachePoll(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	assert := assert.New(t)

	httpmock.RegisterResponder("GET", "https://test.app-133.cage.evervault.com/.well-known/attestation",
		httpmock.NewStringResponder(200, `{"attestation_doc": "1aGVsbG8gd29ybGQ="}`))

	httpmock.RegisterResponder("GET", "https://test.app-133.cage.evervault.com/.well-known/attestation",
		httpmock.NewStringResponder(200, `{"attestation_doc": "aGVsbG8gd29ybGQgMg=="}`))

	cache, _ := evervault.newAttestationCache("test.app-133.cage.evervault.com", 1)

	doc := cache.Get()
	decodedDoc, _ := base64.StdEncoding.DecodeString("aGVsbG8gd29ybGQgMg==")
	assert.Contains(string(doc), string(decodedDoc))

	time.Sleep(1 * time.Second)

	newDoc := cache.Get()
	newDecodedDoc, _ := base64.StdEncoding.DecodeString("aGVsbG8gd29ybGQgMg==")

	assert.Contains(string(newDoc), string(newDecodedDoc))
}
