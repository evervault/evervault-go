package attestation_test

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"testing"
	"testing/synctest"
	"time"

	"github.com/evervault/evervault-go/internal/attestation"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)


type Fixture struct {
	Doc 				string
	Timestamp 	string
	Cert 				string
	Digest 			string
}

func NewFixture(t *testing.T, prefix string) Fixture {
	doc, err := os.ReadFile(fmt.Sprintf("testdata/%s_attestation_doc.txt", prefix))
	require.NoError(t, err)
	
	expected_ts, err := os.ReadFile(fmt.Sprintf("testdata/%s_expected_timestamp.txt", prefix))
	require.NoError(t, err)
	
	expected_cert, err := os.ReadFile(fmt.Sprintf("testdata/%s_expected_cert.txt", prefix))
	require.NoError(t, err)

	loadedFixture := Fixture {
		Doc: string(doc),
		Timestamp: string(expected_ts),
		Cert: string(expected_cert),
		Digest: "SHA384",
	}
	return loadedFixture
}

func TestAttestationDocCacheInit(t *testing.T) {
	synctest.Run(func () {
		format := "Jan 2 15:04:05 2006 MST"
		fixedTime, err := time.Parse(format, "Sep 10 13:36:26 2025 UTC") // pinned time for fixture
		require.NoError(t, err)
		time.Sleep(time.Until(fixedTime))
		synctest.Wait()

		httpmock.Activate()
		defer httpmock.DeactivateAndReset()

		assert := assert.New(t)

		firstFixture := NewFixture(t, "20250910133616")
		httpmock.RegisterResponder("GET", "https://test.app-133.cage.evervault.com/.well-known/attestation",
			httpmock.NewStringResponder(200, fmt.Sprintf(`{"attestation_doc": "%s"}`, firstFixture.Doc)))

		cache, err := attestation.NewAttestationCache("test.app-133.cage.evervault.com", 2700)
		require.NoError(t, err)

		doc := cache.Get()

		assert.Equal(doc.Digest, firstFixture.Digest)
		encodedCertificate := base64.StdEncoding.EncodeToString(doc.Certificate)
		assert.Equal(encodedCertificate, firstFixture.Cert)
		assert.Equal(fmt.Sprintf("%d",doc.Timestamp), firstFixture.Timestamp)
		cache.StopPolling()
	})
}

func TestAttestationDocCachePoll(t *testing.T) {
	synctest.Run(func () {
		format := "Jan 2 15:04:05 2006 MST"
		fixedTime, err := time.Parse(format, "Sep 10 13:36:26 2025 UTC") // pinned time for fixture
		require.NoError(t, err)
		time.Sleep(time.Until(fixedTime))
		synctest.Wait()

		httpmock.Activate()
		defer httpmock.DeactivateAndReset()
	
		assert := assert.New(t)
	
		callCount := 0

		firstFixture := NewFixture(t, "20250910133616")
		secondFixture := NewFixture(t, "20250910141940")
	
		responder := httpmock.Responder(func(req *http.Request) (*http.Response, error) {
			callCount++
			if callCount == 1 {
				return httpmock.NewStringResponse(200, fmt.Sprintf(`{"attestation_doc": "%s"}`, firstFixture.Doc)), nil
			}
			return httpmock.NewStringResponse(200, fmt.Sprintf(`{"attestation_doc": "%s"}`, secondFixture.Doc)), nil
		})
	
		httpmock.RegisterResponder("GET", "https://test.app-133.cage.evervault.com/.well-known/attestation", responder)
	
		duration := 60 * time.Second
		cache, err := attestation.NewAttestationCache("test.app-133.cage.evervault.com", duration)
		require.NoError(t, err)
	
		doc := cache.Get()
		assert.Equal(doc.Digest, firstFixture.Digest)
		encodedCertificate := base64.StdEncoding.EncodeToString(doc.Certificate)
		assert.Equal(encodedCertificate, firstFixture.Cert)
		assert.Equal(fmt.Sprintf("%d",doc.Timestamp), firstFixture.Timestamp)
	
		secondFixtureFixedTime, err := time.Parse(format, "Sep 10 14:19:40 2025 UTC") // pinned time for fixture
		require.NoError(t, err)

		time.Sleep(time.Until(secondFixtureFixedTime))
		synctest.Wait()
	
		newDoc := cache.Get()
	
		assert.Equal(newDoc.Digest, secondFixture.Digest)
		newDocEncodedCertificate := base64.StdEncoding.EncodeToString(newDoc.Certificate)
		assert.Equal(newDocEncodedCertificate, secondFixture.Cert)
		assert.Equal(fmt.Sprintf("%d",newDoc.Timestamp), secondFixture.Timestamp)
		cache.StopPolling()
	})
}
