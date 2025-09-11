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
	"github.com/evervault/evervault-go/internal/testhelper"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
)


type Fixture struct {
	Doc 				string
	Timestamp 	string
	Cert 				string
	Digest 			string
}

func NewFixture(prefix string) Fixture {
	doc, _ := os.ReadFile(fmt.Sprintf("testdata/%s_attestation_doc.txt", prefix))
	expected_ts, _ := os.ReadFile(fmt.Sprintf("testdata/%s_expected_timestamp.txt", prefix))
	expected_cert, _ := os.ReadFile(fmt.Sprintf("testdata/%s_expected_cert.txt", prefix))

	loadedFixture := Fixture {
		Doc: string(doc),
		Timestamp: string(expected_ts),
		Cert: string(expected_cert),
		Digest: "SHA384",
	}
	return loadedFixture
}


func TestAttestationDocCacheInit(t *testing.T) {
	testhelper.SyncTest(t, func (t *testing.T) {
		format := "Jan 2 15:04:05 2006 MST"
		fixedTime, _ := time.Parse(format, "Sep 10 13:36:26 2025 UTC") // pinned time for fixture
		time.Sleep(time.Until(fixedTime))
		synctest.Wait()

		httpmock.Activate()
		defer httpmock.DeactivateAndReset()

		assert := assert.New(t)

		firstFixture := NewFixture("20250910133616")
		httpmock.RegisterResponder("GET", "https://test.app-133.cage.evervault.com/.well-known/attestation",
			httpmock.NewStringResponder(200, fmt.Sprintf(`{"attestation_doc": "%s"}`, firstFixture.Doc)))

		cache, _ := attestation.NewAttestationCache("test.app-133.cage.evervault.com", 2700)
		doc := cache.Get()

		assert.Equal(doc.Digest, firstFixture.Digest)
		encodedCertificate := base64.StdEncoding.EncodeToString(doc.Certificate)
		assert.Equal(encodedCertificate, firstFixture.Cert)
		assert.Equal(fmt.Sprintf("%d",doc.Timestamp), firstFixture.Timestamp)
		cache.StopPolling()
	})
}

func TestAttestationDocCachePoll(t *testing.T) {
	testhelper.SyncTest(t, func (t *testing.T) {
		format := "Jan 2 15:04:05 2006 MST"
		fixedTime, _ := time.Parse(format, "Sep 10 13:36:26 2025 UTC") // pinned time for fixture
		time.Sleep(time.Until(fixedTime))
		synctest.Wait()

		httpmock.Activate()
		defer httpmock.DeactivateAndReset()
	
		assert := assert.New(t)
	
		callCount := 0

		firstFixture := NewFixture("20250910133616")
		secondFixture := NewFixture("20250910141940")
	
		responder := httpmock.Responder(func(req *http.Request) (*http.Response, error) {
			callCount++
			if callCount == 1 {
				return httpmock.NewStringResponse(200, fmt.Sprintf(`{"attestation_doc": "%s"}`, firstFixture.Doc)), nil
			}
			return httpmock.NewStringResponse(200, fmt.Sprintf(`{"attestation_doc": "%s"}`, secondFixture.Doc)), nil
		})
	
		httpmock.RegisterResponder("GET", "https://test.app-133.cage.evervault.com/.well-known/attestation", responder)
	
		duration := 60 * time.Second
		cache, _ := attestation.NewAttestationCache("test.app-133.cage.evervault.com", duration)
	
		doc := cache.Get()
		assert.Equal(doc.Digest, firstFixture.Digest)
		encodedCertificate := base64.StdEncoding.EncodeToString(doc.Certificate)
		assert.Equal(encodedCertificate, firstFixture.Cert)
		assert.Equal(fmt.Sprintf("%d",doc.Timestamp), firstFixture.Timestamp)
	
		secondFixtureFixedTime, _ := time.Parse(format, "Sep 10 14:19:40 2025 UTC") // pinned time for fixture
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
