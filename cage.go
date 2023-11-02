package evervault

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/evervault/evervault-go/internal/attestation"
	"github.com/evervault/evervault-go/models"
	"github.com/hf/nitrite"
)

// cageDialTimeout specifies the timeout duration for dialing a cage.
var cageDialTimeout = 5 * time.Second

// filterEmptyPCRs removes empty PCR sets from the given slice.
func filterEmptyPCRs(expectedPCRs []models.PCRs) []models.PCRs {
	var ret []models.PCRs

	for _, pcrs := range expectedPCRs {
		if !pcrs.IsEmpty() {
			ret = append(ret, pcrs)
		}
	}

	return ret
}

// Will return a http.Client that is connected to a specified cage hostname with a fully attested client.
// The Client will attest the connection every time it makes a HTTP request and will return an error on request if it
// fails attestation
//
//	cageURL = "<CAGE_NAME>.<APP_UUID>.cages.evervault.com"
//	expectedPCRs := evervault.PCRs{
//		PCR0: "f039c31c536749ac6b2a9344fcb36881dd1cf066ca44afcaf9369a9877e2d3c85fa738c427d502e01e35994da7458e2d",
//		PCR1: "bcdf05fefccaa8e55bf2c8d6dee9e79bbff31e34bf28a99aa19e6b29c37ee80b214a414b7607236edf26fcb78654e63f",
//		PCR2: "71c478711438fe252fbd9b1da56218bea5d630da55aa56431257df77bd42f65a434601bf53be9a1901fcd61680e425c7",
//		PCR8: "1650274b27bf44fba6f1779602399763af9e4567927d771b1b37aeb1ac502c84fbd6a7ab7b05600656a257247529fbb8",
//	}
//
//	cageClient, err := evClient.CagesClient(cageURL, []evervault.PCRs{expectedPCRs})
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	payload, err := json.Marshal(fmt.Sprintf(`{"encrypted": "%s"}`, encrypted))
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	req, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("https://%s/", cageURL), bytes.NewBuffer(payload))
//	req.Close = true
//	req.Header.Set("API-KEY", "<API_KEY>")
//	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
//
//	resp, err := cageClient.Do(req)
func (c *Client) CagesClient(cageHostname string, pcrs interface{}) (*http.Client, error) {

	pcrManager, err := attestation.NewCagePCRManager(cageHostname, c.Config.CagesPollingInterval, pcrs)
	if err != nil {
		return nil, err
	}

	expectedPCRs := pcrManager.Get()

	if len(expectedPCRs) == 0 {
		return nil, ErrNoPCRs
	}

	cache, err := attestation.NewAttestationCache(cageHostname, c.Config.CagesPollingInterval)
	if err != nil {
		return nil, err
	}

	cagesClient := c.cagesClient(cageHostname, cache, pcrManager)

	return cagesClient, nil
}

// cagesClient returns an HTTP client for connecting to the cage.
func (c *Client) cagesClient(cageHostname string, cache *attestation.Cache, provider attestation.PCRManager) *http.Client {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS12,
		ServerName:         cageHostname,
	}

	transport := &http.Transport{
		DisableKeepAlives: true,
		DialTLSContext:    c.createDial(tlsConfig, cache, provider),
	}

	return &http.Client{Transport: transport}
}

// verifyPCRs verifies the expected PCRs against the attestation document.
func verifyPCRs(expectedPCRs []models.PCRs, attestationDocument nitrite.Document) bool {
	attestationPCRs := mapAttestationPCRs(attestationDocument)
	for _, expectedPCR := range expectedPCRs {
		if expectedPCR.Equal(attestationPCRs) {
			return true
		}
	}

	return false
}

// mapAttestationPCRs maps the attestation document's PCRs to a PCRs struct.
func mapAttestationPCRs(attestationPCRs nitrite.Document) models.PCRs {
	// We verify a subset of non zero PCRs
	PCR0 := hex.EncodeToString(attestationPCRs.PCRs[0])
	PCR1 := hex.EncodeToString(attestationPCRs.PCRs[1])
	PCR2 := hex.EncodeToString(attestationPCRs.PCRs[2])
	PCR8 := hex.EncodeToString(attestationPCRs.PCRs[8])

	return models.PCRs{PCR0, PCR1, PCR2, PCR8}
}

// createDial returns a custom dial function that performs attestation on the connection.
func (c *Client) createDial(tlsConfig *tls.Config, cache *attestation.Cache, pcrManager attestation.PCRManager) func(ctx context.Context,
	network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Create a TCP connection
		conn, err := net.DialTimeout(network, addr, cageDialTimeout)
		if err != nil {
			return nil, fmt.Errorf("Error creating cage dial %w", err)
		}

		expectedPCRs := pcrManager.Get()

		// Perform TLS handshake with custom configuration
		tlsConn := tls.Client(conn, tlsConfig)

		err = tlsConn.Handshake()
		if err != nil {
			return nil, fmt.Errorf("Error connecting to cage %w", err)
		}

		cert := tlsConn.ConnectionState().PeerCertificates[0]
		doc := cache.Get()

		attestationDoc, err := attestCert(cert, expectedPCRs, doc)
		if err != nil {
			// Get new attestation doc in case of Cage deployment
			cache.LoadDoc(ctx)

			_, err := attestCert(cert, expectedPCRs, doc)
			if err != nil {
				return nil, fmt.Errorf("Error attesting Connection %w", err)
			}
		}

		if !attestationDoc {
			return nil, ErrAttestionFailure
		}

		return tlsConn, nil
	}
}

// attestCert attests the certificate against the expected PCRs.
func attestCert(certificate *x509.Certificate, expectedPCRs []models.PCRs, attestationDoc []byte) (bool, error) {
	res, err := nitrite.Verify(attestationDoc, nitrite.VerifyOptions{CurrentTime: time.Now()})
	if err != nil {
		return false, fmt.Errorf("unable to verify certificate %w", err)
	}

	if !res.SignatureOK {
		return false, ErrUnVerifiedSignature
	}

	if verified := verifyPCRs(expectedPCRs, *res.Document); !verified {
		return verified, nil
	}

	// Validate that the cert public key is embedded in the attestation doc
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return false, fmt.Errorf("failed to marshal publicKey to bytes %w", err)
	}

	return bytes.Equal(pubKeyBytes, res.Document.UserData), nil
}
