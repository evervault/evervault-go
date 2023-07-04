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
	"strings"
	"time"

	"github.com/hf/nitrite"
)

// cageDialTimeout specifies the timeout duration for dialing a cage.
var cageDialTimeout = 5 * time.Second

// prcEqual Checks if 2 PCR strings are not equal.
func pcrNotEqual(p1, p2 string) bool {
	return p1 != "" && p2 != "" && p1 != p2
}

// PCRs struct for attesting a cage connection against.
type PCRs struct {
	PCR0, PCR1, PCR2, PCR8 string
}

// Check if two PCRs are equal to each other.
func (p *PCRs) Equal(pcrs PCRs) bool {
	if pcrNotEqual(p.PCR0, pcrs.PCR0) {
		return false
	}

	if pcrNotEqual(p.PCR1, pcrs.PCR1) {
		return false
	}

	if pcrNotEqual(p.PCR2, pcrs.PCR2) {
		return false
	}

	if pcrNotEqual(p.PCR8, pcrs.PCR8) {
		return false
	}

	return true
}

// IsEmpty checks if all PCRs in the struct are empty.
func (p *PCRs) IsEmpty() bool {
	return p.PCR0 == "" && p.PCR1 == "" && p.PCR2 == "" && p.PCR8 == ""
}

// filterEmptyPCRs removes empty PCR sets from the given slice.
func filterEmptyPCRs(expectedPCRs []PCRs) []PCRs {
	var ret []PCRs

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
//	cageClient, err := evClient.CageClient(cageURL, []evervault.PCRs{expectedPCRs})
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
func (c *Client) CageClient(cageHostname string, expectedPCRs []PCRs) (*http.Client, error) {
	c.expectedPCRs = filterEmptyPCRs(expectedPCRs)
	if len(c.expectedPCRs) == 0 {
		return nil, ErrNoPCRs
	}

	caCertResponse, err := c.makeRequest(c.Config.EvervaultCagesCaURL, http.MethodGet, nil, "")
	if err != nil {
		return nil, err
	}

	cagesClient, err := c.cagesClient(cageHostname, caCertResponse)
	if err != nil {
		return nil, err
	}

	return cagesClient, nil
}

// cagesClient returns an HTTP client for connecting to the cage.
func (c *Client) cagesClient(cageHostname string, caCert []byte) (*http.Client, error) {
	transport, err := c.cagesTransport(cageHostname, caCert)
	if err != nil {
		return nil, err
	}

	return &http.Client{Transport: transport}, nil
}

// cagesTransport returns the HTTP transport for connecting to the cage.
func (c *Client) cagesTransport(cageHostname string, caCert []byte) (*http.Transport, error) {
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("error getting system cert pool %w", err)
	}

	rootCAs.AppendCertsFromPEM(caCert)
	tlsConfig := &tls.Config{
		InsecureSkipVerify: false,
		RootCAs:            rootCAs,
		MinVersion:         tls.VersionTLS12,
		ServerName:         cageHostname,
	}

	customDial := c.createDial(tlsConfig)

	return &http.Transport{
		DisableKeepAlives: true,
		DialTLSContext:    customDial,
	}, nil
}

// attestCert attests the certificate against the expected PCRs.
func attestCert(certificate *x509.Certificate, expectedPCRs []PCRs) (bool, error) {
	// Extract the largest DNS name from the certificate
	largestIndex := 0
	for i := 1; i < len(certificate.DNSNames); i++ {
		if len(certificate.DNSNames[i]) > len(certificate.DNSNames[largestIndex]) {
			largestIndex = i
		}
	}

	coseDNSValue := certificate.DNSNames[largestIndex]
	// extract the COSE signature from the DNS name
	coseSig := strings.Split(coseDNSValue, ".")[0]
	// decode the hex encoded COSE signature
	hexDecodedDNS, err := hex.DecodeString(coseSig)
	if err != nil {
		return false, fmt.Errorf("unable to decode certificate %w", err)
	}

	res, err := nitrite.Verify(hexDecodedDNS, nitrite.VerifyOptions{CurrentTime: time.Now()})
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

// verifyPCRs verifies the expected PCRs against the attestation document.
func verifyPCRs(expectedPCRs []PCRs, attestationDocument nitrite.Document) bool {
	attestationPCRs := mapAttestationPCRs(attestationDocument)
	for _, expectedPCR := range expectedPCRs {
		if expectedPCR.Equal(attestationPCRs) {
			return true
		}
	}

	return false
}

// mapAttestationPCRs maps the attestation document's PCRs to a PCRs struct.
func mapAttestationPCRs(attestationPCRs nitrite.Document) PCRs {
	// We verify a subset of non zero PCRs
	PCR0 := hex.EncodeToString(attestationPCRs.PCRs[0])
	PCR1 := hex.EncodeToString(attestationPCRs.PCRs[1])
	PCR2 := hex.EncodeToString(attestationPCRs.PCRs[2])
	PCR8 := hex.EncodeToString(attestationPCRs.PCRs[8])

	return PCRs{PCR0, PCR1, PCR2, PCR8}
}

// createDial returns a custom dial function that performs attestation on the connection.
func (c *Client) createDial(tlsConfig *tls.Config) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Create a TCP connection
		conn, err := net.DialTimeout(network, addr, cageDialTimeout)
		if err != nil {
			return nil, fmt.Errorf("Error creating cage dial %w", err)
		}

		// Perform TLS handshake with custom configuration
		tlsConn := tls.Client(conn, tlsConfig)

		err = tlsConn.Handshake()
		if err != nil {
			return nil, fmt.Errorf("Error connecting to cage %w", err)
		}

		cert := tlsConn.ConnectionState().PeerCertificates[0]

		attesationDoc, err := attestCert(cert, c.expectedPCRs)
		if err != nil {
			return nil, fmt.Errorf("Error attesting Connection %w", err)
		}

		if !attesationDoc {
			return nil, ErrAttestionFailure
		}

		return tlsConn, nil
	}
}