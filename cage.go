package evervault

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/hf/nitrite"
)

var (
	ErrAttestionFailure = errors.New("attestation failed")
	cageDialTimeout     = 5 * time.Second
)

type PCRs struct {
	PCR0 string
	PCR1 string
	PCR2 string
	PCR8 string
}

// Will return a http.Client that is connected to a specified cage hostname with a fully attested client.
func (c *Client) CageClient(cageHostname string, expectedPCRs []PCRs) (*http.Client, error) {
	c.expectedPCRs = expectedPCRs

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

func (c *Client) cagesClient(cageHostname string, caCert []byte) (*http.Client, error) {
	transport, err := c.cagesTransport(cageHostname, caCert)
	if err != nil {
		return nil, err
	}

	return &http.Client{Transport: transport}, nil
}

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
		DialTLS:           customDial,
	}, nil
}

func AttestConnection(cert []byte, expectedPCRs []PCRs) (bool, error) {
	// 1) extract the X509Certificate certificate from the bytes
	certificate, err := x509.ParseCertificate(cert)
	if err != nil {
		return false, fmt.Errorf("unable to parse certificate %w", err)
	}
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

	verified := VerifyPCRs(expectedPCRs, *res.Document)

	return verified, nil
}

func VerifyPCRs(expectedPCRs []PCRs, attestationDocument nitrite.Document) bool {
	attestationPCRs := mapAttestationPCRs(attestationDocument)
	for _, expectedPCR := range expectedPCRs {
		isEqual := expectedPCR == attestationPCRs
		return isEqual
	}

	return false
}

func mapAttestationPCRs(attestationPCRs nitrite.Document) PCRs {
	// We verify a subset of non zero PCRs
	PCR0 := attestationPCRs.PCRs[0]
	PCR1 := attestationPCRs.PCRs[1]
	PCR2 := attestationPCRs.PCRs[2]
	PCR8 := attestationPCRs.PCRs[8]

	return PCRs{
		PCR0: hex.EncodeToString(PCR0),
		PCR1: hex.EncodeToString(PCR1),
		PCR2: hex.EncodeToString(PCR2),
		PCR8: hex.EncodeToString(PCR8),
	}
}

func (c *Client) createDial(tlsConfig *tls.Config) func(network, addr string) (net.Conn, error) {
	return func(network, addr string) (net.Conn, error) {
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

		attesationDoc, err := AttestConnection(cert.Raw, c.expectedPCRs)
		if err != nil {
			return nil, fmt.Errorf("Error attesting Connection %w", err)
		}

		if !attesationDoc {
			return nil, ErrAttestionFailure
		}

		return tlsConn, nil
	}
}
