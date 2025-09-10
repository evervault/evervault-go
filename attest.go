package evervault

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"github.com/evervault/evervault-go/attestation"
	internalAttestation "github.com/evervault/evervault-go/internal/attestation"
	"github.com/hf/nitrite"
)

const loadDocTimeout = 30 * time.Second

// mapAttestationPCRs maps the attestation document's PCRs to a PCRs struct.
// If PCR 0, 1 or 2 are empty, then this function returns an error.
func mapAttestationPCRs(attestationPCRs nitrite.Document) (attestation.PCRs, error) {
	// We verify a subset of non zero PCRs
	PCR0, ok := attestationPCRs.PCRs[0]
	if !ok {
		return attestation.PCRs{}, fmt.Errorf("missing PCR0 in returned attestation document")
	}
	PCR1, ok := attestationPCRs.PCRs[1]
	if !ok {
		return attestation.PCRs{}, fmt.Errorf("missing PCR1 in returned attestation document")
	}
	PCR2, ok := attestationPCRs.PCRs[2]
	if !ok {
		return attestation.PCRs{}, fmt.Errorf("missing PCR2 in returned attestation document")
	}

	PCR8 := attestationPCRs.PCRs[8]

	return attestation.PCRs{
		PCR0: hex.EncodeToString(PCR0),
		PCR1: hex.EncodeToString(PCR1),
		PCR2: hex.EncodeToString(PCR2),
		PCR8: hex.EncodeToString(PCR8),
	}, nil
}

// attestCert attests the certificate against the expected PCRs.
func attestCert(certificate *x509.Certificate, expectedPCRs []attestation.PCRs, remoteAttestationDoc nitrite.Document) (bool, error) {
	if verified := verifyPCRs(expectedPCRs, remoteAttestationDoc); !verified {
		return verified, nil
	}

	// Validate that the cert public key is embedded in the attestation doc
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return false, fmt.Errorf("failed to marshal publicKey to bytes %w", err)
	}

	return bytes.Equal(pubKeyBytes, remoteAttestationDoc.UserData), nil
}

// verifyPCRs verifies the expected PCRs against the attestation document.
func verifyPCRs(expectedPCRs []attestation.PCRs, remoteAttestationDoc nitrite.Document) bool {
	attestationPCRs, err := mapAttestationPCRs(remoteAttestationDoc)
	if err != nil {
		return false
	}
	for _, expectedPCR := range expectedPCRs {
		if expectedPCR.SatisfiedBy(attestationPCRs) {
			return true
		}
	}

	return false
}

// filterEmptyPCRs removes empty PCR sets from the given slice.
func filterEmptyPCRs(expectedPCRs []attestation.PCRs) []attestation.PCRs {
	var ret []attestation.PCRs

	for _, pcrs := range expectedPCRs {
		if !pcrs.IsEmpty() {
			ret = append(ret, pcrs)
		}
	}

	return ret
}

// dialTimeout specifies the timeout duration for dialing a remote host.
var dialTimeout = 5 * time.Second

// createDial returns a custom dial function that performs attestation on the connection.
func (c *Client) createDial(
	tlsConfig *tls.Config,
	cache *internalAttestation.Cache,
	pcrManager internalAttestation.PCRManager,
) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(dialCtx context.Context, network, addr string) (net.Conn, error) {
		if network != "tcp" {
			return nil, ErrUnsupportedNetworkType
		}

		// Create a TCP connection
		conn, err := net.DialTimeout(network, addr, dialTimeout)
		if err != nil {
			return nil, fmt.Errorf("error creating cage dial %w", err)
		}

		expectedPCRs := pcrManager.Get()

		// Perform TLS handshake with custom configuration
		tlsConn := tls.Client(conn, tlsConfig)
		if err = tlsConn.Handshake(); err != nil {
			return nil, fmt.Errorf("error connecting to cage %w", err)
		}

		cert := tlsConn.ConnectionState().PeerCertificates[0]
		doc := cache.Get()

		attestationDoc, err := attestCert(cert, *expectedPCRs, doc)
		if err != nil {
			loadCtx, cancel := context.WithTimeout(dialCtx, loadDocTimeout)
			defer cancel()

			cache.LoadDoc(loadCtx)

			attestationDoc, err = attestCert(cert, *expectedPCRs, cache.Get())
			if err != nil {
				return nil, fmt.Errorf("error attesting Connection %w", err)
			}
		}

		if !attestationDoc {
			return nil, ErrAttestionFailure
		}

		return tlsConn, nil
	}
}
