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

// mapAttestationPCRs maps the attestation document's PCRs to a PCRs struct.
func mapAttestationPCRs(attestationPCRs nitrite.Document) attestation.PCRs {
	// We verify a subset of non zero PCRs
	PCR0 := hex.EncodeToString(attestationPCRs.PCRs[0])
	PCR1 := hex.EncodeToString(attestationPCRs.PCRs[1])
	PCR2 := hex.EncodeToString(attestationPCRs.PCRs[2])
	PCR8 := hex.EncodeToString(attestationPCRs.PCRs[8])

	return attestation.PCRs{PCR0: PCR0, PCR1: PCR1, PCR2: PCR2, PCR8: PCR8}
}

// attestCert attests the certificate against the expected PCRs.
func attestCert(certificate *x509.Certificate, expectedPCRs []attestation.PCRs, attestationDoc []byte) (bool, error) {
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

// verifyPCRs verifies the expected PCRs against the attestation document.
func verifyPCRs(expectedPCRs []attestation.PCRs, attestationDocument nitrite.Document) bool {
	attestationPCRs := mapAttestationPCRs(attestationDocument)
	for _, expectedPCR := range expectedPCRs {
		if expectedPCR.Equal(attestationPCRs) {
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
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
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

		err = tlsConn.Handshake()
		if err != nil {
			return nil, fmt.Errorf("error connecting to cage %w", err)
		}

		cert := tlsConn.ConnectionState().PeerCertificates[0]
		doc := cache.Get()

		attestationDoc, err := attestCert(cert, *expectedPCRs, doc)
		if err != nil {
			// Get new attestation doc in case of Cage deployment
			cache.LoadDoc(ctx)

			_, err := attestCert(cert, *expectedPCRs, doc)
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
