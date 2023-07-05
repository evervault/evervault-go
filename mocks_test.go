package evervault_test

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/evervault/evervault-go"
	evCrypto "github.com/evervault/evervault-go/internal/crypto"
)

var now = time.Now()

type mockedEv struct {
	client  *evervault.Client
	server  *httptest.Server
	cage    *httptest.Server
	ca      *httptest.Server
	cageURL string
}

func (m *mockedEv) Close() {
	m.server.Close()
	m.cage.Close()
	m.ca.Close()
}

func makeMockedClient(t *testing.T, mockResponse map[string]any) *mockedEv {
	t.Helper()

	server := startMockHTTPServer(mockResponse)
	rootCACert, rootCAKey := generateRootCACertificate(t)
	caServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, reader *http.Request) {
		writer.WriteHeader(http.StatusOK)
		writer.Header().Set("Content-Type", "application/x-x509-ca-cert")
		certBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: rootCACert.Raw,
		})

		if _, err := writer.Write(certBytes); err != nil {
			t.Fatalf("error writing cert: %s", err)
		}
	}))
	cage := startMockCage(t, rootCACert, rootCAKey)
	client := mockedClient(t, server, caServer)

	parsedURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("error parsing server url: %s", err)
	}

	_, port, err := net.SplitHostPort(parsedURL.Host)
	if err != nil {
		t.Fatalf("error spliting host: %s", err)
	}

	cageURL := fmt.Sprintf("localhost:%s", port)

	return &mockedEv{client, server, cage, caServer, cageURL}
}

type cageRequestData map[string]interface{}

type cageResponseData struct {
	Message string                 `json:"message"`
	Body    map[string]interface{} `json:"body"`
}

type PCRs struct {
	PCR0 string `asn1:"tag:0"`
	PCR1 string `asn1:"tag:1"`
	PCR2 string `asn1:"tag:2"`
	PCR8 string `asn1:"tag:8"`
}

func startMockCage(t *testing.T, rootCA *x509.Certificate, rootCAKey crypto.PrivateKey) *httptest.Server {
	t.Helper()

	pcrs := PCRs{
		PCR0: "f039c31c536749ac6b2a9344fcb36881dd1cf066ca44afcaf9369a9877e2d3c85fa738c427d502e01e35994da7458e2d",
		PCR1: "bcdf05fefccaa8e55bf2c8d6dee9e79bbff31e34bf28a99aa19e6b29c37ee80b214a414b7607236edf26fcb78654e63f",
		PCR2: "71c478711438fe252fbd9b1da56218bea5d630da55aa56431257df77bd42f65a434601bf53be9a1901fcd61680e425c7",
		PCR8: "1650274b27bf44fba6f1779602399763af9e4567927d771b1b37aeb1ac502c84fbd6a7ab7b05600656a257247529fbb8",
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			http.Error(writer, "Error reading request body", http.StatusInternalServerError)
			return
		}
		defer request.Body.Close()

		var requestData cageRequestData

		if len(body) > 0 {
			err = json.Unmarshal(body, &requestData)
			if err != nil {
				http.Error(writer, "Error parsing JSON", http.StatusBadRequest)
				return
			}
		} else {
			requestData = make(map[string]interface{})
		}

		responseData := cageResponseData{
			Message: "Hello! I'm writing to you from within an enclave",
			Body:    requestData,
		}

		responseBody, err := json.Marshal(responseData)
		if err != nil {
			http.Error(writer, "Error creating response JSON", http.StatusInternalServerError)
			return
		}

		writer.Header().Set("Content-Type", "application/json")

		if _, err = writer.Write(responseBody); err != nil {
			log.Printf("Error writing response: %v", err)
		}
	}))

	cert := generateSSLCertWithPCRs(t, pcrs, rootCA, rootCAKey)
	server.TLS.Certificates = []tls.Certificate{cert}

	return server
}

func generateRootCACertificate(t *testing.T) (*x509.Certificate, crypto.PrivateKey) {
	t.Helper()

	rootCAKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal("failed to generate private key", err)
	}

	rootCATemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Root CA",
			Organization: []string{"Example Inc"},
		},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             now,
		NotAfter:              now.Add(time.Hour * 6),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	derBytes, err := x509.CreateCertificate(
		rand.Reader,
		rootCATemplate,
		rootCATemplate,
		&rootCAKey.PublicKey,
		rootCAKey,
	)
	if err != nil {
		t.Fatal("failed to create certificate", err)
	}

	certificate, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatal("failed to encode certificate: %w", err)
	}

	return certificate, rootCAKey
}

func generateSSLCertWithPCRs(
	t *testing.T,
	pcrs PCRs,
	rootCA *x509.Certificate,
	rootCAKey crypto.PrivateKey,
) tls.Certificate {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal("failed to generate private key", err)
	}

	extValue, err := asn1.Marshal(pcrs)
	if err != nil {
		t.Fatal("Failed to marshal PCRs", err)
	}

	psrsID := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             now,
		NotAfter:              now.Add(4 * time.Hour),
		BasicConstraintsValid: true,
		ExtraExtensions:       []pkix.Extension{{Id: psrsID, Critical: false, Value: extValue}},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, rootCA, &privateKey.PublicKey, rootCAKey)
	if err != nil {
		t.Fatal("failed to create certificate", err)
	}

	certBuffer := &bytes.Buffer{}
	if err = pem.Encode(certBuffer, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		t.Fatal("failed to encode certificate", err)
	}

	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatal("failed to marshal ECDSA private key", err)
	}

	keyBuffer := &bytes.Buffer{}
	if err = pem.Encode(keyBuffer, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKeyBytes}); err != nil {
		t.Fatal("failed to encode private key", err)
	}

	certificate, err := tls.X509KeyPair(certBuffer.Bytes(), keyBuffer.Bytes())
	if err != nil {
		t.Fatal("failed to create certificate", err)
	}

	certificate.Certificate = append(certificate.Certificate, rootCA.Raw)

	return certificate
}

func testFuncHandler(writer http.ResponseWriter, reader *http.Request, mockResponse map[string]any) {
	apiKey := reader.Header.Get("API-KEY")
	authHeader := reader.Header.Get("Authorization")

	if apiKey == "" && authHeader == "" {
		writer.WriteHeader(http.StatusUnauthorized)
		return
	}

	writer.WriteHeader(http.StatusOK)
	writer.Header().Set("Content-Type", "application/json")

	appUUIDResponse, appUUIDOk := mockResponse["appUuid"].(string)
	if !appUUIDOk {
		appUUIDResponse = ""
	}

	runIDResposne, ok := mockResponse["runId"].(string)
	if !ok {
		runIDResposne = ""
	}

	resultResponse, ok := mockResponse["result"].(map[string]any)
	if !ok {
		resultResponse = map[string]any{}
	}

	responseBody := evervault.FunctionRunResponse{
		AppUUID: appUUIDResponse,
		RunID:   runIDResposne,
		Result:  resultResponse,
	}
	if err := json.NewEncoder(writer).Encode(responseBody); err != nil {
		log.Printf("error encoding json: %s", err)
	}
}

func startMockHTTPServer(mockResponse map[string]any) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, reader *http.Request) {
		if reader.URL.Path == "/test_function" {
			testFuncHandler(writer, reader, mockResponse)
			return
		}

		if reader.URL.Path == "/v2/functions/test_function/run-token" {
			writer.WriteHeader(http.StatusOK)
			writer.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(writer).Encode(evervault.RunTokenResponse{Token: "test_token"}); err != nil {
				log.Printf("error encoding json: %s", err)
			}

			return
		}

		ephemeralECDHCurve := ecdh.P256()

		ephemeralECDHKey, err := ephemeralECDHCurve.GenerateKey(rand.Reader)
		if err != nil {
			log.Printf("error generating key: %s", err)
		}

		ephemeralPublicKey := ephemeralECDHKey.PublicKey().Bytes()
		compressedEphemeralPublicKey := evCrypto.CompressPublicKey(ephemeralPublicKey)
		keys := evervault.KeysResponse{
			TeamUUID:                "test_team_uuid",
			Key:                     "test_key",
			EcdhKey:                 "ras_key",
			EcdhP256Key:             base64.StdEncoding.EncodeToString(compressedEphemeralPublicKey),
			EcdhP256KeyUncompressed: base64.StdEncoding.EncodeToString(ephemeralPublicKey),
		}
		writer.WriteHeader(http.StatusOK)
		writer.Header().Set("Content-Type", "application/json")

		if err := json.NewEncoder(writer).Encode(keys); err != nil {
			log.Printf("error encoding json: %s", err)
		}
	}))

	return server
}

func mockedClient(t *testing.T, server, ca *httptest.Server) *evervault.Client {
	t.Helper()

	config := evervault.Config{
		EvervaultCaURL:      server.URL,
		EvervaultCagesCaURL: ca.URL,
		EvAPIURL:            server.URL,
		FunctionRunURL:      server.URL,
		RelayURL:            server.URL,
	}

	client, err := evervault.MakeCustomClient("test_api_key", "test_app_uuid", config)
	if err != nil {
		t.Fail()
	}

	return client
}
