package evervault

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

type AttestationCache struct {
	cageURL       	string
	pollingInterval time.Duration
	doc             []byte
	mutex           sync.RWMutex
}

func NewAttestationCache(cageDomain string, pollingInterval time.Duration) *AttestationCache {
	cageURL := fmt.Sprintf("https://%s/.well-known/attestation", cageDomain)
	doc, _ := getDoc(cageURL)

	cache := &AttestationCache{
		cageURL:      	 cageURL,
		pollingInterval: pollingInterval,
		doc:             doc,
		mutex:           sync.RWMutex{},
	}

	go cache.pollAPI(cageURL, pollingInterval)

	return cache
}

func (c *AttestationCache) Set(doc []byte) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.doc = doc
}

func (c *AttestationCache) Get() []byte {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	return c.doc
}

type CageDocResponse struct {
	AttesationDoc string `json:"attestation_doc"`
}

func getDoc(apiEndpoint string) ([]byte, error) {
	resp, err := http.Get(apiEndpoint)
	if err != nil {
		fmt.Println("Error getting attestation doc:", err)
	}
	defer resp.Body.Close()

	var response CageDocResponse
	err = json.NewDecoder(resp.Body).Decode(&response)

	if err != nil {
		log.Fatalf("Error parsing JSON: %v", err)
	}

	return base64.StdEncoding.DecodeString(response.AttesationDoc)
}

func (c *AttestationCache) refreshDoc() {
	docBytes, err := getDoc(c.cageURL)
	if err != nil {
		log.Fatalf("Error getting attestation doc: %v", err)
	}
	c.Set(docBytes)
}

func (c *AttestationCache) pollAPI(cageURL string, interval time.Duration) {
	ticker := time.NewTicker(interval)

	for {
		select {
		case <-ticker.C:
			docBytes, err := getDoc(cageURL)
			if err != nil {
				log.Fatalf("Error getting attestation doc: %v", err)
			}
			c.Set(docBytes)
		}
	}
}
