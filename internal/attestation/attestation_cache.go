package attestation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"
)

type Cache struct {
	cageURL  *url.URL
	doc      []byte
	mutex    sync.RWMutex
	client   http.Client
	ticker   *time.Ticker
	stopPoll chan bool
}

const (
	pollTimeout    = 10 * time.Second
	maxRetries     = 3
	initialBackoff = 1 * time.Second
	maxBackoff     = 5 * time.Second
)

func NewAttestationCache(cageDomain string, pollingInterval time.Duration) (*Cache, error) {
	cageURL, err := url.Parse(fmt.Sprintf("https://%s/.well-known/attestation", cageDomain))
	if err != nil {
		return nil, fmt.Errorf("cage url could not be parsed %w", err)
	}

	cache := &Cache{
		cageURL:  cageURL,
		doc:      make([]byte, 0),
		mutex:    sync.RWMutex{},
		client:   http.Client{Timeout: pollTimeout},
		ticker:   time.NewTicker(pollingInterval),
		stopPoll: make(chan bool),
	}

	ctx, cancel := context.WithTimeout(context.Background(), pollTimeout)
	defer cancel()

	cache.LoadDoc(ctx)

	go cache.pollAPI()

	return cache, nil
}

func (c *Cache) Set(doc []byte) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.doc = doc
}

func (c *Cache) Get() []byte {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	return c.doc
}

func (c *Cache) StopPolling() {
	c.stopPoll <- true
}

//nolint:tagliatelle
type CageDocResponse struct {
	AttestationDoc string `json:"attestation_doc"`
}

func (c *Cache) getDoc(ctx context.Context) ([]byte, error) {
	var lastErr error

	backoff := initialBackoff

	for retry := 0; retry < maxRetries; retry++ {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("context cancelled while getting attestation doc: %w", ctx.Err())
		default:
			docBytes, err := c.tryGetDoc(ctx)
			if err == nil {
				return docBytes, nil
			}

			lastErr = err
			
			if retry < maxRetries-1 {
				log.Printf("Attempt %d failed, retrying in %v: %v", retry+1, backoff, err)

				select {
				case <-ctx.Done():
					return nil, fmt.Errorf("context cancelled during retry backoff: %w", ctx.Err())
				case <-time.After(backoff):
				}

				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
			}
		}
	}

	return nil, fmt.Errorf("failed to get attesatation document after %d retries, last error: %w", maxRetries, lastErr)
}

func (c *Cache) tryGetDoc(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, c.cageURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("could not generate attestation doc request: %w", err)
	}

	req = req.WithContext(ctx)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not get attestation doc: %w", err)
	}
	defer resp.Body.Close()

	var response CageDocResponse
	if err = json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("error decoding attestation doc json: %w", err)
	}

	docBytes, err := base64.StdEncoding.DecodeString(response.AttestationDoc)
	if err != nil {
		return nil, fmt.Errorf("error decoding attestation doc: %w", err)
	}

	return docBytes, nil
}

func (c *Cache) LoadDoc(ctx context.Context) {
	docBytes, err := c.getDoc(ctx)
	if err != nil {
		log.Printf("could not get attestation doc: %v", err)
	}

	c.Set(docBytes)
}

func (c *Cache) pollAPI() {
	ctx, cancel := context.WithTimeout(context.Background(), pollTimeout)
	defer cancel()

	for {
		select {
		case <-c.ticker.C:
			docBytes, err := c.getDoc(ctx)
			if err != nil {
				log.Printf("couldn't get attestation doc: %v", err)
			}

			c.Set(docBytes)
		case <-c.stopPoll:
			c.ticker.Stop()
			return
		}
	}
}
