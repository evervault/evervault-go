package attestation

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/evervault/evervault-go/attestation"
)

type PCRManager interface {
	Get() *[]attestation.PCRs
}

type StaticProvider struct {
	pcrs *[]attestation.PCRs
}

type PollingProvider struct {
	getPcrs func() ([]attestation.PCRs, error)
	pcrs    *[]attestation.PCRs
	mutex   sync.RWMutex
	ticker  *time.Ticker
	cancel  context.CancelFunc
}

func NewPollingPCRManager(pollingInterval time.Duration,
	getPcrs func() ([]attestation.PCRs, error),
) *PollingProvider {
	emptyPCRs := []attestation.PCRs{}
	ctx, cancel := context.WithCancel(context.Background())
	cache := &PollingProvider{
		getPcrs: getPcrs,
		pcrs:    &emptyPCRs,
		mutex:   sync.RWMutex{},
		ticker:  time.NewTicker(pollingInterval),
		cancel:  cancel,
	}

	cache.load()

	go cache.pollAPI(ctx)

	return cache
}

func NewStaticPCRManager(pcrs []attestation.PCRs) *StaticProvider {
	return &StaticProvider{
		pcrs: &pcrs,
	}
}

func (c *PollingProvider) Set(pcrs *[]attestation.PCRs) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.pcrs = pcrs
}

func (c *PollingProvider) Get() *[]attestation.PCRs {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	return c.pcrs
}

func (c *StaticProvider) Get() *[]attestation.PCRs {
	return c.pcrs
}

func (c *PollingProvider) StopPolling() {
	c.cancel()
}

func (c *PollingProvider) load() {
	pcrs, err := c.getPcrs()
	if err != nil {
		log.Printf("could not get pcrs doc: %v", err)
	}

	c.Set(&pcrs)
}

func (c *PollingProvider) pollAPI(ctx context.Context) {
	for {
		select {
		case <-c.ticker.C:
			pcrs, err := c.getPcrs()
			if err != nil {
				log.Printf("couldn't get pcrs: %v", err)
			}

			c.Set(&pcrs)
		case <-ctx.Done():
			c.ticker.Stop()
			return
		}
	}
}
