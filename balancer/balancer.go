package balancer

import (
	"fmt"
	"math/rand"
	"net/http"
	"sync"
	"time"
)

// Backend represents a service backend
type Backend struct {
	URL     string
	Healthy bool
	mu      sync.RWMutex
}

// SetHealthy sets health status
func (b *Backend) SetHealthy(healthy bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.Healthy = healthy
}

// IsHealthy returns health status
func (b *Backend) IsHealthy() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.Healthy
}

// Balancer manages load balancing
type Balancer struct {
	backends map[string][]*Backend
	mu       sync.RWMutex
	strategy Strategy
	client   *http.Client
}

// Strategy defines load balancing strategy
type Strategy string

const (
	StrategyRoundRobin Strategy = "round_robin"
	StrategyRandom     Strategy = "random"
	StrategyLeastConn  Strategy = "least_conn"
)

// NewBalancer creates a new balancer
func NewBalancer(strategy Strategy) *Balancer {
	return &Balancer{
		backends: make(map[string][]*Backend),
		strategy: strategy,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// AddBackend adds a backend for a service
func (b *Balancer) AddBackend(serviceName, url string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	backends := b.backends[serviceName]
	for _, be := range backends {
		if be.URL == url {
			return // already exists
		}
	}

	backends = append(backends, &Backend{
		URL:     url,
		Healthy: true,
	})
	b.backends[serviceName] = backends
}

// RemoveBackend removes a backend
func (b *Balancer) RemoveBackend(serviceName, url string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	backends := b.backends[serviceName]
	newBackends := make([]*Backend, 0)
	for _, be := range backends {
		if be.URL != url {
			newBackends = append(newBackends, be)
		}
	}
	b.backends[serviceName] = newBackends
}

// UpdateBackends updates backend list for a service
func (b *Balancer) UpdateBackends(serviceName string, urls []string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	existing := make(map[string]bool)
	for _, url := range urls {
		existing[url] = true
	}

	// Remove non-existent ones
	backends := b.backends[serviceName]
	newBackends := make([]*Backend, 0)
	for _, be := range backends {
		if existing[be.URL] {
			newBackends = append(newBackends, be)
		}
	}

	// Add new ones
	for _, url := range urls {
		found := false
		for _, be := range newBackends {
			if be.URL == url {
				found = true
				break
			}
		}
		if !found {
			newBackends = append(newBackends, &Backend{
				URL:     url,
				Healthy: true,
			})
		}
	}

	b.backends[serviceName] = newBackends
}

// GetBackend returns next backend according to strategy
func (b *Balancer) GetBackend(serviceName string) (*Backend, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	backends := b.backends[serviceName]
	if len(backends) == 0 {
		return nil, fmt.Errorf("no backends available for service: %s", serviceName)
	}

	// Filter only healthy backends
	healthy := make([]*Backend, 0)
	for _, be := range backends {
		if be.IsHealthy() {
			healthy = append(healthy, be)
		}
	}

	if len(healthy) == 0 {
		return nil, fmt.Errorf("no healthy backends available for service: %s", serviceName)
	}

	switch b.strategy {
	case StrategyRoundRobin:
		return b.roundRobin(healthy), nil
	case StrategyRandom:
		return b.random(healthy), nil
	case StrategyLeastConn:
		return b.leastConn(healthy), nil
	default:
		return healthy[0], nil
	}
}

// roundRobin returns next backend in round-robin fashion
func (b *Balancer) roundRobin(backends []*Backend) *Backend {
	// Simple implementation - can be improved with a counter
	return backends[rand.Intn(len(backends))]
}

// random returns a random backend
func (b *Balancer) random(backends []*Backend) *Backend {
	return backends[rand.Intn(len(backends))]
}

// leastConn returns backend with least connections
// Simplified implementation - always returns first
func (b *Balancer) leastConn(backends []*Backend) *Backend {
	return backends[0]
}

// HealthCheck checks backend health
func (b *Balancer) HealthCheck(backend *Backend) bool {
	resp, err := b.client.Get(backend.URL + "/health")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// StartHealthChecker starts periodic health checking
func (b *Balancer) StartHealthChecker(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			b.mu.RLock()
			allBackends := make([]*Backend, 0)
			for _, backends := range b.backends {
				allBackends = append(allBackends, backends...)
			}
			b.mu.RUnlock()

			for _, backend := range allBackends {
				healthy := b.HealthCheck(backend)
				backend.SetHealthy(healthy)
			}
		}
	}()
}

// SetBackendHealth sets backend health status
func (b *Balancer) SetBackendHealth(serviceName, url string, healthy bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	backends := b.backends[serviceName]
	for _, be := range backends {
		if be.URL == url {
			be.SetHealthy(healthy)
			break
		}
	}
}
