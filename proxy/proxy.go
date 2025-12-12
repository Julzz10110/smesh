package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	"smesh/balancer"
	"smesh/ca"
	"smesh/discovery"
)

// Proxy represents sidecar proxy
type Proxy struct {
	serviceName     string
	ca              *ca.CA
	discovery       *discovery.Discovery
	discoveryClient *discovery.Client
	balancer        *balancer.Balancer
	tlsConfig       *tls.Config
	server          *http.Server
	httpServer      *http.Server
	mu              sync.RWMutex
}

// NewProxy creates a new proxy
func NewProxy(serviceName string, caURL string, discoveryAddr string) (*Proxy, error) {
	// Initialize CA client (simplified version - in reality HTTP client is needed)
	// For demonstration, create local CA
	// Use empty string for in-memory mode (proxy doesn't need persistence)
	certAuthority, err := ca.NewCA("")
	if err != nil {
		return nil, fmt.Errorf("failed to create CA: %w", err)
	}

	// Get TLS configuration
	tlsConfig, err := certAuthority.GetTLSConfig(serviceName, true)
	if err != nil {
		return nil, fmt.Errorf("failed to get TLS config: %w", err)
	}

	// Create balancer
	lb := balancer.NewBalancer(balancer.StrategyRoundRobin)

	// Start health checker
	lb.StartHealthChecker(10 * time.Second)

	p := &Proxy{
		serviceName: serviceName,
		ca:          certAuthority,
		balancer:    lb,
		tlsConfig:   tlsConfig,
	}

	// Initialize discovery client (if needed)
	if discoveryAddr != "" {
		p.discoveryClient = discovery.NewClient(discoveryAddr)
	}

	return p, nil
}

// Start starts the proxy server
func (p *Proxy) Start(port string) error {
	// Create HTTP mux for health check and proxy (non-TLS)
	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("HTTP Health check request from %s", r.RemoteAddr)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	
	// Add proxy endpoint to HTTP server too
	httpMux.HandleFunc("/proxy/", p.handleProxy)
	
	// Start HTTP server for health checks and proxy on a different port
	healthPort := ":8081"
	p.httpServer = &http.Server{
		Addr:    healthPort,
		Handler: httpMux,
	}
	go func() {
		log.Printf("Proxy HTTP server starting on %s (for health checks and proxy)", healthPort)
		if err := p.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP server error: %v", err)
		}
	}()

	// Create TLS mux for actual proxy
	mux := http.NewServeMux()

	// Health check endpoint on TLS - should work without client certificate
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		// Log for debugging
		log.Printf("TLS Health check request from %s, TLS: %v", r.RemoteAddr, r.TLS != nil)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Proxy endpoint - proxies requests to other services
	mux.HandleFunc("/proxy/", p.handleProxy)

	// Service discovery endpoint - registers service
	mux.HandleFunc("/register", p.handleRegister)

	// Update backends from discovery
	mux.HandleFunc("/update-backends", p.handleUpdateBackends)

	// Create HTTP server with TLS
	p.server = &http.Server{
		Addr:      port,
		Handler:   mux,
		TLSConfig: p.tlsConfig,
	}

	log.Printf("Proxy starting on %s for service %s", port, p.serviceName)
	
	// Verify certificates are configured
	if len(p.tlsConfig.Certificates) == 0 {
		return fmt.Errorf("no TLS certificates configured")
	}
	
	// Create TLS listener manually for better control
	listener, err := net.Listen("tcp", port)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", port, err)
	}
	
	tlsListener := tls.NewListener(listener, p.tlsConfig)
	log.Printf("Proxy TLS listener created, accepting connections...")
	
	return p.server.Serve(tlsListener)
}

// Shutdown gracefully shuts down the proxy server
func (p *Proxy) Shutdown() error {
	var errs []error
	
	// Shutdown TLS server
	if p.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := p.server.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("failed to shutdown TLS server: %w", err))
		}
	}
	
	// Shutdown HTTP server
	if p.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := p.httpServer.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("failed to shutdown HTTP server: %w", err))
		}
	}
	
	// Close CA
	if p.ca != nil {
		if err := p.ca.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close CA: %w", err))
		}
	}
	
	if len(errs) > 0 {
		return fmt.Errorf("shutdown errors: %v", errs)
	}
	
	return nil
}

// handleProxy handles request proxying
func (p *Proxy) handleProxy(w http.ResponseWriter, r *http.Request) {
	// Extract target service name from path
	// Format: /proxy/service-name/path
	path := r.URL.Path[len("/proxy/"):]
	if path == "" {
		http.Error(w, "Service name required", http.StatusBadRequest)
		return
	}

	// Find first slash to separate service name and path
	var serviceName, targetPath string
	for i, char := range path {
		if char == '/' {
			serviceName = path[:i]
			targetPath = path[i:]
			break
		}
	}

	if serviceName == "" {
		serviceName = path
		targetPath = "/"
	}

	// Get backend from balancer
	backend, err := p.balancer.GetBackend(serviceName)
	if err != nil {
		log.Printf("No backend available for service %s: %v", serviceName, err)
		http.Error(w, fmt.Sprintf("No backend available: %v", err), http.StatusServiceUnavailable)
		return
	}

	log.Printf("Proxying request to %s for service %s", backend.URL, serviceName)

	// Create URL for proxying
	targetURL, err := url.Parse(backend.URL)
	if err != nil {
		log.Printf("Invalid backend URL %s: %v", backend.URL, err)
		http.Error(w, fmt.Sprintf("Invalid backend URL: %v", err), http.StatusInternalServerError)
		return
	}

	// Create reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	
	// Only use TLS transport if target URL is HTTPS
	if targetURL.Scheme == "https" {
		proxy.Transport = &http.Transport{
			TLSClientConfig: p.tlsConfig,
		}
	}

	// Update request
	r.URL.Path = targetPath
	r.URL.Host = targetURL.Host
	r.URL.Scheme = targetURL.Scheme
	r.Host = targetURL.Host

	// Proxy request
	proxy.ServeHTTP(w, r)
}

// handleRegister registers service in discovery
func (p *Proxy) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	address := r.FormValue("address")
	if address == "" {
		address = "localhost"
	}

	port := r.FormValue("port")
	if port == "" {
		http.Error(w, "Port required", http.StatusBadRequest)
		return
	}

	service := &discovery.ServiceInfo{
		Name:    p.serviceName,
		Address: address,
		Port:    parsePort(port),
		Healthy: true,
	}

	if p.discovery != nil {
		if err := p.discovery.Register(service); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else if p.discoveryClient != nil {
		if err := p.discoveryClient.Register(service); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Registered"))
}

// handleUpdateBackends updates backend list from discovery
func (p *Proxy) handleUpdateBackends(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	serviceName := r.URL.Query().Get("service")
	if serviceName == "" {
		http.Error(w, "Service name required", http.StatusBadRequest)
		return
	}

	if p.discoveryClient == nil && p.discovery == nil {
		http.Error(w, "Discovery not configured", http.StatusInternalServerError)
		return
	}

	var services []*discovery.ServiceInfo
	if p.discovery != nil {
		services = p.discovery.GetServices(serviceName)
	} else if p.discoveryClient != nil {
		var err error
		services, err = p.discoveryClient.GetServices(serviceName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	urls := make([]string, 0, len(services))
	for _, s := range services {
		// Use HTTP for services (they run on HTTP, not HTTPS)
		urls = append(urls, fmt.Sprintf("http://%s:%d", s.Address, s.Port))
	}

	p.balancer.UpdateBackends(serviceName, urls)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Backends updated"))
}

// parsePort parses port from string
func parsePort(s string) int {
	var port int
	fmt.Sscanf(s, "%d", &port)
	if port == 0 {
		port = 8080
	}
	return port
}

// DirectProxy creates a direct proxy without load balancing
func DirectProxy(targetURL string, tlsConfig *tls.Config) http.Handler {
	target, _ := url.Parse(targetURL)
	return httputil.NewSingleHostReverseProxy(target)
}

// ProxyRequest proxies a single request
func ProxyRequest(w http.ResponseWriter, r *http.Request, targetURL string, tlsConfig *tls.Config) error {
	target, err := url.Parse(targetURL)
	if err != nil {
		return err
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	r.URL.Host = target.Host
	r.URL.Scheme = target.Scheme
	r.Host = target.Host

	proxy.ServeHTTP(w, r)
	return nil
}

// UpdateBackendsFromDiscovery updates backends from discovery
func (p *Proxy) UpdateBackendsFromDiscovery() error {
	var allServices map[string][]*discovery.ServiceInfo
	var err error

	if p.discovery != nil {
		allServices = p.discovery.GetAllServices()
	} else if p.discoveryClient != nil {
		allServices, err = p.discoveryClient.GetAllServices()
		if err != nil {
			return fmt.Errorf("failed to get services from discovery: %w", err)
		}
	} else {
		return fmt.Errorf("discovery not configured")
	}

	if len(allServices) == 0 {
		log.Printf("No services found in discovery")
		return nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Update backends for each service
	updatedCount := 0
	for serviceName, services := range allServices {
		urls := make([]string, 0, len(services))
		for _, s := range services {
			if s.Healthy {
				// Use HTTP for services (they run on HTTP, not HTTPS)
				urls = append(urls, fmt.Sprintf("http://%s:%d", s.Address, s.Port))
			}
		}
		if len(urls) > 0 {
			log.Printf("Updating backends for %s: %v", serviceName, urls)
			p.balancer.UpdateBackends(serviceName, urls)
			updatedCount++
		} else {
			log.Printf("No healthy backends found for service %s", serviceName)
		}
	}

	if updatedCount == 0 {
		return fmt.Errorf("no healthy services found in discovery")
	}

	log.Printf("Updated backends for %d service(s)", updatedCount)
	return nil
}

// StartDiscoveryUpdater starts periodic backend updates from discovery
func (p *Proxy) StartDiscoveryUpdater(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			if err := p.UpdateBackendsFromDiscovery(); err != nil {
				log.Printf("Failed to update backends: %v", err)
			}
		}
	}()
}
