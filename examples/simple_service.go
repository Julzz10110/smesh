package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"smesh/discovery"
)

// SimpleService represents a simple HTTP service
type SimpleService struct {
	name    string
	port    string
	disco   *discovery.Client
	healthy bool
}

func NewSimpleService(name, port, discoveryAddr string) *SimpleService {
	return &SimpleService{
		name:    name,
		port:    port,
		disco:   discovery.NewClient(discoveryAddr),
		healthy: true,
	}
}

func (s *SimpleService) Start() error {
	mux := http.NewServeMux()

	// Health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if s.healthy {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("Unhealthy"))
		}
	})

	// Main endpoint
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"service": s.name,
			"port":    s.port,
			"time":    time.Now().Format(time.RFC3339),
		}
		json.NewEncoder(w).Encode(response)
	})

	// Register in discovery
	go s.register()

	// Periodically update health status
	go s.updateHealth()

	log.Printf("Service %s starting on port %s", s.name, s.port)
	return http.ListenAndServe(":"+s.port, mux)
}

func (s *SimpleService) register() {
	// Wait a bit before registration
	time.Sleep(2 * time.Second)

	service := &discovery.ServiceInfo{
		Name:    s.name,
		Address: "localhost",
		Port:    parsePort(s.port),
		Healthy: true,
	}

	if err := s.disco.Register(service); err != nil {
		log.Printf("Failed to register service: %v", err)
	} else {
		log.Printf("Service %s registered in discovery", s.name)
	}
}

func (s *SimpleService) updateHealth() {
	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {
		if err := s.disco.UpdateHealth(s.name, "localhost:"+s.port, s.healthy); err != nil {
			log.Printf("Failed to update health: %v", err)
		}
	}
}

func parsePort(s string) int {
	var port int
	fmt.Sscanf(s, "%d", &port)
	if port == 0 {
		port = 8080
	}
	return port
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: simple_service <name> <port> [discovery_addr]")
		os.Exit(1)
	}

	name := os.Args[1]
	port := os.Args[2]
	discoveryAddr := "http://localhost:12001"
	if len(os.Args) > 3 {
		discoveryAddr = os.Args[3]
	}

	service := NewSimpleService(name, port, discoveryAddr)
	if err := service.Start(); err != nil {
		log.Fatalf("Failed to start service: %v", err)
	}
}
