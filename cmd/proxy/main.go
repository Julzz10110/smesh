package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"smesh/proxy"
)

func main() {
	serviceName := flag.String("service-name", "service1", "Service name")
	port := flag.String("port", ":8080", "Proxy port")
	caURL := flag.String("ca-url", "http://localhost:8443", "CA server URL")
	discoveryAddr := flag.String("discovery-addr", "http://localhost:12001", "Discovery server address")
	flag.Parse()

	p, err := proxy.NewProxy(*serviceName, *caURL, *discoveryAddr)
	if err != nil {
		log.Fatalf("Failed to create proxy: %v", err)
	}

	// Start backend updates from discovery
	p.StartDiscoveryUpdater(30 * time.Second)

	// Do initial backend update immediately
	log.Printf("Performing initial backend update from discovery...")
	if err := p.UpdateBackendsFromDiscovery(); err != nil {
		log.Printf("Warning: Failed to update backends initially: %v", err)
		log.Printf("Backends will be updated automatically every 30 seconds")
	} else {
		log.Printf("Initial backend update completed")
	}

	// Setup graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Start proxy in goroutine
	go func() {
		log.Printf("Proxy starting for service %s on %s", *serviceName, *port)
		if err := p.Start(*port); err != nil {
			log.Printf("Proxy server error: %v", err)
		}
	}()

	// Wait for interrupt signal
	<-sigChan
	log.Println("Shutting down Proxy server...")

	if err := p.Shutdown(); err != nil {
		log.Printf("Error during shutdown: %v", err)
	} else {
		log.Println("Proxy server stopped gracefully")
	}
}
