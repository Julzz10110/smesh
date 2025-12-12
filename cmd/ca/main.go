package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"smesh/ca"
)

func main() {
	port := flag.String("port", ":8443", "Port for CA HTTP server")
	dbPath := flag.String("db", "./ca.db", "Path to CA database file")
	flag.Parse()

	caInstance, err := ca.NewCA(*dbPath)
	if err != nil {
		log.Fatalf("Failed to create CA: %v", err)
	}
	defer caInstance.Close()

	// Setup graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Start server in goroutine
	go func() {
		log.Printf("CA server starting on %s (database: %s)", *port, *dbPath)
		if err := caInstance.StartHTTPServer(*port); err != nil {
			log.Printf("CA server error: %v", err)
		}
	}()

	// Wait for interrupt signal
	<-sigChan
	log.Println("Shutting down CA server...")

	if err := caInstance.Shutdown(); err != nil {
		log.Printf("Error during shutdown: %v", err)
	} else {
		log.Println("CA server stopped gracefully")
	}
}

