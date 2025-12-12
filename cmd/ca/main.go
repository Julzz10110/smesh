package main

import (
	"flag"
	"log"

	"smesh/ca"
)

func main() {
	port := flag.String("port", ":8443", "Port for CA HTTP server")
	dbPath := flag.String("db", "./ca.db", "Path to CA database file")
	flag.Parse()

	ca, err := ca.NewCA(*dbPath)
	if err != nil {
		log.Fatalf("Failed to create CA: %v", err)
	}
	defer ca.Close()

	log.Printf("CA server starting on %s (database: %s)", *port, *dbPath)
	if err := ca.StartHTTPServer(*port); err != nil {
		log.Fatalf("Failed to start CA server: %v", err)
	}
}

