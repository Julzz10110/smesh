package main

import (
	"flag"
	"log"

	"smesh/ca"
)

func main() {
	port := flag.String("port", ":8443", "Port for CA HTTP server")
	flag.Parse()

	ca, err := ca.NewCA()
	if err != nil {
		log.Fatalf("Failed to create CA: %v", err)
	}

	log.Printf("CA server starting on %s", *port)
	if err := ca.StartHTTPServer(*port); err != nil {
		log.Fatalf("Failed to start CA server: %v", err)
	}
}

