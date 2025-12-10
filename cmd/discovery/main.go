package main

import (
	"flag"
	"log"
	"os"

	"smesh/discovery"
)

func main() {
	nodeID := flag.String("node-id", "node1", "Node ID")
	bindAddr := flag.String("bind", ":12000", "Bind address")
	raftDir := flag.String("raft-dir", "./raft", "Raft data directory")
	joinAddr := flag.String("join", "", "Address of existing node to join")
	httpPort := flag.String("http-port", ":12001", "HTTP API port")
	flag.Parse()

	// Create directory for Raft
	if err := os.MkdirAll(*raftDir, 0755); err != nil {
		log.Fatalf("Failed to create raft directory: %v", err)
	}

	// Create discovery
	d, err := discovery.NewDiscovery(*nodeID, *bindAddr, *raftDir)
	if err != nil {
		log.Fatalf("Failed to create discovery: %v", err)
	}

	// Join cluster if address is specified
	if *joinAddr != "" {
		// Use advertise address for join (if bind starts with ':', add localhost)
		joinRaftAddr := *bindAddr
		if len(*bindAddr) > 0 && (*bindAddr)[0] == ':' {
			joinRaftAddr = "localhost" + *bindAddr
		}

		if err := d.Join(*nodeID, joinRaftAddr); err != nil {
			log.Printf("Failed to join cluster: %v", err)
		} else {
			log.Printf("Joined cluster at %s", *joinAddr)
		}
	}

	// Start HTTP server
	log.Printf("Discovery HTTP server starting on %s", *httpPort)
	if err := d.StartHTTPServer(*httpPort); err != nil {
		log.Fatalf("Failed to start HTTP server: %v", err)
	}
}
