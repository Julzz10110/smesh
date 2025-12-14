package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func loadCertificates(certFile, keyFile, caFile string) (*tls.Certificate, *x509.CertPool, error) {
	// Load client certificate and key
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read cert file: %w", err)
	}

	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read key file: %w", err)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Load CA certificate
	caPEMData, err := os.ReadFile(caFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read CA cert file: %w", err)
	}

	// Clean up the PEM data - handle potential encoding issues
	caPEMStr := string(caPEMData)
	
	// Remove BOM if present (UTF-8 BOM)
	caPEMStr = strings.TrimPrefix(caPEMStr, "\ufeff")
	
	caPEMStr = strings.TrimSpace(caPEMStr)
	caPEMBytes := []byte(caPEMStr)
	
	// Try to decode PEM
	block, rest := pem.Decode(caPEMBytes)
	if block == nil {
		// Debug: show what we got
		preview := caPEMStr
		if len(preview) > 100 {
			preview = preview[:100]
		}
		return nil, nil, fmt.Errorf("failed to decode CA certificate PEM. First 100 chars: %q", preview)
	}
	
	// If there's more data after the first PEM block, log warning but continue
	if len(rest) > 0 && strings.TrimSpace(string(rest)) != "" {
		fmt.Printf("Warning: CA certificate file contains additional data after PEM block\n")
	}

	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(caCert)

	return &cert, caCertPool, nil
}

func testEndpoint(name, url string, cert *tls.Certificate, caCertPool *x509.CertPool) {
	fmt.Printf("\nTesting %s: %s\n", name, url)
	fmt.Println(strings.Repeat("-", 60))

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{*cert},
				RootCAs:      caCertPool,
				ServerName:   "localhost",
			},
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		fmt.Printf("❌ FAILED: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("❌ FAILED to read response: %v\n", err)
		return
	}

	fmt.Printf("✓ SUCCESS\n")
	fmt.Printf("  Status: %s (%d)\n", resp.Status, resp.StatusCode)
	fmt.Printf("  Response: %s\n", string(body))
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run test-mtls-client.go <endpoint_url>")
		fmt.Println("Example: go run test-mtls-client.go https://localhost:9001/health")
		os.Exit(1)
	}

	url := os.Args[1]

	// Look for certificate files in current directory
	certFile := "test-client.crt"
	keyFile := "test-client.key"
	caFile := "ca.crt"

	// Check if files exist
	for _, file := range []string{certFile, keyFile, caFile} {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			fmt.Printf("Error: Certificate file not found: %s\n", file)
			fmt.Println("Please run .\\test-mtls.ps1 first to generate certificates")
			os.Exit(1)
		}
	}

	fmt.Println("=== SMesh mTLS Client Test ===")
	fmt.Printf("URL: %s\n", url)
	fmt.Printf("Using certificates: %s, %s, %s\n", certFile, keyFile, caFile)

	// Load certificates
	cert, caCertPool, err := loadCertificates(certFile, keyFile, caFile)
	if err != nil {
		log.Fatalf("Failed to load certificates: %v", err)
	}

	// Test the endpoint
	testEndpoint("Endpoint", url, cert, caCertPool)

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("Test complete!")
}

