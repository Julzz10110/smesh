package ca

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client represents a client for CA API
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a new CA client
func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// GetCACert gets CA certificate
func (c *Client) GetCACert() (*x509.Certificate, error) {
	resp, err := c.httpClient.Get(c.baseURL + "/ca/cert")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get CA cert: status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

// GetCertificate gets certificate for a service
func (c *Client) GetCertificate(serviceName string) ([]byte, []byte, error) {
	resp, err := c.httpClient.Get(c.baseURL + "/cert/" + serviceName)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("failed to get certificate: status %d", resp.StatusCode)
	}

	var result struct {
		Cert string `json:"cert"`
		Key  string `json:"key"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return []byte(result.Cert), []byte(result.Key), nil
}

// GenerateCertificate generates a new certificate
func (c *Client) GenerateCertificate(serviceName string) error {
	resp, err := c.httpClient.Post(c.baseURL+"/cert/generate?service="+serviceName, "", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to generate certificate: status %d", resp.StatusCode)
	}

	return nil
}

// GetTLSConfig gets TLS configuration for a service
func (c *Client) GetTLSConfig(serviceName string, isServer bool) (*tls.Config, error) {
	// Get CA certificate
	caCert, err := c.GetCACert()
	if err != nil {
		return nil, err
	}

	// Generate certificate for service
	if err := c.GenerateCertificate(serviceName); err != nil {
		return nil, err
	}

	// Get certificate and key
	certPEM, keyPEM, err := c.GetCertificate(serviceName)
	if err != nil {
		return nil, err
	}

	// Parse certificate and key
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	// Create CA pool
	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(caCert)

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		ClientCAs:    caCertPool,
	}

	if isServer {
		config.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return config, nil
}
