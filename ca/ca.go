package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// CA represents Certificate Authority
type CA struct {
	caCert    *x509.Certificate
	caKey     *rsa.PrivateKey
	certStore map[string]*CertInfo
	mu        sync.RWMutex
}

// CertInfo contains certificate information
type CertInfo struct {
	Cert      *x509.Certificate
	Key       *rsa.PrivateKey
	ExpiresAt time.Time
	Serial    *big.Int
}

// NewCA creates a new CA
func NewCA() (*CA, error) {
	ca := &CA{
		certStore: make(map[string]*CertInfo),
	}

	// Generate CA key
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA key: %w", err)
	}

	// Create CA certificate
	caCert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"SMesh CA"},
			Country:       []string{"RU"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // 10 years
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caCertBytes, err := x509.CreateCertificate(rand.Reader, caCert, caCert, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	caCertParsed, err := x509.ParseCertificate(caCertBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	ca.caCert = caCertParsed
	ca.caKey = caKey

	return ca, nil
}

// GenerateCertificate generates a new certificate for a service
func (ca *CA) GenerateCertificate(serviceName string, validityDays int) (*x509.Certificate, *rsa.PrivateKey, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	// Check existing certificate
	if certInfo, exists := ca.certStore[serviceName]; exists {
		// If certificate is still valid (more than 7 days until expiration), return it
		if time.Until(certInfo.ExpiresAt) > 7*24*time.Hour {
			return certInfo.Cert, certInfo.Key, nil
		}
	}

	// Generate new key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key: %w", err)
	}

	// Create certificate
	serial := big.NewInt(time.Now().Unix())
	cert := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   serviceName,
			Organization: []string{"SMesh Service"},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 0, validityDays),
		SubjectKeyId: []byte{1, 2, 3, 4, 5},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		DNSNames:     []string{serviceName, "localhost"},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca.caCert, &key.PublicKey, ca.caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	certParsed, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Save certificate
	ca.certStore[serviceName] = &CertInfo{
		Cert:      certParsed,
		Key:       key,
		ExpiresAt: certParsed.NotAfter,
		Serial:    serial,
	}

	return certParsed, key, nil
}

// GetCACert returns CA certificate in PEM format
func (ca *CA) GetCACert() ([]byte, error) {
	ca.mu.RLock()
	defer ca.mu.RUnlock()

	return ca.caCert.Raw, nil
}

// GetCACertPEM returns CA certificate in PEM format
func (ca *CA) GetCACertPEM() ([]byte, error) {
	caCertBytes, err := ca.GetCACert()
	if err != nil {
		return nil, err
	}

	caCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCertBytes,
	})

	return caCertPEM, nil
}

// GetCertificatePEM returns certificate and key in PEM format
func (ca *CA) GetCertificatePEM(serviceName string) ([]byte, []byte, error) {
	ca.mu.RLock()
	defer ca.mu.RUnlock()

	certInfo, exists := ca.certStore[serviceName]
	if !exists {
		return nil, nil, fmt.Errorf("certificate not found for service: %s", serviceName)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certInfo.Cert.Raw,
	})

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certInfo.Key),
	})

	return certPEM, keyPEM, nil
}

// RotateCertificate forcibly rotates the certificate
func (ca *CA) RotateCertificate(serviceName string) error {
	_, _, err := ca.GenerateCertificate(serviceName, 30)
	return err
}

// GetTLSConfig returns TLS configuration for client/server
func (ca *CA) GetTLSConfig(serviceName string, isServer bool) (*tls.Config, error) {
	cert, key, err := ca.GenerateCertificate(serviceName, 30)
	if err != nil {
		return nil, err
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  key,
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(ca.caCert)

	config := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		RootCAs:      caCertPool,
		ClientCAs:    caCertPool,
	}

	if isServer {
		config.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return config, nil
}

// StartHTTPServer starts HTTP server for CA API
func (ca *CA) StartHTTPServer(port string) error {
	mux := http.NewServeMux()

	// Get CA certificate
	mux.HandleFunc("/ca/cert", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		caCertPEM, err := ca.GetCACertPEM()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write(caCertPEM)
	})

	// Get certificate for service
	mux.HandleFunc("/cert/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		serviceName := r.URL.Path[len("/cert/"):]
		if serviceName == "" {
			http.Error(w, "Service name required", http.StatusBadRequest)
			return
		}

		certPEM, keyPEM, err := ca.GetCertificatePEM(serviceName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		response := map[string]string{
			"cert": string(certPEM),
			"key":  string(keyPEM),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	// Generate new certificate
	mux.HandleFunc("/cert/generate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		serviceName := r.URL.Query().Get("service")
		if serviceName == "" {
			http.Error(w, "Service name required", http.StatusBadRequest)
			return
		}

		_, _, err := ca.GenerateCertificate(serviceName, 30)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Certificate generated"))
	})

	// Certificate rotation
	mux.HandleFunc("/cert/rotate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		serviceName := r.URL.Query().Get("service")
		if serviceName == "" {
			http.Error(w, "Service name required", http.StatusBadRequest)
			return
		}

		err := ca.RotateCertificate(serviceName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Certificate rotated"))
	})

	server := &http.Server{
		Addr:    port,
		Handler: mux,
	}

	return server.ListenAndServe()
}
