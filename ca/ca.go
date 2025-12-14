package ca

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/boltdb/bolt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// Metrics for CA
	caCertificatesGenerated = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ca_certificates_generated_total",
			Help: "Total number of certificates generated",
		},
		[]string{"service"},
	)
	caCertificateRotations = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ca_certificate_rotations_total",
			Help: "Total number of certificate rotations",
		},
		[]string{"service"},
	)
	caHTTPRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ca_http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "endpoint", "status"},
	)
	caHTTPRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ca_http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "endpoint"},
	)
	caCertificatesCount = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "ca_certificates_count",
			Help: "Current number of certificates stored",
		},
	)
)

func init() {
	prometheus.MustRegister(caCertificatesGenerated)
	prometheus.MustRegister(caCertificateRotations)
	prometheus.MustRegister(caHTTPRequests)
	prometheus.MustRegister(caHTTPRequestDuration)
	prometheus.MustRegister(caCertificatesCount)
}

// CA represents Certificate Authority
type CA struct {
	caCert    *x509.Certificate
	caKey     *rsa.PrivateKey
	certStore map[string]*CertInfo
	db        *bolt.DB
	dbPath    string
	server    *http.Server
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
// If dbPath is empty, certificates will be stored only in memory
func NewCA(dbPath string) (*CA, error) {
	ca := &CA{
		certStore: make(map[string]*CertInfo),
		dbPath:     dbPath,
	}

	// Open database if path is provided
	if dbPath != "" {
		// Create directory if it doesn't exist
		if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
			return nil, fmt.Errorf("failed to create CA directory: %w", err)
		}

		db, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 1 * time.Second})
		if err != nil {
			return nil, fmt.Errorf("failed to open CA database: %w", err)
		}
		ca.db = db

		// Create buckets
		if err := ca.initDB(); err != nil {
			db.Close()
			return nil, fmt.Errorf("failed to initialize database: %w", err)
		}

		// Load CA certificate and key
		if err := ca.loadCA(); err != nil {
			// If CA doesn't exist, generate new one
			if err := ca.generateCA(); err != nil {
				db.Close()
				return nil, fmt.Errorf("failed to generate CA: %w", err)
			}
		}

		// Load existing certificates
		if err := ca.loadCertificates(); err != nil {
			db.Close()
			return nil, fmt.Errorf("failed to load certificates: %w", err)
		}
	} else {
		// In-memory mode: generate CA
		if err := ca.generateCA(); err != nil {
			return nil, fmt.Errorf("failed to generate CA: %w", err)
		}
	}

	return ca, nil
}

// Close closes the CA database
func (ca *CA) Close() error {
	if ca.db != nil {
		return ca.db.Close()
	}
	return nil
}

// generateCA generates a new CA certificate and key
func (ca *CA) generateCA() error {
	// Generate CA key
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate CA key: %w", err)
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
		return fmt.Errorf("failed to create CA certificate: %w", err)
	}

	caCertParsed, err := x509.ParseCertificate(caCertBytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	ca.caCert = caCertParsed
	ca.caKey = caKey

	// Save CA to database if available
	if ca.db != nil {
		if err := ca.saveCA(); err != nil {
			return fmt.Errorf("failed to save CA: %w", err)
		}
	}

	return nil
}

// initDB initializes database buckets
func (ca *CA) initDB() error {
	return ca.db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("ca"))
		if err != nil {
			return err
		}
		_, err = tx.CreateBucketIfNotExists([]byte("certificates"))
		return err
	})
}

// saveCA saves CA certificate and key to database
func (ca *CA) saveCA() error {
	return ca.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("ca"))

		// Save CA certificate
		caCertPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: ca.caCert.Raw,
		})
		if err := bucket.Put([]byte("certificate"), caCertPEM); err != nil {
			return err
		}

		// Save CA key
		caKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(ca.caKey),
		})
		return bucket.Put([]byte("key"), caKeyPEM)
	})
}

// loadCA loads CA certificate and key from database
func (ca *CA) loadCA() error {
	return ca.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("ca"))
		if bucket == nil {
			return fmt.Errorf("CA bucket not found")
		}

		// Load CA certificate
		caCertPEM := bucket.Get([]byte("certificate"))
		if caCertPEM == nil {
			return fmt.Errorf("CA certificate not found")
		}

		block, _ := pem.Decode(caCertPEM)
		if block == nil {
			return fmt.Errorf("failed to decode CA certificate PEM")
		}

		caCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse CA certificate: %w", err)
		}

		// Load CA key
		caKeyPEM := bucket.Get([]byte("key"))
		if caKeyPEM == nil {
			return fmt.Errorf("CA key not found")
		}

		block, _ = pem.Decode(caKeyPEM)
		if block == nil {
			return fmt.Errorf("failed to decode CA key PEM")
		}

		caKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse CA key: %w", err)
		}

		ca.caCert = caCert
		ca.caKey = caKey

		return nil
	})
}

// loadCertificates loads all certificates from database
func (ca *CA) loadCertificates() error {
	return ca.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("certificates"))
		if bucket == nil {
			return nil // No certificates bucket yet
		}

		return bucket.ForEach(func(serviceName, data []byte) error {
			var storedData struct {
				Cert      []byte    `json:"cert"`
				Key       []byte    `json:"key"`
				ExpiresAt time.Time `json:"expiresAt"`
				Serial    string    `json:"serial"`
			}

			if err := json.Unmarshal(data, &storedData); err != nil {
				return fmt.Errorf("failed to unmarshal certificate for %s: %w", serviceName, err)
			}

			// Parse certificate
			cert, err := x509.ParseCertificate(storedData.Cert)
			if err != nil {
				return fmt.Errorf("failed to parse certificate for %s: %w", serviceName, err)
			}

			// Parse key
			key, err := x509.ParsePKCS1PrivateKey(storedData.Key)
			if err != nil {
				return fmt.Errorf("failed to parse key for %s: %w", serviceName, err)
			}

			// Parse serial number
			serial := new(big.Int)
			serial.SetString(storedData.Serial, 10)

			certInfo := &CertInfo{
				Cert:      cert,
				Key:       key,
				ExpiresAt: storedData.ExpiresAt,
				Serial:    serial,
			}

		ca.certStore[string(serviceName)] = certInfo
		return nil
	})
	})
	// Update metrics after loading
	caCertificatesCount.Set(float64(len(ca.certStore)))
	return nil
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
		DNSNames:     []string{serviceName, "localhost", "127.0.0.1"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
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
	certInfo := &CertInfo{
		Cert:      certParsed,
		Key:       key,
		ExpiresAt: certParsed.NotAfter,
		Serial:    serial,
	}
	ca.certStore[serviceName] = certInfo

	// Update metrics
	caCertificatesGenerated.WithLabelValues(serviceName).Inc()
	caCertificatesCount.Set(float64(len(ca.certStore)))

	// Save to database if available
	if ca.db != nil {
		if err := ca.saveCertificate(serviceName, certInfo); err != nil {
			// Log error but don't fail - certificate is in memory
			fmt.Printf("Warning: failed to save certificate to database: %v\n", err)
		}
	}

	return certParsed, key, nil
}

// saveCertificate saves a certificate to database
func (ca *CA) saveCertificate(serviceName string, certInfo *CertInfo) error {
	return ca.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("certificates"))
		if bucket == nil {
			return fmt.Errorf("certificates bucket not found")
		}

		// Serialize certificate info (without the actual cert/key objects)
		data := map[string]interface{}{
			"cert":      certInfo.Cert.Raw,
			"key":       x509.MarshalPKCS1PrivateKey(certInfo.Key),
			"expiresAt": certInfo.ExpiresAt,
			"serial":    certInfo.Serial.String(),
		}

		jsonData, err := json.Marshal(data)
		if err != nil {
			return fmt.Errorf("failed to marshal certificate: %w", err)
		}

		return bucket.Put([]byte(serviceName), jsonData)
	})
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
	if err == nil {
		caCertificateRotations.WithLabelValues(serviceName).Inc()
	}
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
		MinVersion:   tls.VersionTLS12,
		// Don't restrict MaxVersion - let Go choose the best
		// Don't restrict CipherSuites - let Go choose the best for compatibility
		PreferServerCipherSuites: false,
	}

	if isServer {
		// Require and verify client certificates for proper mTLS
		config.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return config, nil
}

// StartHTTPServer starts HTTP server for CA API
func (ca *CA) StartHTTPServer(port string) error {
	mux := http.NewServeMux()

	// Metrics endpoint
	mux.Handle("/metrics", promhttp.Handler())

	// Middleware for metrics
	metricsMiddleware := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			endpoint := r.URL.Path

			// Create a response writer wrapper to capture status code
			wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			next.ServeHTTP(wrapped, r)

			duration := time.Since(start).Seconds()
			status := http.StatusText(wrapped.statusCode)
			if status == "" {
				status = fmt.Sprintf("%d", wrapped.statusCode)
			}

			caHTTPRequests.WithLabelValues(r.Method, endpoint, fmt.Sprintf("%d", wrapped.statusCode)).Inc()
			caHTTPRequestDuration.WithLabelValues(r.Method, endpoint).Observe(duration)
		}
	}

	// Get CA certificate
	mux.HandleFunc("/ca/cert", metricsMiddleware(func(w http.ResponseWriter, r *http.Request) {
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
	}))

	// Get certificate for service
	mux.HandleFunc("/cert/", metricsMiddleware(func(w http.ResponseWriter, r *http.Request) {
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
	}))

	// Generate new certificate
	mux.HandleFunc("/cert/generate", metricsMiddleware(func(w http.ResponseWriter, r *http.Request) {
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
	}))

	// Certificate rotation
	mux.HandleFunc("/cert/rotate", metricsMiddleware(func(w http.ResponseWriter, r *http.Request) {
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
	}))

	// Auto-generate certificate endpoint (for service bootstrap)
	// This endpoint allows services to automatically get their certificates
	mux.HandleFunc("/cert/auto/", metricsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		serviceName := r.URL.Path[len("/cert/auto/"):]
		if serviceName == "" {
			http.Error(w, "Service name required", http.StatusBadRequest)
			return
		}

		// Auto-generate certificate if it doesn't exist
		_, _, err := ca.GenerateCertificate(serviceName, 30)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Return certificate in PEM format
		certPEM, keyPEM, err := ca.GetCertificatePEM(serviceName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		response := map[string]string{
			"cert": string(certPEM),
			"key":  string(keyPEM),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))

	ca.server = &http.Server{
		Addr:    port,
		Handler: mux,
	}

	return ca.server.ListenAndServe()
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Shutdown gracefully shuts down the CA server
func (ca *CA) Shutdown() error {
	if ca.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := ca.server.Shutdown(ctx); err != nil {
			return fmt.Errorf("failed to shutdown HTTP server: %w", err)
		}
	}
	return nil
}
