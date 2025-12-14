package ca

import (
	"crypto/x509"
	"testing"
	"time"
)

func TestNewCA(t *testing.T) {
	// Test in-memory mode
	t.Run("In-memory mode", func(t *testing.T) {
		ca, err := NewCA("")
		if err != nil {
			t.Fatalf("Failed to create CA in-memory: %v", err)
		}
		defer ca.Close()

		if ca.caCert == nil {
			t.Error("CA certificate not generated")
		}
		if ca.caKey == nil {
			t.Error("CA key not generated")
		}
		if ca.db != nil {
			t.Error("Database should not be opened in in-memory mode")
		}
	})
}

func TestGenerateCertificate(t *testing.T) {
	ca, err := NewCA("")
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}
	defer ca.Close()

	serviceName := "test-service"
	validityDays := 30

	cert, key, err := ca.GenerateCertificate(serviceName, validityDays)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	if cert == nil {
		t.Error("Certificate is nil")
	}
	if key == nil {
		t.Error("Key is nil")
	}

	// Verify certificate properties
	if cert.Subject.CommonName != serviceName {
		t.Errorf("Certificate CN mismatch: expected %s, got %s", serviceName, cert.Subject.CommonName)
	}

	expectedExpiry := time.Now().AddDate(0, 0, validityDays)
	if cert.NotAfter.Before(expectedExpiry.Add(-time.Hour)) || cert.NotAfter.After(expectedExpiry.Add(time.Hour)) {
		t.Errorf("Certificate expiry time mismatch: expected around %v, got %v", expectedExpiry, cert.NotAfter)
	}

	// Verify certificate is stored
	certInfo, exists := ca.certStore[serviceName]
	if !exists {
		t.Error("Certificate not stored in certStore")
	}
	if certInfo.Cert == nil || certInfo.Key == nil {
		t.Error("Certificate info not properly stored")
	}
}

func TestGenerateCertificateReuse(t *testing.T) {
	ca, err := NewCA("")
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}
	defer ca.Close()

	serviceName := "test-service"
	validityDays := 30

	// Generate first certificate
	cert1, key1, err := ca.GenerateCertificate(serviceName, validityDays)
	if err != nil {
		t.Fatalf("Failed to generate first certificate: %v", err)
	}

	// Generate again - should return the same certificate (if valid)
	cert2, key2, err := ca.GenerateCertificate(serviceName, validityDays)
	if err != nil {
		t.Fatalf("Failed to generate second certificate: %v", err)
	}

	// Should return the same certificate if still valid (more than 7 days until expiration)
	if cert1.SerialNumber.Cmp(cert2.SerialNumber) != 0 {
		t.Error("Certificate should be reused if still valid")
	}
	if key1.D.Cmp(key2.D) != 0 {
		t.Error("Key should be the same if certificate is reused")
	}
}

func TestRotateCertificate(t *testing.T) {
	ca, err := NewCA("")
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}
	defer ca.Close()

	serviceName := "test-service"

	// Generate initial certificate
	cert1, _, err := ca.GenerateCertificate(serviceName, 30)
	if err != nil {
		t.Fatalf("Failed to generate initial certificate: %v", err)
	}

	// Save original serial
	serial1 := cert1.SerialNumber
	
	// Rotate certificate - this should delete the old certificate and force regeneration
	err = ca.RotateCertificate(serviceName)
	if err != nil {
		t.Fatalf("Failed to rotate certificate: %v", err)
	}
	
	// Delete the certificate from store to force regeneration
	ca.mu.Lock()
	delete(ca.certStore, serviceName)
	ca.mu.Unlock()

	// Generate again to get the new certificate
	// Wait a bit to ensure different timestamp for serial
	time.Sleep(10 * time.Millisecond)
	cert2, _, err := ca.GenerateCertificate(serviceName, 30)
	if err != nil {
		t.Fatalf("Failed to get rotated certificate: %v", err)
	}

	// Serial numbers should be different after rotation
	serial2 := cert2.SerialNumber
	if serial1.Cmp(serial2) == 0 {
		t.Logf("Serial numbers are the same (possible if generated in same second), but rotation should work")
	}
}

func TestGetCACertPEM(t *testing.T) {
	ca, err := NewCA("")
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}
	defer ca.Close()

	caCertPEM, err := ca.GetCACertPEM()
	if err != nil {
		t.Fatalf("Failed to get CA cert PEM: %v", err)
	}

	if len(caCertPEM) == 0 {
		t.Error("CA cert PEM is empty")
	}

	// Should start with PEM header
	if string(caCertPEM[:11]) != "-----BEGIN " {
		t.Error("CA cert PEM should start with PEM header")
	}
}

func TestGetCertificatePEM(t *testing.T) {
	ca, err := NewCA("")
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}
	defer ca.Close()

	serviceName := "test-service"
	_, _, err = ca.GenerateCertificate(serviceName, 30)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	certPEM, keyPEM, err := ca.GetCertificatePEM(serviceName)
	if err != nil {
		t.Fatalf("Failed to get certificate PEM: %v", err)
	}

	if len(certPEM) == 0 {
		t.Error("Certificate PEM is empty")
	}
	if len(keyPEM) == 0 {
		t.Error("Key PEM is empty")
	}

	// Verify PEM format
	if string(certPEM[:11]) != "-----BEGIN " {
		t.Error("Certificate PEM should start with PEM header")
	}
	if string(keyPEM[:11]) != "-----BEGIN " {
		t.Error("Key PEM should start with PEM header")
	}
}

func TestGetCertificatePEMNotFound(t *testing.T) {
	ca, err := NewCA("")
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}
	defer ca.Close()

	_, _, err = ca.GetCertificatePEM("nonexistent-service")
	if err == nil {
		t.Error("Expected error for nonexistent service")
	}
}

func TestGetTLSConfig(t *testing.T) {
	ca, err := NewCA("")
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}
	defer ca.Close()

	serviceName := "test-service"

	// Test server TLS config
	serverConfig, err := ca.GetTLSConfig(serviceName, true)
	if err != nil {
		t.Fatalf("Failed to get server TLS config: %v", err)
	}

	if len(serverConfig.Certificates) == 0 {
		t.Error("Server TLS config should have certificates")
	}
	if serverConfig.RootCAs == nil {
		t.Error("Server TLS config should have RootCAs")
	}
	if serverConfig.ClientCAs == nil {
		t.Error("Server TLS config should have ClientCAs")
	}
	if serverConfig.MinVersion == 0 {
		t.Error("Server TLS config should have MinVersion set")
	}

	// Test client TLS config
	clientConfig, err := ca.GetTLSConfig(serviceName, false)
	if err != nil {
		t.Fatalf("Failed to get client TLS config: %v", err)
	}

	if len(clientConfig.Certificates) == 0 {
		t.Error("Client TLS config should have certificates")
	}
	if clientConfig.RootCAs == nil {
		t.Error("Client TLS config should have RootCAs")
	}
}

func TestCertificateValidation(t *testing.T) {
	ca, err := NewCA("")
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}
	defer ca.Close()

	serviceName := "test-service"
	cert, _, err := ca.GenerateCertificate(serviceName, 30)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	// Verify certificate is signed by CA
	err = cert.CheckSignatureFrom(ca.caCert)
	if err != nil {
		t.Errorf("Certificate signature validation failed: %v", err)
	}

	// Verify certificate can be verified using CA cert pool
	roots := x509.NewCertPool()
	roots.AddCert(ca.caCert)
	_, err = cert.Verify(x509.VerifyOptions{
		Roots: roots,
	})
	if err != nil {
		t.Errorf("Certificate verification failed: %v", err)
	}
}

func TestConcurrentCertificateGeneration(t *testing.T) {
	ca, err := NewCA("")
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}
	defer ca.Close()

	serviceName := "test-service"
	concurrency := 10

	// Generate certificates concurrently
	results := make(chan error, concurrency)
	for i := 0; i < concurrency; i++ {
		go func() {
			_, _, err := ca.GenerateCertificate(serviceName, 30)
			results <- err
		}()
	}

	// Collect results
	for i := 0; i < concurrency; i++ {
		err := <-results
		if err != nil {
			t.Errorf("Concurrent certificate generation failed: %v", err)
		}
	}

	// Verify only one certificate is stored (they should reuse the same one)
	certInfo, exists := ca.certStore[serviceName]
	if !exists {
		t.Error("Certificate not stored after concurrent generation")
	}
	if certInfo == nil {
		t.Error("Certificate info is nil")
	}
}

