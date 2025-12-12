package ca

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPersistentStorage(t *testing.T) {
	// Create temporary database path
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_ca.db")

	// Test 1: Create CA and generate certificates
	t.Run("Create and save certificates", func(t *testing.T) {
		ca, err := NewCA(dbPath)
		if err != nil {
			t.Fatalf("Failed to create CA: %v", err)
		}
		defer ca.Close()

		// Generate certificates
		service1 := "test-service-1"
		service2 := "test-service-2"

		cert1, key1, err := ca.GenerateCertificate(service1, 30)
		if err != nil {
			t.Fatalf("Failed to generate certificate for %s: %v", service1, err)
		}

		cert2, key2, err := ca.GenerateCertificate(service2, 30)
		if err != nil {
			t.Fatalf("Failed to generate certificate for %s: %v", service2, err)
		}

		// Verify certificates are in memory
		if cert1 == nil || key1 == nil {
			t.Error("Certificate 1 not stored in memory")
		}
		if cert2 == nil || key2 == nil {
			t.Error("Certificate 2 not stored in memory")
		}

		// Close CA to ensure data is flushed
		if err := ca.Close(); err != nil {
			t.Fatalf("Failed to close CA: %v", err)
		}

		// Verify database file exists
		if _, err := os.Stat(dbPath); os.IsNotExist(err) {
			t.Fatalf("Database file not created: %s", dbPath)
		}
	})

	// Test 2: Reload CA and verify certificates are restored
	t.Run("Reload and verify certificates", func(t *testing.T) {
		ca, err := NewCA(dbPath)
		if err != nil {
			t.Fatalf("Failed to reload CA: %v", err)
		}
		defer ca.Close()

		service1 := "test-service-1"
		service2 := "test-service-2"

		// Try to get certificates - they should be loaded from database
		cert1PEM, key1PEM, err := ca.GetCertificatePEM(service1)
		if err != nil {
			t.Fatalf("Failed to get certificate for %s: %v", service1, err)
		}

		if len(cert1PEM) == 0 || len(key1PEM) == 0 {
			t.Error("Certificate 1 not restored from database")
		}

		cert2PEM, key2PEM, err := ca.GetCertificatePEM(service2)
		if err != nil {
			t.Fatalf("Failed to get certificate for %s: %v", service2, err)
		}

		if len(cert2PEM) == 0 || len(key2PEM) == 0 {
			t.Error("Certificate 2 not restored from database")
		}

		// Verify CA certificate is loaded
		caCert, err := ca.GetCACert()
		if err != nil {
			t.Fatalf("Failed to get CA certificate: %v", err)
		}

		if len(caCert) == 0 {
			t.Error("CA certificate not loaded from database")
		}
	})

	// Test 3: Verify certificate expiration is preserved
	t.Run("Certificate expiration preserved", func(t *testing.T) {
		ca, err := NewCA(dbPath)
		if err != nil {
			t.Fatalf("Failed to reload CA: %v", err)
		}
		defer ca.Close()

		service1 := "test-service-1"

		// Get certificate info
		ca.mu.RLock()
		certInfo, exists := ca.certStore[service1]
		ca.mu.RUnlock()

		if !exists {
			t.Fatalf("Certificate for %s not found", service1)
		}

		// Verify expiration is in the future
		if certInfo.ExpiresAt.Before(time.Now()) {
			t.Error("Certificate expiration date is in the past")
		}

		// Verify expiration is approximately 30 days from now (with some tolerance)
		expectedExpiry := time.Now().Add(30 * 24 * time.Hour)
		diff := certInfo.ExpiresAt.Sub(expectedExpiry)
		if diff > 24*time.Hour || diff < -24*time.Hour {
			t.Errorf("Certificate expiration date is incorrect. Expected ~30 days, got %v", certInfo.ExpiresAt)
		}
	})
}

func TestInMemoryMode(t *testing.T) {
	// Test that in-memory mode still works (empty dbPath)
	ca, err := NewCA("")
	if err != nil {
		t.Fatalf("Failed to create in-memory CA: %v", err)
	}
	defer ca.Close()

	// Generate certificate
	cert, key, err := ca.GenerateCertificate("test-service", 30)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	if cert == nil || key == nil {
		t.Error("Certificate not generated in in-memory mode")
	}
}

func TestCACertificatePersistence(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_ca_cert.db")

	// Create first CA
	ca1, err := NewCA(dbPath)
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	ca1Cert, err := ca1.GetCACert()
	if err != nil {
		t.Fatalf("Failed to get CA certificate: %v", err)
	}

	ca1.Close()

	// Create second CA with same database
	ca2, err := NewCA(dbPath)
	if err != nil {
		t.Fatalf("Failed to reload CA: %v", err)
	}
	defer ca2.Close()

	ca2Cert, err := ca2.GetCACert()
	if err != nil {
		t.Fatalf("Failed to get CA certificate: %v", err)
	}

	// Verify certificates are the same
	if len(ca1Cert) != len(ca2Cert) {
		t.Error("CA certificates have different lengths")
	}

	// Compare byte by byte
	for i := range ca1Cert {
		if ca1Cert[i] != ca2Cert[i] {
			t.Error("CA certificates are different after reload")
			break
		}
	}
}

