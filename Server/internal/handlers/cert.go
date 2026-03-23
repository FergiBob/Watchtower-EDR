package handlers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

// SetupCertificates ensures server.crt and server.key exist for TLS
func SetupCertificates(fqdn string) error {

	// Check if they already exist to prevent orphaning agents
	if _, err := os.Stat("./internal/data/server.crt"); err == nil {
		return nil
	}

	// Generate Private Key (Modern P-256 Curve)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Set Certificate Identity and Expiration (Extended for ease of use and the nature of self-signed certificates)
	notBefore := time.Now()
	notAfter := notBefore.Add(10 * 365 * 24 * time.Hour) // 10 Years

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Watchtower EDR"},
			CommonName:   fqdn,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,

		// CRITICAL: The SAN (Subject Alternative Name)
		// This is what the Agent's TLS handshake actually checks.
		DNSNames:    []string{fqdn, "localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	// 3. Create the Self-Signed Certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// 4. Save Public Certificate (server.crt)
	certOut, _ := os.Create("./internal/data/server.crt")
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()

	// 5. Save Private Key (server.key)
	keyOut, _ := os.OpenFile("./internal/data/server.key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	privBytes, _ := x509.MarshalECPrivateKey(priv)
	pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})
	keyOut.Close()

	return nil
}
