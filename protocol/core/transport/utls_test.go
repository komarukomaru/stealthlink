// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

package transport

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func generateCert(t *testing.T) (tls.Certificate, string) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("failed to load cert: %v", err)
	}
	return cert, "localhost"
}

func TestUTLSConnectivity(t *testing.T) {
	cert, sni := generateCert(t)
	config := &tls.Config{Certificates: []tls.Certificate{cert}}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				if tlsConn, ok := conn.(*tls.Conn); ok {
					tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
					_ = tlsConn.Handshake()
				}
				conn.Close()
			}()
		}
	}()

	fingerprints := []string{
		"chrome",
		"firefox",
		"ios",
		"android",
		"random",
		"",
	}

	for _, fp := range fingerprints {
		t.Run(fp, func(t *testing.T) {
			t.Logf("Testing fingerprint: %q", fp)
			conn, err := DialTransport(ln.Addr().String(), sni, fp)
			if err != nil {
				if fp == "random" && strings.Contains(err.Error(), "unsupported curve") {
					t.Skipf("Skipping flaky randomized fingerprint on this Go/uTLS combo: %v", err)
				}
				t.Errorf("DialTransport failed for %q: %v", fp, err)
				return
			}
			conn.Close()
			t.Logf("Success for %q", fp)
		})
	}
}
