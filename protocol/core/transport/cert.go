// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

package transport

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

const certDialTimeout = 5 * time.Second

func GenerateStealthCert(sni string) (tls.Certificate, error) {
	if sni == "" {
		sni = "localhost"
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	return selfSign(baseLeafTemplate(sni), key)
}

func CloneCertFromTarget(dest, fallbackSNI string) (tls.Certificate, error) {
	host := hostOnly(dest)
	if fallbackSNI == "" {
		fallbackSNI = host
	}

	leaf, err := fetchLeafCert(dest)
	if err != nil || leaf == nil {
		return GenerateStealthCert(fallbackSNI)
	}

	key, err := keyMatchingLeaf(leaf)
	if err != nil {
		return GenerateStealthCert(fallbackSNI)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               leaf.Subject,
		DNSNames:              leaf.DNSNames,
		NotBefore:             leaf.NotBefore,
		NotAfter:              leaf.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if len(tmpl.DNSNames) == 0 {
		tmpl.DNSNames = []string{host}
	}
	if tmpl.Subject.CommonName == "" {
		tmpl.Subject.CommonName = host
	}

	cert, err := selfSign(tmpl, key)
	if err != nil {
		return GenerateStealthCert(fallbackSNI)
	}
	return cert, nil
}

func baseLeafTemplate(sni string) x509.Certificate {
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	now := time.Now()
	return x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: sni},
		DNSNames:              []string{sni},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
}

func selfSign(tmpl x509.Certificate, key crypto.Signer) (tls.Certificate, error) {
	if skid, err := subjectKeyID(key.Public()); err == nil {
		tmpl.SubjectKeyId = skid
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, err
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}

func fetchLeafCert(dest string) (*x509.Certificate, error) {
	addr := dest
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "443")
	}
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: certDialTimeout},
		"tcp", addr,
		&tls.Config{ServerName: hostOnly(dest), InsecureSkipVerify: true},
	)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("target presented no certificate")
	}
	return certs[0], nil
}

func keyMatchingLeaf(leaf *x509.Certificate) (crypto.Signer, error) {
	switch leaf.PublicKeyAlgorithm {
	case x509.RSA:
		bits := 2048
		if pub, ok := leaf.PublicKey.(*rsa.PublicKey); ok && pub.N.BitLen() >= 3072 {
			bits = pub.N.BitLen()
		}
		return rsa.GenerateKey(rand.Reader, bits)
	default:
		curve := elliptic.P256()
		if pub, ok := leaf.PublicKey.(*ecdsa.PublicKey); ok {
			curve = pub.Curve
		}
		return ecdsa.GenerateKey(curve, rand.Reader)
	}
}

func subjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	sum := sha1.Sum(spki)
	return sum[:], nil
}

func hostOnly(dest string) string {
	if host, _, err := net.SplitHostPort(dest); err == nil {
		return host
	}
	return dest
}
