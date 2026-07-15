// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

package transport

import (
	"crypto/x509"
	"testing"
	"time"
)

func leafOf(t *testing.T, sni string) *x509.Certificate {
	t.Helper()
	cert, err := GenerateStealthCert(sni)
	if err != nil {
		t.Fatalf("GenerateStealthCert(%q) failed: %v", sni, err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return leaf
}

func TestGenerateStealthCertHasNoImpersonationTell(t *testing.T) {
	leaf := leafOf(t, "example.org")

	for _, org := range leaf.Subject.Organization {
		if org != "" {
			t.Errorf("leaf carries Organization %q; DV-style leaf should have none", org)
		}
	}
	if leaf.Subject.CommonName != "example.org" {
		t.Errorf("CommonName = %q, want example.org", leaf.Subject.CommonName)
	}
	if len(leaf.DNSNames) == 0 || leaf.DNSNames[0] != "example.org" {
		t.Errorf("DNSNames = %v, want [example.org]", leaf.DNSNames)
	}
	if len(leaf.SubjectKeyId) == 0 {
		t.Error("SubjectKeyId is empty; real leaves set it")
	}
}

func TestGenerateStealthCertValidityLooksLikeACME(t *testing.T) {
	leaf := leafOf(t, "example.org")

	lifetime := leaf.NotAfter.Sub(leaf.NotBefore)
	if lifetime > 100*24*time.Hour {
		t.Errorf("cert lifetime %v is too long; expected ACME-like ~90d", lifetime)
	}
	if !leaf.NotBefore.Before(time.Now()) {
		t.Error("NotBefore should be in the past")
	}
}

func TestCloneCertFromTargetFallsBack(t *testing.T) {
	cert, err := CloneCertFromTarget("127.0.0.1:1", "fallback.example")
	if err != nil {
		t.Fatalf("clone should fall back, got error: %v", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse fallback leaf: %v", err)
	}
	if leaf.Subject.CommonName != "fallback.example" {
		t.Errorf("fallback CommonName = %q, want fallback.example", leaf.Subject.CommonName)
	}
}
