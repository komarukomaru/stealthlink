// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

package main

import "testing"

func TestTLSCertFoldsIntoCamouflage(t *testing.T) {
	c := &Config{}
	c.TLS.CertFile = "/etc/ssl/fullchain.pem"
	c.TLS.KeyFile = "/etc/ssl/privkey.pem"

	sc := c.ToServerConfig()
	if sc.Camouflage.CertFile != "/etc/ssl/fullchain.pem" || sc.Camouflage.KeyFile != "/etc/ssl/privkey.pem" {
		t.Fatalf("tls cert not applied: got cert=%q key=%q", sc.Camouflage.CertFile, sc.Camouflage.KeyFile)
	}
}

func TestExplicitCamouflageCertWins(t *testing.T) {
	c := &Config{}
	c.TLS.CertFile = "/tls/cert.pem"
	c.TLS.KeyFile = "/tls/key.pem"
	c.Camouflage.CertFile = "/cam/cert.pem"
	c.Camouflage.KeyFile = "/cam/key.pem"

	sc := c.ToServerConfig()
	if sc.Camouflage.CertFile != "/cam/cert.pem" || sc.Camouflage.KeyFile != "/cam/key.pem" {
		t.Fatalf("explicit camouflage cert should win: got cert=%q key=%q", sc.Camouflage.CertFile, sc.Camouflage.KeyFile)
	}
}
