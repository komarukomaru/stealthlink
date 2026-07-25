// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

package transport

import "testing"

func TestVlessLinkRoundTrip(t *testing.T) {
	entry := &ServerEntry{
		Address:     "example.com:443",
		UUID:        "b831381d-6324-4d53-ad4f-8cda48b30811",
		SNI:         "example.com",
		Fingerprint: "chrome",
		XHTTP: &XHTTPConfig{
			Path: "/xhttp",
			Host: "cdn.example.com",
			Mode: "packet-up",
			Extra: XHTTPExtra{
				XPaddingBytes: "100-1000",
			},
		},
	}

	link, err := GenerateVlessLink(entry, "test")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	got, err := ParseVlessLink(link)
	if err != nil {
		t.Fatalf("parse(%q): %v", link, err)
	}

	if got.Address != entry.Address || got.UUID != entry.UUID || got.SNI != entry.SNI || got.Fingerprint != entry.Fingerprint {
		t.Fatalf("round trip mismatch: %+v", got)
	}
	if got.XHTTP == nil || got.XHTTP.Path != entry.XHTTP.Path || got.XHTTP.Host != entry.XHTTP.Host || got.XHTTP.Mode != entry.XHTTP.Mode {
		t.Fatalf("xhttp round trip mismatch: %+v", got.XHTTP)
	}
	if got.XHTTP.Extra.XPaddingBytes != entry.XHTTP.Extra.XPaddingBytes {
		t.Fatalf("xhttp extra round trip mismatch: %+v", got.XHTTP.Extra)
	}
}

func TestTrojanLinkRoundTrip(t *testing.T) {
	entry := &ServerEntry{
		Address:        "example.com:443",
		TrojanPassword: "s3cr3t",
		SNI:            "example.com",
		Fingerprint:    "chrome",
		GRPC:           &GRPCConfig{ServiceName: "GunService", MultiMode: true, Authority: "api"},
	}

	link, err := GenerateTrojanLink(entry, "test")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	got, err := ParseTrojanLink(link)
	if err != nil {
		t.Fatalf("parse(%q): %v", link, err)
	}

	if got.Address != entry.Address || got.TrojanPassword != entry.TrojanPassword || got.SNI != entry.SNI || got.Fingerprint != entry.Fingerprint {
		t.Fatalf("round trip mismatch: %+v", got)
	}
	if got.GRPC == nil || got.GRPC.ServiceName != entry.GRPC.ServiceName {
		t.Fatalf("grpc round trip mismatch: %+v", got.GRPC)
	}
	if !got.GRPC.MultiMode {
		t.Fatalf("expected mode=multi to round trip, got %+v", got.GRPC)
	}
	if got.GRPC.Authority != "api" {
		t.Fatalf("authority = %q, want %q", got.GRPC.Authority, "api")
	}
}

func TestTrojanLinkRejectsUnknownSecurity(t *testing.T) {
	link := "trojan://s3cr3t@example.com:443?type=grpc&security=xtls"
	if _, err := ParseTrojanLink(link); err == nil {
		t.Fatal("expected unknown security to be rejected")
	}
}

func TestTrojanLinkRejectsRealityWithoutKeys(t *testing.T) {
	link := "trojan://s3cr3t@example.com:443?type=grpc&security=reality"
	if _, err := ParseTrojanLink(link); err == nil {
		t.Fatal("expected security=reality without pbk/sid to be rejected")
	}
}

func TestTrojanLinkRealityRoundTrip(t *testing.T) {
	_, pub, err := GenerateRealityKeypair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}

	entry := &ServerEntry{
		Address:        "example.com:443",
		TrojanPassword: "s3cr3t",
		SNI:            "kicker.de",
		Fingerprint:    "random",
		GRPC: &GRPCConfig{
			ServiceName:      "gRPC",
			MultiMode:        true,
			Security:         "reality",
			RealityPublicKey: pub,
			RealityShortID:   "05",
		},
	}

	link, err := GenerateTrojanLink(entry, "test")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	got, err := ParseTrojanLink(link)
	if err != nil {
		t.Fatalf("parse(%q): %v", link, err)
	}

	if got.GRPC == nil || got.GRPC.Security != "reality" {
		t.Fatalf("expected security=reality to round trip, got %+v", got.GRPC)
	}
	if got.GRPC.RealityPublicKey != pub {
		t.Fatalf("public key = %q, want %q", got.GRPC.RealityPublicKey, pub)
	}
	if got.GRPC.RealityShortID != "05" {
		t.Fatalf("short id = %q, want %q", got.GRPC.RealityShortID, "05")
	}
	if !got.GRPC.MultiMode {
		t.Fatalf("expected mode=multi to round trip alongside security=reality, got %+v", got.GRPC)
	}
}

func TestImportLinkDispatch(t *testing.T) {
	entry := &ServerEntry{Address: "example.com:443", UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", XHTTP: &XHTTPConfig{}}
	link, err := GenerateVlessLink(entry, "")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	got, err := ImportLink(link)
	if err != nil {
		t.Fatalf("ImportLink: %v", err)
	}
	if got.Transport != "vless-xhttp" {
		t.Fatalf("transport = %q, want vless-xhttp", got.Transport)
	}

	if _, err := ImportLink("not-a-known-scheme://foo"); err == nil {
		t.Fatal("expected error for unrecognized scheme")
	}
}
