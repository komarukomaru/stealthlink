// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

package transport

import (
	"io"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMirageNormalizePath(t *testing.T) {
	cases := map[string]string{
		"":          mirage_default_path,
		"v1/x":      "/v1/x",
		"/v1/x/":    "/v1/x",
		"/a/b/c///": "/a/b/c",
		"nolead":    "/nolead",
	}
	for in, want := range cases {
		if got := mirage_normalize_path(in); got != want {
			t.Errorf("normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMirageEndToEnd(t *testing.T) {
	const psk = "test-secret-key"
	auth := NewAuthManager([]*UserRecord{{ID: "t", PSK: psk}})

	handler := new_mirage_handler(auth, "/v2/media/segments", func(conn net.Conn, session *AuthSession) {
		defer conn.Close()
		header := make([]byte, 7)
		if _, err := io.ReadFull(conn, header); err != nil {
			return
		}
		if header[0] != AddrIPv4 {
			conn.Write([]byte{0x01})
			return
		}
		conn.Write([]byte{0x00})
		io.Copy(conn, conn)
	})

	ts := httptest.NewTLSServer(handler)
	defer ts.Close()
	target := strings.TrimPrefix(ts.URL, "https://")

	conn, err := mirage_dial_vpn(target, "example.com", "/v2/media/segments", psk, true, AddrIPv4, "203.0.113.5", 80)
	if err != nil {
		t.Fatalf("mirage_dial_vpn: %v", err)
	}
	defer conn.Close()

	payload := []byte("hello mirage over split-http")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	got := make([]byte, len(payload))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo = %q, want %q", got, payload)
	}
}

func TestMirageRejectsBadAuth(t *testing.T) {
	auth := NewAuthManager([]*UserRecord{{ID: "t", PSK: "real-key"}})
	handler := new_mirage_handler(auth, "/v2/media/segments", func(conn net.Conn, session *AuthSession) {
		conn.Close()
	})
	ts := httptest.NewTLSServer(handler)
	defer ts.Close()
	target := strings.TrimPrefix(ts.URL, "https://")

	_, err := mirage_dial_vpn(target, "example.com", "/v2/media/segments", "wrong-key", true, AddrIPv4, "203.0.113.5", 80)
	if err == nil {
		t.Fatal("expected failure with wrong PSK")
	}
}
