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

func TestWebRTCNormalizePath(t *testing.T) {
	if got := webrtc_normalize_path(""); got != webrtc_default_path {
		t.Errorf("empty = %q, want %q", got, webrtc_default_path)
	}
	if got := webrtc_normalize_path("rtc/x"); got != "/rtc/x" {
		t.Errorf("got %q, want /rtc/x", got)
	}
}

func TestWebRTCEndToEnd(t *testing.T) {
	const psk = "webrtc-secret-key"
	auth := NewAuthManager([]*UserRecord{{ID: "t", PSK: psk}})

	handler := &webrtc_handler{
		auth: auth,
		path: webrtc_default_path,
		stun: nil,
		onSession: func(conn net.Conn, session *AuthSession) {
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
		},
	}

	ts := httptest.NewTLSServer(handler)
	defer ts.Close()
	target := strings.TrimPrefix(ts.URL, "https://")

	client, err := webrtc_dial(target, "example.com", "", "chrome", psk, nil, true)
	if err != nil {
		t.Fatalf("webrtc_dial: %v", err)
	}
	defer client.Close()

	conn, err := client.open(AddrIPv4, "203.0.113.5", 80)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer conn.Close()

	payload := []byte("hello webrtc data channel tunnel")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo = %q, want %q", got, payload)
	}
}

func TestWebRTCRejectsBadAuth(t *testing.T) {
	auth := NewAuthManager([]*UserRecord{{ID: "t", PSK: "real-key"}})
	handler := &webrtc_handler{
		auth:      auth,
		path:      webrtc_default_path,
		onSession: func(conn net.Conn, session *AuthSession) { conn.Close() },
	}
	ts := httptest.NewTLSServer(handler)
	defer ts.Close()
	target := strings.TrimPrefix(ts.URL, "https://")

	if _, err := webrtc_dial(target, "example.com", "", "chrome", "wrong-key", nil, true); err == nil {
		t.Fatal("expected failure with wrong PSK")
	}
}
