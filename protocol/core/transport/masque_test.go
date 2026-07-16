// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

package transport

import (
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

func TestMasqueNormalizePath(t *testing.T) {
	if got := masque_normalize_path(""); got != masque_default_path {
		t.Errorf("empty path = %q, want %q", got, masque_default_path)
	}
	if got := masque_normalize_path("custom/p"); got != "/custom/p" {
		t.Errorf("path = %q, want /custom/p", got)
	}
}

func startMasqueTestServer(t *testing.T, auth *AuthManager, onSession func(net.Conn, *AuthSession)) (string, func()) {
	t.Helper()
	cert, err := GenerateStealthCert("example.com")
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("udp listen: %v", err)
	}
	srv := &http3.Server{
		Handler:         &masque_handler{auth: auth, onSession: onSession},
		TLSConfig:       &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}},
		EnableDatagrams: true,
	}
	go srv.Serve(udpConn)
	return udpConn.LocalAddr().String(), func() {
		srv.Close()
		udpConn.Close()
	}
}

func TestMasqueEndToEnd(t *testing.T) {
	const psk = "masque-secret-key"
	auth := NewAuthManager([]*UserRecord{{ID: "t", PSK: psk}})

	addr, stop := startMasqueTestServer(t, auth, func(conn net.Conn, session *AuthSession) {
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
	defer stop()

	cc, qconn, tr, err := masque_new_client_conn(addr, "example.com", true)
	if err != nil {
		t.Fatalf("masque_new_client_conn: %v", err)
	}
	defer func() {
		qconn.CloseWithError(0, "")
		tr.Close()
	}()

	conn, err := masque_open_stream(cc, "example.com", "", psk, AddrIPv4, "203.0.113.5", 80)
	if err != nil {
		t.Fatalf("masque_open_stream: %v", err)
	}
	defer conn.Close()

	payload := []byte("hello masque h3")
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

func TestMasqueRejectsBadAuth(t *testing.T) {
	auth := NewAuthManager([]*UserRecord{{ID: "t", PSK: "real-key"}})
	addr, stop := startMasqueTestServer(t, auth, func(conn net.Conn, session *AuthSession) {
		conn.Close()
	})
	defer stop()

	cc, qconn, tr, err := masque_new_client_conn(addr, "example.com", true)
	if err != nil {
		t.Fatalf("masque_new_client_conn: %v", err)
	}
	defer func() {
		qconn.CloseWithError(0, "")
		tr.Close()
	}()

	if _, err := masque_open_stream(cc, "example.com", "", "wrong-key", AddrIPv4, "203.0.113.5", 80); err == nil {
		t.Fatal("expected failure with wrong PSK")
	}
}
