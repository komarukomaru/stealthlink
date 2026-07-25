// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

package transport

import (
	"bytes"
	"io"
	"net"
	"testing"
)

func TestTrojanRequestRoundTrip(t *testing.T) {
	cases := []struct {
		name     string
		addrType byte
		addr     string
	}{
		{"ipv4", AddrIPv4, "203.0.113.5"},
		{"domain", AddrDomain, "example.com"},
		{"ipv6", AddrIPv6, "2001:db8::1"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			encoded := trojan_encode_request("s3cr3t", tc.addrType, tc.addr, 443)

			hash, cmd, addrType, addr, port, err := trojan_read_request(bytes.NewReader(encoded))
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if hash != trojanPasswordHash("s3cr3t") {
				t.Errorf("hash mismatch")
			}
			if cmd != trojanCmdConnect {
				t.Errorf("cmd = %d, want %d", cmd, trojanCmdConnect)
			}
			if addrType != tc.addrType {
				t.Errorf("addrType = %d, want %d", addrType, tc.addrType)
			}
			if addr != tc.addr {
				t.Errorf("addr = %q, want %q", addr, tc.addr)
			}
			if port != 443 {
				t.Errorf("port = %d, want 443", port)
			}
		})
	}
}

func TestTrojanAcceptRejectsUnknownPassword(t *testing.T) {
	clients := newTrojanClientMap(TrojanConfig{Clients: []TrojanClient{{Password: "real-secret"}}})

	server, client := net.Pipe()
	defer server.Close()

	go func() {
		defer client.Close()
		req := trojan_encode_request("wrong-secret", AddrIPv4, "203.0.113.5", 80)
		client.Write(req)
	}()

	if _, _, _, _, err := trojan_accept(server, clients); err == nil {
		t.Fatal("expected trojan_accept to reject unknown password")
	}
}

func TestRecordingConn(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	go func() {
		defer server.Close()
		server.Write([]byte("hello"))
		server.Write([]byte(" world"))
	}()

	rec := newRecordingConn(client)
	buf := make([]byte, 5)
	if _, err := io.ReadFull(rec, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	rest := make([]byte, 6)
	if _, err := io.ReadFull(rec, rest); err != nil {
		t.Fatalf("read: %v", err)
	}

	if got := string(rec.Recorded()); got != "hello world" {
		t.Fatalf("Recorded() = %q, want %q", got, "hello world")
	}
}

func TestTrojanClientServerLoopback(t *testing.T) {
	clients := newTrojanClientMap(TrojanConfig{Clients: []TrojanClient{{Password: "s3cr3t", Email: "t"}}})

	server, client := net.Pipe()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		c, addrType, addr, port, err := trojan_accept(server, clients)
		if err != nil {
			t.Errorf("trojan_accept: %v", err)
			return
		}
		if c.Email != "t" || addrType != AddrDomain || addr != "example.com" || port != 443 {
			t.Errorf("unexpected request: email=%s addrType=%d addr=%s port=%d", c.Email, addrType, addr, port)
		}
		io.Copy(server, server)
	}()

	wrapped := trojan_wrap_client(client, "s3cr3t", AddrDomain, "example.com", 443)
	payload := []byte("hello trojan")
	if _, err := wrapped.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(wrapped, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo = %q, want %q", got, payload)
	}

	wrapped.Close()
	<-serverDone
}
