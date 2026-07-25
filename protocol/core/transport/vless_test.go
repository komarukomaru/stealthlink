// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

package transport

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestVlessUUIDRoundTrip(t *testing.T) {
	const s = "b831381d-6324-4d53-ad4f-8cda48b30811"
	id, err := parseVlessUUID(s)
	if err != nil {
		t.Fatalf("parseVlessUUID: %v", err)
	}
	if got := formatVlessUUID(id); got != s {
		t.Fatalf("formatVlessUUID = %q, want %q", got, s)
	}
}

func TestVlessRequestRoundTrip(t *testing.T) {
	cases := []struct {
		name     string
		addrType byte
		addr     string
	}{
		{"ipv4", vlessAddrIPv4, "203.0.113.5"},
		{"domain", vlessAddrDomain, "example.com"},
		{"ipv6", vlessAddrIPv6, "2001:db8::1"},
	}

	uuid, err := parseVlessUUID("b831381d-6324-4d53-ad4f-8cda48b30811")
	if err != nil {
		t.Fatalf("parseVlessUUID: %v", err)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := vless_encode_request(uuid, vlessCmdTCP, tc.addrType, tc.addr, 443)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}

			gotUUID, cmd, addrType, addr, port, err := vless_read_request(bytes.NewReader(encoded))
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if gotUUID != uuid {
				t.Errorf("uuid = %x, want %x", gotUUID, uuid)
			}
			if cmd != vlessCmdTCP {
				t.Errorf("cmd = %d, want %d", cmd, vlessCmdTCP)
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

func TestVlessResponseRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := vless_write_response(&buf); err != nil {
		t.Fatalf("write response: %v", err)
	}
	if err := vless_read_response(&buf); err != nil {
		t.Fatalf("read response: %v", err)
	}
}

func TestVlessAcceptRejectsUnknownClient(t *testing.T) {
	clients := newVlessClientMap(VlessConfig{Clients: []VlessClient{{ID: "b831381d-6324-4d53-ad4f-8cda48b30811"}}})

	server, client := net.Pipe()
	defer server.Close()

	otherUUID, _ := parseVlessUUID("00000000-0000-0000-0000-000000000000")
	go func() {
		defer client.Close()
		req, _ := vless_encode_request(otherUUID, vlessCmdTCP, vlessAddrIPv4, "203.0.113.5", 80)
		client.Write(req)
	}()

	if _, _, _, _, err := vless_accept(server, clients); err == nil {
		t.Fatal("expected vless_accept to reject unknown uuid")
	}
}

// TestVlessClientServerLoopback uses a real TCP loopback rather than
// net.Pipe: net.Pipe is fully unbuffered/synchronous, and the client's
// single merged header+payload Write combined with the server's own
// blocking response-header Write (before it loops back to read the rest of
// that payload) would deadlock two goroutines with no kernel buffer to
// break the cycle. In production this can't happen - the XHTTP/gRPC
// carriers this rides on always have an independent forwarding loop
// draining the pipe - so a real socket (which has that same buffering) is
// the representative thing to test against here.
func TestVlessClientServerLoopback(t *testing.T) {
	uuid, _ := parseVlessUUID("b831381d-6324-4d53-ad4f-8cda48b30811")
	clients := newVlessClientMap(VlessConfig{Clients: []VlessClient{{ID: "b831381d-6324-4d53-ad4f-8cda48b30811", Email: "t"}}})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		c, addrType, addr, port, err := vless_accept(conn, clients)
		if err != nil {
			t.Errorf("vless_accept: %v", err)
			return
		}
		if c.Email != "t" || addrType != vlessAddrDomain || addr != "example.com" || port != 443 {
			t.Errorf("unexpected request: email=%s addrType=%d addr=%s port=%d", c.Email, addrType, addr, port)
		}
		io.Copy(conn, conn)
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	wrapped := vless_wrap_client(client, uuid, vlessAddrDomain, "example.com", 443)
	payload := []byte("hello vless")
	if _, err := wrapped.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	got := make([]byte, len(payload))
	wrapped.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(wrapped, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo = %q, want %q", got, payload)
	}

	wrapped.Close()
	<-serverDone
}
