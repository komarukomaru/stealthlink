// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

package transport

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestMCVarintRoundTrip(t *testing.T) {
	for _, v := range []int{0, 1, 2, 127, 128, 255, 300, 765, 25565, 2097151, 1 << 28} {
		buf := mc_append_varint(nil, v)
		got, n, err := mc_decode_varint(buf)
		if err != nil {
			t.Fatalf("decode %d: %v", v, err)
		}
		if got != v || n != len(buf) {
			t.Fatalf("varint %d round trip: got %d (n=%d, len=%d)", v, got, n, len(buf))
		}
	}
}

func startRedstoneTestServer(t *testing.T, cfg RedstoneConfig) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go redstone_serve(conn, cfg, func(c net.Conn) {
				defer c.Close()
				authBuf := make([]byte, 56)
				if _, err := io.ReadFull(c, authBuf); err != nil {
					return
				}
				header := make([]byte, 7)
				if _, err := io.ReadFull(c, header); err != nil {
					return
				}
				if header[0] != AddrIPv4 {
					c.Write([]byte{0x01})
					return
				}
				c.Write([]byte{0x00})
				io.Copy(c, c)
			})
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func TestRedstoneStatusResponse(t *testing.T) {
	addr, stop := startRedstoneTestServer(t, RedstoneConfig{MOTD: "Hypixel", Version: "1.20.4"})
	defer stop()

	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()

	_, portStr, _ := net.SplitHostPort(addr)
	p, _ := net.LookupPort("tcp", portStr)

	if err := mc_write_handshake(raw, 765, "mc.example.com", uint16(p), 1); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if err := mc_write_packet(raw, 0x00, nil); err != nil {
		t.Fatalf("status request: %v", err)
	}

	br := bufio.NewReader(raw)
	raw.SetReadDeadline(time.Now().Add(5 * time.Second))
	id, payload, err := mc_read_packet(br)
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	if id != 0x00 {
		t.Fatalf("status packet id = %d, want 0", id)
	}
	jsonLen, n, err := mc_decode_varint(payload)
	if err != nil {
		t.Fatalf("status string len: %v", err)
	}
	body := payload[n : n+jsonLen]

	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("status JSON invalid: %v (%s)", err, body)
	}
	if !strings.Contains(string(body), "Hypixel") {
		t.Errorf("status MOTD missing: %s", body)
	}
}

func TestRedstoneEndToEnd(t *testing.T) {
	addr, stop := startRedstoneTestServer(t, RedstoneConfig{})
	defer stop()

	conn, err := redstone_dial(addr, "mc.example.com", "psk-any", AddrIPv4, "203.0.113.5", 80)
	if err != nil {
		t.Fatalf("redstone_dial: %v", err)
	}
	defer conn.Close()

	payload := []byte("hello redstone tunnel over minecraft")
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
