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

func TestXHTTPNormalizePath(t *testing.T) {
	cases := map[string]string{
		"":          xhttp_default_path,
		"v1/x":      "/v1/x",
		"/v1/x/":    "/v1/x",
		"/a/b/c///": "/a/b/c",
	}
	for in, want := range cases {
		if got := xhttp_normalize_path(in); got != want {
			t.Errorf("normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseXHTTPRange(t *testing.T) {
	cases := []struct {
		in     string
		defMin int
		defMax int
		wantLo int
		wantHi int
	}{
		{"100-1000", 1, 2, 100, 1000},
		{"50", 1, 2, 50, 50},
		{"", 5, 10, 5, 10},
		{"garbage", 5, 10, 5, 10},
	}
	for _, tc := range cases {
		lo, hi := parseXHTTPRange(tc.in, tc.defMin, tc.defMax)
		if lo != tc.wantLo || hi != tc.wantHi {
			t.Errorf("parseXHTTPRange(%q) = (%d,%d), want (%d,%d)", tc.in, lo, hi, tc.wantLo, tc.wantHi)
		}
	}
}

func xhttpEchoHandler(path string, extra XHTTPExtra) *xhttp_handler {
	return new_xhttp_handler(path, extra, func(conn net.Conn) {
		defer conn.Close()
		io.Copy(conn, conn)
	})
}

func testXHTTPRoundTrip(t *testing.T, mode string, h2 bool) {
	handler := xhttpEchoHandler("/xhttp", XHTTPExtra{})

	ts := httptest.NewUnstartedServer(handler)
	ts.TLS = nil
	ts.EnableHTTP2 = h2
	ts.StartTLS()
	defer ts.Close()

	target := strings.TrimPrefix(ts.URL, "https://")
	cfg := XHTTPConfig{Path: "/xhttp", Mode: mode}

	conn, err := xhttp_dial(target, "example.com", cfg, "", true)
	if err != nil {
		t.Fatalf("xhttp_dial: %v", err)
	}
	defer conn.Close()

	payload := []byte("hello xhttp over " + mode)
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

func TestXHTTPPacketUp(t *testing.T) {
	testXHTTPRoundTrip(t, "packet-up", false)
}

func TestXHTTPStreamUp(t *testing.T) {
	testXHTTPRoundTrip(t, "stream-up", false)
}

func TestXHTTPStreamOne(t *testing.T) {
	testXHTTPRoundTrip(t, "stream-one", true)
}
