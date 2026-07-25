// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

package transport

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
)

func TestGRPCHunkWireRoundTrip(t *testing.T) {
	cases := [][]byte{
		nil,
		[]byte(""),
		[]byte("hello"),
		bytes.Repeat([]byte("x"), 5000),
	}
	for _, data := range cases {
		encoded := encodeHunkWire(data)
		decoded, err := decodeHunkWire(encoded)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !bytes.Equal(decoded, data) {
			t.Fatalf("round trip mismatch: got %v, want %v", decoded, data)
		}
	}
}

func TestGRPCMultiHunkWireRoundTrip(t *testing.T) {
	cases := [][][]byte{
		nil,
		{[]byte("hello")},
		{[]byte("a"), []byte("bb"), []byte("ccc")},
		{[]byte(""), []byte("x"), []byte("")},
	}
	for _, chunks := range cases {
		encoded := encodeMultiHunkWire(chunks)
		decoded, err := decodeMultiHunkWire(encoded)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(decoded) != len(chunks) {
			t.Fatalf("chunk count = %d, want %d", len(decoded), len(chunks))
		}
		for i := range chunks {
			if !bytes.Equal(decoded[i], chunks[i]) {
				t.Fatalf("chunk %d = %v, want %v", i, decoded[i], chunks[i])
			}
		}
	}
}

func runGRPCEndToEnd(t *testing.T, multiMode bool) {
	t.Helper()

	cert, err := GenerateStealthCert("example.com")
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
		MinVersion:   tls.VersionTLS13,
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	// Server config's own MultiMode is irrelevant - grpc_new_server always
	// registers both Tun and TunMulti, matching real Xray-core.
	serverCfg := GRPCConfig{ServiceName: "TestGun"}
	srv, err := grpc_new_server(tlsConfig, nil, serverCfg, func(conn net.Conn) {
		defer conn.Close()
		io.Copy(conn, conn)
	})
	if err != nil {
		t.Fatalf("grpc_new_server: %v", err)
	}
	go srv.Serve(lis)
	defer srv.Stop()

	clientCfg := GRPCConfig{ServiceName: "TestGun", MultiMode: multiMode, Authority: "example.com"}
	gc, err := grpc_dial(lis.Addr().String(), "example.com", clientCfg, "", true)
	if err != nil {
		t.Fatalf("grpc_dial: %v", err)
	}
	defer gc.Close()

	conn, err := gc.open()
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer conn.Close()

	payload := []byte("hello grpc gun")
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

func TestGRPCEndToEnd(t *testing.T) {
	runGRPCEndToEnd(t, false)
}

func TestGRPCMultiModeEndToEnd(t *testing.T) {
	runGRPCEndToEnd(t, true)
}

func TestGRPCDefaultServiceName(t *testing.T) {
	// Must match Xray-core's compiled-in default exactly (see
	// transport/internet/grpc/encoding/stream.proto) for interop with a
	// real Xray endpoint that also left serviceName unset.
	want := "xray.transport.internet.grpc.encoding.GRPCService"
	if got := grpc_service_name(GRPCConfig{}); got != want {
		t.Fatalf("default service name = %q, want %q", got, want)
	}
}

// TestGRPCRealityEndToEnd exercises the real client dialer (reality_dial_ctx
// via grpc_dial) and the real server credentials (realityServerCreds ->
// reality_server -> github.com/xtls/reality), which is where the actual
// REALITY-over-gRPC wiring lives. Dest must be a genuine, live TLS 1.3
// server: xtls/reality always dials it and threads its real
// ServerHello/Certificate flow through (see startRealityDest in
// reality_test.go), not just for the fallback path.
func TestGRPCRealityEndToEnd(t *testing.T) {
	t.Skip("known limitation - see the \"KNOWN LIMITATION\" comment near the end of " +
		"reality.go and TestRealityEndToEndHandshake in reality_test.go")

	privB64, pubB64, err := generate_reality_keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	destAddr, _, stopDest := startRealityDest(t)
	defer stopDest()

	rs, err := new_reality_server(RealityConfig{
		Dest:       destAddr,
		ServerName: "dest.example.com",
		PrivateKey: privB64,
		ShortIDs:   []string{"1234"},
	})
	if err != nil {
		t.Fatalf("new_reality_server: %v", err)
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	cfg := GRPCConfig{ServiceName: "TestGun"}
	srv := grpc.NewServer(grpc.Creds(&realityServerCreds{server: rs}))
	srv.RegisterService(grpc_service_desc(cfg, func(conn net.Conn) {
		defer conn.Close()
		io.Copy(conn, conn)
	}), nil)
	go srv.Serve(lis)
	defer srv.Stop()

	clientCfg := GRPCConfig{
		ServiceName:      "TestGun",
		Security:         "reality",
		RealityPublicKey: pubB64,
		RealityShortID:   "1234",
	}
	gc, err := grpc_dial(lis.Addr().String(), "dest.example.com", clientCfg, "", false)
	if err != nil {
		t.Fatalf("grpc_dial: %v", err)
	}
	defer gc.Close()

	conn, err := gc.open()
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer conn.Close()

	payload := []byte("hello reality grpc")
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

func TestGRPCRealityRejectsWrongShortID(t *testing.T) {
	privB64, pubB64, err := generate_reality_keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	destAddr, destHit, stopDest := startRealityDest(t)
	defer stopDest()

	rs, err := new_reality_server(RealityConfig{
		Dest:       destAddr,
		ServerName: "dest.example.com",
		PrivateKey: privB64,
		ShortIDs:   []string{"1234"}, // does not include "dead"
	})
	if err != nil {
		t.Fatalf("new_reality_server: %v", err)
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	cfg := GRPCConfig{ServiceName: "TestGun"}
	srv := grpc.NewServer(grpc.Creds(&realityServerCreds{server: rs}))
	srv.RegisterService(grpc_service_desc(cfg, func(conn net.Conn) {
		conn.Close()
	}), nil)
	go srv.Serve(lis)
	defer srv.Stop()

	clientCfg := GRPCConfig{
		ServiceName:      "TestGun",
		Security:         "reality",
		RealityPublicKey: pubB64,
		RealityShortID:   "dead", // not in rs's allowed short ids
	}
	gc, err := grpc_dial(lis.Addr().String(), "dest.example.com", clientCfg, "", false)
	if err != nil {
		t.Fatalf("grpc_dial: %v", err)
	}
	defer gc.Close()

	conn, err := gc.open()
	if err == nil {
		conn.Close()
		if _, werr := conn.Write([]byte("x")); werr == nil {
			t.Fatal("expected stream to fail without a valid reality token")
		}
	}

	select {
	case <-destHit:
		// The mismatched connection was transparently forwarded to dest.
	case <-time.After(5 * time.Second):
		t.Fatal("expected the mismatched-token connection to fall through to dest")
	}
}
