// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

package transport

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestServeTrojanDecoyRelaysToBackend(t *testing.T) {
	decoyLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("decoy listen: %v", err)
	}
	defer decoyLis.Close()
	go func() {
		conn, err := decoyLis.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.Copy(conn, conn)
	}()

	s := NewServer(ServerConfig{
		Trojan:      TrojanConfig{DecoyAddr: decoyLis.Addr().String()},
		FirewallCfg: DefaultFirewallConfig(),
	})

	clientConn, serverSideConn := net.Pipe()
	go s.serveTrojanDecoy(serverSideConn, []byte("already-read-bytes"))

	got := make([]byte, len("already-read-bytes"))
	clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(clientConn, got); err != nil {
		t.Fatalf("read replayed prefix: %v", err)
	}
	if string(got) != "already-read-bytes" {
		t.Fatalf("replayed prefix = %q, want %q", got, "already-read-bytes")
	}

	if _, err := clientConn.Write([]byte("more data")); err != nil {
		t.Fatalf("write: %v", err)
	}
	more := make([]byte, len("more data"))
	if _, err := io.ReadFull(clientConn, more); err != nil {
		t.Fatalf("read echoed data: %v", err)
	}
	if string(more) != "more data" {
		t.Fatalf("echoed data = %q, want %q", more, "more data")
	}

	clientConn.Close()
}

func TestServeTrojanDecoyNoopWithoutConfig(t *testing.T) {
	s := NewServer(ServerConfig{FirewallCfg: DefaultFirewallConfig()})

	serverSide, clientSide := net.Pipe()
	done := make(chan struct{})
	go func() {
		s.serveTrojanDecoy(serverSide, []byte("irrelevant"))
		close(done)
	}()

	buf := make([]byte, 1)
	clientSide.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := clientSide.Read(buf); err == nil {
		t.Fatal("expected no data and a closed connection when DecoyAddr is unset")
	}
	<-done
}
