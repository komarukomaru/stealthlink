// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

package transport

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
)

func startQUICEchoServer(t *testing.T) (string, func()) {
	t.Helper()
	cert, err := GenerateStealthCert("example.com")
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("udp listen: %v", err)
	}
	tr := &quic.Transport{Conn: udpConn}
	ln, err := tr.Listen(
		&tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}},
		&quic.Config{MaxIdleTimeout: 30 * time.Second, MaxIncomingStreams: 256},
	)
	if err != nil {
		t.Fatalf("quic listen: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go func(conn *quic.Conn) {
				authStream, err := conn.AcceptStream(context.Background())
				if err != nil {
					return
				}
				reader := NewFrameReader(authStream)
				frame, err := reader.ReadTypedFrame()
				if err != nil || frame.Type != FrameAuth {
					authStream.Close()
					return
				}
				w := NewFrameWriter(authStream)
				w.WriteTypedFrame(EncodeAuthResponse(AuthStatusOK, nil))
				w.Flush()
				authStream.Close()

				for {
					stream, err := conn.AcceptStream(context.Background())
					if err != nil {
						return
					}
					go func(stream *quic.Stream) {
						defer stream.Close()
						var first [1]byte
						if _, err := io.ReadFull(stream, first[:]); err != nil {
							return
						}
						if _, _, _, err := ReadAddressHeaderWithFirstByte(first[0], stream); err != nil {
							stream.Write([]byte{0x01})
							return
						}
						stream.Write([]byte{0x00})
						io.Copy(stream, stream)
					}(stream)
				}
			}(conn)
		}
	}()

	return udpConn.LocalAddr().String(), func() {
		ln.Close()
		tr.Close()
		udpConn.Close()
	}
}

func TestUQUICInteropWithQuicGoServer(t *testing.T) {
	addr, stop := startQUICEchoServer(t)
	defer stop()

	sess, err := uquic_dial(addr, "example.com", "chrome", true)
	if err != nil {
		t.Fatalf("uquic_dial: %v", err)
	}
	defer sess.Close()

	if err := uquic_authenticate(sess, "any-psk"); err != nil {
		t.Fatalf("uquic_authenticate: %v", err)
	}

	conn, err := uquic_open_target(sess, AddrIPv4, "203.0.113.5", 80)
	if err != nil {
		t.Fatalf("uquic_open_target: %v", err)
	}
	defer conn.Close()

	payload := []byte("hello uquic chrome fingerprint")
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

func TestUQUICFirefoxSpec(t *testing.T) {
	if _, err := uquic_spec("firefox"); err != nil {
		t.Fatalf("firefox spec: %v", err)
	}
	if _, err := uquic_spec("chrome"); err != nil {
		t.Fatalf("chrome spec: %v", err)
	}
}
