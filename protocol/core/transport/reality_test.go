// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

package transport

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

func TestRealitySealOpenRoundTrip(t *testing.T) {
	priv_b64, pub_b64, err := generate_reality_keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	priv, err := parse_x25519_private(priv_b64)
	if err != nil {
		t.Fatalf("parse priv: %v", err)
	}
	pub, err := parse_x25519_public(pub_b64)
	if err != nil {
		t.Fatalf("parse pub: %v", err)
	}

	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("eph: %v", err)
	}
	client_shared, err := eph.ECDH(pub)
	if err != nil {
		t.Fatalf("client ecdh: %v", err)
	}
	server_shared, err := priv.ECDH(eph.PublicKey())
	if err != nil {
		t.Fatalf("server ecdh: %v", err)
	}

	sid, err := parse_short_id("0011223344556677")
	if err != nil {
		t.Fatalf("short id: %v", err)
	}
	hour := time.Now().Unix() / 3600

	box, err := reality_seal(client_shared, sid, hour)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	got_sid, got_hour, ok := reality_open(server_shared, box)
	if !ok {
		t.Fatal("open failed with correct shared secret")
	}
	if got_sid != sid || got_hour != hour {
		t.Fatalf("mismatch: sid %x/%x hour %d/%d", got_sid, sid, got_hour, hour)
	}
}

func TestRealityOpenRejectsWrongKey(t *testing.T) {
	priv_a, _, _ := generate_reality_keypair()
	_, pub_b, _ := generate_reality_keypair()

	a, _ := parse_x25519_private(priv_a)
	b, _ := parse_x25519_public(pub_b)

	eph, _ := ecdh.X25519().GenerateKey(rand.Reader)
	client_shared, _ := eph.ECDH(b)
	server_shared, _ := a.ECDH(eph.PublicKey())

	sid, _ := parse_short_id("aabb")
	box, _ := reality_seal(client_shared, sid, time.Now().Unix()/3600)

	if _, _, ok := reality_open(server_shared, box); ok {
		t.Fatal("open should fail across mismatched keypairs")
	}
}

func synthetic_hello(pub *ecdh.PublicKey, box [32]byte) []byte {
	peek := make([]byte, 76)
	peek[0] = 0x16
	peek[5] = 0x01
	copy(peek[11:43], box[:])
	peek[43] = 32
	copy(peek[44:76], pub.Bytes())
	return peek
}

func TestRealityMatchDiscriminates(t *testing.T) {
	priv_b64, pub_b64, _ := generate_reality_keypair()
	priv, _ := parse_x25519_private(priv_b64)
	server_pub, _ := parse_x25519_public(pub_b64)

	sid, _ := parse_short_id("cafe")
	disp := &reality_dispatcher{
		priv:    priv,
		allowed: map[[reality_short_id_len]byte]bool{sid: true},
	}

	eph, _ := ecdh.X25519().GenerateKey(rand.Reader)
	shared, _ := eph.ECDH(server_pub)
	box, _ := reality_seal(shared, sid, time.Now().Unix()/3600)
	if !disp.match(synthetic_hello(eph.PublicKey(), box)) {
		t.Fatal("valid client hello should match")
	}

	unknown_sid, _ := parse_short_id("dead")
	box2, _ := reality_seal(shared, unknown_sid, time.Now().Unix()/3600)
	if disp.match(synthetic_hello(eph.PublicKey(), box2)) {
		t.Fatal("unknown short id must not match")
	}

	box[0] ^= 0xff
	if disp.match(synthetic_hello(eph.PublicKey(), box)) {
		t.Fatal("tampered auth box must not match")
	}

	if disp.match([]byte{0x16, 0, 0, 0, 0, 0x01}) {
		t.Fatal("short buffer must not match")
	}
}

func TestRealityEndToEndHandshakeAndFallback(t *testing.T) {
	priv_b64, pub_b64, _ := generate_reality_keypair()
	priv, _ := parse_x25519_private(priv_b64)
	server_pub, _ := parse_x25519_public(pub_b64)
	sid, _ := parse_short_id("1234")

	dest_hit := make(chan byte, 1)
	dest_ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("dest listen: %v", err)
	}
	defer dest_ln.Close()
	go func() {
		for {
			c, err := dest_ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				b := make([]byte, 1)
				if _, err := io.ReadFull(c, b); err == nil {
					select {
					case dest_hit <- b[0]:
					default:
					}
				}
			}(c)
		}
	}()

	cert, err := GenerateStealthCert("example.com")
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	disp := &reality_dispatcher{
		priv:    priv,
		allowed: map[[reality_short_id_len]byte]bool{sid: true},
		dest:    dest_ln.Addr().String(),
		cert:    &cert,
	}

	srv_ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("srv listen: %v", err)
	}
	defer srv_ln.Close()
	go func() {
		for {
			c, err := srv_ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				pconn, err := NewPeekingConn(c, 128)
				if err != nil {
					c.Close()
					return
				}
				tconn, ours := disp.accept(pconn)
				if !ours {
					return
				}
				defer tconn.Close()
				if err := tconn.(*tls.Conn).Handshake(); err != nil {
					return
				}
				buf := make([]byte, 4)
				if _, err := io.ReadFull(tconn, buf); err != nil {
					return
				}
				tconn.Write(buf)
			}(c)
		}
	}()

	conn, err := reality_dial(srv_ln.Addr().String(), "example.com", "chrome", server_pub, sid)
	if err != nil {
		t.Fatalf("reality_dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	echo := make([]byte, 4)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, echo); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(echo) != "ping" {
		t.Fatalf("echo = %q, want ping", echo)
	}

	prober, err := net.Dial("tcp", srv_ln.Addr().String())
	if err != nil {
		t.Fatalf("prober dial: %v", err)
	}
	defer prober.Close()
	prober.Write([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01})

	select {
	case b := <-dest_hit:
		if b != 0x16 {
			t.Fatalf("dest first byte = %#x, want 0x16", b)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("prober traffic was not spliced to dest")
	}
}
