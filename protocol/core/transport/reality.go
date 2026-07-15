// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

package transport

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"

	utls "github.com/refraction-networking/utls"
)

type RealityConfig struct {
	Enabled    bool     `json:"enabled"`
	Dest       string   `json:"dest"`
	ServerName string   `json:"server_name"`
	PrivateKey string   `json:"private_key"`
	PublicKey  string   `json:"public_key"`
	ShortID    string   `json:"short_id"`
	ShortIDs   []string `json:"short_ids"`
}

const (
	reality_short_id_len = 8
	reality_dial_timeout = 15 * time.Second
	reality_hkdf_info    = "stealthlink-reality-v1|clienthello-auth"
)

func GenerateRealityKeypair() (privateKey string, publicKey string, err error) {
	return generate_reality_keypair()
}

func generate_reality_keypair() (string, string, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(priv.Bytes()), enc.EncodeToString(priv.PublicKey().Bytes()), nil
}

func decode_key_bytes(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty key")
	}
	for _, dec := range []*base64.Encoding{base64.RawURLEncoding, base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding} {
		if b, err := dec.DecodeString(s); err == nil && len(b) == 32 {
			return b, nil
		}
	}
	if b, err := hex.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	return nil, fmt.Errorf("key must be 32 bytes (base64 or hex)")
}

func parse_x25519_private(s string) (*ecdh.PrivateKey, error) {
	b, err := decode_key_bytes(s)
	if err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPrivateKey(b)
}

func parse_x25519_public(s string) (*ecdh.PublicKey, error) {
	b, err := decode_key_bytes(s)
	if err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPublicKey(b)
}

func parse_short_id(s string) ([reality_short_id_len]byte, error) {
	var out [reality_short_id_len]byte
	s = strings.TrimSpace(s)
	if s == "" {
		return out, nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return out, fmt.Errorf("short_id must be hex: %w", err)
	}
	if len(b) > reality_short_id_len {
		return out, fmt.Errorf("short_id too long: max %d bytes", reality_short_id_len)
	}
	copy(out[:], b)
	return out, nil
}

func reality_derive(shared []byte) ([32]byte, [12]byte, error) {
	var key [32]byte
	var nonce [12]byte
	r := hkdf.New(sha256.New, shared, nil, []byte(reality_hkdf_info))
	if _, err := io.ReadFull(r, key[:]); err != nil {
		return key, nonce, err
	}
	if _, err := io.ReadFull(r, nonce[:]); err != nil {
		return key, nonce, err
	}
	return key, nonce, nil
}

func reality_seal(shared []byte, sid [reality_short_id_len]byte, hour int64) ([32]byte, error) {
	var out [32]byte
	key, nonce, err := reality_derive(shared)
	if err != nil {
		return out, err
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return out, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return out, err
	}
	pt := make([]byte, 16)
	copy(pt[:reality_short_id_len], sid[:])
	binary.BigEndian.PutUint64(pt[reality_short_id_len:], uint64(hour))
	ct := gcm.Seal(nil, nonce[:], pt, nil)
	if len(ct) != 32 {
		return out, fmt.Errorf("unexpected sealed length %d", len(ct))
	}
	copy(out[:], ct)
	return out, nil
}

func reality_open(shared []byte, box [32]byte) ([reality_short_id_len]byte, int64, bool) {
	var sid [reality_short_id_len]byte
	key, nonce, err := reality_derive(shared)
	if err != nil {
		return sid, 0, false
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return sid, 0, false
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return sid, 0, false
	}
	pt, err := gcm.Open(nil, nonce[:], box[:], nil)
	if err != nil || len(pt) != 16 {
		return sid, 0, false
	}
	copy(sid[:], pt[:reality_short_id_len])
	hour := int64(binary.BigEndian.Uint64(pt[reality_short_id_len:]))
	return sid, hour, true
}

func reality_hello_id(fingerprint string) utls.ClientHelloID {
	switch strings.ToLower(strings.TrimSpace(fingerprint)) {
	case "firefox":
		return utls.HelloFirefox_Auto
	case "edge":
		return utls.HelloEdge_Auto
	case "safari":
		return utls.HelloSafari_Auto
	case "ios":
		return utls.HelloIOS_Auto
	case "android":
		return utls.HelloAndroid_11_OkHttp
	case "360":
		return utls.Hello360_Auto
	case "qq":
		return utls.HelloQQ_Auto
	case "random":
		return utls.HelloRandomized
	default:
		return utls.HelloChrome_Auto
	}
}

func reality_dial(server_addr, server_name, fingerprint string, server_pub *ecdh.PublicKey, sid [reality_short_id_len]byte) (net.Conn, error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := eph.ECDH(server_pub)
	if err != nil {
		return nil, fmt.Errorf("ecdh failed: %w", err)
	}

	hour := time.Now().Unix() / 3600
	box, err := reality_seal(shared, sid, hour)
	if err != nil {
		return nil, err
	}

	tcp, err := net.DialTimeout("tcp", server_addr, reality_dial_timeout)
	if err != nil {
		return nil, fmt.Errorf("tcp dial failed: %w", err)
	}

	uconf := &utls.Config{
		ServerName:         server_name,
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
	}
	uconn := utls.UClient(tcp, uconf, reality_hello_id(fingerprint))

	if err := uconn.BuildHandshakeState(); err != nil {
		tcp.Close()
		return nil, fmt.Errorf("build hello failed: %w", err)
	}

	epub := eph.PublicKey().Bytes()
	uconn.HandshakeState.Hello.SessionId = epub
	if err := uconn.SetClientRandom(box[:]); err != nil {
		tcp.Close()
		return nil, err
	}

	if err := uconn.Handshake(); err != nil {
		tcp.Close()
		return nil, fmt.Errorf("reality handshake failed: %w", err)
	}

	TuneTCPConn(tcp)
	return uconn, nil
}

func reality_dial_vpn(server_addr, server_name, fingerprint, psk string, server_pub *ecdh.PublicKey, sid [reality_short_id_len]byte, addr_type byte, addr string, port uint16) (net.Conn, error) {
	conn, err := reality_dial(server_addr, server_name, fingerprint, server_pub, sid)
	if err != nil {
		return nil, err
	}

	auth, err := GenerateAuthPayload(psk)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("auth generation failed: %w", err)
	}

	header := EncodeAddress(addr_type, addr, port)
	combined := make([]byte, len(auth)+len(header))
	copy(combined, auth)
	copy(combined[len(auth):], header)
	if _, err := conn.Write(combined); err != nil {
		conn.Close()
		return nil, fmt.Errorf("auth write failed: %w", err)
	}

	status := make([]byte, 1)
	conn.SetDeadline(time.Now().Add(reality_dial_timeout))
	if _, err := io.ReadFull(conn, status); err != nil {
		conn.Close()
		return nil, fmt.Errorf("status read failed: %w", err)
	}
	conn.SetDeadline(time.Time{})

	if status[0] != 0x00 {
		conn.Close()
		switch status[0] {
		case 0x01:
			return nil, fmt.Errorf("authentication denied")
		case 0x02:
			return nil, fmt.Errorf("target connection failed")
		case 0x03:
			return nil, fmt.Errorf("blocked by firewall")
		default:
			return nil, fmt.Errorf("connect error: status=%d", status[0])
		}
	}
	return conn, nil
}

type reality_dispatcher struct {
	priv    *ecdh.PrivateKey
	allowed map[[reality_short_id_len]byte]bool
	dest    string
	cert    *tls.Certificate
}

func new_reality_dispatcher(cfg RealityConfig) (*reality_dispatcher, error) {
	priv, err := parse_x25519_private(cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("reality private_key: %w", err)
	}
	if cfg.Dest == "" {
		return nil, fmt.Errorf("reality dest is required")
	}

	allowed := make(map[[reality_short_id_len]byte]bool)
	ids := cfg.ShortIDs
	if cfg.ShortID != "" {
		ids = append(ids, cfg.ShortID)
	}
	if len(ids) == 0 {
		var zero [reality_short_id_len]byte
		allowed[zero] = true
	}
	for _, s := range ids {
		sid, perr := parse_short_id(s)
		if perr != nil {
			return nil, perr
		}
		allowed[sid] = true
	}

	sni := cfg.ServerName
	if sni == "" {
		sni = hostOnly(cfg.Dest)
	}
	cert, err := CloneCertFromTarget(cfg.Dest, sni)
	if err != nil {
		return nil, fmt.Errorf("reality cert: %w", err)
	}

	return &reality_dispatcher{
		priv:    priv,
		allowed: allowed,
		dest:    cfg.Dest,
		cert:    &cert,
	}, nil
}

func reality_peek(conn net.Conn, min, max int) (*PeekingConn, error) {
	buf := make([]byte, max)
	total := 0
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for total < min {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			break
		}
		if total >= max {
			break
		}
	}
	conn.SetReadDeadline(time.Time{})
	if total == 0 {
		return nil, fmt.Errorf("empty read")
	}
	return &PeekingConn{Conn: conn, peekBuf: buf[:total]}, nil
}

func is_reality_client_hello(peek []byte) bool {
	return len(peek) >= 76 && peek[0] == 0x16 && peek[5] == 0x01 && peek[43] == 32
}

func reality_hour_fresh(hour int64) bool {
	now := time.Now().Unix() / 3600
	return hour == now || hour == now-1 || hour == now+1
}

func (d *reality_dispatcher) accept(pconn *PeekingConn) (net.Conn, bool) {
	if authed := d.match(pconn.Peek()); authed {
		tconf := &tls.Config{
			Certificates: []tls.Certificate{*d.cert},
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"http/1.1", "h2"},
		}
		return tls.Server(pconn, tconf), true
	}
	d.fallback(pconn)
	return nil, false
}

func (d *reality_dispatcher) match(peek []byte) bool {
	if !is_reality_client_hello(peek) {
		return false
	}
	pub, err := ecdh.X25519().NewPublicKey(peek[44:76])
	if err != nil {
		return false
	}
	shared, err := d.priv.ECDH(pub)
	if err != nil {
		return false
	}
	var box [32]byte
	copy(box[:], peek[11:43])
	sid, hour, ok := reality_open(shared, box)
	if !ok || !d.allowed[sid] || !reality_hour_fresh(hour) {
		return false
	}
	return true
}

func (d *reality_dispatcher) fallback(pconn *PeekingConn) {
	addr := d.dest
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "443")
	}
	up, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		pconn.Close()
		return
	}
	go func() {
		io.Copy(up, pconn)
		up.Close()
	}()
	io.Copy(pconn, up)
	pconn.Close()
}
