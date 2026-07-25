// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

package transport

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sync"
)

// Trojan request layout (Xray/trojan-gfw compatible):
//
//	hex(SHA224(password))(56) + CRLF + cmd(1) + SOCKS5-address + CRLF
//
// The address part (atype 0x01 IPv4 / 0x03 Domain / 0x04 IPv6 + addr + port)
// is byte-identical to the existing EncodeAddress/DecodeAddress helpers in
// framing.go, so those are reused directly instead of duplicating a codec.
const (
	trojanCmdConnect byte = 0x01
	trojanCmdUDP     byte = 0x03

	trojanPasswordHexLen = 56
)

var trojanCRLF = []byte{'\r', '\n'}

type TrojanClient struct {
	Password string `json:"password"`
	Email    string `json:"email,omitempty"`
}

type TrojanConfig struct {
	Clients []TrojanClient `json:"clients"`
	// DecoyAddr, if set, is a "host:port" backend the server transparently
	// relays to when Trojan auth fails (wrong or missing password),
	// instead of just closing the connection - the gRPC-carried analogue
	// of classic Trojan-over-TCP falling through to a real website on a
	// bad password, so a wrong password (or an active prober) sees normal
	// looking traffic rather than an abrupt close.
	DecoyAddr string `json:"decoy_addr,omitempty"`
}

func trojanPasswordHash(password string) string {
	sum := sha256.Sum224([]byte(password))
	return hex.EncodeToString(sum[:])
}

type trojanClientMap struct {
	byHash map[string]*TrojanClient
}

func newTrojanClientMap(cfg TrojanConfig) *trojanClientMap {
	m := &trojanClientMap{byHash: make(map[string]*TrojanClient, len(cfg.Clients))}
	for i := range cfg.Clients {
		c := &cfg.Clients[i]
		if c.Password == "" {
			continue
		}
		m.byHash[trojanPasswordHash(c.Password)] = c
	}
	return m
}

func (m *trojanClientMap) lookup(hash string) *TrojanClient {
	if m == nil {
		return nil
	}
	return m.byHash[hash]
}

func trojan_encode_request(password string, addrType byte, addr string, port uint16) []byte {
	hash := trojanPasswordHash(password)
	addrBuf := EncodeAddress(addrType, addr, port)

	buf := make([]byte, 0, trojanPasswordHexLen+2+1+len(addrBuf)+2)
	buf = append(buf, []byte(hash)...)
	buf = append(buf, trojanCRLF...)
	buf = append(buf, trojanCmdConnect)
	buf = append(buf, addrBuf...)
	buf = append(buf, trojanCRLF...)
	return buf
}

func trojan_read_request(r io.Reader) (hash string, cmd, addrType byte, addr string, port uint16, err error) {
	hdr := make([]byte, trojanPasswordHexLen+2)
	if _, err = io.ReadFull(r, hdr); err != nil {
		return
	}
	if hdr[trojanPasswordHexLen] != '\r' || hdr[trojanPasswordHexLen+1] != '\n' {
		err = fmt.Errorf("trojan: malformed header (missing CRLF)")
		return
	}
	hash = string(hdr[:trojanPasswordHexLen])

	cmdBuf := make([]byte, 1)
	if _, err = io.ReadFull(r, cmdBuf); err != nil {
		return
	}
	cmd = cmdBuf[0]
	if cmd != trojanCmdConnect && cmd != trojanCmdUDP {
		err = fmt.Errorf("trojan: unsupported command %d", cmd)
		return
	}

	addrType, addr, port, err = readTrojanAddress(r)
	if err != nil {
		return
	}

	crlf := make([]byte, 2)
	if _, err = io.ReadFull(r, crlf); err != nil {
		return
	}
	if crlf[0] != '\r' || crlf[1] != '\n' {
		err = fmt.Errorf("trojan: malformed header (missing trailing CRLF)")
	}
	return
}

// readTrojanAddress mirrors DecodeAddress but reads directly off a stream
// (the Trojan header isn't length-prefixed as a whole, so we can't buffer
// the whole thing up front the way DecodeAddress expects).
func readTrojanAddress(r io.Reader) (addrType byte, addr string, port uint16, err error) {
	return ReadAddressHeader(r)
}

// trojan_client_conn wraps a raw byte-stream carrier (a gRPC Gun stream)
// and speaks Trojan on top of it, merging the request header into the
// first Write. There is no response header in Trojan - a successful auth
// just starts relaying immediately, so Read is a plain passthrough.
type trojan_client_conn struct {
	net.Conn
	mu         sync.Mutex
	headerSent bool

	password string
	addrType byte
	addr     string
	port     uint16
}

func trojan_wrap_client(conn net.Conn, password string, addrType byte, addr string, port uint16) net.Conn {
	return &trojan_client_conn{Conn: conn, password: password, addrType: addrType, addr: addr, port: port}
}

func (c *trojan_client_conn) Write(b []byte) (int, error) {
	c.mu.Lock()
	sendHeader := !c.headerSent
	c.headerSent = true
	c.mu.Unlock()

	if !sendHeader {
		return c.Conn.Write(b)
	}

	header := trojan_encode_request(c.password, c.addrType, c.addr, c.port)
	payload := make([]byte, len(header)+len(b))
	copy(payload, header)
	copy(payload[len(header):], b)
	if _, err := c.Conn.Write(payload); err != nil {
		return 0, err
	}
	return len(b), nil
}

// trojan_accept reads and validates a Trojan request off conn (a freshly
// accepted gRPC Gun stream) and returns the resolved target. On bad
// password the caller relays to a decoy backend (see recordingConn below)
// instead of just closing. The caller relays conn <-> target directly
// afterwards, there is nothing to strip on the response side.
func trojan_accept(conn net.Conn, clients *trojanClientMap) (client *TrojanClient, addrType byte, addr string, port uint16, err error) {
	hash, cmd, addrType, addr, port, err := trojan_read_request(conn)
	if err != nil {
		return nil, 0, "", 0, err
	}
	if cmd != trojanCmdConnect {
		return nil, 0, "", 0, fmt.Errorf("trojan: unsupported command %d", cmd)
	}
	client = clients.lookup(hash)
	if client == nil {
		return nil, 0, "", 0, fmt.Errorf("trojan: unknown client")
	}
	return client, addrType, addr, port, nil
}

// recordingConn wraps a net.Conn and remembers every byte read through it.
// trojan_accept consumes the request header directly off the wire with no
// way to "rewind"; wrapping the connection in this before calling it means
// a failed parse (bad password, or not a Trojan request at all - the
// server can't and shouldn't distinguish the two) can still replay exactly
// what was read to a decoy backend, so the fallback is byte-transparent
// rather than starting the decoy stream mid-request.
type recordingConn struct {
	net.Conn
	recorded []byte
}

func newRecordingConn(conn net.Conn) *recordingConn {
	return &recordingConn{Conn: conn}
}

func (r *recordingConn) Read(b []byte) (int, error) {
	n, err := r.Conn.Read(b)
	if n > 0 {
		r.recorded = append(r.recorded, b[:n]...)
	}
	return n, err
}

func (r *recordingConn) Recorded() []byte {
	return r.recorded
}
