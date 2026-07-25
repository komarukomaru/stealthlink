// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

package transport

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
)

// VLESS request/response layout (Xray-compatible):
//
//	request:  ver(1)=0x00 + uuid(16) + addonsLen(1) + addons(N) + cmd(1) + port(2 BE) + addrType(1) + addr
//	response: ver(1) + addonsLen(1) + addons(N)
//
// Note the port is written *before* the address (protocol.PortThenAddress in
// Xray), and VLESS's own address-type byte values (0x01 IPv4 / 0x02 Domain /
// 0x03 IPv6) differ from the SOCKS5-style AddrIPv4/AddrDomain/AddrIPv6
// constants used elsewhere in this package for the StealthLink protocol.
const (
	vlessVersion byte = 0x00

	vlessCmdTCP byte = 0x01
	vlessCmdUDP byte = 0x02
	vlessCmdMux byte = 0x03

	vlessAddrIPv4   byte = 0x01
	vlessAddrDomain byte = 0x02
	vlessAddrIPv6   byte = 0x03
)

type VlessClient struct {
	ID    string `json:"id"`
	Email string `json:"email,omitempty"`
	// Flow is accepted for config compatibility but not implemented (no
	// xtls-rprx-vision support in this build) - plain VLESS only.
	Flow string `json:"flow,omitempty"`
}

type VlessConfig struct {
	Clients []VlessClient `json:"clients"`
}

func parseVlessUUID(s string) ([16]byte, error) {
	var out [16]byte
	s = strings.ReplaceAll(s, "-", "")
	if len(s) != 32 {
		return out, fmt.Errorf("vless: invalid uuid %q", s)
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return out, fmt.Errorf("vless: invalid uuid %q: %w", s, err)
	}
	copy(out[:], b)
	return out, nil
}

func formatVlessUUID(b [16]byte) string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

type vlessClientMap struct {
	byUUID map[[16]byte]*VlessClient
}

func newVlessClientMap(cfg VlessConfig) *vlessClientMap {
	m := &vlessClientMap{byUUID: make(map[[16]byte]*VlessClient, len(cfg.Clients))}
	for i := range cfg.Clients {
		c := &cfg.Clients[i]
		id, err := parseVlessUUID(c.ID)
		if err != nil {
			continue
		}
		m.byUUID[id] = c
	}
	return m
}

func (m *vlessClientMap) lookup(uuid [16]byte) *VlessClient {
	if m == nil {
		return nil
	}
	return m.byUUID[uuid]
}

func vless_encode_addr_port(cmd, addrType byte, addr string, port uint16) ([]byte, error) {
	buf := make([]byte, 0, 24)
	buf = append(buf, cmd)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, port)
	buf = append(buf, portBuf...)

	switch addrType {
	case vlessAddrIPv4:
		ip := net.ParseIP(addr).To4()
		if ip == nil {
			return nil, fmt.Errorf("vless: invalid ipv4 address %q", addr)
		}
		buf = append(buf, vlessAddrIPv4)
		buf = append(buf, ip...)
	case vlessAddrIPv6:
		ip := net.ParseIP(addr).To16()
		if ip == nil {
			return nil, fmt.Errorf("vless: invalid ipv6 address %q", addr)
		}
		buf = append(buf, vlessAddrIPv6)
		buf = append(buf, ip...)
	case vlessAddrDomain:
		if len(addr) > 255 {
			addr = addr[:255]
		}
		buf = append(buf, vlessAddrDomain, byte(len(addr)))
		buf = append(buf, addr...)
	default:
		return nil, fmt.Errorf("vless: unknown address type %d", addrType)
	}
	return buf, nil
}

func vless_encode_request(uuid [16]byte, cmd, addrType byte, addr string, port uint16) ([]byte, error) {
	cmdAddr, err := vless_encode_addr_port(cmd, addrType, addr, port)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 0, 19+len(cmdAddr))
	buf = append(buf, vlessVersion)
	buf = append(buf, uuid[:]...)
	buf = append(buf, 0x00) // addons length: none
	buf = append(buf, cmdAddr...)
	return buf, nil
}

func vless_read_request(r io.Reader) (uuid [16]byte, cmd, addrType byte, addr string, port uint16, err error) {
	hdr := make([]byte, 18) // ver(1) + uuid(16) + addonsLen(1)
	if _, err = io.ReadFull(r, hdr); err != nil {
		return
	}
	if hdr[0] != vlessVersion {
		err = fmt.Errorf("vless: unsupported version %d", hdr[0])
		return
	}
	copy(uuid[:], hdr[1:17])

	if addonsLen := int(hdr[17]); addonsLen > 0 {
		if _, err = io.CopyN(io.Discard, r, int64(addonsLen)); err != nil {
			return
		}
	}

	cmdBuf := make([]byte, 1)
	if _, err = io.ReadFull(r, cmdBuf); err != nil {
		return
	}
	cmd = cmdBuf[0]
	if cmd == vlessCmdMux {
		err = fmt.Errorf("vless: mux command not supported")
		return
	}

	portBuf := make([]byte, 2)
	if _, err = io.ReadFull(r, portBuf); err != nil {
		return
	}
	port = binary.BigEndian.Uint16(portBuf)

	atBuf := make([]byte, 1)
	if _, err = io.ReadFull(r, atBuf); err != nil {
		return
	}
	addrType = atBuf[0]

	switch addrType {
	case vlessAddrIPv4:
		b := make([]byte, 4)
		if _, err = io.ReadFull(r, b); err != nil {
			return
		}
		addr = net.IP(b).String()
	case vlessAddrIPv6:
		b := make([]byte, 16)
		if _, err = io.ReadFull(r, b); err != nil {
			return
		}
		addr = net.IP(b).String()
	case vlessAddrDomain:
		lb := make([]byte, 1)
		if _, err = io.ReadFull(r, lb); err != nil {
			return
		}
		db := make([]byte, int(lb[0]))
		if _, err = io.ReadFull(r, db); err != nil {
			return
		}
		addr = string(db)
	default:
		err = fmt.Errorf("vless: unknown address type %d", addrType)
	}
	return
}

func vless_write_response(w io.Writer) error {
	_, err := w.Write([]byte{vlessVersion, 0x00})
	return err
}

func vless_read_response(r io.Reader) error {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return err
	}
	if addonsLen := int(hdr[1]); addonsLen > 0 {
		if _, err := io.CopyN(io.Discard, r, int64(addonsLen)); err != nil {
			return err
		}
	}
	return nil
}

// vless_client_conn wraps a raw byte-stream carrier (an XHTTP conn) and
// speaks VLESS on top of it: the request header is merged into the first
// Write to save a round trip, and the response header is stripped off the
// first Read. TCP (vlessCmdTCP) only - UDP over VLESS/XHTTP is not wired up,
// matching every other SetDialer-based transport in this package.
type vless_client_conn struct {
	net.Conn
	mu         sync.Mutex
	headerSent bool
	respRead   bool

	uuid     [16]byte
	addrType byte
	addr     string
	port     uint16
}

func vless_wrap_client(conn net.Conn, uuid [16]byte, addrType byte, addr string, port uint16) net.Conn {
	return &vless_client_conn{Conn: conn, uuid: uuid, addrType: addrType, addr: addr, port: port}
}

func (c *vless_client_conn) Write(b []byte) (int, error) {
	c.mu.Lock()
	sendHeader := !c.headerSent
	c.headerSent = true
	c.mu.Unlock()

	if !sendHeader {
		return c.Conn.Write(b)
	}

	header, err := vless_encode_request(c.uuid, vlessCmdTCP, c.addrType, c.addr, c.port)
	if err != nil {
		return 0, err
	}
	payload := make([]byte, len(header)+len(b))
	copy(payload, header)
	copy(payload[len(header):], b)
	if _, err := c.Conn.Write(payload); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *vless_client_conn) Read(b []byte) (int, error) {
	c.mu.Lock()
	needResp := !c.respRead
	c.respRead = true
	c.mu.Unlock()

	if needResp {
		if err := vless_read_response(c.Conn); err != nil {
			return 0, err
		}
	}
	return c.Conn.Read(b)
}

// socks5ToVlessAddrType maps the SOCKS5-style AddrIPv4/AddrDomain/AddrIPv6
// constants (used by SOCKSProxy's dialer callback) onto VLESS's own address
// type byte values, which only coincidentally agree for IPv4.
func socks5ToVlessAddrType(t byte) byte {
	switch t {
	case AddrDomain:
		return vlessAddrDomain
	case AddrIPv6:
		return vlessAddrIPv6
	default:
		return vlessAddrIPv4
	}
}

// vless_accept reads and validates a VLESS request off conn (a freshly
// accepted XHTTP stream), writes the response header on success, and
// returns the resolved target. The caller relays conn <-> target directly
// afterwards - no further wrapping needed on the server side.
func vless_accept(conn net.Conn, clients *vlessClientMap) (client *VlessClient, addrType byte, addr string, port uint16, err error) {
	uuid, cmd, addrType, addr, port, err := vless_read_request(conn)
	if err != nil {
		return nil, 0, "", 0, err
	}
	if cmd != vlessCmdTCP {
		return nil, 0, "", 0, fmt.Errorf("vless: unsupported command %d", cmd)
	}
	client = clients.lookup(uuid)
	if client == nil {
		return nil, 0, "", 0, fmt.Errorf("vless: unknown client")
	}
	if err = vless_write_response(conn); err != nil {
		return nil, 0, "", 0, err
	}
	return client, addrType, addr, port, nil
}
