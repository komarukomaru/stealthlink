// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

package transport

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

type RedstoneConfig struct {
	Enabled         bool   `json:"enabled"`
	MOTD            string `json:"motd"`
	Version         string `json:"version"`
	ProtocolVersion int    `json:"protocol_version"`
}

const (
	mc_tunnel_id      = 0x17
	mc_max_packet     = 2 * 1024 * 1024
	mc_chunk_size     = 16 * 1024
	mc_default_proto  = 765
	mc_default_ver    = "1.20.4"
	mc_default_motd   = "A Minecraft Server"
	mc_handshake_wait = 15 * time.Second
)

func mc_append_varint(buf []byte, v int) []byte {
	u := uint32(v)
	for {
		b := byte(u & 0x7F)
		u >>= 7
		if u != 0 {
			b |= 0x80
		}
		buf = append(buf, b)
		if u == 0 {
			return buf
		}
	}
}

func mc_read_varint(r io.ByteReader) (int, error) {
	var result uint32
	var shift uint
	for i := 0; i < 5; i++ {
		b, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		result |= uint32(b&0x7F) << shift
		if b&0x80 == 0 {
			return int(int32(result)), nil
		}
		shift += 7
	}
	return 0, fmt.Errorf("varint too long")
}

func mc_decode_varint(data []byte) (int, int, error) {
	var result uint32
	var shift uint
	for i := 0; i < len(data) && i < 5; i++ {
		b := data[i]
		result |= uint32(b&0x7F) << shift
		if b&0x80 == 0 {
			return int(int32(result)), i + 1, nil
		}
		shift += 7
	}
	return 0, 0, fmt.Errorf("varint decode failed")
}

func mc_append_string(buf []byte, s string) []byte {
	buf = mc_append_varint(buf, len(s))
	return append(buf, []byte(s)...)
}

func mc_write_packet(w io.Writer, packetID int, data []byte) error {
	var pkt []byte
	pkt = mc_append_varint(pkt, packetID)
	pkt = append(pkt, data...)

	var out []byte
	out = mc_append_varint(out, len(pkt))
	out = append(out, pkt...)
	_, err := w.Write(out)
	return err
}

func mc_read_packet(br *bufio.Reader) (int, []byte, error) {
	length, err := mc_read_varint(br)
	if err != nil {
		return 0, nil, err
	}
	if length <= 0 || length > mc_max_packet {
		return 0, nil, fmt.Errorf("invalid packet length %d", length)
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(br, data); err != nil {
		return 0, nil, err
	}
	id, n, err := mc_decode_varint(data)
	if err != nil {
		return 0, nil, err
	}
	return id, data[n:], nil
}

func mc_random_username() string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
	b := make([]byte, 10)
	rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

type mc_conn struct {
	net.Conn
	br   *bufio.Reader
	wid  int
	rbuf []byte
}

func new_mc_conn(conn net.Conn, br *bufio.Reader) *mc_conn {
	return &mc_conn{Conn: conn, br: br, wid: mc_tunnel_id}
}

func (c *mc_conn) Read(p []byte) (int, error) {
	for len(c.rbuf) == 0 {
		_, payload, err := mc_read_packet(c.br)
		if err != nil {
			return 0, err
		}
		c.rbuf = payload
	}
	n := copy(p, c.rbuf)
	c.rbuf = c.rbuf[n:]
	return n, nil
}

func (c *mc_conn) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > mc_chunk_size {
			chunk = chunk[:mc_chunk_size]
		}
		if err := mc_write_packet(c.Conn, c.wid, chunk); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

func mc_write_handshake(w io.Writer, protocolVersion int, host string, port uint16, nextState int) error {
	var data []byte
	data = mc_append_varint(data, protocolVersion)
	data = mc_append_string(data, host)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, port)
	data = append(data, portBuf...)
	data = mc_append_varint(data, nextState)
	return mc_write_packet(w, 0x00, data)
}

func mc_write_login_start(w io.Writer, username string) error {
	var data []byte
	data = mc_append_string(data, username)
	return mc_write_packet(w, 0x00, data)
}

func mc_write_login_success(w io.Writer, username string) error {
	uuid := make([]byte, 16)
	rand.Read(uuid)
	var data []byte
	data = append(data, uuid...)
	data = mc_append_string(data, username)
	data = mc_append_varint(data, 0)
	return mc_write_packet(w, 0x02, data)
}

func mc_parse_handshake(data []byte) (nextState int, err error) {
	_, n, err := mc_decode_varint(data)
	if err != nil {
		return 0, err
	}
	data = data[n:]
	if len(data) < 1 {
		return 0, fmt.Errorf("handshake too short")
	}
	strLen, n, err := mc_decode_varint(data)
	if err != nil {
		return 0, err
	}
	data = data[n:]
	if len(data) < strLen+2 {
		return 0, fmt.Errorf("handshake host truncated")
	}
	data = data[strLen+2:]
	nextState, _, err = mc_decode_varint(data)
	if err != nil {
		return 0, err
	}
	return nextState, nil
}

func mc_status_json(motd, version string, proto int) string {
	return fmt.Sprintf(`{"version":{"name":%q,"protocol":%d},"players":{"max":20,"online":0,"sample":[]},"description":{"text":%q}}`,
		version, proto, motd)
}

func mc_handle_status(br *bufio.Reader, w io.Writer, motd, version string, proto int) {
	if _, _, err := mc_read_packet(br); err != nil {
		return
	}
	var data []byte
	data = mc_append_string(data, mc_status_json(motd, version, proto))
	if err := mc_write_packet(w, 0x00, data); err != nil {
		return
	}
	id, payload, err := mc_read_packet(br)
	if err == nil && id == 0x01 {
		mc_write_packet(w, 0x01, payload)
	}
}

func redstone_defaults(cfg RedstoneConfig) (motd, version string, proto int) {
	motd = cfg.MOTD
	if motd == "" {
		motd = mc_default_motd
	}
	version = cfg.Version
	if version == "" {
		version = mc_default_ver
	}
	proto = cfg.ProtocolVersion
	if proto == 0 {
		proto = mc_default_proto
	}
	return
}

func redstone_serve(raw net.Conn, cfg RedstoneConfig, on_tunnel func(net.Conn)) {
	br := bufio.NewReader(raw)
	raw.SetReadDeadline(time.Now().Add(mc_handshake_wait))
	id, data, err := mc_read_packet(br)
	if err != nil || id != 0x00 {
		raw.Close()
		return
	}
	nextState, err := mc_parse_handshake(data)
	if err != nil {
		raw.Close()
		return
	}

	motd, version, proto := redstone_defaults(cfg)

	switch nextState {
	case 1:
		mc_handle_status(br, raw, motd, version, proto)
		raw.Close()
	case 2:
		if _, _, err := mc_read_packet(br); err != nil {
			raw.Close()
			return
		}
		if err := mc_write_login_success(raw, mc_random_username()); err != nil {
			raw.Close()
			return
		}
		raw.SetReadDeadline(time.Time{})
		on_tunnel(new_mc_conn(raw, br))
	default:
		raw.Close()
	}
}

func redstone_dial(server_addr, host, psk string, addr_type byte, addr string, port uint16) (net.Conn, error) {
	raw, err := net.DialTimeout("tcp", server_addr, mc_handshake_wait)
	if err != nil {
		return nil, fmt.Errorf("tcp dial failed: %w", err)
	}

	handshakePort := uint16(25565)
	if _, portStr, splitErr := net.SplitHostPort(server_addr); splitErr == nil {
		if p, perr := net.LookupPort("tcp", portStr); perr == nil {
			handshakePort = uint16(p)
		}
	}

	br := bufio.NewReader(raw)
	if err := mc_write_handshake(raw, mc_default_proto, host, handshakePort, 2); err != nil {
		raw.Close()
		return nil, fmt.Errorf("handshake write failed: %w", err)
	}
	if err := mc_write_login_start(raw, mc_random_username()); err != nil {
		raw.Close()
		return nil, fmt.Errorf("login start failed: %w", err)
	}

	raw.SetReadDeadline(time.Now().Add(mc_handshake_wait))
	if _, _, err := mc_read_packet(br); err != nil {
		raw.Close()
		return nil, fmt.Errorf("login response failed: %w", err)
	}
	raw.SetReadDeadline(time.Time{})

	conn := new_mc_conn(raw, br)

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
	conn.SetReadDeadline(time.Now().Add(mc_handshake_wait))
	if _, err := io.ReadFull(conn, status); err != nil {
		conn.Close()
		return nil, fmt.Errorf("status read failed: %w", err)
	}
	conn.SetReadDeadline(time.Time{})

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
