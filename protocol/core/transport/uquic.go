// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

package transport

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	uquic "github.com/refraction-networking/uquic"
	utls "github.com/refraction-networking/utls"
)

func uquic_spec(fingerprint string) (uquic.QUICSpec, error) {
	var id uquic.QUICID
	switch strings.ToLower(strings.TrimSpace(fingerprint)) {
	case "firefox":
		id = uquic.QUICFirefox_116
	default:
		id = uquic.QUICChrome_115_IPv4
	}
	return uquic.QUICID2Spec(id)
}

type uquic_session struct {
	conn      uquic.Connection
	transport *uquic.UTransport
	udpConn   *net.UDPConn
}

func (u *uquic_session) Close() error {
	if u.conn != nil {
		u.conn.CloseWithError(0, "")
	}
	if u.transport != nil {
		u.transport.Close()
	}
	if u.udpConn != nil {
		u.udpConn.Close()
	}
	return nil
}

func uquic_dial(server_addr, sni, fingerprint string, insecure bool) (*uquic_session, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", server_addr)
	if err != nil {
		return nil, fmt.Errorf("udp resolve failed: %w", err)
	}
	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, fmt.Errorf("udp listen failed: %w", err)
	}

	spec, err := uquic_spec(fingerprint)
	if err != nil {
		udpConn.Close()
		return nil, fmt.Errorf("quic fingerprint failed: %w", err)
	}

	quicConf := &uquic.Config{
		KeepAlivePeriod: 15 * time.Second,
		MaxIdleTimeout:  120 * time.Second,
	}
	spec.UpdateConfig(quicConf)

	tr := &uquic.UTransport{
		Transport: &uquic.Transport{Conn: udpConn},
		QUICSpec:  &spec,
	}

	tlsConf := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: insecure,
		NextProtos:         []string{"h3"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := tr.Dial(ctx, udpAddr, tlsConf, quicConf)
	if err != nil {
		tr.Close()
		udpConn.Close()
		return nil, fmt.Errorf("uquic dial failed: %w", err)
	}

	return &uquic_session{conn: conn, transport: tr, udpConn: udpConn}, nil
}

func uquic_authenticate(sess *uquic_session, psk string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, err := sess.conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("auth stream open failed: %w", err)
	}

	writer := NewFrameWriter(stream)
	reader := NewFrameReader(stream)

	authFrame, err := EncodeAuthFrame(psk)
	if err != nil {
		stream.Close()
		return fmt.Errorf("auth frame creation failed: %w", err)
	}
	writer.WriteTypedFrame(authFrame)
	writer.Flush()

	resp, err := reader.ReadTypedFrame()
	if err != nil || resp.Type != FrameAuthResp {
		stream.Close()
		return fmt.Errorf("auth response failed")
	}
	if len(resp.Payload) < 1 || resp.Payload[0] != AuthStatusOK {
		stream.Close()
		return fmt.Errorf("auth denied")
	}
	stream.Close()
	return nil
}

func uquic_open_target(sess *uquic_session, addr_type byte, addr string, port uint16) (net.Conn, error) {
	stream, err := sess.conn.OpenStreamSync(context.Background())
	if err != nil {
		return nil, fmt.Errorf("stream open failed: %w", err)
	}

	header := EncodeAddress(addr_type, addr, port)
	if _, err := stream.Write(header); err != nil {
		stream.Close()
		return nil, fmt.Errorf("address write failed: %w", err)
	}

	ack := make([]byte, 1)
	stream.SetReadDeadline(time.Now().Add(15 * time.Second))
	if _, err := io.ReadFull(stream, ack); err != nil {
		stream.Close()
		return nil, fmt.Errorf("ack read failed: %w", err)
	}
	stream.SetReadDeadline(time.Time{})

	if ack[0] != 0x00 {
		stream.Close()
		return nil, fmt.Errorf("connect rejected: status=%d", ack[0])
	}

	return &masque_conn{masque_rw: stream}, nil
}
