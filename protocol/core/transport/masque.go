// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

package transport

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type MasqueConfig struct {
	Enabled bool   `json:"enabled"`
	Path    string `json:"path"`
}

const (
	masque_default_path   = "/.well-known/masque/udp/"
	masque_proto          = "connect-udp"
	masque_handshake_wait = 10 * time.Second
	masque_dial_deadline  = 15 * time.Second
)

func masque_normalize_path(p string) string {
	if p == "" {
		return masque_default_path
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

type masque_rw interface {
	io.Reader
	io.Writer
	io.Closer
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

type masque_conn struct {
	masque_rw
}

type masque_addr struct{}

func (masque_addr) Network() string { return "masque" }
func (masque_addr) String() string  { return "h3" }

func (masque_conn) LocalAddr() net.Addr  { return masque_addr{} }
func (masque_conn) RemoteAddr() net.Addr { return masque_addr{} }

func masque_new_client_conn(server_addr, sni string, insecure bool) (*http3.ClientConn, *quic.Conn, *quic.Transport, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", server_addr)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("udp resolve failed: %w", err)
	}
	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("udp listen failed: %w", err)
	}
	udpConn.SetReadBuffer(16 * 1024 * 1024)
	udpConn.SetWriteBuffer(16 * 1024 * 1024)

	tr := &quic.Transport{Conn: udpConn}
	tlsConf := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: insecure,
		NextProtos:         []string{"h3"},
		MinVersion:         tls.VersionTLS13,
	}
	quicConf := &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: 15 * time.Second,
		MaxIdleTimeout:  120 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), masque_handshake_wait)
	defer cancel()

	qconn, err := tr.Dial(ctx, udpAddr, tlsConf, quicConf)
	if err != nil {
		tr.Close()
		udpConn.Close()
		return nil, nil, nil, fmt.Errorf("quic dial failed: %w", err)
	}

	h3tr := &http3.Transport{EnableDatagrams: true}
	cc := h3tr.NewClientConn(qconn)

	select {
	case <-cc.ReceivedSettings():
	case <-time.After(masque_handshake_wait):
		qconn.CloseWithError(0, "")
		tr.Close()
		return nil, nil, nil, fmt.Errorf("h3 settings timeout")
	}
	if !cc.Settings().EnableExtendedConnect {
		qconn.CloseWithError(0, "")
		tr.Close()
		return nil, nil, nil, fmt.Errorf("server did not enable extended connect")
	}

	return cc, qconn, tr, nil
}

func masque_connect_request(ctx context.Context, sni, path, auth_b64 string) *http.Request {
	req := (&http.Request{
		Method:     http.MethodConnect,
		Proto:      masque_proto,
		ProtoMajor: 3,
		URL:        &url.URL{Scheme: "https", Host: sni, Path: masque_normalize_path(path)},
		Host:       sni,
		Header:     make(http.Header),
	}).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+auth_b64)
	req.Header.Set("Capsule-Protocol", "?1")
	return req
}

func masque_open_stream(cc *http3.ClientConn, sni, path, psk string, addr_type byte, addr string, port uint16) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), masque_dial_deadline)
	defer cancel()

	str, err := cc.OpenRequestStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("open request stream failed: %w", err)
	}

	auth, err := GenerateAuthPayload(psk)
	if err != nil {
		str.Close()
		return nil, fmt.Errorf("auth generation failed: %w", err)
	}

	req := masque_connect_request(ctx, sni, path, base64.StdEncoding.EncodeToString(auth))
	if err := str.SendRequestHeader(req); err != nil {
		str.Close()
		return nil, fmt.Errorf("send connect failed: %w", err)
	}

	resp, err := str.ReadResponse()
	if err != nil {
		str.Close()
		return nil, fmt.Errorf("read connect response failed: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		str.Close()
		return nil, fmt.Errorf("connect rejected: status %d", resp.StatusCode)
	}

	conn := &masque_conn{masque_rw: str}

	header := EncodeAddress(addr_type, addr, port)
	if _, err := conn.Write(header); err != nil {
		conn.Close()
		return nil, fmt.Errorf("address write failed: %w", err)
	}

	status := make([]byte, 1)
	conn.SetReadDeadline(time.Now().Add(masque_dial_deadline))
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

type masque_handler struct {
	auth      *AuthManager
	onSession func(conn net.Conn, session *AuthSession)
}

func (h *masque_handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		mirage_serve_decoy(w)
		return
	}

	session, ok := masque_authenticate(h.auth, r)
	if !ok {
		mirage_serve_decoy(w)
		return
	}

	streamer, ok := w.(http3.HTTPStreamer)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	stream := streamer.HTTPStream()
	h.onSession(&masque_conn{masque_rw: stream}, session)
}

func masque_authenticate(auth *AuthManager, r *http.Request) (*AuthSession, bool) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" {
		return nil, false
	}
	data, err := base64.StdEncoding.DecodeString(token)
	if err != nil || len(data) < 56 {
		return nil, false
	}
	session, err := auth.ValidateAuth(data[:56], remoteAddrOf(r))
	if err != nil {
		return nil, false
	}
	return session, true
}
