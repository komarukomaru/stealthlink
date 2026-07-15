// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

package transport

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

type MirageConfig struct {
	Enabled bool   `json:"enabled"`
	Path    string `json:"path"`
}

const (
	mirage_default_path  = "/v2/media/segments"
	mirage_chunk_size    = 16 * 1024
	mirage_max_body      = 2 * 1024 * 1024
	mirage_dial_deadline = 15 * time.Second
)

func mirage_normalize_path(p string) string {
	if p == "" {
		return mirage_default_path
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return strings.TrimRight(p, "/")
}

func random_session_id() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func mirage_http_client(host, fingerprint string, insecure bool) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				raw, err := (&net.Dialer{Timeout: mirage_dial_deadline}).DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				uconn := utls.UClient(raw, &utls.Config{
					ServerName:         host,
					InsecureSkipVerify: insecure,
					NextProtos:         []string{"http/1.1"},
				}, reality_hello_id(fingerprint))
				if err := uconn.HandshakeContext(ctx); err != nil {
					raw.Close()
					return nil, err
				}
				return uconn, nil
			},
			MaxIdleConns:        32,
			MaxIdleConnsPerHost: 32,
			MaxConnsPerHost:     0,
			IdleConnTimeout:     90 * time.Second,
		},
	}
}

func mirage_dial(target_addr, host, path, fingerprint, auth_b64 string, insecure bool) (net.Conn, error) {
	session, err := random_session_id()
	if err != nil {
		return nil, err
	}

	if host == "" {
		host = hostOnly(target_addr)
	}
	base := "https://" + target_addr + mirage_normalize_path(path)
	client := mirage_http_client(host, fingerprint, insecure)

	get_req, err := http.NewRequest("GET", base+"/"+session, nil)
	if err != nil {
		return nil, err
	}
	get_req.Host = host
	get_req.Header.Set("Authorization", "Bearer "+auth_b64)
	get_req.Header.Set("Accept", "*/*")

	get_resp, err := client.Do(get_req)
	if err != nil {
		return nil, fmt.Errorf("mirage downlink failed: %w", err)
	}
	if get_resp.StatusCode != http.StatusOK {
		get_resp.Body.Close()
		return nil, fmt.Errorf("mirage downlink status %d", get_resp.StatusCode)
	}

	local, pump := net.Pipe()
	mc := &mirage_conn{Conn: local, body: get_resp.Body, client: client}

	go func() {
		io.Copy(pump, get_resp.Body)
		pump.Close()
		mc.Close()
	}()

	go func() {
		mirage_uplink_loop(pump, client, base, session, host, auth_b64)
		mc.Close()
	}()

	return mc, nil
}

type mirage_conn struct {
	net.Conn
	body   io.Closer
	client *http.Client
	once   sync.Once
}

func (m *mirage_conn) Close() error {
	m.once.Do(func() {
		m.body.Close()
		m.Conn.Close()
		if m.client != nil {
			m.client.CloseIdleConnections()
		}
	})
	return nil
}

func mirage_uplink_loop(pump net.Conn, client *http.Client, base, session, host, auth_b64 string) {
	buf := make([]byte, mirage_chunk_size)
	var seq uint64
	for {
		n, err := pump.Read(buf)
		if n > 0 {
			url := fmt.Sprintf("%s/%s/%d", base, session, seq)
			req, rerr := http.NewRequest("POST", url, strings.NewReader(string(buf[:n])))
			if rerr != nil {
				break
			}
			req.Host = host
			req.Header.Set("Authorization", "Bearer "+auth_b64)
			req.Header.Set("Content-Type", "application/octet-stream")

			resp, derr := client.Do(req)
			if derr != nil {
				break
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				break
			}
			seq++
		}
		if err != nil {
			break
		}
	}
	pump.Close()
	client.CloseIdleConnections()
}

func mirage_dial_vpn(target_addr, host, path, fingerprint, psk string, insecure bool, addr_type byte, addr string, port uint16) (net.Conn, error) {
	auth, err := GenerateAuthPayload(psk)
	if err != nil {
		return nil, fmt.Errorf("auth generation failed: %w", err)
	}
	auth_b64 := base64.StdEncoding.EncodeToString(auth)

	conn, err := mirage_dial(target_addr, host, path, fingerprint, auth_b64, insecure)
	if err != nil {
		return nil, err
	}

	header := EncodeAddress(addr_type, addr, port)
	if _, err := conn.Write(header); err != nil {
		conn.Close()
		return nil, fmt.Errorf("address write failed: %w", err)
	}

	status := make([]byte, 1)
	conn.SetReadDeadline(time.Now().Add(mirage_dial_deadline))
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

type mirage_handler struct {
	auth      *AuthManager
	path      string
	onSession func(conn net.Conn, session *AuthSession)

	mu       sync.Mutex
	sessions map[string]net.Conn
}

func new_mirage_handler(auth *AuthManager, path string, onSession func(net.Conn, *AuthSession)) *mirage_handler {
	return &mirage_handler{
		auth:      auth,
		path:      mirage_normalize_path(path),
		onSession: onSession,
		sessions:  make(map[string]net.Conn),
	}
}

func (h *mirage_handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, h.path+"/") {
		mirage_serve_decoy(w)
		return
	}
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, h.path), "/")
	parts := strings.Split(rest, "/")

	switch {
	case r.Method == http.MethodGet && len(parts) == 1 && parts[0] != "":
		h.handle_downlink(w, r, parts[0])
	case r.Method == http.MethodPost && len(parts) == 2 && parts[0] != "":
		h.handle_uplink(w, r, parts[0])
	default:
		mirage_serve_decoy(w)
	}
}

func (h *mirage_handler) authenticate(r *http.Request) (*AuthSession, bool) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" {
		return nil, false
	}
	data, err := base64.StdEncoding.DecodeString(token)
	if err != nil || len(data) < 56 {
		return nil, false
	}
	session, err := h.auth.ValidateAuth(data[:56], remoteAddrOf(r))
	if err != nil {
		return nil, false
	}
	return session, true
}

func (h *mirage_handler) handle_downlink(w http.ResponseWriter, r *http.Request, session string) {
	auth_session, ok := h.authenticate(r)
	if !ok {
		mirage_serve_decoy(w)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		mirage_serve_decoy(w)
		return
	}

	server_conn, pump := net.Pipe()

	h.mu.Lock()
	if _, exists := h.sessions[session]; exists {
		h.mu.Unlock()
		server_conn.Close()
		pump.Close()
		mirage_serve_decoy(w)
		return
	}
	h.sessions[session] = pump
	h.mu.Unlock()

	defer func() {
		h.mu.Lock()
		delete(h.sessions, session)
		h.mu.Unlock()
		pump.Close()
		server_conn.Close()
	}()

	go func() {
		<-r.Context().Done()
		pump.Close()
		server_conn.Close()
	}()

	go h.onSession(server_conn, auth_session)

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	buf := make([]byte, mirage_chunk_size)
	for {
		n, err := pump.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			flusher.Flush()
		}
		if err != nil {
			return
		}
	}
}

func (h *mirage_handler) handle_uplink(w http.ResponseWriter, r *http.Request, session string) {
	h.mu.Lock()
	pump := h.sessions[session]
	h.mu.Unlock()
	if pump == nil {
		mirage_serve_decoy(w)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, mirage_max_body))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if len(body) > 0 {
		if _, werr := pump.Write(body); werr != nil {
			w.WriteHeader(http.StatusGone)
			return
		}
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
}

func mirage_serve_decoy(w http.ResponseWriter) {
	w.Header().Set("Server", "nginx/1.24.0")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	io.WriteString(w, "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx/1.24.0</center>\r\n</body>\r\n</html>\r\n")
}

func remoteAddrOf(r *http.Request) net.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return &net.TCPAddr{IP: net.ParseIP(host)}
}
