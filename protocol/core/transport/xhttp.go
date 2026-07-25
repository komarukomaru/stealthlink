// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// XHTTP is a raw byte-stream transport carrier (Xray-compatible "xhttp"),
// independent of whatever proxy protocol (VLESS, ...) rides on top of it.
// It never sees auth data - that lives entirely inside the tunneled bytes.
type XHTTPConfig struct {
	Path  string     `json:"path"`
	Host  string     `json:"host"`
	Mode  string     `json:"mode"` // auto | packet-up | stream-up | stream-one
	Extra XHTTPExtra `json:"extra"`
}

type XHTTPExtra struct {
	NoGRPCHeader         bool   `json:"noGRPCHeader,omitempty"`
	NoSSEHeader          bool   `json:"noSSEHeader,omitempty"`
	XPaddingBytes        string `json:"xPaddingBytes,omitempty"`
	ScMaxEachPostBytes   string `json:"scMaxEachPostBytes,omitempty"`
	ScMaxConcurrentPosts string `json:"scMaxConcurrentPosts,omitempty"`
	ScMinPostsIntervalMs string `json:"scMinPostsIntervalMs,omitempty"`
	ScMaxBufferedPosts   int    `json:"scMaxBufferedPosts,omitempty"`
	KeepAlivePeriod      int    `json:"keepAlivePeriod,omitempty"`
}

const (
	xhttp_default_path  = "/xhttp"
	xhttp_chunk_size    = 16 * 1024
	xhttp_max_body      = 4 * 1024 * 1024
	xhttp_dial_deadline = 15 * time.Second
)

func xhttp_normalize_path(p string) string {
	if p == "" {
		return xhttp_default_path
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return strings.TrimRight(p, "/")
}

func xhttp_resolve_mode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "packet-up":
		return "packet-up"
	case "stream-up":
		return "stream-up"
	case "stream-one":
		return "stream-one"
	default:
		return "auto"
	}
}

// parseXHTTPRange parses Xray-style "min-max" (or a bare "n") range strings
// used throughout the XHTTP extra settings, falling back to the given
// defaults on anything malformed or empty.
func parseXHTTPRange(s string, defMin, defMax int) (int, int) {
	s = strings.TrimSpace(s)
	if s == "" {
		return defMin, defMax
	}
	parts := strings.SplitN(s, "-", 2)
	lo, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return defMin, defMax
	}
	if len(parts) == 1 {
		return lo, lo
	}
	hi, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil || hi < lo {
		return lo, lo
	}
	return lo, hi
}

func xhttp_padding_value(extra XHTTPExtra) string {
	lo, hi := parseXHTTPRange(extra.XPaddingBytes, 100, 1000)
	n := randomInt(lo, hi)
	if n <= 0 {
		return ""
	}
	return strings.Repeat("0", n)
}

// xhttp_h1_client is a plain HTTP/1.1-over-uTLS client, shared with mirage
// (packet-up and stream-up both ride on independent short-lived requests,
// so h1.1 keep-alive connection pooling is enough).
func xhttp_h1_client(host, fingerprint string, insecure bool) *http.Client {
	return mirage_http_client(host, fingerprint, insecure)
}

// xhttp_h2_client forces a real HTTP/2 connection (via uTLS ALPN "h2"),
// required for stream-one's full-duplex single request.
func xhttp_h2_client(host, fingerprint string, insecure bool) *http.Client {
	return &http.Client{
		Transport: &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				raw, err := (&net.Dialer{Timeout: xhttp_dial_deadline}).DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				uconn := utls.UClient(raw, &utls.Config{
					ServerName:         host,
					InsecureSkipVerify: insecure,
					NextProtos:         []string{"h2"},
				}, reality_hello_id(fingerprint))
				if err := uconn.HandshakeContext(ctx); err != nil {
					raw.Close()
					return nil, err
				}
				return uconn, nil
			},
		},
	}
}

type xhttp_conn struct {
	net.Conn
	body   io.Closer
	client *http.Client
	once   sync.Once
}

func (x *xhttp_conn) Close() error {
	x.once.Do(func() {
		if x.body != nil {
			x.body.Close()
		}
		x.Conn.Close()
		if x.client != nil {
			x.client.CloseIdleConnections()
		}
	})
	return nil
}

// xhttp_dial opens a new XHTTP session to target_addr and returns a raw
// byte-stream net.Conn. mode "auto" tries stream-one (real H2 full duplex)
// first and falls back to packet-up, matching Xray's own auto-negotiation
// intent.
func xhttp_dial(target_addr, host string, cfg XHTTPConfig, fingerprint string, insecure bool) (net.Conn, error) {
	mode := xhttp_resolve_mode(cfg.Mode)

	if mode == "stream-one" || mode == "auto" {
		conn, err := xhttp_dial_stream_one(target_addr, host, cfg, fingerprint, insecure)
		if err == nil {
			return conn, nil
		}
		if mode == "stream-one" {
			return nil, err
		}
		// auto: fall through to packet-up
	}

	upMode := mode
	if upMode != "stream-up" {
		upMode = "packet-up"
	}
	return xhttp_dial_multi(target_addr, host, cfg, fingerprint, insecure, upMode)
}

func xhttp_dial_multi(target_addr, host string, cfg XHTTPConfig, fingerprint string, insecure bool, mode string) (net.Conn, error) {
	session, err := random_session_id()
	if err != nil {
		return nil, err
	}
	if host == "" {
		host = hostOnly(target_addr)
	}
	base := "https://" + target_addr + xhttp_normalize_path(cfg.Path)
	client := xhttp_h1_client(host, fingerprint, insecure)

	get_req, err := http.NewRequest(http.MethodGet, base+"/"+session, nil)
	if err != nil {
		return nil, err
	}
	get_req.Host = host
	if cfg.Extra.NoSSEHeader {
		get_req.Header.Set("Accept", "*/*")
	} else {
		get_req.Header.Set("Accept", "text/event-stream")
	}
	if pad := xhttp_padding_value(cfg.Extra); pad != "" {
		get_req.Header.Set("X-Padding", pad)
	}

	get_resp, err := client.Do(get_req)
	if err != nil {
		return nil, fmt.Errorf("xhttp downlink failed: %w", err)
	}
	if get_resp.StatusCode != http.StatusOK {
		get_resp.Body.Close()
		return nil, fmt.Errorf("xhttp downlink status %d", get_resp.StatusCode)
	}

	local, pump := net.Pipe()
	xc := &xhttp_conn{Conn: local, body: get_resp.Body, client: client}

	go func() {
		io.Copy(pump, get_resp.Body)
		pump.Close()
		xc.Close()
	}()

	go func() {
		if mode == "stream-up" {
			xhttp_streamup_uplink(pump, client, base, session, host, cfg)
		} else {
			xhttp_packetup_uplink(pump, client, base, session, host, cfg)
		}
		xc.Close()
	}()

	return xc, nil
}

func xhttp_streamup_uplink(pump net.Conn, client *http.Client, base, session, host string, cfg XHTTPConfig) {
	pr, pw := io.Pipe()
	req, err := http.NewRequest(http.MethodPost, base+"/"+session, pr)
	if err != nil {
		pump.Close()
		return
	}
	req.Host = host
	req.ContentLength = -1
	req.Header.Set("Content-Type", "application/octet-stream")
	if pad := xhttp_padding_value(cfg.Extra); pad != "" {
		req.Header.Set("X-Padding", pad)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		resp, derr := client.Do(req)
		if derr != nil {
			return
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	buf := make([]byte, xhttp_chunk_size)
	for {
		n, err := pump.Read(buf)
		if n > 0 {
			if _, werr := pw.Write(buf[:n]); werr != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}
	pw.Close()
	<-done
	pump.Close()
}

func xhttp_packetup_uplink(pump net.Conn, client *http.Client, base, session, host string, cfg XHTTPConfig) {
	loMax, hiMax := parseXHTTPRange(cfg.Extra.ScMaxEachPostBytes, 1000000, 1000000)
	loConc, hiConc := parseXHTTPRange(cfg.Extra.ScMaxConcurrentPosts, 100, 200)
	loInt, hiInt := parseXHTTPRange(cfg.Extra.ScMinPostsIntervalMs, 30, 30)

	maxEach := randomInt(loMax, hiMax)
	if maxEach <= 0 || maxEach > xhttp_max_body {
		maxEach = xhttp_max_body
	}
	maxConcurrent := randomInt(loConc, hiConc)
	if maxConcurrent <= 0 {
		maxConcurrent = 1
	}
	minInterval := time.Duration(randomInt(loInt, hiInt)) * time.Millisecond

	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	var seq uint64
	var lastPost time.Time
	var mu sync.Mutex

	buf := make([]byte, maxEach)
	for {
		n, err := pump.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])

			mu.Lock()
			if wait := minInterval - time.Since(lastPost); wait > 0 {
				time.Sleep(wait)
			}
			lastPost = time.Now()
			mySeq := seq
			seq++
			mu.Unlock()

			sem <- struct{}{}
			wg.Add(1)
			go func(data []byte, sequence uint64) {
				defer wg.Done()
				defer func() { <-sem }()
				xhttp_post_chunk(client, base, session, host, sequence, data, cfg)
			}(chunk, mySeq)
		}
		if err != nil {
			break
		}
	}
	wg.Wait()
	pump.Close()
}

func xhttp_post_chunk(client *http.Client, base, session, host string, seq uint64, data []byte, cfg XHTTPConfig) {
	url := fmt.Sprintf("%s/%s/%d", base, session, seq)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return
	}
	req.Host = host
	req.Header.Set("Content-Type", "application/octet-stream")
	if pad := xhttp_padding_value(cfg.Extra); pad != "" {
		req.Header.Set("X-Padding", pad)
	}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

// xhttp_dial_stream_one opens a single full-duplex HTTP/2 PUT request:
// the request body is the uplink, the response body is the downlink. Best
// effort - more CDN/proxy-fragile than packet-up/stream-up, same caveat
// Xray's own docs carry for this mode.
func xhttp_dial_stream_one(target_addr, host string, cfg XHTTPConfig, fingerprint string, insecure bool) (net.Conn, error) {
	session, err := random_session_id()
	if err != nil {
		return nil, err
	}
	if host == "" {
		host = hostOnly(target_addr)
	}
	url := "https://" + target_addr + xhttp_normalize_path(cfg.Path) + "/" + session
	client := xhttp_h2_client(host, fingerprint, insecure)

	pr, pw := io.Pipe()
	req, err := http.NewRequest(http.MethodPut, url, pr)
	if err != nil {
		return nil, err
	}
	req.Host = host
	req.ContentLength = -1
	req.Header.Set("Content-Type", "application/octet-stream")
	if pad := xhttp_padding_value(cfg.Extra); pad != "" {
		req.Header.Set("X-Padding", pad)
	}

	respCh := make(chan *http.Response, 1)
	errCh := make(chan error, 1)
	go func() {
		resp, derr := client.Do(req)
		if derr != nil {
			errCh <- derr
			return
		}
		respCh <- resp
	}()

	select {
	case err := <-errCh:
		pw.Close()
		return nil, fmt.Errorf("xhttp stream-one failed: %w", err)
	case resp := <-respCh:
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			pw.Close()
			return nil, fmt.Errorf("xhttp stream-one status %d", resp.StatusCode)
		}
		return &xhttp_duplex_conn{writer: pw, reader: resp.Body, client: client}, nil
	case <-time.After(xhttp_dial_deadline):
		pw.Close()
		return nil, fmt.Errorf("xhttp stream-one handshake timed out")
	}
}

// xhttp_duplex_conn adapts a streamed request body (write side) and the
// matching response body (read side) of one HTTP/2 request into a net.Conn.
type xhttp_duplex_conn struct {
	writer *io.PipeWriter
	reader io.ReadCloser
	client *http.Client
	once   sync.Once
}

func (c *xhttp_duplex_conn) Read(b []byte) (int, error)  { return c.reader.Read(b) }
func (c *xhttp_duplex_conn) Write(b []byte) (int, error) { return c.writer.Write(b) }
func (c *xhttp_duplex_conn) Close() error {
	c.once.Do(func() {
		c.writer.Close()
		c.reader.Close()
		if c.client != nil {
			c.client.CloseIdleConnections()
		}
	})
	return nil
}
func (c *xhttp_duplex_conn) LocalAddr() net.Addr                { return xhttp_addr{} }
func (c *xhttp_duplex_conn) RemoteAddr() net.Addr               { return xhttp_addr{} }
func (c *xhttp_duplex_conn) SetDeadline(t time.Time) error      { return nil }
func (c *xhttp_duplex_conn) SetReadDeadline(t time.Time) error  { return nil }
func (c *xhttp_duplex_conn) SetWriteDeadline(t time.Time) error { return nil }

type xhttp_addr struct{}

func (xhttp_addr) Network() string { return "xhttp" }
func (xhttp_addr) String() string  { return "xhttp" }

// --- server side ---

type xhttp_session struct {
	pump net.Conn

	mu      sync.Mutex
	nextSeq uint64
	pending map[uint64][]byte
	closed  bool
}

func (s *xhttp_session) deliverOrdered(seq uint64, data []byte, maxBuffered int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}

	if seq != s.nextSeq {
		if maxBuffered <= 0 {
			maxBuffered = 30
		}
		if len(s.pending) < maxBuffered {
			buf := make([]byte, len(data))
			copy(buf, data)
			s.pending[seq] = buf
		}
		return
	}

	s.pump.Write(data)
	s.nextSeq++

	for {
		next, ok := s.pending[s.nextSeq]
		if !ok {
			break
		}
		delete(s.pending, s.nextSeq)
		s.pump.Write(next)
		s.nextSeq++
	}
}

type xhttp_handler struct {
	path      string
	extra     XHTTPExtra
	onSession func(conn net.Conn)

	mu       sync.Mutex
	sessions map[string]*xhttp_session
}

func new_xhttp_handler(path string, extra XHTTPExtra, onSession func(net.Conn)) *xhttp_handler {
	return &xhttp_handler{
		path:      xhttp_normalize_path(path),
		extra:     extra,
		onSession: onSession,
		sessions:  make(map[string]*xhttp_session),
	}
}

func (h *xhttp_handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, h.path+"/") {
		xhttp_serve_decoy(w)
		return
	}
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, h.path), "/")
	parts := strings.Split(rest, "/")

	switch {
	case r.Method == http.MethodGet && len(parts) == 1 && parts[0] != "":
		h.handle_downlink(w, r, parts[0])
	case r.Method == http.MethodPost && len(parts) == 2 && parts[0] != "":
		if seq, err := strconv.ParseUint(parts[1], 10, 64); err == nil {
			h.handle_uplink_packet(w, r, parts[0], seq)
			return
		}
		xhttp_serve_decoy(w)
	case r.Method == http.MethodPost && len(parts) == 1 && parts[0] != "":
		h.handle_uplink_stream(w, r, parts[0])
	case r.Method == http.MethodPut && len(parts) == 1 && parts[0] != "":
		h.handle_stream_one(w, r, parts[0])
	default:
		xhttp_serve_decoy(w)
	}
}

func (h *xhttp_handler) newSession(session string) (*xhttp_session, bool) {
	server_conn, pump := net.Pipe()
	sess := &xhttp_session{pump: pump, pending: make(map[uint64][]byte)}

	h.mu.Lock()
	if _, exists := h.sessions[session]; exists {
		h.mu.Unlock()
		server_conn.Close()
		pump.Close()
		return nil, false
	}
	h.sessions[session] = sess
	h.mu.Unlock()

	go h.onSession(server_conn)
	return sess, true
}

func (h *xhttp_handler) dropSession(session string) {
	h.mu.Lock()
	sess := h.sessions[session]
	delete(h.sessions, session)
	h.mu.Unlock()
	if sess != nil {
		sess.mu.Lock()
		sess.closed = true
		sess.mu.Unlock()
		sess.pump.Close()
	}
}

func (h *xhttp_handler) handle_downlink(w http.ResponseWriter, r *http.Request, session string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		xhttp_serve_decoy(w)
		return
	}

	sess, created := h.newSession(session)
	if !created {
		xhttp_serve_decoy(w)
		return
	}
	defer h.dropSession(session)

	go func() {
		<-r.Context().Done()
		h.dropSession(session)
	}()

	if h.extra.NoSSEHeader {
		w.Header().Set("Content-Type", "application/octet-stream")
	} else {
		w.Header().Set("Content-Type", "text/event-stream")
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	buf := make([]byte, xhttp_chunk_size)
	for {
		n, err := sess.pump.Read(buf)
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

func (h *xhttp_handler) handle_uplink_packet(w http.ResponseWriter, r *http.Request, session string, seq uint64) {
	h.mu.Lock()
	sess := h.sessions[session]
	h.mu.Unlock()
	if sess == nil {
		xhttp_serve_decoy(w)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, xhttp_max_body))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if len(body) > 0 {
		sess.deliverOrdered(seq, body, h.extra.ScMaxBufferedPosts)
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
}

func (h *xhttp_handler) handle_uplink_stream(w http.ResponseWriter, r *http.Request, session string) {
	h.mu.Lock()
	sess := h.sessions[session]
	h.mu.Unlock()
	if sess == nil {
		xhttp_serve_decoy(w)
		return
	}

	buf := make([]byte, xhttp_chunk_size)
	for {
		n, err := r.Body.Read(buf)
		if n > 0 {
			sess.pump.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
}

func (h *xhttp_handler) handle_stream_one(w http.ResponseWriter, r *http.Request, session string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		xhttp_serve_decoy(w)
		return
	}

	sess, created := h.newSession(session)
	if !created {
		xhttp_serve_decoy(w)
		return
	}
	defer h.dropSession(session)

	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, xhttp_chunk_size)
		for {
			n, err := sess.pump.Read(buf)
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
	}()

	buf := make([]byte, xhttp_chunk_size)
	for {
		n, err := r.Body.Read(buf)
		if n > 0 {
			sess.pump.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
	<-done
}

func xhttp_serve_decoy(w http.ResponseWriter) {
	w.Header().Set("Server", "nginx/1.24.0")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	io.WriteString(w, "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx/1.24.0</center>\r\n</body>\r\n</html>\r\n")
}
