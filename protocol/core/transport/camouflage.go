// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type CamouflageConfig struct {
	Enabled    bool   `json:"enabled"`
	WebRoot    string `json:"web_root"`
	CertFile   string `json:"cert_file"`
	KeyFile    string `json:"key_file"`
	SecretPath string `json:"secret_path"`
	IndexFile  string `json:"index_file"`
	TargetURL  string `json:"target"`
}

func DefaultCamouflageConfig() CamouflageConfig {
	return CamouflageConfig{
		Enabled:    false,
		WebRoot:    "/var/www/html",
		SecretPath: "/api/v2/sync",
		IndexFile:  "index.html",
	}
}

type CamouflageServer struct {
	config       CamouflageConfig
	auth         *AuthManager
	firewall     *Firewall
	replayFilter *ReplayFilter
	tlsConfig    *tls.Config
	fileServer   http.Handler
	targetURL    *url.URL
	httpClient   *http.Client

	mu         sync.RWMutex
	vpnHandler func(conn net.Conn, session *AuthSession)
	listener   net.Listener
}

func NewCamouflageServer(config CamouflageConfig, auth *AuthManager, fw *Firewall, rf *ReplayFilter) (*CamouflageServer, error) {
	cs := &CamouflageServer{
		config:       config,
		auth:         auth,
		firewall:     fw,
		replayFilter: rf,
	}

	if config.TargetURL != "" {
		parsed, err := url.Parse(config.TargetURL)
		if err != nil {
			return nil, fmt.Errorf("invalid target URL: %w", err)
		}
		if parsed.Scheme == "" {
			parsed.Scheme = "https"
		}
		cs.targetURL = parsed
		cs.httpClient = &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
				MaxIdleConns:      50,
				IdleConnTimeout:   90 * time.Second,
				DisableKeepAlives: false,
				MaxConnsPerHost:   20,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		log.Printf("[Camouflage] Target mode: proxying to %s", config.TargetURL)
	} else if config.WebRoot != "" {
		if _, err := os.Stat(config.WebRoot); err == nil {
			cs.fileServer = http.FileServer(http.Dir(config.WebRoot))
		} else {
			cs.fileServer = http.HandlerFunc(defaultWebHandler)
		}
	} else {
		cs.fileServer = http.HandlerFunc(defaultWebHandler)
	}

	if config.CertFile != "" && config.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS cert: %w", err)
		}
		cs.tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"http/1.1", "h2"},
		}
	} else {
		sni := "cloudflare-dns.com"
		if cs.targetURL != nil {
			sni = cs.targetURL.Hostname()
		}
		cert, err := generateSelfSignedCert(sni)
		if err != nil {
			return nil, fmt.Errorf("failed to generate self-signed cert: %w", err)
		}
		cs.tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"http/1.1", "h2"},
		}
		log.Printf("[Camouflage] Generated self-signed cert for %s", sni)
	}

	return cs, nil
}

func (cs *CamouflageServer) SetVPNHandler(handler func(conn net.Conn, session *AuthSession)) {
	cs.mu.Lock()
	cs.vpnHandler = handler
	cs.mu.Unlock()
}

func (cs *CamouflageServer) Start(addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen failed: %w", err)
	}

	if cs.tlsConfig != nil {
		log.Printf("[Camouflage] TLS server listening on %s (real cert)", addr)
	} else {
		log.Printf("[Camouflage] Plain TCP server listening on %s (self-signed)", addr)
	}

	cs.listener = listener

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go cs.handleConnectionWrapped(conn)
	}
}

func (cs *CamouflageServer) handleConnectionWrapped(conn net.Conn) {
	if cs.replayFilter != nil {
		pConn, err := NewPeekingConn(conn, 64)
		if err != nil {
			conn.Close()
			return
		}

		peekData := pConn.Peek()
		if len(peekData) > 11+32 && peekData[0] == 0x16 {
			randomBytes := peekData[11 : 11+32]
			if cs.replayFilter.CheckAndAdd(randomBytes) {
				pConn.Close()
				return
			}
		}
		conn = pConn
	}

	if cs.tlsConfig != nil {
		conn = tls.Server(conn, cs.tlsConfig)
	}

	cs.handleConnection(conn)
}

func (cs *CamouflageServer) handleConnection(conn net.Conn) {
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		conn.Close()
		return
	}

	data := buf[:n]

	if isHTTPRequest(data) {
		cs.handleHTTPRequest(conn, data)
		return
	}

	if len(data) >= 56 {
		session, err := cs.auth.ValidateAuth(data[:56], conn.RemoteAddr())
		if err == nil {
			conn.SetDeadline(time.Time{})

			cs.mu.RLock()
			handler := cs.vpnHandler
			cs.mu.RUnlock()

			if handler != nil {
				remainder := data[56:]
				if len(remainder) > 0 {
					conn = &prefixConn{Conn: conn, prefix: remainder}
				}
				handler(conn, session)
				return
			}
		}
	}

	cs.sendFakeResponse(conn)
	conn.Close()
}

func (cs *CamouflageServer) handleHTTPRequest(conn net.Conn, initialData []byte) {
	request := string(initialData)
	lines := strings.Split(request, "\r\n")

	if len(lines) == 0 {
		cs.sendFakeResponse(conn)
		conn.Close()
		return
	}

	parts := strings.Fields(lines[0])
	if len(parts) < 2 {
		cs.sendFakeResponse(conn)
		conn.Close()
		return
	}

	method := parts[0]
	path := parts[1]

	authHeader := ""
	for _, line := range lines[1:] {
		if strings.HasPrefix(strings.ToLower(line), "authorization:") {
			authHeader = strings.TrimSpace(line[len("authorization:"):])
			break
		}
	}

	if path != cs.config.SecretPath && strings.Contains(path, "sync") {
		log.Printf("[Camouflage] Mismatch! Expected: '%s' (%x), Got: '%s' (%x)", cs.config.SecretPath, cs.config.SecretPath, path, path)
	}

	if path == cs.config.SecretPath && authHeader != "" {
		authToken := strings.TrimPrefix(authHeader, "Bearer ")
		authData, decErr := base64.StdEncoding.DecodeString(authToken)
		if decErr != nil {
			log.Printf("[Camouflage] Auth decode error: %v", decErr)
			authData = []byte(authToken)
		}

		if len(authData) >= 56 {
			session, err := cs.auth.ValidateAuth(authData[:56], conn.RemoteAddr())
			if err == nil {
				response := "HTTP/1.1 200 OK\r\n" +
					"Content-Type: application/octet-stream\r\n" +
					"Transfer-Encoding: chunked\r\n" +
					"Connection: keep-alive\r\n" +
					"Cache-Control: no-store\r\n" +
					"\r\n"
				conn.Write([]byte(response))
				conn.SetDeadline(time.Time{})

				cs.mu.RLock()
				handler := cs.vpnHandler
				cs.mu.RUnlock()

				if handler != nil {
					handler(conn, session)
					return
				}
			} else {
				log.Printf("[Camouflage] Auth validation failed: %v", err)
			}
		} else {
			log.Printf("[Camouflage] Auth data short: %d", len(authData))
		}
	} else if path == cs.config.SecretPath {
		log.Printf("[Camouflage] Secret path matches but no auth header")
	}

	_ = method
	cs.serveWebContent(conn, path)
}

func (cs *CamouflageServer) serveWebContent(conn net.Conn, path string) {
	if cs.targetURL != nil {
		cs.proxyToTarget(conn, "GET", path, nil)
		return
	}

	if path == "/" || path == "" {
		path = "/" + cs.config.IndexFile
	}

	filePath := filepath.Join(cs.config.WebRoot, filepath.Clean(path))
	if !strings.HasPrefix(filePath, cs.config.WebRoot) {
		cs.send404(conn)
		conn.Close()
		return
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		cs.send404(conn)
		conn.Close()
		return
	}

	contentType := "text/html; charset=utf-8"
	ext := filepath.Ext(filePath)
	switch ext {
	case ".css":
		contentType = "text/css"
	case ".js":
		contentType = "application/javascript"
	case ".json":
		contentType = "application/json"
	case ".png":
		contentType = "image/png"
	case ".jpg", ".jpeg":
		contentType = "image/jpeg"
	case ".svg":
		contentType = "image/svg+xml"
	case ".ico":
		contentType = "image/x-icon"
	case ".woff2":
		contentType = "font/woff2"
	case ".woff":
		contentType = "font/woff"
	}

	response := fmt.Sprintf("HTTP/1.1 200 OK\r\n"+
		"Content-Type: %s\r\n"+
		"Content-Length: %d\r\n"+
		"Server: nginx/1.24.0\r\n"+
		"Date: %s\r\n"+
		"Connection: keep-alive\r\n"+
		"\r\n", contentType, len(data), time.Now().UTC().Format(http.TimeFormat))

	conn.Write([]byte(response))
	conn.Write(data)
	conn.Close()
}

func (cs *CamouflageServer) proxyToTarget(conn net.Conn, method string, path string, headers map[string]string) {
	defer conn.Close()

	targetURL := *cs.targetURL
	targetURL.Path = path

	req, err := http.NewRequest(method, targetURL.String(), nil)
	if err != nil {
		cs.sendFakeResponse(conn)
		return
	}

	req.Host = cs.targetURL.Host
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Connection", "keep-alive")

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := cs.httpClient.Do(req)
	if err != nil {
		log.Printf("[Camouflage] Target proxy error: %v", err)
		cs.sendFakeResponse(conn)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		cs.sendFakeResponse(conn)
		return
	}

	var headerBuf strings.Builder
	headerBuf.WriteString(fmt.Sprintf("HTTP/1.1 %d %s\r\n", resp.StatusCode, resp.Status))

	skipHeaders := map[string]bool{
		"Transfer-Encoding": true,
		"Content-Length":    true,
		"Connection":        true,
		"Alt-Svc":           true,
	}

	for key, vals := range resp.Header {
		if skipHeaders[key] {
			continue
		}
		for _, v := range vals {
			headerBuf.WriteString(fmt.Sprintf("%s: %s\r\n", key, v))
		}
	}

	headerBuf.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
	headerBuf.WriteString("Connection: close\r\n")
	headerBuf.WriteString("\r\n")

	conn.Write([]byte(headerBuf.String()))
	conn.Write(body)
}

func (cs *CamouflageServer) send404(conn net.Conn) {
	body := `<!DOCTYPE html>
<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx/1.24.0</center>
</body>
</html>`

	response := fmt.Sprintf("HTTP/1.1 404 Not Found\r\n"+
		"Content-Type: text/html\r\n"+
		"Content-Length: %d\r\n"+
		"Server: nginx/1.24.0\r\n"+
		"Date: %s\r\n"+
		"Connection: close\r\n"+
		"\r\n%s", len(body), time.Now().UTC().Format(http.TimeFormat), body)

	conn.Write([]byte(response))
}

func (cs *CamouflageServer) sendFakeResponse(conn net.Conn) {
	if cs.targetURL != nil {
		cs.proxyToTarget(conn, "GET", "/", nil)
		return
	}

	body := `<!DOCTYPE html>
<html>
<head><title>400 Bad Request</title></head>
<body>
<center><h1>400 Bad Request</h1></center>
<hr><center>nginx/1.24.0</center>
</body>
</html>`

	response := fmt.Sprintf("HTTP/1.1 400 Bad Request\r\n"+
		"Content-Type: text/html\r\n"+
		"Content-Length: %d\r\n"+
		"Server: nginx/1.24.0\r\n"+
		"Date: %s\r\n"+
		"Connection: close\r\n"+
		"\r\n%s", len(body), time.Now().UTC().Format(http.TimeFormat), body)

	conn.Write([]byte(response))
}

func isHTTPRequest(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	methods := []string{"GET ", "POST", "PUT ", "HEAD", "DELE", "OPTI", "PATC"}
	prefix := string(data[:4])
	for _, m := range methods {
		if prefix == m {
			return true
		}
	}
	return false
}

func defaultWebHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "nginx/1.24.0")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(200)
	w.Write([]byte(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Welcome</title>
<style>
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;background:#f5f5f5}
.c{text-align:center;padding:2em}
h1{color:#333;font-size:2em;margin-bottom:.5em}
p{color:#666;font-size:1.1em}
</style>
</head>
<body>
<div class="c">
<h1>Welcome</h1>
<p>This server is running normally.</p>
</div>
</body>
</html>`))
}

type prefixConn struct {
	net.Conn
	prefix     []byte
	prefixRead bool
	mu         sync.Mutex
}

func (pc *prefixConn) Read(b []byte) (int, error) {
	pc.mu.Lock()
	if !pc.prefixRead && len(pc.prefix) > 0 {
		n := copy(b, pc.prefix)
		if n >= len(pc.prefix) {
			pc.prefixRead = true
			pc.prefix = nil
		} else {
			pc.prefix = pc.prefix[n:]
		}
		pc.mu.Unlock()
		return n, nil
	}
	pc.mu.Unlock()

	return pc.Conn.Read(b)
}

type ConfigEndpoint struct {
	auth    *AuthManager
	configs map[string]*SubscriptionConfig
	mu      sync.RWMutex
}

func NewConfigEndpoint(auth *AuthManager) *ConfigEndpoint {
	return &ConfigEndpoint{
		auth:    auth,
		configs: make(map[string]*SubscriptionConfig),
	}
}

func (ce *ConfigEndpoint) SetConfig(userID string, config *SubscriptionConfig) {
	ce.mu.Lock()
	defer ce.mu.Unlock()
	ce.configs[userID] = config
}

func (ce *ConfigEndpoint) HandleRequest(conn net.Conn, session *AuthSession) {
	ce.mu.RLock()
	config, ok := ce.configs[session.User.ID]
	ce.mu.RUnlock()

	if !ok {
		conn.Write([]byte("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"))
		conn.Close()
		return
	}

	url, err := EncodeSubscriptionURL(config)
	if err != nil {
		conn.Write([]byte("HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n"))
		conn.Close()
		return
	}

	response := fmt.Sprintf("HTTP/1.1 200 OK\r\n"+
		"Content-Type: text/plain\r\n"+
		"Content-Length: %d\r\n"+
		"Server: nginx/1.24.0\r\n"+
		"\r\n%s", len(url), url)

	conn.Write([]byte(response))
	conn.Close()
}

func (cs *CamouflageServer) Close() error {
	if cs.listener != nil {
		return cs.listener.Close()
	}
	return nil
}

func pipe(dst io.Writer, src io.Reader) {
	buf := make([]byte, 32768)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			dst.Write(buf[:n])
		}
		if err != nil {
			return
		}
	}
}

func generateSelfSignedCert(sni string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Cloudflare Inc"},
			CommonName:   sni,
		},
		DNSNames:              []string{sni},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	keyBytes, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}
