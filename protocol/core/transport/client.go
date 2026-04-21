// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

package transport

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
)

type ClientConfig struct {
	ServerAddr   string
	PSK          string
	SNI          string
	Transport    string
	SecretPath   string
	SOCKSAddr    string
	HTTPAddr     string
	InsecureSkip bool
	PaddingCfg   PaddingConfig
	StealthCfg   StealthConfig
	Subscription *SubscriptionConfig
	Fingerprint  string // https://github.com/komarukomaru/stealthlink/issues/2
}

type Client struct {
	config    ClientConfig
	proxy     *SOCKSProxy
	httpProxy *HTTPProxy
	selector  *ServerSelector

	mu              sync.Mutex
	quicConn        *quic.Conn
	quicTransport   io.Closer
	transportCloser io.Closer
	writer          *FrameWriter
	reader          *FrameReader
	activeServer    *ServerEntry
	activePSK       string
	frameLoopActive bool
	frameInbox      chan Frame
	udpHandlers     map[uint16]chan UDPPayload
	nextUDPAssocID  uint16
	stopChan        chan struct{}
	connected       bool
}

func NewClient(config ClientConfig) *Client {
	if config.SOCKSAddr == "" {
		config.SOCKSAddr = "127.0.0.1:1080"
	}
	if config.Transport == "" {
		config.Transport = "tls"
	}
	if config.SecretPath == "" {
		config.SecretPath = "/api/v2/sync"
	}

	c := &Client{
		config:      config,
		proxy:       NewSOCKSProxy(config.SOCKSAddr),
		frameInbox:  make(chan Frame, 128),
		udpHandlers: make(map[uint16]chan UDPPayload),
		stopChan:    make(chan struct{}),
	}
	c.proxy.SetUDPOpener(c.OpenUDPAssociation)

	if config.HTTPAddr != "" {
		c.httpProxy = NewHTTPProxy(config.HTTPAddr, config.SOCKSAddr)
	}

	if config.Subscription != nil && len(config.Subscription.Servers) > 0 {
		c.selector = NewServerSelector(config.Subscription.Servers)
	} else if config.ServerAddr != "" {
		c.selector = NewServerSelector([]ServerEntry{c.defaultServerEntry()})
	}

	return c
}

func (c *Client) Start() error {
	go c.proxy.Start()

	if c.httpProxy != nil {
		go c.httpProxy.Start()
	}

	if c.config.Subscription != nil && c.config.Subscription.UpdateURL != "" {
		go c.subscriptionUpdateLoop()
	}

	err := c.connectWithRetry()
	log.Printf("[Client] Start() returned: %v", err)
	return err
}

func (c *Client) connectWithRetry() error {
	return c.connectLoop(false)
}

func (c *Client) connectPersistentWithRetry() error {
	return c.connectLoop(true)
}

func (c *Client) connectLoop(persistent bool) error {
	backoff := 500 * time.Millisecond
	maxBackoff := 30 * time.Second

	for {
		err := c.tryConnectCandidates(persistent)
		if err == nil {
			backoff = 500 * time.Millisecond
			c.runLoop()
		} else {
			log.Printf("[Client] Connection failed: %v", err)
			c.resetTransportState()
		}

		select {
		case <-c.stopChan:
			return nil
		default:
		}

		log.Printf("[Client] Reconnecting in %v...", backoff)
		time.Sleep(backoff)
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

func (c *Client) defaultServerEntry() ServerEntry {
	return ServerEntry{
		Address:     c.config.ServerAddr,
		PSK:         c.config.PSK,
		SNI:         c.config.SNI,
		Transport:   c.config.Transport,
		SecretPath:  c.config.SecretPath,
		Fingerprint: c.config.Fingerprint,
	}
}

func (c *Client) resolveAttemptGroups() []serverAttemptGroup {
	if c.selector != nil {
		groups := c.selector.RankServerGroups(c.config.Transport)
		if len(groups) > 0 {
			return groups
		}
	}

	base := c.defaultServerEntry()
	return []serverAttemptGroup{{
		Base:     base,
		Variants: buildTransportVariants(base, c.config.Transport),
	}}
}

func (c *Client) tryConnectCandidates(persistent bool) error {
	groups := c.resolveAttemptGroups()
	if len(groups) == 0 {
		return fmt.Errorf("no servers available")
	}

	var lastErr error
	for _, group := range groups {
		for _, candidate := range group.Variants {
			select {
			case <-c.stopChan:
				return nil
			default:
			}

			c.resetTransportState()

			start := time.Now()
			err := c.connectCandidate(&candidate, persistent)
			if c.selector != nil {
				c.selector.ReportDialResult(candidate, time.Since(start), err)
			}
			if err == nil {
				log.Printf("[Client] Connected to %s via %s", candidate.Address, transportLogLabel(candidate.Transport))
				return nil
			}

			lastErr = err
			log.Printf("[Client] Attempt %s via %s failed: %v", candidate.Address, transportLogLabel(candidate.Transport), err)
			if !shouldRetryOtherTransports(err) {
				break
			}
		}
	}

	if lastErr == nil {
		return fmt.Errorf("all connection attempts failed")
	}
	return lastErr
}

func (c *Client) resolveServer() *ServerEntry {
	groups := c.resolveAttemptGroups()
	if len(groups) == 0 {
		return nil
	}
	if len(groups[0].Variants) > 0 {
		return &groups[0].Variants[0]
	}
	return &groups[0].Base
}

func (c *Client) connect(server *ServerEntry) error {
	transport := server.Transport
	if transport == "" {
		transport = c.config.Transport
	}

	psk := server.PSK
	if psk == "" {
		psk = c.config.PSK
	}

	switch transport {
	case "quic":
		return c.connectQUIC(server, psk)
	default:
		return c.connectTLS(server, psk)
	}
}

func (c *Client) connectCandidate(server *ServerEntry, persistent bool) error {
	psk := server.PSK
	if psk == "" {
		psk = c.config.PSK
	}

	if persistent {
		transport := normalizeTransportPreference(server.Transport)
		if transport == "quic" {
			if err := c.connectQUIC(server, psk); err != nil {
				return err
			}
			if err := c.EnsurePersistentChannel(); err != nil {
				c.resetTransportState()
				return err
			}
			return nil
		}
		return c.connectTLSPersistent(server, psk)
	}

	return c.connect(server)
}

func (c *Client) connectTLS(server *ServerEntry, psk string) error {
	sni := server.SNI
	if sni == "" {
		sni = c.config.SNI
	}
	if sni == "" {
		host, _, _ := net.SplitHostPort(server.Address)
		sni = host
	}

	secretPath := server.SecretPath
	if secretPath == "" {
		secretPath = c.config.SecretPath
	}

	log.Printf("[Client] TLS per-connection mode to %s (SNI: %s)", server.Address, sni)

	serverAddr := server.Address
	fingerprint := server.Fingerprint
	if fingerprint == "" {
		fingerprint = c.config.Fingerprint
	}

	if err := c.probeTLSPath(server.Address, sni, fingerprint); err != nil {
		return err
	}

	c.proxy.SetDialer(func(addrType byte, addr string, port uint16) (net.Conn, error) {
		conn, err := DialVPNServer(serverAddr, sni, psk, secretPath, fingerprint, addrType, addr, port)
		if err != nil {
			log.Printf("[Client] Dial failed %s:%d: %v", addr, port, err)
		}
		return conn, err
	})

	c.mu.Lock()
	c.setActiveServerLocked(server, psk)
	c.connected = true
	c.mu.Unlock()

	return nil
}

func (c *Client) probeTLSPath(serverAddr, sni, fingerprint string) error {
	conn, err := DialTransport(serverAddr, sni, fingerprint)
	if err != nil {
		return err
	}
	return conn.Close()
}

func (c *Client) connectTLSPersistent(server *ServerEntry, psk string) error {
	sni := server.SNI
	if sni == "" {
		sni = c.config.SNI
	}
	if sni == "" {
		host, _, _ := net.SplitHostPort(server.Address)
		sni = host
	}

	secretPath := server.SecretPath
	if secretPath == "" {
		secretPath = c.config.SecretPath
	}

	log.Printf("[Client] TLS persistent mode to %s (SNI: %s)", server.Address, sni)

	fingerprint := server.Fingerprint
	if fingerprint == "" {
		fingerprint = c.config.Fingerprint
	}

	conn, err := DialTransport(server.Address, sni, fingerprint)
	if err != nil {
		return fmt.Errorf("TLS/uTLS dial failed: %w", err)
	}

	authPayload, err := GenerateAuthPayload(psk)
	if err != nil {
		conn.Close()
		return fmt.Errorf("auth generation failed: %w", err)
	}

	if secretPath != "" {
		httpReq := fmt.Sprintf("POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Authorization: Bearer %s\r\n"+
			"Content-Type: application/octet-stream\r\n"+
			"Connection: keep-alive\r\n"+
			"\r\n", secretPath, sni, base64.StdEncoding.EncodeToString(authPayload))

		if _, err := conn.Write([]byte(httpReq)); err != nil {
			conn.Close()
			return fmt.Errorf("HTTP request write failed: %w", err)
		}

		respBuf := make([]byte, 4096)
		conn.SetDeadline(time.Now().Add(15 * time.Second))
		n, err := conn.Read(respBuf)
		if err != nil {
			conn.Close()
			return fmt.Errorf("HTTP response read failed: %w", err)
		}
		resp := string(respBuf[:n])
		if len(resp) < 12 || resp[9:12] != "200" {
			conn.Close()
			return fmt.Errorf("auth failed: %s", resp[:min(50, len(resp))])
		}
		conn.SetDeadline(time.Time{})

		conn.Write([]byte{0x00})
	} else {
		combined := make([]byte, len(authPayload)+1)
		copy(combined, authPayload)
		combined[len(authPayload)] = 0x00
		conn.Write(combined)
	}

	status := make([]byte, 1)
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := io.ReadFull(conn, status); err != nil {
		conn.Close()
		return fmt.Errorf("persistent auth response failed: %w", err)
	}
	conn.SetDeadline(time.Time{})

	if status[0] != AuthStatusOK {
		conn.Close()
		return fmt.Errorf("persistent auth denied: status=%d", status[0])
	}

	c.mu.Lock()
	c.setActiveServerLocked(server, psk)
	c.transportCloser = conn
	c.writer = NewFrameWriter(conn)
	c.reader = NewFrameReader(conn)
	c.connected = true
	c.mu.Unlock()

	log.Printf("[Client] Persistent control channel established")

	// Capture variables for the closure to avoid any potential race if server pointer changes (though unlikely here)
	// 'fingerprint' is already resolved at the top of the function
	serverAddr := server.Address

	c.proxy.SetDialer(func(addrType byte, addr string, port uint16) (net.Conn, error) {
		r, err := DialVPNServer(serverAddr, sni, psk, secretPath, fingerprint, addrType, addr, port)
		if err != nil {
			log.Printf("[Client] Dial failed %s:%d: %v", addr, port, err)
		}
		return r, err
	})

	return nil
}

func (c *Client) connectQUIC(server *ServerEntry, psk string) error {
	sni := server.SNI
	if sni == "" {
		sni = c.config.SNI
	}
	if sni == "" {
		host, _, _ := net.SplitHostPort(server.Address)
		sni = host
	}

	udpAddr, err := net.ResolveUDPAddr("udp", server.Address)
	if err != nil {
		return fmt.Errorf("UDP resolve failed: %w", err)
	}
	log.Printf("[Client] Connecting QUIC to %s (resolved: %s, SNI: %s)...", server.Address, udpAddr.String(), sni)

	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return fmt.Errorf("UDP listen failed: %w", err)
	}

	udpConn.SetReadBuffer(16 * 1024 * 1024)
	udpConn.SetWriteBuffer(16 * 1024 * 1024)

	tr := &quic.Transport{Conn: udpConn}

	tlsConf := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
		MinVersion:         tls.VersionTLS13,
	}

	quicConf := &quic.Config{
		KeepAlivePeriod:                15 * time.Second,
		MaxIdleTimeout:                 120 * time.Second,
		InitialStreamReceiveWindow:     16 * 1024 * 1024,
		MaxStreamReceiveWindow:         64 * 1024 * 1024,
		InitialConnectionReceiveWindow: 32 * 1024 * 1024,
		MaxConnectionReceiveWindow:     128 * 1024 * 1024,
		MaxIncomingStreams:             4096,
		MaxIncomingUniStreams:          32,
		Allow0RTT:                      true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := tr.Dial(ctx, udpAddr, tlsConf, quicConf)
	if err != nil {
		udpConn.Close()
		return fmt.Errorf("QUIC dial failed: %w", err)
	}

	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		conn.CloseWithError(0, "")
		return fmt.Errorf("QUIC stream open failed: %w", err)
	}

	writer := NewFrameWriter(stream)
	reader := NewFrameReader(stream)

	authFrame, err := EncodeAuthFrame(psk)
	if err != nil {
		stream.Close()
		conn.CloseWithError(0, "")
		return fmt.Errorf("auth frame creation failed: %w", err)
	}

	writer.WriteTypedFrame(authFrame)
	writer.Flush()

	respFrame, err := reader.ReadTypedFrame()
	if err != nil || respFrame.Type != FrameAuthResp {
		stream.Close()
		conn.CloseWithError(0, "")
		return fmt.Errorf("auth response failed")
	}

	if len(respFrame.Payload) < 1 || respFrame.Payload[0] != AuthStatusOK {
		stream.Close()
		conn.CloseWithError(0, "")
		return fmt.Errorf("auth denied")
	}

	stream.Close()

	log.Printf("[Client] QUIC authenticated successfully")

	c.mu.Lock()
	c.setActiveServerLocked(server, psk)
	c.quicConn = conn
	c.quicTransport = tr
	c.connected = true
	c.mu.Unlock()

	c.proxy.SetQUIC(conn)

	return nil
}

func (c *Client) EnsurePersistentChannel() error {
	c.mu.Lock()
	if c.writer != nil && c.reader != nil {
		c.mu.Unlock()
		return nil
	}
	conn := c.quicConn
	server := c.activeServer
	psk := c.activePSK
	c.mu.Unlock()

	if conn == nil {
		if server == nil || psk == "" {
			return fmt.Errorf("persistent channel unavailable")
		}
		return c.connectTLSPersistent(server, psk)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("persistent QUIC stream open failed: %w", err)
	}

	if _, err := stream.Write([]byte{0x00}); err != nil {
		stream.Close()
		return fmt.Errorf("persistent QUIC stream init failed: %w", err)
	}

	status := make([]byte, 1)
	stream.SetReadDeadline(time.Now().Add(15 * time.Second))
	_, err = io.ReadFull(stream, status)
	stream.SetReadDeadline(time.Time{})
	if err != nil {
		stream.Close()
		return fmt.Errorf("persistent QUIC stream ack failed: %w", err)
	}
	if status[0] != AuthStatusOK {
		stream.Close()
		return fmt.Errorf("persistent QUIC stream denied: status=%d", status[0])
	}

	writer := NewFrameWriter(stream)
	reader := NewFrameReader(stream)

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.writer != nil && c.reader != nil {
		writer.Close()
		stream.Close()
		return nil
	}

	c.transportCloser = stream
	c.writer = writer
	c.reader = reader
	return nil
}

func (c *Client) runLoop() {
	<-c.stopChan
}

func (c *Client) subscriptionUpdateLoop() {
	interval := time.Duration(c.config.Subscription.UpdateInterval) * time.Second
	if interval < 60*time.Second {
		interval = 3600 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.updateSubscription()
		case <-c.stopChan:
			return
		}
	}
}

func (c *Client) updateSubscription() {
	if c.config.Subscription == nil || c.config.Subscription.UpdateURL == "" {
		return
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(c.config.Subscription.UpdateURL)
	if err != nil {
		log.Printf("[Client] Subscription update failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Printf("[Client] Subscription update: status %d", resp.StatusCode)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	newConfig, err := DecodeSubscriptionURL(string(body))
	if err != nil {
		var directConfig SubscriptionConfig
		if jsonErr := json.Unmarshal(body, &directConfig); jsonErr != nil {
			log.Printf("[Client] Subscription parse failed: %v", err)
			return
		}
		newConfig = &directConfig
	}

	if len(newConfig.Servers) > 0 {
		c.config.Subscription = newConfig
		if c.selector != nil {
			c.selector.UpdateServers(newConfig.Servers)
		} else {
			c.selector = NewServerSelector(newConfig.Servers)
		}
		log.Printf("[Client] Subscription updated: %d servers", len(newConfig.Servers))
	}
}

func (c *Client) Stop() {
	select {
	case <-c.stopChan:
		return
	default:
		close(c.stopChan)
	}

	c.resetTransportState()
	c.proxy.Stop()
}

func (c *Client) resetTransportState() {
	c.mu.Lock()
	writer := c.writer
	closer := c.transportCloser
	quicConn := c.quicConn
	quicTransport := c.quicTransport
	udpHandlers := c.udpHandlers
	frameInbox := c.frameInbox
	c.writer = nil
	c.reader = nil
	c.transportCloser = nil
	c.quicConn = nil
	c.quicTransport = nil
	c.activeServer = nil
	c.activePSK = ""
	c.frameLoopActive = false
	c.udpHandlers = make(map[uint16]chan UDPPayload)
	c.frameInbox = make(chan Frame, 128)
	c.connected = false
	c.mu.Unlock()

	if writer != nil {
		writer.Close()
	}
	if closer != nil {
		closer.Close()
	}
	if quicConn != nil {
		quicConn.CloseWithError(0, "")
	}
	if quicTransport != nil {
		quicTransport.Close()
	}
	for _, ch := range udpHandlers {
		close(ch)
	}
	if frameInbox != nil {
		close(frameInbox)
	}
}

func (c *Client) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}

func (c *Client) GetProxy() *SOCKSProxy {
	return c.proxy
}

func (c *Client) WriteIPFrame(data []byte) error {
	if err := c.EnsurePersistentChannel(); err != nil {
		c.mu.Lock()
		writer := c.writer
		c.mu.Unlock()
		if writer == nil {
			return err
		}
	}

	c.mu.Lock()
	writer := c.writer
	c.mu.Unlock()
	if writer == nil {
		return fmt.Errorf("not connected")
	}
	return writer.WriteTypedFrame(Frame{Type: FrameIP, Payload: data})
}

func (c *Client) ReadFrame() (Frame, error) {
	c.mu.Lock()
	if c.frameLoopActive {
		inbox := c.frameInbox
		c.mu.Unlock()
		frame, ok := <-inbox
		if !ok {
			return Frame{}, fmt.Errorf("not connected")
		}
		return frame, nil
	}
	reader := c.reader
	c.mu.Unlock()

	if reader == nil {
		if err := c.EnsurePersistentChannel(); err != nil {
			c.mu.Lock()
			reader = c.reader
			c.mu.Unlock()
			if reader == nil {
				return Frame{}, err
			}
		} else {
			c.mu.Lock()
			reader = c.reader
			c.mu.Unlock()
		}
	}

	if reader == nil {
		return Frame{}, fmt.Errorf("not connected")
	}
	return reader.ReadTypedFrame()
}

func (c *Client) setActiveServerLocked(server *ServerEntry, psk string) {
	if server == nil {
		c.activeServer = nil
		c.activePSK = ""
		return
	}

	serverCopy := *server
	c.activeServer = &serverCopy
	c.activePSK = psk
}

func (c *Client) dropPersistentChannel() {
	c.mu.Lock()
	writer := c.writer
	closer := c.transportCloser
	udpHandlers := c.udpHandlers
	frameInbox := c.frameInbox
	c.writer = nil
	c.reader = nil
	c.transportCloser = nil
	c.frameLoopActive = false
	c.udpHandlers = make(map[uint16]chan UDPPayload)
	c.frameInbox = make(chan Frame, 128)
	c.mu.Unlock()

	if writer != nil {
		writer.Close()
	}
	if closer != nil {
		closer.Close()
	}
	for _, ch := range udpHandlers {
		close(ch)
	}
	if frameInbox != nil {
		close(frameInbox)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func shouldRetryOtherTransports(err error) bool {
	if err == nil {
		return false
	}

	msg := strings.ToLower(err.Error())
	terminalMarkers := []string{
		"auth denied",
		"authentication denied",
		"persistent auth denied",
		"tunnel auth denied",
		"tun auth denied",
		"invalid psk",
	}
	for _, marker := range terminalMarkers {
		if strings.Contains(msg, marker) {
			return false
		}
	}
	return true
}

func transportLogLabel(transport string) string {
	switch normalizeTransportPreference(transport) {
	case "quic":
		return "quic"
	default:
		return "tls"
	}
}
