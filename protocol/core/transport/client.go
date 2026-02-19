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

	mu        sync.Mutex
	quicConn  *quic.Conn
	writer    *FrameWriter
	reader    *FrameReader
	stopChan  chan struct{}
	connected bool
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
		config:   config,
		proxy:    NewSOCKSProxy(config.SOCKSAddr),
		stopChan: make(chan struct{}),
	}

	if config.HTTPAddr != "" {
		c.httpProxy = NewHTTPProxy(config.HTTPAddr, config.SOCKSAddr)
	}

	if config.Subscription != nil && len(config.Subscription.Servers) > 0 {
		c.selector = NewServerSelector(config.Subscription.Servers)
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
	backoff := 500 * time.Millisecond
	maxBackoff := 30 * time.Second

	for {
		server := c.resolveServer()

		err := c.connect(server)
		if err == nil {
			backoff = 500 * time.Millisecond
			c.runLoop()
		} else {
			log.Printf("[Client] Connection failed: %v", err)
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

func (c *Client) resolveServer() *ServerEntry {
	if c.selector != nil {
		best := c.selector.SelectBestServer(5 * time.Second)
		if best != nil {
			return best
		}
	}

	return &ServerEntry{
		Address:     c.config.ServerAddr,
		PSK:         c.config.PSK,
		SNI:         c.config.SNI,
		Transport:   c.config.Transport,
		SecretPath:  c.config.SecretPath,
		Fingerprint: c.config.Fingerprint,
	}
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

	c.proxy.SetDialer(func(addrType byte, addr string, port uint16) (net.Conn, error) {
		conn, err := DialVPNServer(serverAddr, sni, psk, secretPath, fingerprint, addrType, addr, port)
		if err != nil {
			log.Printf("[Client] Dial failed %s:%d: %v", addr, port, err)
		}
		return conn, err
	})

	c.mu.Lock()
	c.connected = true
	c.mu.Unlock()

	return nil
}

func (c *Client) connectTLSForTUN(server *ServerEntry, psk string) error {
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

	log.Printf("[Client] TLS TUN persistent mode to %s (SNI: %s)", server.Address, sni)

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
		return fmt.Errorf("TUN auth response failed: %w", err)
	}
	conn.SetDeadline(time.Time{})

	if status[0] != AuthStatusOK {
		conn.Close()
		return fmt.Errorf("TUN auth denied: status=%d", status[0])
	}

	c.mu.Lock()
	c.writer = NewFrameWriter(conn)
	c.reader = NewFrameReader(conn)
	c.connected = true
	c.mu.Unlock()

	log.Printf("[Client] TUN persistent connection established")

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

	host, port, _ := net.SplitHostPort(server.Address)

	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("DNS lookup failed for %s: %w", host, err)
	}

	var ip net.IP
	for _, candidate := range ips {
		if candidate.To4() != nil {
			ip = candidate
			break
		}
	}
	if ip == nil && len(ips) > 0 {
		ip = ips[0]
	}
	if ip == nil {
		return fmt.Errorf("no IP addresses found for %s", host)
	}

	addr := net.JoinHostPort(ip.String(), port)
	log.Printf("[Client] Connecting QUIC to %s (resolved: %s, SNI: %s)...", server.Address, addr, sni)

	udpAddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return fmt.Errorf("UDP resolve failed: %w", err)
	}

	udpConn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return fmt.Errorf("UDP listen failed: %w", err)
	}

	udpConn.SetReadBuffer(7 * 1024 * 1024)
	udpConn.SetWriteBuffer(7 * 1024 * 1024)

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
	c.quicConn = conn
	c.connected = true
	c.mu.Unlock()

	c.proxy.SetQUIC(conn)

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

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.writer != nil {
		c.writer.Close()
	}
	if c.quicConn != nil {
		c.quicConn.CloseWithError(0, "")
	}

	c.proxy.Stop()
	c.connected = false
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
	reader := c.reader
	c.mu.Unlock()
	if reader == nil {
		return Frame{}, fmt.Errorf("not connected")
	}
	return reader.ReadTypedFrame()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
