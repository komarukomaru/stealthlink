package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"strconv"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
)

type ServerConfig struct {
	BindAddress string
	SNI         string
	Transport   string
	Camouflage  CamouflageConfig
	Users       []*UserRecord
	FirewallCfg FirewallConfig
	PaddingCfg  PaddingConfig
	StealthCfg  StealthConfig
}

type Server struct {
	config       ServerConfig
	auth         *AuthManager
	firewall     *Firewall
	replayFilter *ReplayFilter

	mu       sync.RWMutex
	sessions map[string]int
}

func NewServer(config ServerConfig) *Server {
	return &Server{
		config:       config,
		auth:         NewAuthManager(config.Users),
		firewall:     NewFirewall(config.FirewallCfg),
		replayFilter: NewReplayFilter(100000, 5*time.Minute),
		sessions:     make(map[string]int),
	}
}

func (s *Server) Start() error {
	if s.config.Transport == "" {
		s.config.Transport = "tls"
	}

	log.Printf("[Server] Starting with transport=%s on %s", s.config.Transport, s.config.BindAddress)

	switch s.config.Transport {
	case "tls":
		return s.startTLS()
	case "quic":
		go func() {
			if err := s.startTLSFallback(); err != nil {
				log.Printf("[Server] TCP fallback listener failed: %v", err)
			}
		}()
		return s.startQUIC()
	default:
		return s.startTLS()
	}
}

func (s *Server) startTLS() error {
	if s.config.Camouflage.Enabled {
		cs, err := NewCamouflageServer(s.config.Camouflage, s.auth, s.firewall, s.replayFilter)
		if err != nil {
			return err
		}
		cs.SetVPNHandler(func(conn net.Conn, session *AuthSession) {
			s.handleDirectConnection(conn, session)
		})
		return cs.Start(s.config.BindAddress)
	}

	listener, err := net.Listen("tcp", s.config.BindAddress)
	if err != nil {
		return err
	}

	tlsConfig, err := s.generateTLSConfigForTransport("tls")
	if err != nil {
		return err
	}

	log.Printf("[Server] TLS server listening on %s", s.config.BindAddress)

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go s.handleTLSConnectionWrapped(conn, tlsConfig)
	}
}

func (s *Server) handleTLSConnectionWrapped(conn net.Conn, tlsConfig *tls.Config) {
	if s.replayFilter != nil {
		pConn, err := NewPeekingConn(conn, 64)
		if err != nil {
			conn.Close()
			return
		}
		peekData := pConn.Peek()
		if len(peekData) > 43 && peekData[0] == 0x16 {
			randomBytes := peekData[11 : 11+32]
			if s.replayFilter.CheckAndAdd(randomBytes) {
				pConn.Close()
				return
			}
		}
		conn = pConn
	}

	tlsConn := tls.Server(conn, tlsConfig)
	s.handleTLSConnection(tlsConn)
}

func (s *Server) startTLSFallback() error {
	if s.config.Camouflage.Enabled {
		cs, err := NewCamouflageServer(s.config.Camouflage, s.auth, s.firewall, s.replayFilter)
		if err != nil {
			return err
		}
		cs.SetVPNHandler(func(conn net.Conn, session *AuthSession) {
			s.handleDirectConnection(conn, session)
		})
		log.Printf("[Server] TLS fallback (camouflage) listening on %s", s.config.BindAddress)
		return cs.Start(s.config.BindAddress)
	}

	tlsConfig, err := s.generateTLSConfigForTransport("tls")
	if err != nil {
		return err
	}

	listener, err := tls.Listen("tcp", s.config.BindAddress, tlsConfig)
	if err != nil {
		return err
	}

	log.Printf("[Server] TLS fallback listening on %s", s.config.BindAddress)

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go s.handleTLSConnection(conn)
	}
}

func (s *Server) handleTLSConnection(conn net.Conn) {
	defer conn.Close()
	TuneTCPConn(conn)

	conn.SetDeadline(time.Now().Add(30 * time.Second))

	authBuf := make([]byte, 56)
	if _, err := io.ReadFull(conn, authBuf); err != nil {
		return
	}

	session, err := s.auth.ValidateAuth(authBuf, conn.RemoteAddr())
	if err != nil {
		log.Printf("[Server] Auth failed from %s: %v", conn.RemoteAddr(), err)
		conn.Write([]byte{0x01})
		return
	}

	conn.SetDeadline(time.Time{})
	s.handleSmartConnection(conn, session)
}

func (s *Server) handleSmartConnection(conn net.Conn, session *AuthSession) {
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	modeBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, modeBuf); err != nil {
		return
	}

	conn.SetDeadline(time.Time{})

	switch modeBuf[0] {
	case 0x00:
		conn.Write([]byte{AuthStatusOK})
		log.Printf("[Server] TUN session from user %s", session.User.ID)
		s.handleTUNSession(conn, session)
	case AddrIPv4, AddrDomain, AddrIPv6:
		s.handleDirectConnectionWithType(conn, session, modeBuf[0])
	default:
		conn.Write([]byte{0x01})
	}
}

func (s *Server) handleTUNSession(conn net.Conn, session *AuthSession) {
	reader := NewFrameReader(conn)
	writer := NewFrameWriter(conn)

	s.firewall.OnConnect(session.User.ID)
	defer s.firewall.OnDisconnect(session.User.ID)

	for {
		frame, err := reader.ReadTypedFrame()
		if err != nil {
			return
		}

		switch frame.Type {
		case FrameIP:
			s.firewall.TrackBandwidth(session.User.ID, int64(len(frame.Payload)))
		case FrameConnect:
			go s.handleFrameConnect(writer, frame, session)
		case FrameClose:
		case FramePadding:
		}
	}
}

func (s *Server) handleFrameConnect(writer *FrameWriter, frame Frame, session *AuthSession) {
	if len(frame.Payload) < 4 {
		return
	}

	streamID := binary.BigEndian.Uint16(frame.Payload[:2])
	addrType := frame.Payload[2]
	remaining := frame.Payload[3:]

	var addr string
	var port uint16

	switch addrType {
	case AddrIPv4:
		if len(remaining) < 6 {
			return
		}
		addr = net.IP(remaining[:4]).String()
		port = binary.BigEndian.Uint16(remaining[4:6])
	case AddrDomain:
		if len(remaining) < 1 {
			return
		}
		dLen := int(remaining[0])
		if len(remaining) < 1+dLen+2 {
			return
		}
		addr = string(remaining[1 : 1+dLen])
		port = binary.BigEndian.Uint16(remaining[1+dLen : 3+dLen])
	case AddrIPv6:
		if len(remaining) < 18 {
			return
		}
		addr = net.IP(remaining[:16]).String()
		port = binary.BigEndian.Uint16(remaining[16:18])
	default:
		return
	}

	if !s.firewall.CheckConnection(session.User.ID, addr, port, session.User) {
		ackPayload := make([]byte, 3)
		binary.BigEndian.PutUint16(ackPayload[:2], streamID)
		ackPayload[2] = 0x01
		writer.WriteTypedFrame(Frame{Type: FrameConnAck, Payload: ackPayload})
		writer.Flush()
		return
	}

	target := net.JoinHostPort(addr, strconv.Itoa(int(port)))
	targetConn, err := net.DialTimeout("tcp4", target, 10*time.Second)
	if err != nil {
		ackPayload := make([]byte, 3)
		binary.BigEndian.PutUint16(ackPayload[:2], streamID)
		ackPayload[2] = 0x02
		writer.WriteTypedFrame(Frame{Type: FrameConnAck, Payload: ackPayload})
		writer.Flush()
		return
	}
	TuneTCPConn(targetConn)

	ackPayload := make([]byte, 3)
	binary.BigEndian.PutUint16(ackPayload[:2], streamID)
	ackPayload[2] = 0x00
	writer.WriteTypedFrame(Frame{Type: FrameConnAck, Payload: ackPayload})
	writer.Flush()

	go func() {
		defer targetConn.Close()
		buf := make([]byte, 65535)
		for {
			n, err := targetConn.Read(buf)
			if n > 0 {
				dataFrame := EncodeDataFrame(streamID, buf[:n])
				writer.WriteTypedFrame(dataFrame)
				writer.Flush()
			}
			if err != nil {
				closePayload := make([]byte, 2)
				binary.BigEndian.PutUint16(closePayload, streamID)
				writer.WriteTypedFrame(Frame{Type: FrameClose, Payload: closePayload})
				writer.Flush()
				return
			}
		}
	}()
}

func (s *Server) handleDirectConnection(conn net.Conn, session *AuthSession) {
	s.handleSmartConnection(conn, session)
}

func (s *Server) handleDirectConnectionWithType(conn net.Conn, session *AuthSession, addrType byte) {
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	var addr string
	var port uint16
	var err error

	switch addrType {
	case AddrIPv4:
		buf := make([]byte, 6)
		if _, err = io.ReadFull(conn, buf); err != nil {
			return
		}
		addr = net.IP(buf[:4]).String()
		port = binary.BigEndian.Uint16(buf[4:6])
	case AddrIPv6:
		buf := make([]byte, 18)
		if _, err = io.ReadFull(conn, buf); err != nil {
			return
		}
		addr = net.IP(buf[:16]).String()
		port = binary.BigEndian.Uint16(buf[16:18])
	case AddrDomain:
		lenBuf := make([]byte, 1)
		if _, err = io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		domainBuf := make([]byte, int(lenBuf[0])+2)
		if _, err = io.ReadFull(conn, domainBuf); err != nil {
			return
		}
		addr = string(domainBuf[:lenBuf[0]])
		port = binary.BigEndian.Uint16(domainBuf[lenBuf[0]:])
	default:
		conn.Write([]byte{0x01})
		return
	}

	conn.SetDeadline(time.Time{})

	if !s.firewall.CheckConnection(session.User.ID, addr, port, session.User) {
		conn.Write([]byte{0x03})
		return
	}

	s.firewall.OnConnect(session.User.ID)
	defer s.firewall.OnDisconnect(session.User.ID)

	s.mu.Lock()
	s.sessions[session.User.ID]++
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.sessions[session.User.ID]--
		if s.sessions[session.User.ID] <= 0 {
			delete(s.sessions, session.User.ID)
		}
		s.mu.Unlock()
	}()

	var targetConn net.Conn
	if session.User.Upstream != nil {
		targetConn, err = DialUpstream(session.User.Upstream, addrType, addr, port)
	} else {
		targetConn, err = DialTarget(addr, port, 10*time.Second)
	}
	if err != nil {
		log.Printf("[Server] Connect failed %s:%d for user %s: %v", addr, port, session.User.ID, err)
		conn.Write([]byte{0x02})
		return
	}
	defer targetConn.Close()

	conn.Write([]byte{0x00})

	BidirectionalRelay(conn, targetConn)
}

func (s *Server) startQUIC() error {
	tlsConfig, err := s.generateTLSConfigForTransport("quic")
	if err != nil {
		return err
	}

	udpAddr, err := net.ResolveUDPAddr("udp", s.config.BindAddress)
	if err != nil {
		return err
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}

	udpConn.SetReadBuffer(7 * 1024 * 1024)
	udpConn.SetWriteBuffer(7 * 1024 * 1024)

	var packetConn net.PacketConn = udpConn
	if s.replayFilter != nil {
		packetConn = &ReplayProtectedPacketConn{PacketConn: udpConn, filter: s.replayFilter}
	}

	tr := &quic.Transport{Conn: packetConn}

	quicConf := &quic.Config{
		KeepAlivePeriod:                15 * time.Second,
		MaxIdleTimeout:                 120 * time.Second,
		DisablePathMTUDiscovery:        false,
		InitialStreamReceiveWindow:     16 * 1024 * 1024,
		MaxStreamReceiveWindow:         64 * 1024 * 1024,
		InitialConnectionReceiveWindow: 32 * 1024 * 1024,
		MaxConnectionReceiveWindow:     128 * 1024 * 1024,
		Allow0RTT:                      true,
	}

	listener, err := tr.Listen(tlsConfig, quicConf)
	if err != nil {
		udpConn.Close()
		return err
	}

	log.Printf("[Server] QUIC server listening on %s", s.config.BindAddress)

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			log.Printf("[Server] QUIC accept error: %v", err)
			continue
		}
		log.Printf("[Server] QUIC connection from %s", conn.RemoteAddr())
		go s.handleQUICConnection(conn)
	}
}

func (s *Server) handleQUICConnection(conn *quic.Conn) {
	authStream, err := conn.AcceptStream(context.Background())
	if err != nil {
		return
	}

	reader := NewFrameReader(authStream)
	frame, err := reader.ReadTypedFrame()
	if err != nil || frame.Type != FrameAuth {
		authStream.Close()
		return
	}

	session, err := s.auth.ValidateAuth(frame.Payload, conn.RemoteAddr())
	if err != nil {
		log.Printf("[Server] QUIC auth failed from %s: %v", conn.RemoteAddr(), err)
		writer := NewFrameWriter(authStream)
		writer.WriteTypedFrame(EncodeAuthResponse(AuthStatusDenied, nil))
		writer.Flush()
		authStream.Close()
		return
	}

	writer := NewFrameWriter(authStream)
	writer.WriteTypedFrame(EncodeAuthResponse(AuthStatusOK, nil))
	writer.Flush()
	authStream.Close()

	log.Printf("[Server] QUIC client authenticated: user=%s from=%s", session.User.ID, session.RemoteIP)

	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			log.Printf("[Server] QUIC client disconnected: user=%s", session.User.ID)
			return
		}
		go s.handleQUICStream(stream, session)
	}
}

func (s *Server) handleQUICStream(stream *quic.Stream, session *AuthSession) {
	defer stream.Close()

	_, addr, port, err := ReadAddressHeader(stream)
	if err != nil {
		stream.Write([]byte{0x01})
		return
	}

	if !s.firewall.CheckConnection(session.User.ID, addr, port, session.User) {
		stream.Write([]byte{0x01})
		return
	}

	s.firewall.OnConnect(session.User.ID)
	defer s.firewall.OnDisconnect(session.User.ID)

	target := net.JoinHostPort(addr, strconv.Itoa(int(port)))
	tcpConn, err := net.DialTimeout("tcp4", target, 10*time.Second)
	if err != nil {
		stream.Write([]byte{0x02})
		return
	}
	defer tcpConn.Close()
	TuneTCPConn(tcpConn)

	stream.Write([]byte{0x00})

	done := make(chan struct{})

	go func() {
		buf := make([]byte, relayBufSize)
		io.CopyBuffer(stream, tcpConn, buf)
		stream.CancelRead(0)
		close(done)
	}()

	buf := make([]byte, relayBufSize)
	io.CopyBuffer(tcpConn, stream, buf)
	tcpConn.Close()
	<-done
}

func (s *Server) generateTLSConfigForTransport(transport string) (*tls.Config, error) {
	if s.config.Camouflage.CertFile != "" && s.config.Camouflage.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(s.config.Camouflage.CertFile, s.config.Camouflage.KeyFile)
		if err != nil {
			return nil, err
		}
		alpn := []string{"http/1.1", "h2"}
		if transport == "quic" {
			alpn = []string{"h3"}
		}
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   alpn,
			MinVersion:   tls.VersionTLS13,
		}, nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	sni := s.config.SNI
	if sni == "" {
		sni = "cloudflare-dns.com"
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Cloudflare Inc"},
			CommonName:   sni,
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	keyBytes, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	alpn := []string{"http/1.1"}
	if transport == "quic" {
		alpn = []string{"h3"}
	}

	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   alpn,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

func (s *Server) GetAuth() *AuthManager {
	return s.auth
}

func (s *Server) ActiveSessions() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}
