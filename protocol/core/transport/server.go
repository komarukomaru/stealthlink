// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

package transport

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type ServerConfig struct {
	BindAddress string
	SNI         string
	Transport   string
	Camouflage  CamouflageConfig
	Reality     RealityConfig
	Mirage      MirageConfig
	Masque      MasqueConfig
	Redstone    RedstoneConfig
	WebRTC      WebRTCConfig
	Vless       VlessConfig
	Trojan      TrojanConfig
	XHTTP       XHTTPConfig
	GRPC        GRPCConfig
	Users       []*UserRecord
	FirewallCfg FirewallConfig
	PaddingCfg  PaddingConfig
	StealthCfg  StealthConfig
}

type Server struct {
	config        ServerConfig
	auth          *AuthManager
	firewall      *Firewall
	replayFilter  *ReplayFilter
	vlessClients  *vlessClientMap
	trojanClients *trojanClientMap

	mu       sync.RWMutex
	sessions map[string]int
}

func NewServer(config ServerConfig) *Server {
	return &Server{
		config:        config,
		auth:          NewAuthManager(config.Users),
		firewall:      NewFirewall(config.FirewallCfg),
		replayFilter:  NewReplayFilter(100000, 5*time.Minute),
		vlessClients:  newVlessClientMap(config.Vless),
		trojanClients: newTrojanClientMap(config.Trojan),
		sessions:      make(map[string]int),
	}
}

func (s *Server) Start() error {
	if s.config.Transport == "" {
		s.config.Transport = "tls"
	}

	log.Printf("[Server] Starting with transport=%s on %s", s.config.Transport, s.config.BindAddress)

	switch s.config.Transport {
	case "reality":
		return s.startReality()
	case "mirage":
		return s.startMirage()
	case "masque":
		return s.startMasque()
	case "redstone":
		return s.startRedstone()
	case "webrtc":
		return s.startWebRTC()
	case "vless-xhttp":
		return s.startVlessXHTTP()
	case "trojan-grpc":
		return s.startTrojanGRPC()
	case "tls":
		return s.startTLS()
	case "quic":
		return s.startQUIC()
	case "any":
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

func (s *Server) startWebRTC() error {
	tlsConfig, err := s.generateTLSConfigForTransport("tls")
	if err != nil {
		return err
	}

	listener, err := net.Listen("tcp", s.config.BindAddress)
	if err != nil {
		return err
	}

	handler := &webrtc_handler{
		auth: s.auth,
		path: webrtc_normalize_path(s.config.WebRTC.Path),
		stun: s.config.WebRTC.STUNServers,
		onSession: func(conn net.Conn, session *AuthSession) {
			s.handleDirectConnection(conn, session)
		},
	}

	srv := &http.Server{
		Handler:     handler,
		TLSConfig:   tlsConfig,
		IdleTimeout: 90 * time.Second,
	}

	log.Printf("[Server] WebRTC signaling server listening on %s (path=%s)", s.config.BindAddress, handler.path)
	return srv.Serve(tls.NewListener(listener, tlsConfig))
}

// replayGuardedListener applies the server's replay filter (TLS ClientHello
// random reuse detection) to every accepted connection before handing it to
// a generic net/http or gRPC server, mirroring the peek-then-check pattern
// handleTLSConnectionWrapped already uses for the plain TLS transport.
type replayGuardedListener struct {
	net.Listener
	filter *ReplayFilter
}

func (l *replayGuardedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}

		pConn, err := NewPeekingConn(conn, 64)
		if err != nil {
			conn.Close()
			continue
		}

		peek := pConn.Peek()
		if len(peek) > 43 && peek[0] == 0x16 {
			if l.filter.CheckAndAdd(peek[11 : 11+32]) {
				pConn.Close()
				continue
			}
		}
		return pConn, nil
	}
}

func ensureALPNH2(cfg *tls.Config) {
	for _, p := range cfg.NextProtos {
		if p == "h2" {
			return
		}
	}
	cfg.NextProtos = append(cfg.NextProtos, "h2")
}

// relayToTarget is the shared VLESS/Trojan tail: firewall check, dial the
// resolved target, relay. Both protocols write their own success/response
// framing (or none, for Trojan) before calling this - from here on it's a
// plain byte-exact bidirectional copy, same as handleDirectConnectionWithType
// uses for the StealthLink direct-connect path. user is nil (VlessClient/
// TrojanClient don't carry per-user port ACLs or upstream cascading in this
// build), so only the global firewall rules (blocked ports, private ranges,
// per-identity connection cap) apply.
func (s *Server) relayToTarget(conn net.Conn, identity string, addrType byte, addr string, port uint16) {
	defer conn.Close()

	if !s.firewall.CheckConnection(identity, addr, port, nil) {
		return
	}
	s.firewall.OnConnect(identity)
	defer s.firewall.OnDisconnect(identity)

	targetConn, err := DialTarget(addr, port, 10*time.Second)
	if err != nil {
		return
	}
	defer targetConn.Close()

	BidirectionalRelay(conn, targetConn)
}

// serveTrojanDecoy is the fallback for a connection that failed Trojan
// auth: instead of an abrupt close, it transparently relays to a
// configured decoy backend, replaying whatever bytes trojan_accept already
// consumed while attempting (and failing) to parse the header. This is the
// closest equivalent, at this layer, of classic Trojan-over-TCP falling
// through to a real website on a bad password - the outer TLS/H2 session
// here is already gRPC, so what gets proxied is the decrypted tunnel
// payload rather than raw TLS bytes, but the effect (no fingerprintable
// "wrong password -> instant RST" signature) is the same. No-op if
// Trojan.DecoyAddr isn't configured.
func (s *Server) serveTrojanDecoy(conn net.Conn, alreadyRead []byte) {
	defer conn.Close()

	decoyAddr := s.config.Trojan.DecoyAddr
	if decoyAddr == "" {
		return
	}

	decoyConn, err := net.DialTimeout("tcp", decoyAddr, 10*time.Second)
	if err != nil {
		return
	}
	defer decoyConn.Close()
	TuneTCPConn(decoyConn)

	if len(alreadyRead) > 0 {
		if _, err := decoyConn.Write(alreadyRead); err != nil {
			return
		}
	}

	BidirectionalRelay(conn, decoyConn)
}

func (s *Server) startVlessXHTTP() error {
	tlsConfig, err := s.generateTLSConfigForTransport("tls")
	if err != nil {
		return err
	}
	ensureALPNH2(tlsConfig)

	listener, err := net.Listen("tcp", s.config.BindAddress)
	if err != nil {
		return err
	}
	var lis net.Listener = listener
	if s.replayFilter != nil {
		lis = &replayGuardedListener{Listener: listener, filter: s.replayFilter}
	}

	handler := new_xhttp_handler(s.config.XHTTP.Path, s.config.XHTTP.Extra, func(conn net.Conn) {
		client, addrType, addr, port, err := vless_accept(conn, s.vlessClients)
		if err != nil {
			conn.Close()
			return
		}
		s.relayToTarget(conn, "vless:"+client.ID, addrType, addr, port)
	})

	srv := &http.Server{
		Handler:     handler,
		TLSConfig:   tlsConfig,
		IdleTimeout: 90 * time.Second,
	}

	log.Printf("[Server] VLESS/XHTTP server listening on %s (path=%s, mode=%s)", s.config.BindAddress, xhttp_normalize_path(s.config.XHTTP.Path), s.config.XHTTP.Mode)
	return srv.Serve(tls.NewListener(lis, tlsConfig))
}

func (s *Server) startTrojanGRPC() error {
	listener, err := net.Listen("tcp", s.config.BindAddress)
	if err != nil {
		return err
	}

	var tlsConfig *tls.Config
	var lis net.Listener = listener

	if grpc_security(s.config.GRPC) == "reality" {
		// REALITY does its own TLS-equivalent handshake per connection
		// (via realityServerCreds, wired inside grpc_new_server) - no
		// tlsConfig/replay-wrapped listener needed at this layer, the
		// custom credentials handle peeking, replay checking, and
		// falling through to Reality.Dest themselves.
	} else {
		tlsConfig, err = s.generateTLSConfigForTransport("tls")
		if err != nil {
			return err
		}
		ensureALPNH2(tlsConfig)
		if s.replayFilter != nil {
			lis = &replayGuardedListener{Listener: listener, filter: s.replayFilter}
		}
	}

	grpcSrv, err := grpc_new_server(tlsConfig, s.replayFilter, s.config.GRPC, func(conn net.Conn) {
		rec := newRecordingConn(conn)
		client, addrType, addr, port, err := trojan_accept(rec, s.trojanClients)
		if err != nil {
			s.serveTrojanDecoy(conn, rec.Recorded())
			return
		}
		s.relayToTarget(conn, "trojan:"+client.Email, addrType, addr, port)
	})
	if err != nil {
		return err
	}

	log.Printf("[Server] Trojan/gRPC server listening on %s (service=%s, security=%s)", s.config.BindAddress, grpc_service_name(s.config.GRPC), grpc_security(s.config.GRPC))
	return grpcSrv.Serve(lis)
}

func (s *Server) startRedstone() error {
	listener, err := net.Listen("tcp", s.config.BindAddress)
	if err != nil {
		return err
	}

	log.Printf("[Server] REDSTONE (Minecraft) server listening on %s", s.config.BindAddress)

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go redstone_serve(conn, s.config.Redstone, func(c net.Conn) {
			s.handleTLSConnection(c)
		})
	}
}

func (s *Server) startMasque() error {
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

	handler := &masque_handler{
		auth: s.auth,
		onSession: func(conn net.Conn, session *AuthSession) {
			s.handleDirectConnection(conn, session)
		},
	}

	srv := &http3.Server{
		Handler:         handler,
		TLSConfig:       tlsConfig,
		EnableDatagrams: true,
	}

	log.Printf("[Server] MASQUE (HTTP/3) server listening on %s", s.config.BindAddress)
	return srv.Serve(udpConn)
}

func (s *Server) startMirage() error {
	handler := new_mirage_handler(s.auth, s.config.Mirage.Path, func(conn net.Conn, session *AuthSession) {
		s.handleDirectConnection(conn, session)
	})

	tlsConfig, err := s.generateTLSConfigForTransport("tls")
	if err != nil {
		return err
	}

	listener, err := net.Listen("tcp", s.config.BindAddress)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Handler:      handler,
		TLSConfig:    tlsConfig,
		ReadTimeout:  0,
		WriteTimeout: 0,
		IdleTimeout:  90 * time.Second,
	}

	log.Printf("[Server] MIRAGE server listening on %s (path=%s)", s.config.BindAddress, mirage_normalize_path(s.config.Mirage.Path))
	return srv.Serve(tls.NewListener(listener, tlsConfig))
}

func (s *Server) startReality() error {
	rs, err := new_reality_server(s.config.Reality)
	if err != nil {
		return err
	}

	listener, err := net.Listen("tcp", s.config.BindAddress)
	if err != nil {
		return err
	}

	log.Printf("[Server] REALITY server listening on %s (dest=%s)", s.config.BindAddress, s.config.Reality.Dest)

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go s.handleRealityConnection(conn, rs)
	}
}

func (s *Server) handleRealityConnection(conn net.Conn, rs *reality_server) {
	// rs.accept already fully handles both outcomes: on success it hands
	// back a handshake-complete net.Conn; on failure it has already run
	// the transparent live-mirrored fallback relay to Dest and closed conn
	// itself, so there is nothing left to do here.
	tconn, err := rs.accept(context.Background(), conn)
	if err != nil {
		return
	}
	s.handleTLSConnection(tconn)
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

func (s *Server) handleTUNSession(rw io.ReadWriter, session *AuthSession) {
	reader := NewFrameReader(rw)
	writer := NewFrameWriter(rw)
	defer writer.Close()

	udpAssocMu := &sync.Mutex{}
	udpAssociations := make(map[uint16]*net.UDPConn)
	defer s.closeUDPAssociations(udpAssociations, udpAssocMu)

	s.firewall.OnConnect(session.User.ID)
	defer s.firewall.OnDisconnect(session.User.ID)

	for {
		frame, err := reader.ReadTypedFramePooled()
		if err != nil {
			return
		}

		switch frame.Type {
		case FrameIP:
			s.firewall.TrackBandwidth(session.User.ID, int64(len(frame.Payload)))
		case FrameConnect:
			payload := make([]byte, len(frame.Payload))
			copy(payload, frame.Payload)
			go s.handleFrameConnect(writer, Frame{Type: frame.Type, Payload: payload}, session)
		case FrameUDP:
			payload := make([]byte, len(frame.Payload))
			copy(payload, frame.Payload)
			go s.handleFrameUDP(writer, Frame{Type: frame.Type, Payload: payload}, session, udpAssocMu, udpAssociations)
		case FrameUDPClose:
			assocID, decodeErr := DecodeUDPCloseFrame(frame.Payload)
			if decodeErr == nil {
				s.closeUDPAssociation(assocID, udpAssociations, udpAssocMu)
			}
		case FrameClose:
		case FramePadding:
		}

		frame.Release()
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

	targetConn, err := DialTarget(addr, port, 10*time.Second)
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

func (s *Server) handleFrameUDP(
	writer *FrameWriter,
	frame Frame,
	session *AuthSession,
	udpAssocMu *sync.Mutex,
	udpAssociations map[uint16]*net.UDPConn,
) {
	payload, err := DecodeUDPFrame(frame.Payload)
	if err != nil {
		return
	}

	if !s.firewall.CheckConnection(session.User.ID, payload.Addr, payload.Port, session.User) {
		return
	}

	udpConn, err := s.getOrCreateUDPAssociation(payload.AssocID, writer, session, udpAssocMu, udpAssociations)
	if err != nil {
		return
	}

	targetAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(payload.Addr, strconv.Itoa(int(payload.Port))))
	if err != nil {
		return
	}

	s.firewall.TrackBandwidth(session.User.ID, int64(len(payload.Data)))
	_, _ = udpConn.WriteToUDP(payload.Data, targetAddr)
}

func (s *Server) getOrCreateUDPAssociation(
	assocID uint16,
	writer *FrameWriter,
	session *AuthSession,
	udpAssocMu *sync.Mutex,
	udpAssociations map[uint16]*net.UDPConn,
) (*net.UDPConn, error) {
	udpAssocMu.Lock()
	if conn := udpAssociations[assocID]; conn != nil {
		udpAssocMu.Unlock()
		return conn, nil
	}
	udpAssocMu.Unlock()

	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	TuneUDPConn(udpConn)

	udpAssocMu.Lock()
	if existing := udpAssociations[assocID]; existing != nil {
		udpAssocMu.Unlock()
		udpConn.Close()
		return existing, nil
	}
	udpAssociations[assocID] = udpConn
	udpAssocMu.Unlock()

	go s.relayUDPResponses(assocID, udpConn, writer, session)
	return udpConn, nil
}

func (s *Server) relayUDPResponses(assocID uint16, udpConn *net.UDPConn, writer *FrameWriter, session *AuthSession) {
	buf := make([]byte, MaxPacketSize)
	for {
		n, srcAddr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n == 0 {
			continue
		}

		addrType := AddrIPv6
		addr := srcAddr.IP.String()
		if ipv4 := srcAddr.IP.To4(); ipv4 != nil {
			addrType = AddrIPv4
			addr = ipv4.String()
		}

		s.firewall.TrackBandwidth(session.User.ID, int64(n))
		if err := writer.WriteTypedFrame(EncodeUDPFrame(assocID, addrType, addr, uint16(srcAddr.Port), buf[:n])); err != nil {
			return
		}
		if err := writer.Flush(); err != nil {
			return
		}
	}
}

func (s *Server) closeUDPAssociation(assocID uint16, udpAssociations map[uint16]*net.UDPConn, udpAssocMu *sync.Mutex) {
	udpAssocMu.Lock()
	conn := udpAssociations[assocID]
	delete(udpAssociations, assocID)
	udpAssocMu.Unlock()
	if conn != nil {
		conn.Close()
	}
}

func (s *Server) closeUDPAssociations(udpAssociations map[uint16]*net.UDPConn, udpAssocMu *sync.Mutex) {
	udpAssocMu.Lock()
	defer udpAssocMu.Unlock()
	for assocID, conn := range udpAssociations {
		delete(udpAssociations, assocID)
		conn.Close()
	}
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

	udpConn.SetReadBuffer(16 * 1024 * 1024)
	udpConn.SetWriteBuffer(16 * 1024 * 1024)

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
		MaxIncomingStreams:             4096,
		MaxIncomingUniStreams:          32,
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

		conn.CloseWithError(quic.ApplicationErrorCode(AuthStatusDenied), "Authentication failed")
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

	var firstByte [1]byte
	if _, err := io.ReadFull(stream, firstByte[:]); err != nil {
		return
	}

	if firstByte[0] == 0x00 {
		if _, err := stream.Write([]byte{AuthStatusOK}); err != nil {
			return
		}
		s.handleTUNSession(stream, session)
		return
	}

	_, addr, port, err := ReadAddressHeaderWithFirstByte(firstByte[0], stream)
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

	tcpConn, err := DialTarget(addr, port, 10*time.Second)
	if err != nil {
		stream.Write([]byte{0x02})
		return
	}
	defer tcpConn.Close()

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

	sni := s.config.SNI
	if sni == "" {
		sni = "localhost"
	}

	var tlsCert tls.Certificate
	var err error
	if s.config.Camouflage.TargetURL != "" {
		if u, perr := url.Parse(s.config.Camouflage.TargetURL); perr == nil && u.Host != "" {
			tlsCert, err = CloneCertFromTarget(u.Host, sni)
		} else {
			tlsCert, err = GenerateStealthCert(sni)
		}
	} else {
		tlsCert, err = GenerateStealthCert(sni)
	}
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
