// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

package transport

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

type SOCKSProxy struct {
	ListenAddr string

	mu        sync.RWMutex
	dialer    func(addrType byte, addr string, port uint16) (net.Conn, error)
	quicConn  *quic.Conn
	udpOpener func() (*UDPAssociation, error)
	stopChan  chan struct{}
}

func NewSOCKSProxy(listenAddr string) *SOCKSProxy {
	return &SOCKSProxy{
		ListenAddr: listenAddr,
		stopChan:   make(chan struct{}),
	}
}

func (sp *SOCKSProxy) SetDialer(fn func(addrType byte, addr string, port uint16) (net.Conn, error)) {
	sp.mu.Lock()
	sp.dialer = fn
	sp.quicConn = nil
	sp.mu.Unlock()
}

func (sp *SOCKSProxy) SetQUIC(conn *quic.Conn) {
	sp.mu.Lock()
	sp.quicConn = conn
	sp.dialer = nil
	sp.mu.Unlock()
}

func (sp *SOCKSProxy) SetUDPOpener(fn func() (*UDPAssociation, error)) {
	sp.mu.Lock()
	sp.udpOpener = fn
	sp.mu.Unlock()
}

func (sp *SOCKSProxy) Start() error {
	listener, err := net.Listen("tcp", sp.ListenAddr)
	if err != nil {
		return fmt.Errorf("socks5 listen failed: %w", err)
	}

	log.Printf("[SOCKS5] Listening on %s", sp.ListenAddr)

	go func() {
		<-sp.stopChan
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-sp.stopChan:
				return nil
			default:
				continue
			}
		}
		go sp.handleSOCKS(conn)
	}
}

func (sp *SOCKSProxy) handleSOCKS(conn net.Conn) {
	defer conn.Close()

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}
	if header[0] != 0x05 {
		return
	}

	methodCount := int(header[1])
	if methodCount == 0 {
		return
	}

	methods := make([]byte, methodCount)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}

	supportsNoAuth := false
	for _, method := range methods {
		if method == 0x00 {
			supportsNoAuth = true
			break
		}
	}
	if !supportsNoAuth {
		conn.Write([]byte{0x05, 0xFF})
		return
	}

	conn.Write([]byte{0x05, 0x00})

	conn.SetDeadline(time.Now().Add(10 * time.Second))
	reqHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, reqHeader); err != nil {
		return
	}

	if reqHeader[0] != 0x05 {
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	cmd := reqHeader[1]
	addrType, addr, port, err := ReadAddressHeaderWithFirstByte(reqHeader[3], conn)
	if err != nil {
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	switch cmd {
	case 0x01:
	case 0x03:
		_ = addrType
		_ = addr
		_ = port
		sp.handleSOCKSUDPAssociate(conn)
		return
	default:
		log.Printf("[SOCKS5] Unsupported command %s (%d)", socksCommandName(cmd), cmd)
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	sp.mu.RLock()
	qc := sp.quicConn
	dialer := sp.dialer
	sp.mu.RUnlock()

	if qc != nil {
		sp.handleSOCKSQUIC(conn, qc, addrType, addr, port)
		return
	}

	if dialer != nil {
		sp.handleSOCKSDirect(conn, dialer, addrType, addr, port)
		return
	}

	conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}

func (sp *SOCKSProxy) handleSOCKSDirect(
	localConn net.Conn,
	dialer func(byte, string, uint16) (net.Conn, error),
	addrType byte, addr string, port uint16,
) {
	remoteConn, err := dialer(addrType, addr, port)
	if err != nil {
		localConn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remoteConn.Close()

	localConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	localConn.SetDeadline(time.Time{})

	BidirectionalRelay(localConn, remoteConn)
}

func (sp *SOCKSProxy) handleSOCKSQUIC(conn net.Conn, qc *quic.Conn, addrType byte, addr string, port uint16) {
	qStream, err := qc.OpenStreamSync(context.Background())
	if err != nil {
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer qStream.Close()

	header := EncodeAddress(addrType, addr, port)
	if _, err := qStream.Write(header); err != nil {
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	ack := make([]byte, 1)
	qStream.SetReadDeadline(time.Now().Add(15 * time.Second))
	if _, err := io.ReadFull(qStream, ack); err != nil || ack[0] != 0x00 {
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	qStream.SetReadDeadline(time.Time{})

	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	conn.SetDeadline(time.Time{})

	done := make(chan struct{})

	go func() {
		buf := make([]byte, relayBufSize)
		io.CopyBuffer(conn, qStream, buf)
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		close(done)
	}()

	buf := make([]byte, relayBufSize)
	io.CopyBuffer(qStream, conn, buf)
	qStream.Close()
	<-done
}

func (sp *SOCKSProxy) handleSOCKSUDPAssociate(conn net.Conn) {
	sp.mu.RLock()
	udpOpener := sp.udpOpener
	sp.mu.RUnlock()

	if udpOpener == nil {
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	assoc, err := udpOpener()
	if err != nil {
		log.Printf("[SOCKS5] UDP association setup failed: %v", err)
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer assoc.Close()

	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Printf("[SOCKS5] UDP relay bind failed: %v", err)
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer udpConn.Close()

	TuneUDPConn(udpConn)

	bindIP := net.ParseIP("127.0.0.1").To4()
	port := uint16(udpConn.LocalAddr().(*net.UDPAddr).Port)
	reply := []byte{0x05, 0x00, 0x00, 0x01}
	reply = append(reply, bindIP...)
	reply = append(reply, 0, 0)
	binary.BigEndian.PutUint16(reply[len(reply)-2:], port)
	if _, err := conn.Write(reply); err != nil {
		return
	}
	conn.SetDeadline(time.Time{})

	done := make(chan struct{})
	var doneOnce sync.Once
	var clientAddrMu sync.RWMutex
	var clientAddr *net.UDPAddr

	go func() {
		_, _ = io.Copy(io.Discard, conn)
		doneOnce.Do(func() { close(done) })
	}()

	go func() {
		for {
			select {
			case <-done:
				return
			case payload, ok := <-assoc.Receive():
				if !ok {
					return
				}

				clientAddrMu.RLock()
				targetAddr := clientAddr
				clientAddrMu.RUnlock()
				if targetAddr == nil {
					continue
				}

				packet := EncodeSOCKSUDPDatagram(payload.AddrType, payload.Addr, payload.Port, payload.Data)
				if _, err := udpConn.WriteToUDP(packet, targetAddr); err != nil {
					doneOnce.Do(func() { close(done) })
					return
				}
			}
		}
	}()

	buf := make([]byte, MaxPacketSize+512)
	for {
		select {
		case <-done:
			return
		default:
		}

		udpConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, srcAddr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			break
		}

		clientAddrMu.Lock()
		if clientAddr == nil {
			addrCopy := *srcAddr
			clientAddr = &addrCopy
		}
		knownClientAddr := clientAddr
		clientAddrMu.Unlock()

		if knownClientAddr != nil && (!srcAddr.IP.Equal(knownClientAddr.IP) || srcAddr.Port != knownClientAddr.Port) {
			continue
		}

		addrType, addr, dstPort, data, parseErr := DecodeSOCKSUDPDatagram(buf[:n])
		if parseErr != nil {
			continue
		}

		if err := assoc.Send(addrType, addr, dstPort, data); err != nil {
			log.Printf("[SOCKS5] UDP relay send failed: %v", err)
			break
		}
	}

	doneOnce.Do(func() { close(done) })
}

func (sp *SOCKSProxy) Stop() {
	select {
	case <-sp.stopChan:
	default:
		close(sp.stopChan)
	}
}

func socksCommandName(cmd byte) string {
	switch cmd {
	case 0x01:
		return "connect"
	case 0x02:
		return "bind"
	case 0x03:
		return "udp associate"
	default:
		return "unknown"
	}
}

func EncodeSOCKSUDPDatagram(addrType byte, addr string, port uint16, data []byte) []byte {
	packet := []byte{0x00, 0x00, 0x00}
	packet = append(packet, EncodeAddress(addrType, addr, port)...)
	packet = append(packet, data...)
	return packet
}

func DecodeSOCKSUDPDatagram(packet []byte) (addrType byte, addr string, port uint16, data []byte, err error) {
	if len(packet) < 4 {
		return 0, "", 0, nil, fmt.Errorf("udp packet too short")
	}
	if packet[0] != 0x00 || packet[1] != 0x00 {
		return 0, "", 0, nil, fmt.Errorf("invalid udp reserved field")
	}
	if packet[2] != 0x00 {
		return 0, "", 0, nil, fmt.Errorf("fragmented udp packets are unsupported")
	}

	addrType, addr, port, data, err = DecodeAddress(packet[3:])
	return
}

type HTTPProxy struct {
	ListenAddr string
	socksAddr  string
}

func NewHTTPProxy(listenAddr string, socksAddr string) *HTTPProxy {
	return &HTTPProxy{
		ListenAddr: listenAddr,
		socksAddr:  socksAddr,
	}
}

func (hp *HTTPProxy) Start() error {
	listener, err := net.Listen("tcp", hp.ListenAddr)
	if err != nil {
		return err
	}

	log.Printf("[HTTP Proxy] Listening on %s (forwarding to SOCKS5 %s)", hp.ListenAddr, hp.socksAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go hp.handleHTTP(conn)
	}
}

func (hp *HTTPProxy) handleHTTP(conn net.Conn) {
	defer conn.Close()

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}

	request := string(buf[:n])
	if len(request) < 10 {
		return
	}

	if request[:7] == "CONNECT" {
		hp.handleConnect(conn, request)
	} else {
		hp.handlePlain(conn, buf[:n])
	}
}

func (hp *HTTPProxy) handleConnect(clientConn net.Conn, request string) {
	var host string
	fmt.Sscanf(request, "CONNECT %s", &host)

	remote, err := net.DialTimeout("tcp", hp.socksAddr, 5*time.Second)
	if err != nil {
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer remote.Close()

	hostname, portStr, err := net.SplitHostPort(host)
	if err != nil {
		clientConn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}

	port := 443
	fmt.Sscanf(portStr, "%d", &port)

	socksReq := []byte{0x05, 0x01, 0x00}
	remote.Write(socksReq)
	resp := make([]byte, 2)
	io.ReadFull(remote, resp)

	connectReq := []byte{0x05, 0x01, 0x00, 0x03, byte(len(hostname))}
	connectReq = append(connectReq, []byte(hostname)...)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(port))
	connectReq = append(connectReq, portBuf...)
	remote.Write(connectReq)

	socksResp := make([]byte, 10)
	io.ReadFull(remote, socksResp)

	if socksResp[1] != 0x00 {
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}

	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	BidirectionalRelay(clientConn, remote)
}

func (hp *HTTPProxy) handlePlain(clientConn net.Conn, initialData []byte) {
	clientConn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
}
