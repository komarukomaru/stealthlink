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

	mu       sync.RWMutex
	dialer   func(addrType byte, addr string, port uint16) (net.Conn, error)
	quicConn *quic.Conn
	stopChan chan struct{}
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

	buf := make([]byte, 258)
	n, err := conn.Read(buf)
	if err != nil || n < 3 {
		return
	}

	if buf[0] != 0x05 {
		return
	}

	conn.Write([]byte{0x05, 0x00})

	conn.SetDeadline(time.Now().Add(10 * time.Second))
	n, err = conn.Read(buf)
	if err != nil || n < 7 {
		return
	}

	if buf[0] != 0x05 || buf[1] != 0x01 {
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var addrType byte
	var addr string
	var port uint16

	switch buf[3] {
	case 0x01:
		if n < 10 {
			return
		}
		addrType = AddrIPv4
		addr = net.IP(buf[4:8]).String()
		port = binary.BigEndian.Uint16(buf[8:10])
	case 0x03:
		dLen := int(buf[4])
		if n < 5+dLen+2 {
			return
		}
		addrType = AddrDomain
		addr = string(buf[5 : 5+dLen])
		port = binary.BigEndian.Uint16(buf[5+dLen : 7+dLen])
	case 0x04:
		if n < 22 {
			return
		}
		addrType = AddrIPv6
		addr = net.IP(buf[4:20]).String()
		port = binary.BigEndian.Uint16(buf[20:22])
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
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

func (sp *SOCKSProxy) Stop() {
	select {
	case <-sp.stopChan:
	default:
		close(sp.stopChan)
	}
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
