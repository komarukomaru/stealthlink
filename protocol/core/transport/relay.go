// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

package transport

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

const relayBufSize = 256 * 1024

func BidirectionalRelay(left, right net.Conn) {
	done := make(chan struct{})

	go func() {
		buf := make([]byte, relayBufSize)
		io.CopyBuffer(right, left, buf)
		closeWrite(right)
		close(done)
	}()

	buf := make([]byte, relayBufSize)
	io.CopyBuffer(left, right, buf)
	closeWrite(left)
	<-done
}

func closeWrite(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.CloseWrite()
		return
	}
	type netConner interface {
		NetConn() net.Conn
	}
	if nc, ok := conn.(netConner); ok {
		if tc, ok := nc.NetConn().(*net.TCPConn); ok {
			tc.CloseWrite()
			return
		}
	}
}

func TuneTCPConn(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
		tc.SetReadBuffer(4 * 1024 * 1024)
		tc.SetWriteBuffer(4 * 1024 * 1024)
		return
	}
	type netConner interface {
		NetConn() net.Conn
	}
	if nc, ok := conn.(netConner); ok {
		TuneTCPConn(nc.NetConn())
	}
}

func TuneUDPConn(conn *net.UDPConn) {
	if conn == nil {
		return
	}
	conn.SetReadBuffer(4 * 1024 * 1024)
	conn.SetWriteBuffer(4 * 1024 * 1024)
}

func DialTarget(addr string, port uint16, timeout time.Duration) (net.Conn, error) {
	target := net.JoinHostPort(addr, strconv.Itoa(int(port)))
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		return nil, err
	}
	TuneTCPConn(conn)
	return conn, nil
}

func ReadAddressHeader(r io.Reader) (addrType byte, addr string, port uint16, err error) {
	header := make([]byte, 1)
	if _, err = io.ReadFull(r, header); err != nil {
		return
	}
	return ReadAddressHeaderWithFirstByte(header[0], r)
}

func ReadAddressHeaderWithFirstByte(firstByte byte, r io.Reader) (addrType byte, addr string, port uint16, err error) {
	addrType = firstByte

	switch addrType {
	case AddrIPv4:
		buf := make([]byte, 6)
		if _, err = io.ReadFull(r, buf); err != nil {
			return
		}
		addr = net.IP(buf[:4]).String()
		port = binary.BigEndian.Uint16(buf[4:6])
	case AddrIPv6:
		buf := make([]byte, 18)
		if _, err = io.ReadFull(r, buf); err != nil {
			return
		}
		addr = net.IP(buf[:16]).String()
		port = binary.BigEndian.Uint16(buf[16:18])
	case AddrDomain:
		lenBuf := make([]byte, 1)
		if _, err = io.ReadFull(r, lenBuf); err != nil {
			return
		}
		domainBuf := make([]byte, int(lenBuf[0])+2)
		if _, err = io.ReadFull(r, domainBuf); err != nil {
			return
		}
		addr = string(domainBuf[:lenBuf[0]])
		port = binary.BigEndian.Uint16(domainBuf[lenBuf[0]:])
	default:
		err = fmt.Errorf("unknown address type: %d", addrType)
	}
	return
}
