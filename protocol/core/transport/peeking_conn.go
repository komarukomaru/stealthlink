// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

package transport

import (
	"fmt"
	"net"
	"syscall"
)

type PeekingConn struct {
	net.Conn
	peekBuf []byte
	readIdx int
}

func NewPeekingConn(conn net.Conn, peekSize int) (*PeekingConn, error) {
	buf := make([]byte, peekSize)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return &PeekingConn{
		Conn:    conn,
		peekBuf: buf[:n],
	}, nil
}

func (c *PeekingConn) Peek() []byte {
	return c.peekBuf
}

func (c *PeekingConn) Read(p []byte) (n int, err error) {
	if c.readIdx < len(c.peekBuf) {
		n = copy(p, c.peekBuf[c.readIdx:])
		c.readIdx += n
		if n == len(p) {
			return n, nil
		}
		return n, nil
	}
	return c.Conn.Read(p)
}

type ReplayProtectedPacketConn struct {
	net.PacketConn
	filter *ReplayFilter
}

func (c *ReplayProtectedPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	for {
		n, addr, err = c.PacketConn.ReadFrom(p)
		if err != nil {
			return
		}

		if c.filter.CheckAndAdd(p[:n]) {
			// log.Printf("Replay detected from %s", addr)
			continue
		}
		return
	}
}

func (c *ReplayProtectedPacketConn) SetReadBuffer(bytes int) error {
	if sc, ok := c.PacketConn.(interface {
		SetReadBuffer(int) error
	}); ok {
		return sc.SetReadBuffer(bytes)
	}
	return nil
}

func (c *ReplayProtectedPacketConn) SetWriteBuffer(bytes int) error {
	if sc, ok := c.PacketConn.(interface {
		SetWriteBuffer(int) error
	}); ok {
		return sc.SetWriteBuffer(bytes)
	}
	return nil
}

func (c *ReplayProtectedPacketConn) SyscallConn() (syscall.RawConn, error) {
	if sc, ok := c.PacketConn.(interface {
		SyscallConn() (syscall.RawConn, error)
	}); ok {
		return sc.SyscallConn()
	}
	return nil, fmt.Errorf("SyscallConn not supported")
}
