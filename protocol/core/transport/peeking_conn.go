package transport

import (
	"net"
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
