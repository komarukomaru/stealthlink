// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

package transport

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	MaxFrameSize  = 65535
	MaxPacketSize = MaxFrameSize

	FrameData     byte = 0x00
	FrameConnect  byte = 0x01
	FrameConnAck  byte = 0x02
	FrameClose    byte = 0x03
	FrameAuth     byte = 0x04
	FrameAuthResp byte = 0x05
	FramePadding  byte = 0x06
	FrameUDP      byte = 0x07
	FrameConfig   byte = 0x08
	FrameIP       byte = 0x09
	FrameUDPClose byte = 0x0A

	AddrIPv4   byte = 0x01
	AddrDomain byte = 0x03
	AddrIPv6   byte = 0x04
)

type Frame struct {
	Type    byte
	Payload []byte
}

type ConnectRequest struct {
	StreamID uint16
	AddrType byte
	Addr     string
	Port     uint16
}

type DataPayload struct {
	StreamID uint16
	Data     []byte
}

type UDPPayload struct {
	AssocID  uint16
	AddrType byte
	Addr     string
	Port     uint16
	Data     []byte
}

func EncodeAddress(addrType byte, addr string, port uint16) []byte {
	var buf []byte
	buf = append(buf, addrType)
	switch addrType {
	case AddrIPv4:
		ip := net.ParseIP(addr).To4()
		if ip == nil {
			ip = make([]byte, 4)
		}
		buf = append(buf, ip...)
	case AddrIPv6:
		ip := net.ParseIP(addr).To16()
		if ip == nil {
			ip = make([]byte, 16)
		}
		buf = append(buf, ip...)
	case AddrDomain:
		if len(addr) > 255 {
			addr = addr[:255]
		}
		buf = append(buf, byte(len(addr)))
		buf = append(buf, []byte(addr)...)
	}
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, port)
	buf = append(buf, portBuf...)
	return buf
}

func DecodeAddress(data []byte) (addrType byte, addr string, port uint16, rest []byte, err error) {
	if len(data) < 1 {
		return 0, "", 0, nil, fmt.Errorf("address data too short")
	}
	addrType = data[0]
	data = data[1:]

	switch addrType {
	case AddrIPv4:
		if len(data) < 6 {
			return 0, "", 0, nil, fmt.Errorf("ipv4 address too short")
		}
		addr = net.IP(data[:4]).String()
		port = binary.BigEndian.Uint16(data[4:6])
		rest = data[6:]
	case AddrIPv6:
		if len(data) < 18 {
			return 0, "", 0, nil, fmt.Errorf("ipv6 address too short")
		}
		addr = net.IP(data[:16]).String()
		port = binary.BigEndian.Uint16(data[16:18])
		rest = data[18:]
	case AddrDomain:
		if len(data) < 1 {
			return 0, "", 0, nil, fmt.Errorf("domain length missing")
		}
		dLen := int(data[0])
		data = data[1:]
		if len(data) < dLen+2 {
			return 0, "", 0, nil, fmt.Errorf("domain data too short")
		}
		addr = string(data[:dLen])
		port = binary.BigEndian.Uint16(data[dLen : dLen+2])
		rest = data[dLen+2:]
	default:
		return 0, "", 0, nil, fmt.Errorf("unknown address type: %d", addrType)
	}
	return
}

func EncodeConnectFrame(streamID uint16, addrType byte, addr string, port uint16) Frame {
	payload := make([]byte, 2)
	binary.BigEndian.PutUint16(payload, streamID)
	payload = append(payload, EncodeAddress(addrType, addr, port)...)
	return Frame{Type: FrameConnect, Payload: payload}
}

func DecodeConnectFrame(payload []byte) (ConnectRequest, error) {
	if len(payload) < 5 {
		return ConnectRequest{}, fmt.Errorf("connect frame too short")
	}
	streamID := binary.BigEndian.Uint16(payload[:2])
	addrType, addr, port, _, err := DecodeAddress(payload[2:])
	if err != nil {
		return ConnectRequest{}, err
	}
	return ConnectRequest{
		StreamID: streamID,
		AddrType: addrType,
		Addr:     addr,
		Port:     port,
	}, nil
}

func EncodeDataFrame(streamID uint16, data []byte) Frame {
	payload := make([]byte, 2+len(data))
	binary.BigEndian.PutUint16(payload, streamID)
	copy(payload[2:], data)
	return Frame{Type: FrameData, Payload: payload}
}

func DecodeDataFrame(payload []byte) (DataPayload, error) {
	if len(payload) < 2 {
		return DataPayload{}, fmt.Errorf("data frame too short")
	}
	return DataPayload{
		StreamID: binary.BigEndian.Uint16(payload[:2]),
		Data:     payload[2:],
	}, nil
}

func EncodeCloseFrame(streamID uint16) Frame {
	payload := make([]byte, 2)
	binary.BigEndian.PutUint16(payload, streamID)
	return Frame{Type: FrameClose, Payload: payload}
}

func EncodeUDPFrame(assocID uint16, addrType byte, addr string, port uint16, data []byte) Frame {
	payload := make([]byte, 2)
	binary.BigEndian.PutUint16(payload, assocID)
	payload = append(payload, EncodeAddress(addrType, addr, port)...)
	payload = append(payload, data...)
	return Frame{Type: FrameUDP, Payload: payload}
}

func DecodeUDPFrame(payload []byte) (UDPPayload, error) {
	if len(payload) < 2 {
		return UDPPayload{}, fmt.Errorf("udp frame too short")
	}

	assocID := binary.BigEndian.Uint16(payload[:2])
	addrType, addr, port, rest, err := DecodeAddress(payload[2:])
	if err != nil {
		return UDPPayload{}, err
	}
	return UDPPayload{
		AssocID:  assocID,
		AddrType: addrType,
		Addr:     addr,
		Port:     port,
		Data:     rest,
	}, nil
}

func EncodeUDPCloseFrame(assocID uint16) Frame {
	payload := make([]byte, 2)
	binary.BigEndian.PutUint16(payload, assocID)
	return Frame{Type: FrameUDPClose, Payload: payload}
}

func DecodeUDPCloseFrame(payload []byte) (uint16, error) {
	if len(payload) != 2 {
		return 0, fmt.Errorf("udp close frame length mismatch: %d", len(payload))
	}
	return binary.BigEndian.Uint16(payload), nil
}

var bufferPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, MaxFrameSize+4)
		return &b
	},
}

func GetBuffer() *[]byte {
	return bufferPool.Get().(*[]byte)
}

func PutBuffer(b *[]byte) {
	bufferPool.Put(b)
}

type PooledPacket struct {
	Data []byte
	Buf  *[]byte
}

func (p *PooledPacket) Release() {
	if p.Buf != nil {
		PutBuffer(p.Buf)
		p.Buf = nil
	}
}

type PooledFrame struct {
	Type    byte
	Payload []byte
	pkt     PooledPacket
}

func (pf *PooledFrame) Release() {
	pf.pkt.Release()
}

type FrameWriter struct {
	w            io.Writer
	mu           sync.Mutex
	batchBuf     []byte
	batchSize    int
	maxBatchSize int
	flushTimer   *time.Timer
	flushChan    chan struct{}
	closeChan    chan struct{}
	directMode   bool
	directBuf    []byte
}

func NewFrameWriter(w io.Writer) *FrameWriter {
	fw := &FrameWriter{
		w:            w,
		batchBuf:     make([]byte, 0, 256*1024),
		maxBatchSize: 128 * 1024,
		flushChan:    make(chan struct{}, 1),
		closeChan:    make(chan struct{}),
	}
	go fw.autoFlusher()
	return fw
}

func NewFrameWriterDirect(w io.Writer) *FrameWriter {
	return &FrameWriter{
		w:          w,
		directMode: true,
		closeChan:  make(chan struct{}),
		directBuf:  make([]byte, 3+MaxFrameSize),
	}
}

func (fw *FrameWriter) WriteTypedFrame(f Frame) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	frameLen := 1 + len(f.Payload)
	if frameLen == 0 || frameLen > MaxFrameSize {
		return nil
	}

	if fw.directMode {
		binary.BigEndian.PutUint16(fw.directBuf, uint16(frameLen))
		fw.directBuf[2] = f.Type
		copy(fw.directBuf[3:], f.Payload)
		_, err := fw.w.Write(fw.directBuf[:2+frameLen])
		return err
	}

	if fw.batchSize+2+frameLen > fw.maxBatchSize {
		if err := fw.flushLocked(); err != nil {
			return err
		}
	}

	headerStart := len(fw.batchBuf)
	fw.batchBuf = append(fw.batchBuf, 0, 0)
	binary.BigEndian.PutUint16(fw.batchBuf[headerStart:], uint16(frameLen))
	fw.batchBuf = append(fw.batchBuf, f.Type)
	fw.batchBuf = append(fw.batchBuf, f.Payload...)
	fw.batchSize += 2 + frameLen

	if fw.batchSize >= fw.maxBatchSize/2 {
		return fw.flushLocked()
	}

	fw.scheduleFlush()
	return nil
}

func (fw *FrameWriter) WriteFrame(data []byte) error {
	if len(data) == 0 || len(data) > MaxFrameSize {
		return nil
	}

	fw.mu.Lock()
	defer fw.mu.Unlock()

	if fw.directMode {
		binary.BigEndian.PutUint16(fw.directBuf, uint16(len(data)))
		copy(fw.directBuf[2:], data)
		_, err := fw.w.Write(fw.directBuf[:2+len(data)])
		return err
	}

	if fw.batchSize+2+len(data) > fw.maxBatchSize {
		if err := fw.flushLocked(); err != nil {
			return err
		}
	}

	headerStart := len(fw.batchBuf)
	fw.batchBuf = append(fw.batchBuf, 0, 0)
	binary.BigEndian.PutUint16(fw.batchBuf[headerStart:], uint16(len(data)))
	fw.batchBuf = append(fw.batchBuf, data...)
	fw.batchSize += 2 + len(data)

	fw.scheduleFlush()
	return nil
}

func (fw *FrameWriter) scheduleFlush() {
	if fw.flushTimer != nil {
		fw.flushTimer.Reset(2 * time.Millisecond)
	} else {
		fw.flushTimer = time.AfterFunc(2*time.Millisecond, func() {
			select {
			case fw.flushChan <- struct{}{}:
			default:
			}
		})
	}
}

func (fw *FrameWriter) Flush() error {
	if fw.directMode {
		return nil
	}
	fw.mu.Lock()
	defer fw.mu.Unlock()
	return fw.flushLocked()
}

func (fw *FrameWriter) flushLocked() error {
	if fw.batchSize == 0 {
		return nil
	}
	_, err := fw.w.Write(fw.batchBuf[:fw.batchSize])
	fw.batchBuf = fw.batchBuf[:0]
	fw.batchSize = 0
	return err
}

func (fw *FrameWriter) autoFlusher() {
	for {
		select {
		case <-fw.flushChan:
			fw.Flush()
		case <-fw.closeChan:
			return
		}
	}
}

func (fw *FrameWriter) Close() error {
	select {
	case <-fw.closeChan:
	default:
		close(fw.closeChan)
	}
	if fw.flushTimer != nil {
		fw.flushTimer.Stop()
	}
	return fw.Flush()
}

type FrameReader struct {
	r      io.Reader
	header [2]byte
}

func NewFrameReader(r io.Reader) *FrameReader {
	return &FrameReader{r: r}
}

func (fr *FrameReader) ReadFrame() (PooledPacket, error) {
	if _, err := io.ReadFull(fr.r, fr.header[:]); err != nil {
		return PooledPacket{}, err
	}

	length := binary.BigEndian.Uint16(fr.header[:])
	if length == 0 {
		return PooledPacket{}, nil
	}
	if length > MaxFrameSize {
		return PooledPacket{}, fmt.Errorf("frame too large: %d", length)
	}

	bufPtr := GetBuffer()
	buf := *bufPtr
	if _, err := io.ReadFull(fr.r, buf[:length]); err != nil {
		PutBuffer(bufPtr)
		return PooledPacket{}, err
	}

	return PooledPacket{Data: buf[:length], Buf: bufPtr}, nil
}

func (fr *FrameReader) ReadTypedFrame() (Frame, error) {
	pf, err := fr.ReadTypedFramePooled()
	if err != nil {
		return Frame{}, err
	}
	defer pf.Release()

	if pf.pkt.Buf == nil && pf.Payload == nil {
		return Frame{}, nil
	}

	data := make([]byte, len(pf.Payload))
	copy(data, pf.Payload)

	return Frame{
		Type:    pf.Type,
		Payload: data,
	}, nil
}

func (fr *FrameReader) ReadTypedFramePooled() (PooledFrame, error) {
	pkt, err := fr.ReadFrame()
	if err != nil {
		return PooledFrame{}, err
	}

	if len(pkt.Data) < 1 {
		pkt.Release()
		return PooledFrame{}, nil
	}

	return PooledFrame{
		Type:    pkt.Data[0],
		Payload: pkt.Data[1:],
		pkt:     pkt,
	}, nil
}

func IsValidIPPacket(data []byte) bool {
	if len(data) < 20 {
		return false
	}
	v := data[0] >> 4
	return v == 4 || v == 6
}
