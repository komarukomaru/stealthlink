// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

package transport

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestFrameWriteRead(t *testing.T) {
	buf := &bytes.Buffer{}
	writer := NewFrameWriter(buf)
	reader := NewFrameReader(buf)

	testData := []byte("hello world")
	writer.WriteFrame(testData)
	writer.Flush()

	pkt, err := reader.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}
	defer pkt.Release()

	if !bytes.Equal(pkt.Data, testData) {
		t.Fatalf("data mismatch: got %q, want %q", pkt.Data, testData)
	}
}

func TestTypedFrameRoundtrip(t *testing.T) {
	buf := &bytes.Buffer{}
	writer := NewFrameWriter(buf)
	reader := NewFrameReader(buf)

	frame := Frame{Type: FrameData, Payload: []byte("test payload")}
	writer.WriteTypedFrame(frame)
	writer.Flush()

	result, err := reader.ReadTypedFrame()
	if err != nil {
		t.Fatalf("ReadTypedFrame failed: %v", err)
	}

	if result.Type != FrameData {
		t.Fatalf("type mismatch: got %d, want %d", result.Type, FrameData)
	}
	if !bytes.Equal(result.Payload, frame.Payload) {
		t.Fatalf("payload mismatch")
	}
}

func TestTypedFrameRoundtripPooled(t *testing.T) {
	buf := &bytes.Buffer{}
	writer := NewFrameWriter(buf)
	reader := NewFrameReader(buf)

	frame := Frame{Type: FrameIP, Payload: []byte("pooled payload")}
	writer.WriteTypedFrame(frame)
	writer.Flush()

	result, err := reader.ReadTypedFramePooled()
	if err != nil {
		t.Fatalf("ReadTypedFramePooled failed: %v", err)
	}
	defer result.Release()

	if result.Type != frame.Type {
		t.Fatalf("type mismatch: got %d, want %d", result.Type, frame.Type)
	}
	if !bytes.Equal(result.Payload, frame.Payload) {
		t.Fatalf("payload mismatch")
	}
	if result.pkt.Buf == nil {
		t.Fatal("expected pooled buffer to be retained")
	}
}

func TestConnectFrame(t *testing.T) {
	frame := EncodeConnectFrame(42, AddrDomain, "example.com", 443)
	req, err := DecodeConnectFrame(frame.Payload)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if req.StreamID != 42 {
		t.Fatalf("stream ID: got %d, want 42", req.StreamID)
	}
	if req.Addr != "example.com" {
		t.Fatalf("addr: got %q, want example.com", req.Addr)
	}
	if req.Port != 443 {
		t.Fatalf("port: got %d, want 443", req.Port)
	}
	if req.AddrType != AddrDomain {
		t.Fatalf("addr type: got %d, want %d", req.AddrType, AddrDomain)
	}
}

func TestConnectFrameIPv4(t *testing.T) {
	frame := EncodeConnectFrame(1, AddrIPv4, "1.2.3.4", 80)
	req, err := DecodeConnectFrame(frame.Payload)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if req.Addr != "1.2.3.4" {
		t.Fatalf("addr: got %q, want 1.2.3.4", req.Addr)
	}
	if req.Port != 80 {
		t.Fatalf("port: got %d, want 80", req.Port)
	}
}

func TestDataFrame(t *testing.T) {
	data := []byte("test data content")
	frame := EncodeDataFrame(100, data)
	dp, err := DecodeDataFrame(frame.Payload)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if dp.StreamID != 100 {
		t.Fatalf("stream ID: got %d, want 100", dp.StreamID)
	}
	if !bytes.Equal(dp.Data, data) {
		t.Fatalf("data mismatch")
	}
}

func TestUDPFrame(t *testing.T) {
	data := []byte("udp payload")
	frame := EncodeUDPFrame(7, AddrIPv4, "8.8.8.8", 53, data)
	udp, err := DecodeUDPFrame(frame.Payload)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if udp.AssocID != 7 {
		t.Fatalf("assoc id: got %d", udp.AssocID)
	}
	if udp.Addr != "8.8.8.8" {
		t.Fatalf("addr: got %q", udp.Addr)
	}
	if udp.Port != 53 {
		t.Fatalf("port: got %d", udp.Port)
	}
	if !bytes.Equal(udp.Data, data) {
		t.Fatalf("data mismatch")
	}
}

func TestAddressEncodeDecode(t *testing.T) {
	tests := []struct {
		addrType byte
		addr     string
		port     uint16
	}{
		{AddrIPv4, "10.0.0.1", 8080},
		{AddrIPv6, "::1", 443},
		{AddrDomain, "google.com", 80},
		{AddrDomain, "very-long-domain-name.example.com", 3000},
	}

	for _, tt := range tests {
		encoded := EncodeAddress(tt.addrType, tt.addr, tt.port)
		aType, addr, port, _, err := DecodeAddress(encoded)
		if err != nil {
			t.Fatalf("decode failed for %s: %v", tt.addr, err)
		}
		if aType != tt.addrType {
			t.Errorf("type mismatch for %s", tt.addr)
		}
		if port != tt.port {
			t.Errorf("port mismatch for %s: got %d want %d", tt.addr, port, tt.port)
		}

		if tt.addrType == AddrIPv4 || tt.addrType == AddrIPv6 {
			gotIP := net.ParseIP(addr)
			wantIP := net.ParseIP(tt.addr)
			if !gotIP.Equal(wantIP) {
				t.Errorf("IP mismatch for %s: got %s", tt.addr, addr)
			}
		} else {
			if addr != tt.addr {
				t.Errorf("addr mismatch: got %q want %q", addr, tt.addr)
			}
		}
	}
}

func TestReadAddressHeaderWithFirstByte(t *testing.T) {
	encoded := EncodeAddress(AddrDomain, "example.com", 443)
	addrType, addr, port, err := ReadAddressHeaderWithFirstByte(encoded[0], bytes.NewReader(encoded[1:]))
	if err != nil {
		t.Fatalf("ReadAddressHeaderWithFirstByte failed: %v", err)
	}
	if addrType != AddrDomain {
		t.Fatalf("addr type mismatch: got %d", addrType)
	}
	if addr != "example.com" {
		t.Fatalf("addr mismatch: got %q", addr)
	}
	if port != 443 {
		t.Fatalf("port mismatch: got %d", port)
	}
}

func TestMultipleFrames(t *testing.T) {
	buf := &bytes.Buffer{}
	writer := NewFrameWriter(buf)

	for i := 0; i < 100; i++ {
		data := make([]byte, 4)
		binary.BigEndian.PutUint32(data, uint32(i))
		writer.WriteFrame(data)
	}
	writer.Flush()

	reader := NewFrameReader(buf)
	for i := 0; i < 100; i++ {
		pkt, err := reader.ReadFrame()
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		val := binary.BigEndian.Uint32(pkt.Data)
		if val != uint32(i) {
			t.Fatalf("frame %d: got %d", i, val)
		}
		pkt.Release()
	}
}

func TestIsValidIPPacket(t *testing.T) {
	ipv4 := make([]byte, 20)
	ipv4[0] = 0x45
	if !IsValidIPPacket(ipv4) {
		t.Fatal("valid IPv4 packet rejected")
	}

	ipv6 := make([]byte, 40)
	ipv6[0] = 0x60
	if !IsValidIPPacket(ipv6) {
		t.Fatal("valid IPv6 packet rejected")
	}

	short := make([]byte, 10)
	if IsValidIPPacket(short) {
		t.Fatal("short packet accepted")
	}

	invalid := make([]byte, 20)
	invalid[0] = 0x30
	if IsValidIPPacket(invalid) {
		t.Fatal("invalid version accepted")
	}
}

func TestAuthValidation(t *testing.T) {
	users := []*UserRecord{
		{ID: "user1", PSK: "test-key-123"},
		{ID: "user2", PSK: "other-key-456"},
	}
	am := NewAuthManager(users)

	payload, err := GenerateAuthPayload("test-key-123")
	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}

	addr := &net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 1234}
	session, err := am.ValidateAuth(payload, addr)
	if err != nil {
		t.Fatalf("validate failed: %v", err)
	}
	if session.User.ID != "user1" {
		t.Fatalf("wrong user: %s", session.User.ID)
	}

	badPayload, _ := GenerateAuthPayload("wrong-key")
	_, err = am.ValidateAuth(badPayload, addr)
	if err == nil {
		t.Fatal("bad key should fail")
	}
}

func TestAuthRateLimit(t *testing.T) {
	users := []*UserRecord{{ID: "user1", PSK: "key1"}}
	am := NewAuthManager(users)
	addr := &net.TCPAddr{IP: net.ParseIP("5.5.5.5"), Port: 1234}

	for i := 0; i < 1001; i++ {
		badPayload, _ := GenerateAuthPayload("wrong")
		am.ValidateAuth(badPayload, addr)
	}

	goodPayload, _ := GenerateAuthPayload("key1")
	_, err := am.ValidateAuth(goodPayload, addr)
	if err == nil {
		t.Fatal("should be rate limited")
	}
}

func TestAuthExpiration(t *testing.T) {
	users := []*UserRecord{
		{ID: "expired", PSK: "key1", ExpiresAt: "2020-01-01T00:00:00Z"},
	}
	am := NewAuthManager(users)

	payload, _ := GenerateAuthPayload("key1")
	addr := &net.TCPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1}
	_, err := am.ValidateAuth(payload, addr)
	if err == nil {
		t.Fatal("expired user should fail")
	}
}

func TestFirewallPortBlocking(t *testing.T) {
	cfg := DefaultFirewallConfig()
	fw := NewFirewall(cfg)

	user := &UserRecord{ID: "test"}

	if fw.CheckConnection("test", "1.2.3.4", 25, user) {
		t.Fatal("port 25 should be blocked")
	}
	if fw.CheckConnection("test", "1.2.3.4", 587, user) {
		t.Fatal("port 587 should be blocked")
	}
	if !fw.CheckConnection("test", "1.2.3.4", 443, user) {
		t.Fatal("port 443 should be allowed")
	}
	if !fw.CheckConnection("test", "1.2.3.4", 80, user) {
		t.Fatal("port 80 should be allowed")
	}
}

func TestFirewallPrivateRange(t *testing.T) {
	cfg := DefaultFirewallConfig()
	fw := NewFirewall(cfg)
	user := &UserRecord{ID: "test"}

	if fw.CheckConnection("test", "192.168.1.1", 80, user) {
		t.Fatal("private IP should be blocked")
	}
	if fw.CheckConnection("test", "10.0.0.1", 80, user) {
		t.Fatal("private IP should be blocked")
	}
	if fw.CheckConnection("test", "127.0.0.1", 80, user) {
		t.Fatal("loopback should be blocked")
	}
	if !fw.CheckConnection("test", "8.8.8.8", 80, user) {
		t.Fatal("public IP should be allowed")
	}
}

func TestFirewallAllowedPorts(t *testing.T) {
	cfg := FirewallConfig{}
	fw := NewFirewall(cfg)

	user := &UserRecord{
		ID: "restricted",
		AllowedPorts: []PortRange{
			{From: 80, To: 80},
			{From: 443, To: 443},
		},
	}

	if !fw.CheckConnection("restricted", "1.1.1.1", 80, user) {
		t.Fatal("port 80 should be allowed")
	}
	if !fw.CheckConnection("restricted", "1.1.1.1", 443, user) {
		t.Fatal("port 443 should be allowed")
	}
	if fw.CheckConnection("restricted", "1.1.1.1", 8080, user) {
		t.Fatal("port 8080 should be blocked")
	}
}

func TestFirewallConnectionLimit(t *testing.T) {
	cfg := FirewallConfig{MaxConnectionsPerUser: 3}
	fw := NewFirewall(cfg)
	user := &UserRecord{ID: "test"}

	fw.OnConnect("test")
	fw.OnConnect("test")
	fw.OnConnect("test")

	if fw.CheckConnection("test", "1.1.1.1", 443, user) {
		t.Fatal("should hit connection limit")
	}

	fw.OnDisconnect("test")
	if !fw.CheckConnection("test", "1.1.1.1", 443, user) {
		t.Fatal("should allow after disconnect")
	}
}

func TestSubscriptionURL(t *testing.T) {
	config := &SubscriptionConfig{
		Version: 1,
		Name:    "Test VPN",
		Servers: []ServerEntry{
			{Address: "vpn1.example.com:443", PSK: "key1", SNI: "vpn1.example.com", Weight: 10, Transport: "tls"},
			{Address: "vpn2.example.com:443", PSK: "key2", SNI: "vpn2.example.com", Weight: 5, Transport: "quic"},
		},
		UpdateURL:      "https://config.example.com/sub/token123",
		UpdateInterval: 3600,
	}

	url, err := EncodeSubscriptionURL(config)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	if url[:14] != "stealthlink://" {
		t.Fatalf("bad scheme: %s", url[:14])
	}

	decoded, err := DecodeSubscriptionURL(url)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if decoded.Name != "Test VPN" {
		t.Fatalf("name: got %q", decoded.Name)
	}
	if len(decoded.Servers) != 2 {
		t.Fatalf("servers: got %d", len(decoded.Servers))
	}
	if decoded.Servers[0].Address != "vpn1.example.com:443" {
		t.Fatalf("server addr: got %q", decoded.Servers[0].Address)
	}
	if decoded.Servers[1].Transport != "quic" {
		t.Fatalf("transport: got %q", decoded.Servers[1].Transport)
	}
	if decoded.UpdateURL != "https://config.example.com/sub/token123" {
		t.Fatalf("update url: got %q", decoded.UpdateURL)
	}
}

func TestServerSelector(t *testing.T) {
	servers := []ServerEntry{
		{Address: "a:443", Weight: 100},
		{Address: "b:443", Weight: 1},
	}

	ss := NewServerSelector(servers)

	counts := map[string]int{}
	for i := 0; i < 1000; i++ {
		s := ss.SelectServer()
		counts[s.Address]++
	}

	if counts["a:443"] < 800 {
		t.Fatalf("weighted selection broken: a=%d b=%d", counts["a:443"], counts["b:443"])
	}
}

func TestBuildTransportVariants(t *testing.T) {
	variants := buildTransportVariants(ServerEntry{Address: "a:443", Transport: "auto"}, "quic")
	if len(variants) != 2 {
		t.Fatalf("expected 2 variants, got %d", len(variants))
	}
	if variants[0].Transport != "quic" || variants[1].Transport != "tls" {
		t.Fatalf("unexpected order for auto/quic preference: %q then %q", variants[0].Transport, variants[1].Transport)
	}

	variants = buildTransportVariants(ServerEntry{Address: "a:443", Transport: "tls"}, "quic")
	if variants[0].Transport != "tls" || variants[1].Transport != "quic" {
		t.Fatalf("unexpected order for explicit tls: %q then %q", variants[0].Transport, variants[1].Transport)
	}
}

func TestServerSelectorRankServerGroupsPrefersHealthyTransport(t *testing.T) {
	ss := NewServerSelector([]ServerEntry{
		{Address: "edge.example.com:443", Weight: 1, Transport: "auto"},
	})

	ss.ReportDialResult(ServerEntry{Address: "edge.example.com:443", Weight: 1, Transport: "quic"}, 0, fmt.Errorf("quic dial failed"))
	ss.ReportDialResult(ServerEntry{Address: "edge.example.com:443", Weight: 1, Transport: "tls"}, 20*time.Millisecond, nil)

	groups := ss.RankServerGroups("quic")
	if len(groups) != 1 {
		t.Fatalf("expected single group, got %d", len(groups))
	}
	if len(groups[0].Variants) != 2 {
		t.Fatalf("expected 2 variants, got %d", len(groups[0].Variants))
	}
	if groups[0].Variants[0].Transport != "tls" {
		t.Fatalf("expected tls to be preferred after quic failure, got %q", groups[0].Variants[0].Transport)
	}
}

func TestServerSelectorRankServerGroupsPrefersHealthyServer(t *testing.T) {
	ss := NewServerSelector([]ServerEntry{
		{Address: "bad.example.com:443", Weight: 1, Transport: "auto"},
		{Address: "good.example.com:443", Weight: 1, Transport: "auto"},
	})

	ss.ReportDialResult(ServerEntry{Address: "bad.example.com:443", Weight: 1, Transport: "tls"}, 0, fmt.Errorf("timeout"))
	ss.ReportDialResult(ServerEntry{Address: "good.example.com:443", Weight: 1, Transport: "tls"}, 15*time.Millisecond, nil)

	groups := ss.RankServerGroups("tls")
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}
	if groups[0].Base.Address != "good.example.com:443" {
		t.Fatalf("expected healthy server first, got %q", groups[0].Base.Address)
	}
}

func TestPaddingEngine(t *testing.T) {
	buf := &bytes.Buffer{}
	writer := NewFrameWriter(buf)

	cfg := DefaultPaddingConfig()
	cfg.DummyInterval = 100 * time.Millisecond
	pe := NewPaddingEngine(writer, cfg)

	time.Sleep(300 * time.Millisecond)
	pe.Stop()
	writer.Flush()

	if buf.Len() == 0 {
		t.Fatal("padding engine should have generated dummy traffic")
	}
}

func TestNormalizePacketSize(t *testing.T) {
	data := make([]byte, 50)
	normalized := NormalizePacketSize(data)
	if len(normalized) != 64 {
		t.Fatalf("normalized to %d, expected 64", len(normalized))
	}

	data = make([]byte, 100)
	normalized = NormalizePacketSize(data)
	if len(normalized) != 128 {
		t.Fatalf("normalized to %d, expected 128", len(normalized))
	}
}

func TestAuthFrameEncoding(t *testing.T) {
	frame, err := EncodeAuthFrame("test-psk")
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	if frame.Type != FrameAuth {
		t.Fatalf("wrong type: %d", frame.Type)
	}
	if len(frame.Payload) != 56 {
		t.Fatalf("payload length: got %d, want 56", len(frame.Payload))
	}
}

func TestCloseFrame(t *testing.T) {
	frame := EncodeCloseFrame(42)
	if frame.Type != FrameClose {
		t.Fatalf("wrong type")
	}
	if len(frame.Payload) != 2 {
		t.Fatalf("payload length: %d", len(frame.Payload))
	}
	sid := binary.BigEndian.Uint16(frame.Payload)
	if sid != 42 {
		t.Fatalf("stream id: %d", sid)
	}
}

func TestUDPCloseFrame(t *testing.T) {
	frame := EncodeUDPCloseFrame(17)
	if frame.Type != FrameUDPClose {
		t.Fatalf("wrong type")
	}

	assocID, err := DecodeUDPCloseFrame(frame.Payload)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if assocID != 17 {
		t.Fatalf("assoc id: got %d", assocID)
	}
}

func TestSOCKSUDPDatagram(t *testing.T) {
	data := []byte("voice payload")
	packet := EncodeSOCKSUDPDatagram(AddrDomain, "discord.media", 50000, data)

	addrType, addr, port, decodedData, err := DecodeSOCKSUDPDatagram(packet)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if addrType != AddrDomain {
		t.Fatalf("addr type: got %d", addrType)
	}
	if addr != "discord.media" {
		t.Fatalf("addr: got %q", addr)
	}
	if port != 50000 {
		t.Fatalf("port: got %d", port)
	}
	if !bytes.Equal(decodedData, data) {
		t.Fatalf("data mismatch")
	}
}

func TestDecodeSOCKSUDPDatagramRejectsFragments(t *testing.T) {
	packet := EncodeSOCKSUDPDatagram(AddrIPv4, "1.1.1.1", 53, []byte("dns"))
	packet[2] = 0x01

	if _, _, _, _, err := DecodeSOCKSUDPDatagram(packet); err == nil {
		t.Fatal("expected fragmented packet to be rejected")
	}
}
