// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

package transport

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	grpcinsecure "google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/keepalive"
)

// gRPC "Gun" transport (Xray-compatible): a raw byte-stream carrier, one
// bidirectional gRPC stream per proxied connection, multiplexed over a
// single shared HTTP/2 connection. Like XHTTP, it never sees auth data -
// that lives entirely inside the tunneled bytes (Trojan, in this build).
type GRPCConfig struct {
	ServiceName string `json:"serviceName"`
	// MultiMode selects Xray's "TunMulti" method/message shape instead of
	// plain "Tun". The server always registers both regardless of this
	// setting (real Xray does the same - server accepts either from any
	// client); MultiMode only controls which one *this client* dials with.
	MultiMode bool `json:"multiMode"`
	// Authority overrides the gRPC :authority pseudo-header (like an HTTP
	// Host override) - useful behind a CDN where the TLS SNI and the
	// logical gRPC service host differ. Falls back to the TLS SNI when
	// unset, matching Xray's own precedence.
	Authority           string `json:"authority,omitempty"`
	IdleTimeout         int    `json:"idle_timeout"`
	HealthCheckTimeout  int    `json:"health_check_timeout"`
	PermitWithoutStream bool   `json:"permit_without_stream"`
	InitialWindowsSize  int    `json:"initial_windows_size"`
	UserAgent           string `json:"user_agent"`

	// Security selects the TLS-layer strategy: "" or "tls" (default, plain
	// TLS/uTLS with the server's configured cert) or "reality". REALITY
	// replaces the TLS handshake with the scheme the standalone "reality"
	// transport uses (see reality.go) - probes that don't present a valid
	// token get transparently proxied to Reality.Dest instead of seeing
	// our service at all.
	Security string `json:"security,omitempty"`
	// RealityPublicKey/RealityShortID/RealityMldsa65Verify are the
	// client-side REALITY credentials (dialing a reality-protected
	// server). RealityMldsa65Verify is the optional post-quantum
	// signature public key ("pqv" in share links) - leave empty to skip
	// that check.
	RealityPublicKey     string `json:"reality_public_key,omitempty"`
	RealityShortID       string `json:"reality_short_id,omitempty"`
	RealityMldsa65Verify string `json:"reality_mldsa65_verify,omitempty"`
	// Reality is the server-side REALITY configuration (protecting this
	// server) - same shape as the standalone reality transport's config.
	Reality RealityConfig `json:"reality,omitempty"`
}

func grpc_security(cfg GRPCConfig) string {
	switch cfg.Security {
	case "reality":
		return "reality"
	default:
		return "tls"
	}
}

const (
	grpcTunMethod      = "Tun"
	grpcTunMultiMethod = "TunMulti"
	// grpcDefaultServiceName mirrors Xray's compiled-in default (the full
	// proto package + service name) used when serviceName is left empty -
	// see transport/internet/grpc/encoding/stream.proto in Xray-core.
	grpcDefaultServiceName = "xray.transport.internet.grpc.encoding.GRPCService"
)

func grpc_service_name(cfg GRPCConfig) string {
	if cfg.ServiceName != "" {
		return cfg.ServiceName
	}
	return grpcDefaultServiceName
}

// --- wire codec ---
//
// Xray's GRPCService exchanges two message shapes (see stream.proto in
// Xray-core): `message Hunk { bytes data = 1; }` for the plain "Tun"
// method, and `message MultiHunk { repeated bytes data = 1; }` for
// "TunMulti" (used to batch several chunks into one gRPC message and cut
// per-message framing overhead). Both only ever touch field 1, so their
// wire encoding is fully deterministic and can be hand-rolled without
// pulling in protoc-generated code. This implementation always sends
// MultiHunk with exactly one element per message rather than batching -
// still wire-correct (a real Xray receiver handles any element count) but
// doesn't reproduce Xray's own send-side batching optimization.
type hunkMsg struct {
	Data []byte
}

type multiHunkMsg struct {
	Data [][]byte
}

func encodeHunkWire(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	return appendLenDelimField(nil, data)
}

func decodeHunkWire(buf []byte) ([]byte, error) {
	if len(buf) == 0 {
		return nil, nil
	}
	data, rest, err := readLenDelimField(buf)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("grpc: trailing bytes after hunk field")
	}
	return data, nil
}

func encodeMultiHunkWire(chunks [][]byte) []byte {
	var buf []byte
	for _, c := range chunks {
		buf = appendLenDelimField(buf, c)
	}
	return buf
}

func decodeMultiHunkWire(buf []byte) ([][]byte, error) {
	var out [][]byte
	for len(buf) > 0 {
		data, rest, err := readLenDelimField(buf)
		if err != nil {
			return nil, err
		}
		out = append(out, data)
		buf = rest
	}
	return out, nil
}

// appendLenDelimField appends one protobuf field-1/wiretype-2 entry (tag
// 0x0A + varint length + bytes) to buf. Used for both Hunk.data (a single
// bytes field) and MultiHunk.data (a repeated bytes field, which on the
// wire is just this same tag repeated once per element).
func appendLenDelimField(buf, data []byte) []byte {
	var varintBuf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(varintBuf[:], uint64(len(data)))
	buf = append(buf, 0x0A)
	buf = append(buf, varintBuf[:n]...)
	buf = append(buf, data...)
	return buf
}

func readLenDelimField(buf []byte) (data, rest []byte, err error) {
	if buf[0] != 0x0A {
		return nil, nil, fmt.Errorf("grpc: unexpected field tag 0x%02x", buf[0])
	}
	length, n := binary.Uvarint(buf[1:])
	if n <= 0 {
		return nil, nil, fmt.Errorf("grpc: malformed field length")
	}
	start := 1 + n
	end := start + int(length)
	if end > len(buf) {
		return nil, nil, fmt.Errorf("grpc: field length overruns buffer")
	}
	return buf[start:end], buf[end:], nil
}

// hunkCodec is registered under the name "proto", overriding grpc-go's
// default codec registration for this process. This keeps the wire
// content-type as the bare "application/grpc" (no "+subtype") that any
// real gRPC/Xray Gun endpoint expects, instead of a private
// "application/grpc+customname" only our own client/server would
// understand. Safe here because this process doesn't use gRPC for
// anything else.
type hunkCodec struct{}

func (hunkCodec) Marshal(v interface{}) ([]byte, error) {
	switch m := v.(type) {
	case *hunkMsg:
		return encodeHunkWire(m.Data), nil
	case *multiHunkMsg:
		return encodeMultiHunkWire(m.Data), nil
	default:
		return nil, fmt.Errorf("grpc: unsupported message type %T", v)
	}
}

func (hunkCodec) Unmarshal(data []byte, v interface{}) error {
	switch m := v.(type) {
	case *hunkMsg:
		d, err := decodeHunkWire(data)
		if err != nil {
			return err
		}
		m.Data = d
		return nil
	case *multiHunkMsg:
		d, err := decodeMultiHunkWire(data)
		if err != nil {
			return err
		}
		m.Data = d
		return nil
	default:
		return fmt.Errorf("grpc: unsupported message type %T", v)
	}
}

func (hunkCodec) Name() string { return "proto" }

func init() {
	encoding.RegisterCodec(hunkCodec{})
}

// --- net.Conn adapter over a gRPC bidi stream ---

type grpcMsgStream interface {
	SendMsg(m interface{}) error
	RecvMsg(m interface{}) error
}

type grpc_stream_conn struct {
	stream  grpcMsgStream
	readBuf []byte
	closeFn func() error
}

func newGrpcStreamConn(stream grpcMsgStream, closeFn func() error) *grpc_stream_conn {
	return &grpc_stream_conn{stream: stream, closeFn: closeFn}
}

// Read/Write are each only ever called from a single dedicated goroutine
// (BidirectionalRelay's two io.CopyBuffer directions), which matches
// grpc-go's documented safe-concurrency contract: SendMsg and RecvMsg may
// run concurrently with each other, just not with themselves.
func (c *grpc_stream_conn) Read(b []byte) (int, error) {
	for len(c.readBuf) == 0 {
		var m hunkMsg
		if err := c.stream.RecvMsg(&m); err != nil {
			return 0, err
		}
		c.readBuf = m.Data
	}
	n := copy(b, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *grpc_stream_conn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if err := c.stream.SendMsg(&hunkMsg{Data: b}); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *grpc_stream_conn) Close() error {
	if c.closeFn != nil {
		return c.closeFn()
	}
	return nil
}

// grpc_multi_stream_conn is the TunMulti counterpart of grpc_stream_conn:
// same net.Conn adapter, but each message on the wire is a MultiHunk
// (repeated bytes) rather than a single Hunk. Every Write here sends a
// MultiHunk with exactly one element - see the wire codec comment above.
type grpc_multi_stream_conn struct {
	stream  grpcMsgStream
	readBuf []byte
	closeFn func() error
}

func newGrpcMultiStreamConn(stream grpcMsgStream, closeFn func() error) *grpc_multi_stream_conn {
	return &grpc_multi_stream_conn{stream: stream, closeFn: closeFn}
}

func (c *grpc_multi_stream_conn) Read(b []byte) (int, error) {
	for len(c.readBuf) == 0 {
		var m multiHunkMsg
		if err := c.stream.RecvMsg(&m); err != nil {
			return 0, err
		}
		for _, chunk := range m.Data {
			c.readBuf = append(c.readBuf, chunk...)
		}
	}
	n := copy(b, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *grpc_multi_stream_conn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if err := c.stream.SendMsg(&multiHunkMsg{Data: [][]byte{b}}); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *grpc_multi_stream_conn) Close() error {
	if c.closeFn != nil {
		return c.closeFn()
	}
	return nil
}

func (c *grpc_multi_stream_conn) LocalAddr() net.Addr                { return grpcAddr{} }
func (c *grpc_multi_stream_conn) RemoteAddr() net.Addr               { return grpcAddr{} }
func (c *grpc_multi_stream_conn) SetDeadline(_ time.Time) error      { return nil }
func (c *grpc_multi_stream_conn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *grpc_multi_stream_conn) SetWriteDeadline(_ time.Time) error { return nil }

type grpcAddr struct{}

func (grpcAddr) Network() string { return "grpc" }
func (grpcAddr) String() string  { return "grpc" }

func (c *grpc_stream_conn) LocalAddr() net.Addr                { return grpcAddr{} }
func (c *grpc_stream_conn) RemoteAddr() net.Addr               { return grpcAddr{} }
func (c *grpc_stream_conn) SetDeadline(_ time.Time) error      { return nil }
func (c *grpc_stream_conn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *grpc_stream_conn) SetWriteDeadline(_ time.Time) error { return nil }

func grpc_keepalive_times(cfg GRPCConfig) (t, timeout time.Duration) {
	t = time.Duration(cfg.IdleTimeout) * time.Second
	if t <= 0 {
		t = 20 * time.Second
	}
	timeout = time.Duration(cfg.HealthCheckTimeout) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return
}

// --- server side ---

// grpc_service_desc registers both the plain "Tun" and batched "TunMulti"
// streams under one ServiceDesc, regardless of this server's own MultiMode
// setting - matching real Xray-core, which always accepts either from any
// client and lets the *client's* config pick which one it dials with.
func grpc_service_desc(cfg GRPCConfig, onConn func(net.Conn)) *grpc.ServiceDesc {
	return &grpc.ServiceDesc{
		ServiceName: grpc_service_name(cfg),
		HandlerType: (*any)(nil),
		Streams: []grpc.StreamDesc{
			{
				StreamName:    grpcTunMethod,
				Handler:       grpc_tun_handler(onConn),
				ServerStreams: true,
				ClientStreams: true,
			},
			{
				StreamName:    grpcTunMultiMethod,
				Handler:       grpc_tun_multi_handler(onConn),
				ServerStreams: true,
				ClientStreams: true,
			},
		},
		Metadata: "gun.proto",
	}
}

func grpc_tun_handler(onConn func(net.Conn)) func(interface{}, grpc.ServerStream) error {
	return func(_ interface{}, stream grpc.ServerStream) error {
		conn := newGrpcStreamConn(stream, func() error { return nil })
		onConn(conn)
		return nil
	}
}

func grpc_tun_multi_handler(onConn func(net.Conn)) func(interface{}, grpc.ServerStream) error {
	return func(_ interface{}, stream grpc.ServerStream) error {
		conn := newGrpcMultiStreamConn(stream, func() error { return nil })
		onConn(conn)
		return nil
	}
}

// grpc_new_server builds the gRPC server. tlsConfig is only used (and must
// be non-nil) when cfg.Security != "reality" - in REALITY mode, TLS is
// instead handled per-connection by realityServerCreds, which delegates
// entirely to reality.go's reality_server (backed by github.com/xtls/reality)
// before grpc-go ever sees the connection as HTTP/2.
func grpc_new_server(tlsConfig *tls.Config, replayFilter *ReplayFilter, cfg GRPCConfig, onConn func(net.Conn)) (*grpc.Server, error) {
	kaTime, kaTimeout := grpc_keepalive_times(cfg)

	var credsOpt grpc.ServerOption
	if grpc_security(cfg) == "reality" {
		rs, err := new_reality_server(cfg.Reality)
		if err != nil {
			return nil, fmt.Errorf("grpc: reality setup failed: %w", err)
		}
		credsOpt = grpc.Creds(&realityServerCreds{server: rs})
	} else {
		credsOpt = grpc.Creds(credentials.NewTLS(tlsConfig))
	}

	opts := []grpc.ServerOption{
		credsOpt,
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    kaTime,
			Timeout: kaTimeout,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             5 * time.Second,
			PermitWithoutStream: cfg.PermitWithoutStream,
		}),
	}
	if cfg.InitialWindowsSize > 0 {
		opts = append(opts, grpc.InitialWindowSize(int32(cfg.InitialWindowsSize)))
	}

	srv := grpc.NewServer(opts...)
	srv.RegisterService(grpc_service_desc(cfg, onConn), nil)
	return srv, nil
}

// realityServerCreds implements credentials.TransportCredentials by
// layering REALITY (see reality.go's reality_server) in place of a plain
// TLS handshake. grpc-go invokes ServerHandshake from its own
// per-connection goroutine (spawned right after Accept), so this never
// blocks acceptance of other connections - unlike wrapping the
// net.Listener itself would.
type realityServerCreds struct {
	server *reality_server
}

type realityAuthInfo struct{}

func (realityAuthInfo) AuthType() string { return "reality" }

func (c *realityServerCreds) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	// reality_server.accept already fully handles both outcomes: on
	// success it hands back a handshake-complete net.Conn; on failure it
	// has already run the transparent live-mirrored fallback relay to
	// Dest and closed rawConn itself.
	conn, err := c.server.accept(context.Background(), rawConn)
	if err != nil {
		return nil, nil, err
	}
	return conn, realityAuthInfo{}, nil
}

func (c *realityServerCreds) ClientHandshake(context.Context, string, net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, fmt.Errorf("reality: server credentials do not support client handshake")
}

func (c *realityServerCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "tls"}
}

func (c *realityServerCreds) Clone() credentials.TransportCredentials {
	return &realityServerCreds{server: c.server}
}

func (c *realityServerCreds) OverrideServerName(string) error { return nil }

// --- client side ---

type grpc_client struct {
	conn        *grpc.ClientConn
	serviceName string
	multiMode   bool
}

func grpc_dial(serverAddr, sni string, cfg GRPCConfig, fingerprint string, insecureSkip bool) (*grpc_client, error) {
	var dialer func(ctx context.Context, addr string) (net.Conn, error)

	if grpc_security(cfg) == "reality" {
		pub, err := parse_x25519_public(cfg.RealityPublicKey)
		if err != nil {
			return nil, fmt.Errorf("grpc: reality public key: %w", err)
		}
		sid, err := parse_short_id(cfg.RealityShortID)
		if err != nil {
			return nil, fmt.Errorf("grpc: reality short id: %w", err)
		}
		var mldsa65Verify []byte
		if cfg.RealityMldsa65Verify != "" {
			mldsa65Verify, err = decode_b64_any(cfg.RealityMldsa65Verify)
			if err != nil {
				return nil, fmt.Errorf("grpc: reality mldsa65 verify key: %w", err)
			}
		}
		dialer = func(ctx context.Context, addr string) (net.Conn, error) {
			return reality_dial_ctx(ctx, addr, sni, fingerprint, []string{"h2"}, pub, sid, mldsa65Verify)
		}
	} else {
		dialer = func(ctx context.Context, addr string) (net.Conn, error) {
			raw, err := (&net.Dialer{Timeout: xhttp_dial_deadline}).DialContext(ctx, "tcp", addr)
			if err != nil {
				return nil, err
			}
			uconn := utls.UClient(raw, &utls.Config{
				ServerName:         sni,
				InsecureSkipVerify: insecureSkip,
				NextProtos:         []string{"h2"},
			}, reality_hello_id(fingerprint))
			if err := uconn.HandshakeContext(ctx); err != nil {
				raw.Close()
				return nil, err
			}
			return uconn, nil
		}
	}

	kaTime, kaTimeout := grpc_keepalive_times(cfg)

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(grpcinsecure.NewCredentials()),
		grpc.WithContextDialer(dialer),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                kaTime,
			Timeout:             kaTimeout,
			PermitWithoutStream: cfg.PermitWithoutStream,
		}),
	}
	if cfg.InitialWindowsSize > 0 {
		opts = append(opts, grpc.WithInitialWindowSize(int32(cfg.InitialWindowsSize)))
	}
	if cfg.UserAgent != "" {
		opts = append(opts, grpc.WithUserAgent(cfg.UserAgent))
	}

	// Authority precedence matches Xray: explicit config value, else the
	// TLS SNI we're dialing with.
	authority := cfg.Authority
	if authority == "" {
		authority = sni
	}
	if authority != "" {
		opts = append(opts, grpc.WithAuthority(authority))
	}

	conn, err := grpc.NewClient(serverAddr, opts...)
	if err != nil {
		return nil, fmt.Errorf("grpc: dial failed: %w", err)
	}
	return &grpc_client{conn: conn, serviceName: grpc_service_name(cfg), multiMode: cfg.MultiMode}, nil
}

func (g *grpc_client) open() (net.Conn, error) {
	ctx := context.Background()

	if g.multiMode {
		desc := &grpc.StreamDesc{StreamName: grpcTunMultiMethod, ServerStreams: true, ClientStreams: true}
		method := "/" + g.serviceName + "/" + grpcTunMultiMethod
		stream, err := g.conn.NewStream(ctx, desc, method)
		if err != nil {
			return nil, fmt.Errorf("grpc: multi stream open failed: %w", err)
		}
		return newGrpcMultiStreamConn(stream, func() error { return stream.CloseSend() }), nil
	}

	desc := &grpc.StreamDesc{StreamName: grpcTunMethod, ServerStreams: true, ClientStreams: true}
	method := "/" + g.serviceName + "/" + grpcTunMethod
	stream, err := g.conn.NewStream(ctx, desc, method)
	if err != nil {
		return nil, fmt.Errorf("grpc: stream open failed: %w", err)
	}
	return newGrpcStreamConn(stream, func() error { return stream.CloseSend() }), nil
}

func (g *grpc_client) Close() error {
	if g.conn != nil {
		return g.conn.Close()
	}
	return nil
}
