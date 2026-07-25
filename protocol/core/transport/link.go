// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

package transport

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Share-link import/export for the two industry-standard protocols, so
// servers configured here can be dropped into (or imported from) v2rayN /
// NekoBox / Xray-core style clients.
//
//	vless://<uuid>@host:port?encryption=none&security=tls&sni=...&fp=...&type=xhttp&host=...&path=...&mode=...#remark
//	trojan://<password>@host:port?security=tls&sni=...&type=grpc&serviceName=...&mode=gun#remark
//
// XHTTP's extra padding/anti-detection knobs (xPaddingBytes, scMax...) have
// no standardized share-link query params across the ecosystem yet, so they
// round-trip through our own "extra=<base64-json>" param: it survives
// between our own client and generator and is simply ignored by other
// clients that don't recognize it.

func ParseVlessLink(uri string) (*ServerEntry, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("vless link: %w", err)
	}
	if u.Scheme != "vless" {
		return nil, fmt.Errorf("vless link: unexpected scheme %q", u.Scheme)
	}
	if u.User == nil || u.User.Username() == "" {
		return nil, fmt.Errorf("vless link: missing uuid")
	}
	host := u.Hostname()
	port := u.Port()
	if host == "" || port == "" {
		return nil, fmt.Errorf("vless link: missing host/port")
	}

	q := u.Query()
	if t := q.Get("type"); t != "" && t != "xhttp" {
		return nil, fmt.Errorf("vless link: unsupported transport type %q (only xhttp is supported)", t)
	}

	entry := &ServerEntry{
		Address:     net.JoinHostPort(host, port),
		UUID:        u.User.Username(),
		SNI:         q.Get("sni"),
		Transport:   "vless-xhttp",
		Fingerprint: q.Get("fp"),
		XHTTP: &XHTTPConfig{
			Path: q.Get("path"),
			Host: q.Get("host"),
			Mode: q.Get("mode"),
		},
	}

	if extraB64 := q.Get("extra"); extraB64 != "" {
		if raw, derr := base64.RawURLEncoding.DecodeString(extraB64); derr == nil {
			var extra XHTTPExtra
			if json.Unmarshal(raw, &extra) == nil {
				entry.XHTTP.Extra = extra
			}
		}
	}

	return entry, nil
}

func GenerateVlessLink(entry *ServerEntry, remark string) (string, error) {
	if entry.UUID == "" {
		return "", fmt.Errorf("vless link: entry has no uuid")
	}
	host, port, err := net.SplitHostPort(entry.Address)
	if err != nil {
		return "", fmt.Errorf("vless link: invalid address %q: %w", entry.Address, err)
	}

	q := url.Values{}
	q.Set("encryption", "none")
	q.Set("security", "tls")
	q.Set("type", "xhttp")
	if entry.SNI != "" {
		q.Set("sni", entry.SNI)
	}
	if entry.Fingerprint != "" {
		q.Set("fp", entry.Fingerprint)
	}
	if entry.XHTTP != nil {
		if entry.XHTTP.Path != "" {
			q.Set("path", entry.XHTTP.Path)
		}
		if entry.XHTTP.Host != "" {
			q.Set("host", entry.XHTTP.Host)
		}
		if entry.XHTTP.Mode != "" {
			q.Set("mode", entry.XHTTP.Mode)
		}
		if raw, jerr := json.Marshal(entry.XHTTP.Extra); jerr == nil && string(raw) != "{}" {
			q.Set("extra", base64.RawURLEncoding.EncodeToString(raw))
		}
	}

	u := url.URL{
		Scheme:   "vless",
		User:     url.User(entry.UUID),
		Host:     net.JoinHostPort(host, port),
		RawQuery: q.Encode(),
		Fragment: remark,
	}
	return u.String(), nil
}

func ParseTrojanLink(uri string) (*ServerEntry, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("trojan link: %w", err)
	}
	if u.Scheme != "trojan" {
		return nil, fmt.Errorf("trojan link: unexpected scheme %q", u.Scheme)
	}
	if u.User == nil || u.User.Username() == "" {
		return nil, fmt.Errorf("trojan link: missing password")
	}
	host := u.Hostname()
	port := u.Port()
	if host == "" || port == "" {
		return nil, fmt.Errorf("trojan link: missing host/port")
	}

	q := u.Query()
	if t := q.Get("type"); t != "" && t != "grpc" {
		return nil, fmt.Errorf("trojan link: unsupported transport type %q (only grpc is supported)", t)
	}

	sec := q.Get("security")
	if sec != "" && sec != "tls" && sec != "reality" {
		return nil, fmt.Errorf("trojan link: unsupported security %q (only tls and reality are supported)", sec)
	}

	grpcCfg := &GRPCConfig{
		ServiceName: q.Get("serviceName"),
		MultiMode:   q.Get("mode") == "multi",
		Authority:   q.Get("authority"),
	}
	if sec == "reality" {
		if q.Get("pbk") == "" || q.Get("sid") == "" {
			return nil, fmt.Errorf("trojan link: security=reality requires pbk and sid")
		}
		grpcCfg.Security = "reality"
		grpcCfg.RealityPublicKey = q.Get("pbk")
		grpcCfg.RealityShortID = q.Get("sid")
		// pqv (post-quantum REALITY key material) isn't implemented here -
		// if the server enforces it, our classic-only ClientHello won't be
		// recognized and the connection will transparently fall through
		// to the server's decoy destination instead of reaching Trojan.
	}

	return &ServerEntry{
		Address:        net.JoinHostPort(host, port),
		TrojanPassword: u.User.Username(),
		SNI:            q.Get("sni"),
		Transport:      "trojan-grpc",
		Fingerprint:    q.Get("fp"),
		GRPC:           grpcCfg,
	}, nil
}

func GenerateTrojanLink(entry *ServerEntry, remark string) (string, error) {
	if entry.TrojanPassword == "" {
		return "", fmt.Errorf("trojan link: entry has no password")
	}
	host, port, err := net.SplitHostPort(entry.Address)
	if err != nil {
		return "", fmt.Errorf("trojan link: invalid address %q: %w", entry.Address, err)
	}

	q := url.Values{}
	q.Set("security", "tls")
	q.Set("type", "grpc")
	q.Set("mode", "gun")
	if entry.SNI != "" {
		q.Set("sni", entry.SNI)
	}
	if entry.Fingerprint != "" {
		q.Set("fp", entry.Fingerprint)
	}
	if entry.GRPC != nil {
		if entry.GRPC.ServiceName != "" {
			q.Set("serviceName", entry.GRPC.ServiceName)
		}
		if entry.GRPC.MultiMode {
			q.Set("mode", "multi")
		}
		if entry.GRPC.Authority != "" {
			q.Set("authority", entry.GRPC.Authority)
		}
		if entry.GRPC.Security == "reality" {
			q.Set("security", "reality")
			q.Set("pbk", entry.GRPC.RealityPublicKey)
			q.Set("sid", entry.GRPC.RealityShortID)
		}
	}

	u := url.URL{
		Scheme:   "trojan",
		User:     url.User(entry.TrojanPassword),
		Host:     net.JoinHostPort(host, port),
		RawQuery: q.Encode(),
		Fragment: remark,
	}
	return u.String(), nil
}

// ImportLink dispatches on URI scheme: stealthlink://, vless://, trojan://.
// For a stealthlink:// subscription carrying multiple servers, the first
// entry is returned - callers that want the full list should call
// DecodeSubscriptionURL directly instead.
func ImportLink(uri string) (*ServerEntry, error) {
	switch {
	case strings.HasPrefix(uri, "vless://"):
		return ParseVlessLink(uri)
	case strings.HasPrefix(uri, "trojan://"):
		return ParseTrojanLink(uri)
	case strings.HasPrefix(uri, subscriptionScheme):
		cfg, err := DecodeSubscriptionURL(uri)
		if err != nil {
			return nil, err
		}
		if len(cfg.Servers) == 0 {
			return nil, fmt.Errorf("subscription has no servers")
		}
		return &cfg.Servers[0], nil
	default:
		return nil, fmt.Errorf("unrecognized link scheme")
	}
}
