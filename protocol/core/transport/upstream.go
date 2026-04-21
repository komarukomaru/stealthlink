// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

package transport

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

func DialVPNServer(serverAddr, sni, psk, secretPath, fingerprint string, addrType byte, addr string, port uint16) (net.Conn, error) {
	if sni == "" {
		host, _, _ := net.SplitHostPort(serverAddr)
		sni = host
	}

	conn, err := DialTransport(serverAddr, sni, fingerprint)
	if err != nil {
		return nil, err
	}

	authPayload, err := GenerateAuthPayload(psk)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("auth generation failed: %w", err)
	}

	addrHeader := EncodeAddress(addrType, addr, port)

	if secretPath != "" {
		httpReq := fmt.Sprintf("POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Authorization: Bearer %s\r\n"+
			"Content-Type: application/octet-stream\r\n"+
			"Connection: keep-alive\r\n"+
			"\r\n", secretPath, sni, base64.StdEncoding.EncodeToString(authPayload))

		if _, err := conn.Write([]byte(httpReq)); err != nil {
			conn.Close()
			return nil, fmt.Errorf("HTTP request write failed: %w", err)
		}

		respBuf := make([]byte, 4096)
		conn.SetDeadline(time.Now().Add(15 * time.Second))
		n, err := conn.Read(respBuf)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("HTTP response read failed: %w", err)
		}

		resp := string(respBuf[:n])
		if len(resp) < 12 || resp[9:12] != "200" {
			conn.Close()
			return nil, fmt.Errorf("auth failed: %s", resp[:min(50, len(resp))])
		}
		conn.SetDeadline(time.Time{})

		if _, err := conn.Write(addrHeader); err != nil {
			conn.Close()
			return nil, fmt.Errorf("address write failed: %w", err)
		}
	} else {
		combined := make([]byte, len(authPayload)+len(addrHeader))
		copy(combined, authPayload)
		copy(combined[len(authPayload):], addrHeader)
		if _, err := conn.Write(combined); err != nil {
			conn.Close()
			return nil, fmt.Errorf("auth+address write failed: %w", err)
		}
	}

	status := make([]byte, 1)
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := io.ReadFull(conn, status); err != nil {
		conn.Close()
		return nil, fmt.Errorf("status read failed: %w", err)
	}
	conn.SetDeadline(time.Time{})

	if status[0] != 0x00 {
		conn.Close()
		switch status[0] {
		case 0x01:
			return nil, fmt.Errorf("authentication denied")
		case 0x02:
			return nil, fmt.Errorf("target connection failed")
		case 0x03:
			return nil, fmt.Errorf("blocked by firewall")
		default:
			return nil, fmt.Errorf("connect error: status=%d", status[0])
		}
	}

	return conn, nil
}

func DialUpstream(config *UpstreamConfig, addrType byte, addr string, port uint16) (net.Conn, error) {
	secretPath := config.SecretPath
	if secretPath == "" {
		secretPath = "/api/v2/sync"
	}
	return DialVPNServer(config.Address, config.SNI, config.PSK, secretPath, config.Fingerprint, addrType, addr, port)
}

func DialTransport(serverAddr, sni, fingerprint string) (net.Conn, error) {
	var conn net.Conn
	var err error

	if fingerprint == "" {
		tlsConf := &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
			NextProtos:         []string{"http/1.1"},
		}

		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: 15 * time.Second}, "tcp", serverAddr, tlsConf)
		if err != nil {
			return nil, fmt.Errorf("TLS dial failed: %w", err)
		}
	} else {
		conn, err = dialUTLS(serverAddr, sni, fingerprint)
		if err != nil {
			return nil, err
		}
	}
	TuneTCPConn(conn)
	return conn, nil
}

func dialUTLS(serverAddr, sni, fingerprint string) (net.Conn, error) {
	// https://github.com/komarukomaru/stealthlink/issues/2
	var helloID utls.ClientHelloID
	switch strings.ToLower(fingerprint) {
	case "chrome":
		helloID = utls.HelloChrome_Auto
	case "firefox":
		helloID = utls.HelloFirefox_Auto
	case "edge":
		helloID = utls.HelloEdge_Auto
	case "safari":
		helloID = utls.HelloSafari_Auto
	case "ios":
		helloID = utls.HelloIOS_Auto
	case "android":
		helloID = utls.HelloAndroid_11_OkHttp
	case "360":
		helloID = utls.Hello360_Auto
	case "qq":
		helloID = utls.HelloQQ_Auto
	case "random":
		helloID = utls.HelloRandomized
	default:
		helloID = utls.HelloChrome_Auto
	}

	config := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
	}

	conn, err := net.DialTimeout("tcp", serverAddr, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("TCP dial failed: %w", err)
	}

	uConn := utls.UClient(conn, config, helloID)
	if err := uConn.Handshake(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("uTLS handshake failed: %w", err)
	}

	return uConn, nil
}
