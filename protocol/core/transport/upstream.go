package transport

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"time"
)

func DialVPNServer(serverAddr, sni, psk, secretPath string, addrType byte, addr string, port uint16) (net.Conn, error) {
	if sni == "" {
		host, _, _ := net.SplitHostPort(serverAddr)
		sni = host
	}

	tlsConf := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"http/1.1"},
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 15 * time.Second}, "tcp", serverAddr, tlsConf)
	if err != nil {
		return nil, fmt.Errorf("TLS dial failed: %w", err)
	}
	TuneTCPConn(conn)

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
	return DialVPNServer(config.Address, config.SNI, config.PSK, secretPath, addrType, addr, port)
}
