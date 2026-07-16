// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

package transport

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/pion/datachannel"
	"github.com/pion/webrtc/v4"
)

type WebRTCConfig struct {
	Enabled     bool     `json:"enabled"`
	Path        string   `json:"path"`
	STUNServers []string `json:"stun_servers"`
}

const (
	webrtc_default_path = "/rtc/o"
	webrtc_chunk_size   = 16 * 1024
	webrtc_open_wait    = 15 * time.Second
	webrtc_connect_wait = 20 * time.Second
)

var webrtc_default_stun = []string{"stun:stun.l.google.com:19302"}

func webrtc_normalize_path(p string) string {
	if p == "" {
		return webrtc_default_path
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

func webrtc_new_api() *webrtc.API {
	se := webrtc.SettingEngine{}
	se.DetachDataChannels()
	return webrtc.NewAPI(webrtc.WithSettingEngine(se))
}

func webrtc_ice_servers(stun []string) []webrtc.ICEServer {
	out := make([]webrtc.ICEServer, 0, len(stun))
	for _, s := range stun {
		if s != "" {
			out = append(out, webrtc.ICEServer{URLs: []string{s}})
		}
	}
	return out
}

type webrtc_conn struct {
	dc      datachannel.ReadWriteCloserDeadliner
	rbuf    []byte
	scratch []byte
}

func new_webrtc_conn(dc datachannel.ReadWriteCloserDeadliner) *webrtc_conn {
	return &webrtc_conn{dc: dc, scratch: make([]byte, 64*1024)}
}

func (c *webrtc_conn) Read(p []byte) (int, error) {
	for len(c.rbuf) == 0 {
		n, err := c.dc.Read(c.scratch)
		if err != nil {
			return 0, err
		}
		c.rbuf = c.scratch[:n]
	}
	n := copy(p, c.rbuf)
	c.rbuf = c.rbuf[n:]
	return n, nil
}

func (c *webrtc_conn) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > webrtc_chunk_size {
			chunk = chunk[:webrtc_chunk_size]
		}
		if _, err := c.dc.Write(chunk); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

func (c *webrtc_conn) Close() error                       { return c.dc.Close() }
func (c *webrtc_conn) LocalAddr() net.Addr                { return masque_addr{} }
func (c *webrtc_conn) RemoteAddr() net.Addr               { return masque_addr{} }
func (c *webrtc_conn) SetReadDeadline(t time.Time) error  { return c.dc.SetReadDeadline(t) }
func (c *webrtc_conn) SetWriteDeadline(t time.Time) error { return c.dc.SetWriteDeadline(t) }

func (c *webrtc_conn) SetDeadline(t time.Time) error {
	if err := c.dc.SetReadDeadline(t); err != nil {
		return err
	}
	return c.dc.SetWriteDeadline(t)
}

type webrtc_client struct {
	pc *webrtc.PeerConnection
}

func (w *webrtc_client) Close() error {
	if w.pc != nil {
		return w.pc.Close()
	}
	return nil
}

func webrtc_dial(server_addr, sni, path, fingerprint, psk string, stun []string, insecure bool) (*webrtc_client, error) {
	pc, err := webrtc_new_api().NewPeerConnection(webrtc.Configuration{ICEServers: webrtc_ice_servers(stun)})
	if err != nil {
		return nil, fmt.Errorf("peer connection failed: %w", err)
	}

	connected := make(chan struct{}, 1)
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		if state == webrtc.PeerConnectionStateConnected {
			select {
			case connected <- struct{}{}:
			default:
			}
		}
	})

	if _, err := pc.CreateDataChannel("keepalive", nil); err != nil {
		pc.Close()
		return nil, err
	}

	offer, err := pc.CreateOffer(nil)
	if err != nil {
		pc.Close()
		return nil, err
	}
	if err := pc.SetLocalDescription(offer); err != nil {
		pc.Close()
		return nil, err
	}
	<-webrtc.GatheringCompletePromise(pc)

	answer, err := webrtc_signal(server_addr, sni, path, fingerprint, psk, *pc.LocalDescription(), insecure)
	if err != nil {
		pc.Close()
		return nil, err
	}
	if err := pc.SetRemoteDescription(answer); err != nil {
		pc.Close()
		return nil, err
	}

	select {
	case <-connected:
	case <-time.After(webrtc_connect_wait):
		pc.Close()
		return nil, fmt.Errorf("webrtc connection timeout")
	}

	return &webrtc_client{pc: pc}, nil
}

func (w *webrtc_client) open(addr_type byte, addr string, port uint16) (net.Conn, error) {
	dc, err := w.pc.CreateDataChannel("t", nil)
	if err != nil {
		return nil, err
	}

	ready := make(chan datachannel.ReadWriteCloserDeadliner, 1)
	fail := make(chan error, 1)
	dc.OnOpen(func() {
		raw, err := dc.DetachWithDeadline()
		if err != nil {
			fail <- err
			return
		}
		ready <- raw
	})

	var raw datachannel.ReadWriteCloserDeadliner
	select {
	case raw = <-ready:
	case err := <-fail:
		dc.Close()
		return nil, err
	case <-time.After(webrtc_open_wait):
		dc.Close()
		return nil, fmt.Errorf("data channel open timeout")
	}

	conn := new_webrtc_conn(raw)

	header := EncodeAddress(addr_type, addr, port)
	if _, err := conn.Write(header); err != nil {
		conn.Close()
		return nil, fmt.Errorf("address write failed: %w", err)
	}

	status := make([]byte, 1)
	conn.SetReadDeadline(time.Now().Add(webrtc_open_wait))
	if _, err := io.ReadFull(conn, status); err != nil {
		conn.Close()
		return nil, fmt.Errorf("status read failed: %w", err)
	}
	conn.SetReadDeadline(time.Time{})

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

func webrtc_signal(server_addr, sni, path, fingerprint, psk string, offer webrtc.SessionDescription, insecure bool) (webrtc.SessionDescription, error) {
	var empty webrtc.SessionDescription

	body, err := json.Marshal(offer)
	if err != nil {
		return empty, err
	}
	auth, err := GenerateAuthPayload(psk)
	if err != nil {
		return empty, err
	}

	client := mirage_http_client(sni, fingerprint, insecure)
	url := "https://" + server_addr + webrtc_normalize_path(path)
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return empty, err
	}
	req.Host = sni
	req.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(auth))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return empty, fmt.Errorf("signaling failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return empty, fmt.Errorf("signaling status %d", resp.StatusCode)
	}

	var answer webrtc.SessionDescription
	if err := json.NewDecoder(resp.Body).Decode(&answer); err != nil {
		return empty, fmt.Errorf("answer decode failed: %w", err)
	}
	return answer, nil
}

type webrtc_handler struct {
	auth      *AuthManager
	path      string
	stun      []string
	onSession func(conn net.Conn, session *AuthSession)
}

func (h *webrtc_handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != h.path {
		mirage_serve_decoy(w)
		return
	}

	session, ok := masque_authenticate(h.auth, r)
	if !ok {
		mirage_serve_decoy(w)
		return
	}

	var offer webrtc.SessionDescription
	if err := json.NewDecoder(io.LimitReader(r.Body, 256*1024)).Decode(&offer); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	pc, err := webrtc_new_api().NewPeerConnection(webrtc.Configuration{ICEServers: webrtc_ice_servers(h.stun)})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		switch state {
		case webrtc.PeerConnectionStateFailed, webrtc.PeerConnectionStateClosed, webrtc.PeerConnectionStateDisconnected:
			pc.Close()
		}
	})

	pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		if dc.Label() == "keepalive" {
			return
		}
		dc.OnOpen(func() {
			raw, err := dc.DetachWithDeadline()
			if err != nil {
				return
			}
			h.onSession(new_webrtc_conn(raw), session)
		})
	})

	if err := pc.SetRemoteDescription(offer); err != nil {
		pc.Close()
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		pc.Close()
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := pc.SetLocalDescription(answer); err != nil {
		pc.Close()
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	<-webrtc.GatheringCompletePromise(pc)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(pc.LocalDescription())
}
