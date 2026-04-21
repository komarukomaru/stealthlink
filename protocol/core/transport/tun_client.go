// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

package transport

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"stealthlink/core/vpn"
)

type TunClient struct {
	client   *Client
	tunDev   *vpn.TunDevice
	cidr     string
	serverIP string
	mu       sync.Mutex
	running  bool
	stopChan chan struct{}
}

func NewTunClient(config ClientConfig, cidr string) *TunClient {
	return &TunClient{
		client:   NewClient(config),
		cidr:     cidr,
		stopChan: make(chan struct{}),
	}
}

func (tc *TunClient) Start() error {
	host, _, _ := net.SplitHostPort(tc.client.config.ServerAddr)
	if ips, err := net.LookupIP(host); err == nil && len(ips) > 0 {
		for _, ip := range ips {
			if ip.To4() != nil {
				tc.serverIP = ip.String()
				break
			}
		}
		if tc.serverIP == "" {
			tc.serverIP = ips[0].String()
		}
	} else {
		tc.serverIP = host
	}

	tunDev, err := vpn.NewTunDevice(tc.cidr)
	if err != nil {
		return fmt.Errorf("TUN creation failed: %v", err)
	}
	tc.tunDev = tunDev

	if err := tunDev.Configure(tc.cidr, tc.serverIP); err != nil {
		tunDev.Close()
		return fmt.Errorf("TUN configuration failed: %v", err)
	}

	log.Printf("[TUN] Interface %s configured with %s", tunDev.Name, tc.cidr)

	go tc.client.proxy.Start()

	if tc.client.httpProxy != nil {
		go tc.client.httpProxy.Start()
	}

	go func() {
		if err := tc.client.connectPersistentWithRetry(); err != nil {
			log.Printf("[TUN] Client connection failed: %v", err)
		}
	}()

	for {
		tc.client.mu.Lock()
		connected := tc.client.connected
		tc.client.mu.Unlock()
		if connected {
			break
		}
		time.Sleep(100 * time.Millisecond)
		select {
		case <-tc.stopChan:
			return fmt.Errorf("stopped before connected")
		default:
		}
	}

	tc.mu.Lock()
	tc.running = true
	tc.mu.Unlock()

	go tc.tunToVPN()
	go tc.vpnToTun()

	log.Printf("[TUN] VPN tunnel active")

	<-tc.stopChan
	return nil
}

func (tc *TunClient) tunToVPN() {
	buf := make([]byte, 65535)
	for {
		select {
		case <-tc.stopChan:
			return
		default:
		}

		n, err := tc.tunDev.ReadPacket(buf)
		if err != nil {
			tc.mu.Lock()
			running := tc.running
			tc.mu.Unlock()
			if !running {
				return
			}
			continue
		}

		if n == 0 {
			continue
		}

		tc.client.mu.Lock()
		writer := tc.client.writer
		tc.client.mu.Unlock()

		if writer == nil {
			continue
		}

		frame := Frame{Type: FrameIP, Payload: buf[:n]}
		writer.WriteTypedFrame(frame)
	}
}

func (tc *TunClient) vpnToTun() {
	for {
		select {
		case <-tc.stopChan:
			return
		default:
		}

		tc.client.mu.Lock()
		reader := tc.client.reader
		tc.client.mu.Unlock()

		if reader == nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}

		frame, err := reader.ReadTypedFramePooled()
		if err != nil {
			tc.mu.Lock()
			running := tc.running
			tc.mu.Unlock()
			if !running {
				return
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}

		if frame.Type == FrameIP {
			tc.tunDev.WritePacket(frame.Payload)
		}
		frame.Release()
	}
}

func (tc *TunClient) Stop() {
	tc.mu.Lock()
	tc.running = false
	tc.mu.Unlock()

	select {
	case <-tc.stopChan:
	default:
		close(tc.stopChan)
	}

	tc.client.Stop()

	if tc.tunDev != nil {
		tc.tunDev.Close()
	}
}
