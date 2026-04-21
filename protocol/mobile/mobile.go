// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

//go:build android

package stealthlink

// Warning! This is unsupported for now!
import (
	"fmt"
	"log"
	"os"
	"stealthlink/core/transport"
	"stealthlink/core/vpn"
	"sync"
)

type Protector interface {
	Protect(fd int) bool
}

type VPNClient struct {
	config   transport.ClientConfig
	client   *transport.Client
	tunDev   *vpn.TunDevice
	mu       sync.Mutex
	running  bool
	stopChan chan struct{}
}

func NewVPNClient(addr string) *VPNClient {
	return &VPNClient{
		config: transport.ClientConfig{
			ServerAddr: addr,
			Transport:  "tls",
			SOCKSAddr:  "127.0.0.1:1080",
			SecretPath: "/api/v2/sync",
			PaddingCfg: transport.DefaultPaddingConfig(),
			StealthCfg: transport.DefaultStealthConfig(),
		},
		stopChan: make(chan struct{}),
	}
}

func (vc *VPNClient) SetPSK(psk string) {
	vc.config.PSK = psk
}

func (vc *VPNClient) SetSNI(sni string) {
	vc.config.SNI = sni
}

func (vc *VPNClient) SetTransport(t string) {
	vc.config.Transport = t
}

func (vc *VPNClient) SetSecretPath(path string) {
	vc.config.SecretPath = path
}

func (vc *VPNClient) Connect(protector Protector, sni string) error {
	if sni != "" {
		vc.config.SNI = sni
	}

	vc.client = transport.NewClient(vc.config)

	go vc.client.Start()

	return nil
}

func (vc *VPNClient) RunTunnel(tunFd int) error {
	tunDev, err := vpn.NewTunDeviceFromFD(tunFd)
	if err != nil {
		return fmt.Errorf("failed to create TUN from FD: %v", err)
	}
	vc.tunDev = tunDev

	vc.mu.Lock()
	vc.running = true
	vc.mu.Unlock()

	log.Printf("[Mobile] Starting tunnel on FD %d", tunFd)

	errCh := make(chan error, 2)

	go func() {
		errCh <- vc.tunToVPN()
	}()

	go func() {
		errCh <- vc.vpnToTun()
	}()

	err = <-errCh
	vc.Disconnect()
	return err
}

func (vc *VPNClient) tunToVPN() error {
	buf := make([]byte, 65535)
	for {
		select {
		case <-vc.stopChan:
			return nil
		default:
		}

		n, err := vc.tunDev.ReadPacket(buf)
		if err != nil {
			vc.mu.Lock()
			running := vc.running
			vc.mu.Unlock()
			if !running {
				return nil
			}
			return fmt.Errorf("TUN read error: %v", err)
		}

		if n == 0 {
			continue
		}

		vc.client.WriteIPFrame(buf[:n])
	}
}

func (vc *VPNClient) vpnToTun() error {
	for {
		select {
		case <-vc.stopChan:
			return nil
		default:
		}

		frame, err := vc.client.ReadFrame()
		if err != nil {
			vc.mu.Lock()
			running := vc.running
			vc.mu.Unlock()
			if !running {
				return nil
			}
			return fmt.Errorf("VPN read error: %v", err)
		}

		if frame.Type == transport.FrameIP {
			vc.tunDev.WritePacket(frame.Payload)
		}
	}
}

func (vc *VPNClient) Disconnect() {
	vc.mu.Lock()
	vc.running = false
	vc.mu.Unlock()

	select {
	case <-vc.stopChan:
	default:
		close(vc.stopChan)
	}

	if vc.client != nil {
		vc.client.Stop()
	}

	if vc.tunDev != nil {
		vc.tunDev.Close()
	}
}

func (vc *VPNClient) IsRunning() bool {
	vc.mu.Lock()
	defer vc.mu.Unlock()
	return vc.running
}

func SetLogOutput(path string) {
	if path == "" {
		log.SetOutput(os.Stdout)
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	log.SetOutput(f)
}
