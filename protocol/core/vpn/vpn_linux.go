// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

//go:build linux && !android

package vpn

import (
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/songgao/water"
)

const tunMTU = 65535

type TunDevice struct {
	iface *water.Interface
	Name  string
}

func NewTunDevice(cidr string) (*TunDevice, error) {
	config := water.Config{
		DeviceType: water.TUN,
	}

	iface, err := water.New(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN device: %v", err)
	}

	log.Printf("Interface created: %s", iface.Name())

	return &TunDevice{
		iface: iface,
		Name:  iface.Name(),
	}, nil
}

func (t *TunDevice) ReadPacket(buf []byte) (int, error) {
	return t.iface.Read(buf)
}

func (t *TunDevice) WritePacket(data []byte) error {
	_, err := t.iface.Write(data)
	return err
}

func (t *TunDevice) Close() error {
	return t.iface.Close()
}

func (t *TunDevice) Configure(cidr string, serverPublicIP string) error {
	log.Printf("Configuring Linux Interface %s with %s...", t.Name, cidr)

	if err := exec.Command("ip", "link", "set", "dev", t.Name, "mtu", "65535").Run(); err != nil {
		log.Printf("Warning: failed to set MTU: %v", err)
	}

	if err := exec.Command("ip", "addr", "add", cidr, "dev", t.Name).Run(); err != nil {
		return fmt.Errorf("ip addr add failed: %v", err)
	}
	if err := exec.Command("ip", "link", "set", "dev", t.Name, "up").Run(); err != nil {
		return fmt.Errorf("ip link set up failed: %v", err)
	}

	exec.Command("ip", "link", "set", "dev", t.Name, "txqueuelen", "1000").Run()

	if serverPublicIP == "" {
		log.Println("Configuring Server NAT...")

		if err := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run(); err != nil {
			log.Printf("Warning: Failed to enable ip_forward: %v", err)
		}

		out, err := exec.Command("bash", "-c", "ip route get 8.8.8.8 | awk '{print $5; exit}'").Output()
		if err != nil {
			log.Printf("Warning: Failed to detect default interface: %v", err)
			return nil
		}
		defIface := strings.TrimSpace(string(out))
		if defIface == "" {
			log.Printf("Warning: Default interface detection returned empty string.")
			return nil
		}
		log.Printf("Detected default interface: %s", defIface)

		setupIptables("nat", "-A", "POSTROUTING", "-o", defIface, "-j", "MASQUERADE")
		setupIptables("filter", "-A", "FORWARD", "-i", t.Name, "-o", defIface, "-j", "ACCEPT")
		setupIptables("filter", "-A", "FORWARD", "-i", defIface, "-o", t.Name, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	}

	return nil
}

func setupIptables(table string, args ...string) {
	cmdArgs := append([]string{"-t", table}, args...)
	cmd := exec.Command("iptables", cmdArgs...)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("iptables warning: %v, output: %s", err, string(out))
	}
}
