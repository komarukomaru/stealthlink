// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

//go:build windows

package vpn

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"

	"golang.zx2c4.com/wireguard/tun"
)

const tunMTU = 65535

type TunDevice struct {
	dev  tun.Device
	Name string
}

func NewTunDevice(cidr string) (*TunDevice, error) {
	name := "stealthlink"
	dev, err := tun.CreateTUN(name, tunMTU)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN device: %v", err)
	}

	realName, err := dev.Name()
	if err != nil {
		realName = name
	}
	log.Printf("Interface created: %s", realName)

	return &TunDevice{
		dev:  dev,
		Name: realName,
	}, nil
}

func (t *TunDevice) ReadPacket(buf []byte) (int, error) {
	buffs := [][]byte{buf}
	sizes := make([]int, 1)

	n, err := t.dev.Read(buffs, sizes, 0)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, nil
	}
	return sizes[0], nil
}

func (t *TunDevice) WritePacket(data []byte) error {
	buffs := [][]byte{data}
	_, err := t.dev.Write(buffs, 0)
	return err
}

func (t *TunDevice) Close() error {
	return t.dev.Close()
}

func (t *TunDevice) Configure(cidr string, serverPublicIP string) error {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid cidr: %v", err)
	}
	mask := net.IP(ipNet.Mask).String()

	log.Printf("Configuring Windows Interface %s: IP=%s Mask=%s", t.Name, ip.String(), mask)

	cmd := exec.Command("netsh", "interface", "ip", "set", "address", t.Name, "static", ip.String(), mask)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("netsh set address failed: %v, output: %s", err, string(out))
	}

	cmd = exec.Command("netsh", "interface", "ip", "set", "dns", t.Name, "static", "8.8.8.8")
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("Warning: netsh set dns failed: %v, output: %s", err, string(out))
	}

	if serverPublicIP != "" {
		gwCmd := exec.Command("powershell", "-Command", "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -ExpandProperty NextHop | Select-Object -First 1)")
		out, err := gwCmd.Output()
		if err == nil {
			physGw := strings.TrimSpace(string(out))
			if physGw != "" {
				log.Printf("Found physical gateway: %s. Adding exclusion route for %s", physGw, serverPublicIP)
				host, _, _ := net.SplitHostPort(serverPublicIP)
				if host == "" {
					host = serverPublicIP
				}
				if ips, err := net.LookupIP(host); err == nil && len(ips) > 0 {
					host = ips[0].String()
				}
				exec.Command("route", "add", host, "mask", "255.255.255.255", physGw).Run()
			}
		} else {
			log.Printf("Warning: Could not determine physical gateway.")
		}

		cmd = exec.Command("netsh", "interface", "ip", "add", "route", "0.0.0.0/0", t.Name, "metric=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Printf("Warning: Failed to add default route: %v, output: %s", err, string(out))
		}
	} else {
		log.Println("Configuring Windows Server NAT...")

		exec.Command("powershell", "-Command", "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters' -Name 'IPEnableRouter' -Value 1").Run()

		natName := "StealthLinkNAT"
		log.Printf("Creating NetNat: %s for %s", natName, cidr)

		exec.Command("powershell", "-Command", fmt.Sprintf("Remove-NetNat -Name '%s' -Confirm:$false -ErrorAction SilentlyContinue", natName)).Run()

		cmdStr := fmt.Sprintf("New-NetNat -Name '%s' -InternalIPInterfaceAddressPrefix '%s'", natName, cidr)
		cmd = exec.Command("powershell", "-Command", cmdStr)
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Printf("Warning: Failed to create NetNat: %v, output: %s", err, string(out))
		}
	}

	return nil
}
