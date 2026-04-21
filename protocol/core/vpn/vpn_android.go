// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

//go:build android

package vpn

import (
	"fmt"
	"os"
)

const tunMTU = 65535

type TunDevice struct {
	fd   *os.File
	Name string
}

func NewTunDeviceFromFD(fd int) (*TunDevice, error) {
	f := os.NewFile(uintptr(fd), "tun")
	if f == nil {
		return nil, fmt.Errorf("invalid file descriptor: %d", fd)
	}
	return &TunDevice{
		fd:   f,
		Name: "tun0",
	}, nil
}

func NewTunDevice(cidr string) (*TunDevice, error) {
	return nil, fmt.Errorf("on Android, use NewTunDeviceFromFD with VpnService file descriptor")
}

func (t *TunDevice) ReadPacket(buf []byte) (int, error) {
	return t.fd.Read(buf)
}

func (t *TunDevice) WritePacket(data []byte) error {
	_, err := t.fd.Write(data)
	return err
}

func (t *TunDevice) Close() error {
	return t.fd.Close()
}

func (t *TunDevice) Configure(cidr string, serverPublicIP string) error {
	return nil
}
