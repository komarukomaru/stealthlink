// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

package transport

type ObfuscationConfig struct {
	SNI           string
	ALPNProtocols []string
	Transport     string
}

func DefaultObfuscationConfig() *ObfuscationConfig {
	return &ObfuscationConfig{
		SNI:           "",
		ALPNProtocols: []string{"http/1.1"},
		Transport:     "tls",
	}
}

func QUICObfuscationConfig() *ObfuscationConfig {
	return &ObfuscationConfig{
		SNI:           "",
		ALPNProtocols: []string{"h3"},
		Transport:     "quic",
	}
}

func (c *ObfuscationConfig) GetALPN() []string {
	if len(c.ALPNProtocols) == 0 {
		if c.Transport == "quic" {
			return []string{"h3"}
		}
		return []string{"http/1.1"}
	}
	return c.ALPNProtocols
}

func (c *ObfuscationConfig) GetSNI() string {
	return c.SNI
}
