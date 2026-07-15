// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

package main

import (
	"encoding/json"
	"os"
	"stealthlink/core/transport"
)

type Config struct {
	BindAddress string `json:"bind_address"`
	SNI         string `json:"sni"`
	Transport   string `json:"transport"`

	Camouflage transport.CamouflageConfig `json:"camouflage"`

	Reality transport.RealityConfig `json:"reality"`

	Mirage transport.MirageConfig `json:"mirage"`

	Users []*transport.UserRecord `json:"users"`

	Firewall transport.FirewallConfig `json:"firewall"`

	Padding struct {
		Enabled         bool `json:"enabled"`
		MinPaddingBytes int  `json:"min_padding_bytes"`
		MaxPaddingBytes int  `json:"max_padding_bytes"`
		NormalizeSize   bool `json:"normalize_size"`
	} `json:"padding"`

	Stealth struct {
		Enabled              bool `json:"enabled"`
		DecoyStreams         bool `json:"decoy_streams"`
		ProtocolPolymorphism bool `json:"protocol_polymorphism"`
		AdaptiveThrottling   bool `json:"adaptive_throttling"`
	} `json:"stealth"`
}

func LoadConfig(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	config := &Config{}
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(config); err != nil {
		return nil, err
	}
	if config.Camouflage.SecretPath == "" {
		config.Camouflage.SecretPath = "/api/v2/sync"
	}
	if config.Camouflage.IndexFile == "" {
		config.Camouflage.IndexFile = "index.html"
	}
	if config.Camouflage.WebRoot == "" && config.Camouflage.TargetURL == "" {
		config.Camouflage.WebRoot = "/var/www/html"
	}
	return config, nil
}

func DefaultConfig() *Config {
	return &Config{
		BindAddress: ":443",
		SNI:         "cloudflare-dns.com",
		Transport:   "tls",
		Camouflage: transport.CamouflageConfig{
			Enabled:    true,
			WebRoot:    "/var/www/html",
			SecretPath: "/api/v2/sync",
			IndexFile:  "index.html",
		},
		Users: []*transport.UserRecord{
			{
				ID:  "default",
				PSK: "change-me-to-a-strong-random-key",
				AllowedPorts: []transport.PortRange{
					{From: 1, To: 65535},
				},
			},
		},
		Firewall: transport.DefaultFirewallConfig(),
		Padding: struct {
			Enabled         bool `json:"enabled"`
			MinPaddingBytes int  `json:"min_padding_bytes"`
			MaxPaddingBytes int  `json:"max_padding_bytes"`
			NormalizeSize   bool `json:"normalize_size"`
		}{
			Enabled:         true,
			MinPaddingBytes: 16,
			MaxPaddingBytes: 256,
			NormalizeSize:   true,
		},
		Stealth: struct {
			Enabled              bool `json:"enabled"`
			DecoyStreams         bool `json:"decoy_streams"`
			ProtocolPolymorphism bool `json:"protocol_polymorphism"`
			AdaptiveThrottling   bool `json:"adaptive_throttling"`
		}{
			Enabled:              true,
			DecoyStreams:         true,
			ProtocolPolymorphism: true,
			AdaptiveThrottling:   true,
		},
	}
}

func (c *Config) ToServerConfig() transport.ServerConfig {
	paddingCfg := transport.DefaultPaddingConfig()
	paddingCfg.Enabled = c.Padding.Enabled
	if c.Padding.MinPaddingBytes > 0 {
		paddingCfg.MinPaddingBytes = c.Padding.MinPaddingBytes
	}
	if c.Padding.MaxPaddingBytes > 0 {
		paddingCfg.MaxPaddingBytes = c.Padding.MaxPaddingBytes
	}
	paddingCfg.NormalizeSize = c.Padding.NormalizeSize

	stealthCfg := transport.DefaultStealthConfig()
	stealthCfg.Enabled = c.Stealth.Enabled
	stealthCfg.DecoyStreams = c.Stealth.DecoyStreams
	stealthCfg.ProtocolPolymorphism = c.Stealth.ProtocolPolymorphism
	stealthCfg.AdaptiveThrottling = c.Stealth.AdaptiveThrottling

	return transport.ServerConfig{
		BindAddress: c.BindAddress,
		SNI:         c.SNI,
		Transport:   c.Transport,
		Camouflage:  c.Camouflage,
		Reality:     c.Reality,
		Mirage:      c.Mirage,
		Users:       c.Users,
		FirewallCfg: c.Firewall,
		PaddingCfg:  paddingCfg,
		StealthCfg:  stealthCfg,
	}
}
