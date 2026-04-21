// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"
	"stealthlink/core/transport"
)

func main() {
	configPath := flag.String("config", "config.json", "Path to config file")
	genConfig := flag.Bool("gen-config", false, "Generate default config file and exit")
	flag.Parse()

	if *genConfig {
		generateDefaultConfig(*configPath)
		return
	}

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Printf("Warning: Failed to load config: %v. Using defaults.", err)
		cfg = DefaultConfig()
	}

	serverCfg := cfg.ToServerConfig()

	log.Printf("=== StealthLink Server ===")
	log.Printf("Transport:  %s", serverCfg.Transport)
	log.Printf("Bind:       %s", serverCfg.BindAddress)
	log.Printf("Camouflage: %v", serverCfg.Camouflage.Enabled)
	log.Printf("Users:      %d", len(serverCfg.Users))
	log.Printf("==========================")

	server := transport.NewServer(serverCfg)

	if err := server.Start(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func generateDefaultConfig(path string) {
	cfg := DefaultConfig()

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal config: %v", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		log.Fatalf("Failed to write config: %v", err)
	}

	log.Printf("Default config written to %s", path)
	log.Println("IMPORTANT: Change the PSK before deploying!")
}
