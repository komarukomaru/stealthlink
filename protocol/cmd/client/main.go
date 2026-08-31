// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"stealthlink/core/transport"
	"syscall"
)

func main() {
	serverAddr := flag.String("server", "", "Server address (host:port)")
	psk := flag.String("psk", "", "Pre-shared key for authentication")
	sni := flag.String("sni", "", "SNI hostname (defaults to server hostname)")
	transportMode := flag.String("transport", "tls", "Transport mode: tls, quic, or auto")
	socksAddr := flag.String("socks", "127.0.0.1:1080", "SOCKS5 proxy listen address")
	httpAddr := flag.String("http", "", "HTTP proxy listen address (optional)")
	secretPath := flag.String("path", "/api/v2/sync", "Secret path for HTTP camouflage auth")
	insecure := flag.Bool("insecure", false, "Skip TLS certificate verification")
	subURL := flag.String("sub", "", "Subscription URL (stealthlink://...)")
	noPadding := flag.Bool("no-padding", false, "Disable traffic padding")
	noStealth := flag.Bool("no-stealth", false, "Disable stealth features")
	fingerprint := flag.String("fingerprint", "", "uTLS fingerprint (chrome, firefox, ios, android, 360, qq, random)") // https://github.com/komarukomaru/stealthlink/issues/2
	realityPubKey := flag.String("reality-key", "", "REALITY server public key (base64) for transport=reality")
	realityShortID := flag.String("reality-short-id", "", "REALITY short id (hex) for transport=reality")
	miragePath := flag.String("mirage-path", "", "HTTP path prefix for transport=mirage (must match server)")
	masquePath := flag.String("masque-path", "", "HTTP/3 CONNECT path for transport=masque (must match server)")
	webrtcPath := flag.String("webrtc-path", "", "HTTPS signaling path for transport=webrtc (must match server)")
	flag.Parse()

	var subscription *transport.SubscriptionConfig

	if *subURL != "" {
		sub, err := transport.DecodeSubscriptionURL(*subURL)
		if err != nil {
			log.Fatalf("Invalid subscription URL: %v", err)
		}
		subscription = sub
		log.Printf("Subscription loaded: %s (%d servers)", sub.Name, len(sub.Servers))
	} else if *serverAddr == "" {
		log.Fatal("Either -server or -sub must be specified")
	}

	paddingCfg := transport.DefaultPaddingConfig()
	if *noPadding {
		paddingCfg.Enabled = false
	}

	stealthCfg := transport.DefaultStealthConfig()
	if *noStealth {
		stealthCfg.Enabled = false
	}

	config := transport.ClientConfig{
		ServerAddr:   *serverAddr,
		PSK:          *psk,
		SNI:          *sni,
		Transport:    *transportMode,
		SecretPath:   *secretPath,
		SOCKSAddr:    *socksAddr,
		HTTPAddr:     *httpAddr,
		InsecureSkip: *insecure,
		PaddingCfg:   paddingCfg,
		StealthCfg:   stealthCfg,
		Subscription: subscription,
		Fingerprint:  *fingerprint,

		RealityPublicKey: *realityPubKey,
		RealityShortID:   *realityShortID,
		MiragePath:       *miragePath,
		MasquePath:       *masquePath,
		WebRTCPath:       *webrtcPath,
	}

	client := transport.NewClient(config)

	log.Printf("=== StealthLink Client ===")
	log.Printf("Transport:  %s", *transportMode)
	log.Printf("SOCKS5:     %s", *socksAddr)
	if *httpAddr != "" {
		log.Printf("HTTP Proxy: %s", *httpAddr)
	}
	if subscription != nil {
		log.Printf("Servers:    %d (via subscription)", len(subscription.Servers))
	} else {
		log.Printf("Server:     %s", *serverAddr)
	}
	log.Printf("==========================")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("Shutting down...")
		client.Stop()
		os.Exit(0)
	}()

	if err := client.Start(); err != nil {
		log.Fatalf("Client failed: %v", err)
	}
}
