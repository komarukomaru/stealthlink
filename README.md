# StealthLink Protocol

StealthLink is a high-performance, censorship-resistant VPN protocol designed to provide secure and fast connectivity even in restrictive network environments. It leverages modern transport standards like TLS 1.3 and QUIC (HTTP/3) combined with advanced stealth techniques to bypass Deep Packet Inspection (DPI).

**Current Status**: Active Development (Beta)

## Features

### Core Capabilities
- **Dual Transport Architecture**:
  - **TLS 1.3**: Standard HTTPS-like traffic for maximum compatibility and stealth.
  - **QUIC (HTTP/3)**: High-performance UDP-based transport for low latency and resilience against packet loss.
- **Advanced Stealth**:
  - **Camouflage**: Mimics legitimate web server traffic (e.g., Microsoft, Cloudflare, Apple) to blend in.
  - **Padding**: Intelligent random padding to defeat packet size analysis.
  - **Protocol Polymorphism**: Dynamic signature modifications to evade static fingerprinting.
  - **Replay Protection**: Rotating Bloom Filter to detect and block active probing attacks (e.g., replayed handshakes).
  - **uTLS Support**: Client mimics popular browser fingerprints (Chrome, Firefox, iOS, etc.) to blend with legitimate traffic.
  - **Adaptive Throttling**: Responds to active probing by throttling or dropping connections to simulate a standard web server.

### User & Network Management
- **Multi-User Support**: Built-in authentication with user-specific bandwidth limits and expiration dates.
- **Firewall & ACL**: Granular control over allowed ports and destination ranges per user.
- **Proxy Mode**: SOCKS5 and HTTP proxy support.

## Project Structure

```bash
protocol/
├── cmd/
│   ├── client/       # Client application entry point
│   └── server/       # Server application entry point
├── core/
│   ├── transport/    # Core protocol logic (TLS, QUIC, Framing, Auth)
│   └── vpn/          # TUN interface and platform-specific network code
└── mobile/           # Mobile bindings (in progress)
```

## Getting Started

### Prerequisites
- Go 1.22 or higher

### Build

**Windows:**
```bash
./build.ps1
```

**Linux:**
```bash
./build.sh
```

## Usage

### Server

1. **Generate Configuration**:
   The server can generate a default configuration file:
   ```bash
   ./server -gen-config
   ```

2. **Run Server**:
   ```bash
   ./server -config config.json
   ```

### Client

The client is configured primarily via command-line flags. It does not currently support a JSON config file argument, but can load subscription links.

1. **CLI Mode** (Manual Configuration):
   ```bash
   ./client -server "1.2.3.4:443" -psk "YOUR-PSK" -sni "www.google.com"
   ```

   **uTLS Fingerprint**:
   To mimic a specific browser (evade DPI blocking), use the `-fingerprint` flag:
   ```bash
   ./client -server "..." -fingerprint chrome
   ```
   Available fingerprints: `chrome`, `firefox`, `edge`, `safari`, `ios`, `android`, `360`, `qq`, `random`.

2. **StealthLink Subscription**:
   Connect using a subscription URL (StealthLink URI):
   ```bash
   ./client -sub "stealthlink://..."
   ```

3. **Proxy Mode**:
   By default, the client starts a SOCKS5 proxy on `127.0.0.1:1080`.
   You can change this or add an HTTP proxy:
   ```bash
   ./client -socks ":1080" -http ":8080" -server "..." ...
   ```

## Configuration

### Transport Modes
The server supports strict transport selection to optimize for specific network conditions or security requirements:

- **`tls`**: Standard TLS 1.3 over TCP. 
  - *Best for*: Maximum compatibility, restrictive firewalls that block UDP.
  - *Behavior*: Listens ONLY on TCP. UDP/QUIC is disabled.
- **`quic`**: HTTP/3 over QUIC (UDP).
  - *Best for*: High performance, low latency, lossy networks.
  - *Behavior*: Listens ONLY on UDP. TCP/TLS fallback is disabled.
- **`any`**: Dual-stack mode.
  - *Best for*: Flexibility. Clients can choose their preferred transport.
  - *Behavior*: Listens on BOTH UDP (QUIC) and TCP (TLS).
- **`reality`**: TLS 1.3 over TCP with REALITY-style handshake authentication.
  - *Best for*: Environments with active TLS probing, where a self-signed certificate would be flagged.
  - *Behavior*: Authentication is embedded in the ClientHello (X25519 key in `session_id`, sealed token in `random`). Authenticated clients are terminated locally with a certificate whose structure is cloned from `dest`. Any other connection (probes, scanners, real browsers) is transparently proxied to the real `dest`, so it sees the genuine site with its genuine CA-signed certificate.

#### REALITY setup

Generate a keypair on the server:

```bash
./server -gen-reality
# private_key (server): <base64>
# public_key  (client): <base64>
```

Put the `private_key` and one or more `short_ids` in the server config (`transport: "reality"`, see `cmd/server/config_reality.example.json`). The `dest` should be a real HTTPS site reachable from the server; `server_name` (SNI) must be a name that `dest` serves.

Connect the client with the matching `public_key` and `short_id`:

```bash
./client -server "1.2.3.4:443" -transport reality -psk "YOUR-PSK" \
  -sni "www.microsoft.com" -fingerprint chrome \
  -reality-key "<public_key>" -reality-short-id "0011223344556677"
```

- **`mirage`**: Tunnel carried inside ordinary HTTP requests, designed to pass cleanly through a CDN.
  - *Best for*: Fronting behind a CDN (e.g. Cloudflare) where the traffic must look like plain HTTP to the CDN itself.
  - *Behavior*: A long-lived `GET` streams the downlink (server → client) as a chunked response; the uplink (client → server) is a sequence of short `POST` requests. Authentication rides in the `Authorization: Bearer` header. Non-tunnel requests get a plain `404` page. Point the client at the CDN hostname and the CDN forwards to the origin.

#### MIRAGE setup

Server config uses `transport: "mirage"` with an optional `path` (see `cmd/server/config_mirage.example.json`). When fronting behind a CDN, terminate TLS at the CDN and give the origin a real certificate via the `tls` section (see below).

```bash
./client -server "cdn.your-domain.com:443" -transport mirage -psk "YOUR-PSK" \
  -sni "cdn.your-domain.com" -mirage-path "/v2/media/segments"
```

- **`masque`**: Genuine HTTP/3 tunnel over QUIC using an Extended CONNECT request (MASQUE-style).
  - *Best for*: UDP-friendly networks where the traffic must survive inspection by a probe that speaks real HTTP/3.
  - *Behavior*: The client opens a real HTTP/3 connection (SETTINGS/HEADERS/DATA frames) and issues a `CONNECT` request with `:protocol = connect-udp`; the server hijacks the stream and tunnels over it. Unlike the raw `quic` transport, an HTTP/3-speaking prober sees a well-formed h3 endpoint. Authentication rides in the `Authorization: Bearer` header; non-CONNECT requests get a plain `404`.

#### MASQUE setup

Server config uses `transport: "masque"` with an optional `path` (see `cmd/server/config_masque.example.json`).

```bash
./client -server "1.2.3.4:443" -transport masque -psk "YOUR-PSK" \
  -sni "www.microsoft.com" -masque-path "/.well-known/masque/udp/"
```

#### Custom TLS certificate

By default every TCP transport (`tls`, `mirage`, ...) generates a blended self-signed certificate. To serve your own certificate instead — required for CDN "Full (strict)" mode or a direct client without `-insecure` — set the top-level `tls` section. It applies to both the plain `tls` transport and `mirage`:

```json
{
    "tls": {
        "cert_file": "/etc/ssl/fullchain.pem",
        "key_file": "/etc/ssl/privkey.pem"
    }
}
```

A certificate set directly on `camouflage.cert_file` still takes precedence when present.

### Server
The server is configured via a JSON file. See `cmd/server/config.example.json` for a complete example.

**Minimal Example:**
```json
{
    "bind_address": ":443",
    "sni": "www.microsoft.com",
    "transport": "tls", // Options: "tls" (TCP only), "quic" (UDP only), "any" (Dual stack)
    "camouflage": {
        "enabled": true,
        "target": "https://www.microsoft.com"
    },
    "users": [
        {
            "id": "user1",
            "psk": "YOUR-SECURE-KEY",
            "max_bandwidth": 1073741824,
            // Optional: "upstream" is used when generating subscription links or for cascading mode.
            // Do NOT set this for standard server users unless you want to redirect their traffic to another VPN.
            "upstream": {
                "fingerprint": "chrome"
            }
        }
    ]
}
```

### DPI Bypass Capabilities
Russia: tested ✅

## Tools
- `generate_link.py`: A helper script to generate `stealthlink://` connection strings for easy client configuration.

## Roadmap

The following items are currently prioritized for development:

- [ ] **Optimize QUIC Protocol**
- [ ] **Protocol Acceleration**
- [ ] **Full Android Support**

## License

This project is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**. 

**Note on historical commits:** The terms of this license apply to the entire codebase and all versions of this project contained within this repository, including all historical commits dating back to the initial commit (`22acb0b`). Any use, modification, or distribution of the code from any point in the repository's history is subject to the AGPL-3.0 terms.
