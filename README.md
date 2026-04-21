# The project hasn't been abandoned, I'm just busy with something else right now

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
