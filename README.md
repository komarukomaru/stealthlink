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
  - **Adaptive Throttling**: Responds to active probing by throttling or dropping connections to simulate a standard web server.

### User & Network Management
- **Multi-User Support**: Built-in authentication with user-specific bandwidth limits and expiration dates.
- **Firewall & ACL**: Granular control over allowed ports and destination ranges per user.
- **Smart Routing**:
  - **VPN Mode**: Full system tunnel using TUN interface (WireGuard/water based).
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

```bash
# Build Server
cd cmd/server
go build -o server

# Build Client
cd ../client
go build -o client
```

## Configuration

### Server
The server is configured via a JSON file. See `cmd/server/config.example.json` for a complete example.

**Minimal Example:**
```json
{
    "bind_address": ":443",
    "sni": "www.microsoft.com",
    "transport": "tls",
    "camouflage": {
        "enabled": true,
        "target": "https://www.microsoft.com"
    },
    "users": [
        {
            "id": "user1",
            "psk": "YOUR-SECURE-KEY",
            "max_bandwidth": 1073741824
        }
    ]
}
```

### Client
The client can connect using a configuration file or command-line arguments.

## Tools
- `generate_link.py`: A helper script to generate `stealthlink://` connection strings for easy client configuration.

## Roadmap

The following items are currently prioritized for development:

- [ ] **Optimize QUIC Protocol**
- [ ] **Protocol Acceleration**
- [ ] **Full Android Support**
