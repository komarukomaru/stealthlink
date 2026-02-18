import json
import base64
import sys

def generate_link(servers, name="My VPN"):
    config = {
        "version": 1,
        "name": name,
        "servers": servers
    }
    
    # Encode JSON to bytes
    json_bytes = json.dumps(config).encode('utf-8')
    
    # Base64 Encode (RawURL: no padding, URL safe)
    # Python's urlsafe_b64encode adds padding, so we must strip it
    encoded = base64.urlsafe_b64encode(json_bytes).decode('utf-8').rstrip('=')
    
    return f"stealthlink://{encoded}"

if __name__ == "__main__":
    # Example Server Configuration
    # You can add multiple servers here for failover/load balancing
    my_servers = [
        {
            "address": "1.2.3.4:443",
            "psk": "your-secret-key-here",
            "sni": "google.com",
            "transport": "tls", # or "quic"
            "weight": 10
        },
        # Uncomment to add a second server
        # {
        #     "address": "5.6.7.8:443",
        #     "psk": "another-key",
        #     "sni": "example.com",
        #     "transport": "quic",
        #     "weight": 5
        # }
    ]

    link = generate_link(my_servers, name="Direct Connection")
    print("Generated StealthLink:")
    print(link)
    
    # To decode and verify:
    # print("\nDecoded Config:")
    # print(json.dumps(json.loads(base64.urlsafe_b64decode(link.split('//')[1] + '==')), indent=2))
