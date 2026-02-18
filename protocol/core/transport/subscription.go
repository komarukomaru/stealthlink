package transport

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"
)

type SubscriptionConfig struct {
	Version        int           `json:"version"`
	Name           string        `json:"name"`
	Servers        []ServerEntry `json:"servers"`
	UpdateURL      string        `json:"update_url,omitempty"`
	UpdateInterval int           `json:"update_interval,omitempty"`
}

type ServerEntry struct {
	Address    string `json:"address"`
	PSK        string `json:"psk"`
	SNI        string `json:"sni"`
	Weight     int    `json:"weight"`
	Transport  string `json:"transport"`
	SecretPath string `json:"secret_path,omitempty"`
}

const subscriptionScheme = "stealthlink://"

func EncodeSubscriptionURL(config *SubscriptionConfig) (string, error) {
	data, err := json.Marshal(config)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(data)
	return subscriptionScheme + encoded, nil
}

func DecodeSubscriptionURL(url string) (*SubscriptionConfig, error) {
	if !strings.HasPrefix(url, subscriptionScheme) {
		return nil, fmt.Errorf("invalid scheme: expected %s", subscriptionScheme)
	}

	encoded := strings.TrimPrefix(url, subscriptionScheme)
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode failed: %w", err)
	}

	config := &SubscriptionConfig{}
	if err := json.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("unmarshal failed: %w", err)
	}

	if config.Version == 0 {
		config.Version = 1
	}

	return config, nil
}

type ServerSelector struct {
	mu      sync.RWMutex
	servers []ServerEntry
	rng     *rand.Rand
}

func NewServerSelector(servers []ServerEntry) *ServerSelector {
	for i := range servers {
		if servers[i].Weight <= 0 {
			servers[i].Weight = 1
		}
		if servers[i].Transport == "" {
			servers[i].Transport = "tls"
		}
	}

	return &ServerSelector{
		servers: servers,
		rng:     rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (ss *ServerSelector) SelectServer() *ServerEntry {
	ss.mu.RLock()
	defer ss.mu.RUnlock()

	if len(ss.servers) == 0 {
		return nil
	}

	totalWeight := 0
	for _, s := range ss.servers {
		totalWeight += s.Weight
	}

	r := ss.rng.Intn(totalWeight)
	cumulative := 0
	for i := range ss.servers {
		cumulative += ss.servers[i].Weight
		if r < cumulative {
			return &ss.servers[i]
		}
	}

	return &ss.servers[0]
}

func (ss *ServerSelector) SelectBestServer(timeout time.Duration) *ServerEntry {
	ss.mu.RLock()
	servers := make([]ServerEntry, len(ss.servers))
	copy(servers, ss.servers)
	ss.mu.RUnlock()

	if len(servers) == 0 {
		return nil
	}

	type pingResult struct {
		index   int
		latency time.Duration
		ok      bool
	}

	results := make(chan pingResult, len(servers))
	for i, s := range servers {
		go func(idx int, entry ServerEntry) {
			start := time.Now()
			conn, err := net.DialTimeout("tcp", entry.Address, timeout)
			if err != nil {
				results <- pingResult{index: idx, ok: false}
				return
			}
			conn.Close()
			results <- pingResult{index: idx, latency: time.Since(start), ok: true}
		}(i, s)
	}

	var best *pingResult
	for i := 0; i < len(servers); i++ {
		r := <-results
		if r.ok && (best == nil || r.latency < best.latency) {
			best = &r
		}
	}

	if best != nil {
		return &servers[best.index]
	}

	return ss.SelectServer()
}

func (ss *ServerSelector) UpdateServers(servers []ServerEntry) {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	for i := range servers {
		if servers[i].Weight <= 0 {
			servers[i].Weight = 1
		}
		if servers[i].Transport == "" {
			servers[i].Transport = "tls"
		}
	}
	ss.servers = servers
}

func (ss *ServerSelector) GetServers() []ServerEntry {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	result := make([]ServerEntry, len(ss.servers))
	copy(result, ss.servers)
	return result
}
