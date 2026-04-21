// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

package transport

import (
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type FirewallConfig struct {
	BlockedPorts          []uint16 `json:"blocked_ports"`
	MaxConnectionsPerUser int      `json:"max_connections_per_user"`
	MaxBandwidthDefault   int64    `json:"max_bandwidth_default"`
	AllowPrivateRanges    bool     `json:"allow_private_ranges"`
}

type Firewall struct {
	config        FirewallConfig
	blockedPorts  map[uint16]bool
	privateRanges []*net.IPNet

	mu             sync.RWMutex
	userConnCounts map[string]*int64
	userBandwidth  map[string]*bandwidthTracker
}

type bandwidthTracker struct {
	bytesUsed   int64
	limit       int64
	windowStart time.Time
}

func DefaultFirewallConfig() FirewallConfig {
	return FirewallConfig{
		BlockedPorts:          []uint16{25, 465, 587, 137, 138, 139, 445},
		MaxConnectionsPerUser: 2000,
		MaxBandwidthDefault:   0,
		AllowPrivateRanges:    false,
	}
}

func NewFirewall(cfg FirewallConfig) *Firewall {
	blocked := make(map[uint16]bool)
	for _, p := range cfg.BlockedPorts {
		blocked[p] = true
	}

	privateRanges := []*net.IPNet{}
	for _, cidr := range []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"fc00::/7",
		"fe80::/10",
		"::1/128",
	} {
		_, ipNet, _ := net.ParseCIDR(cidr)
		if ipNet != nil {
			privateRanges = append(privateRanges, ipNet)
		}
	}

	return &Firewall{
		config:         cfg,
		blockedPorts:   blocked,
		privateRanges:  privateRanges,
		userConnCounts: make(map[string]*int64),
		userBandwidth:  make(map[string]*bandwidthTracker),
	}
}

func (fw *Firewall) CheckConnection(userID string, destAddr string, destPort uint16, user *UserRecord) bool {
	if fw.blockedPorts[destPort] {
		log.Printf("[FW] Blocked port %d for user %s", destPort, userID)
		return false
	}

	if user != nil && len(user.AllowedPorts) > 0 {
		allowed := false
		for _, pr := range user.AllowedPorts {
			if destPort >= pr.From && destPort <= pr.To {
				allowed = true
				break
			}
		}
		if !allowed {
			log.Printf("[FW] Port %d not in allowed range for user %s", destPort, userID)
			return false
		}
	}

	if !fw.config.AllowPrivateRanges {
		ip := net.ParseIP(destAddr)
		if ip != nil {
			for _, priv := range fw.privateRanges {
				if priv.Contains(ip) {
					log.Printf("[FW] Blocked private range %s for user %s", destAddr, userID)
					return false
				}
			}
		}
	}

	if fw.config.MaxConnectionsPerUser > 0 {
		count := fw.getConnCount(userID)
		if int(atomic.LoadInt64(count)) >= fw.config.MaxConnectionsPerUser {
			log.Printf("[FW] Connection limit reached for user %s", userID)
			return false
		}
	}

	return true
}

func (fw *Firewall) getConnCount(userID string) *int64 {
	fw.mu.RLock()
	count, ok := fw.userConnCounts[userID]
	fw.mu.RUnlock()
	if ok {
		return count
	}

	fw.mu.Lock()
	defer fw.mu.Unlock()
	count, ok = fw.userConnCounts[userID]
	if !ok {
		var n int64
		count = &n
		fw.userConnCounts[userID] = count
	}
	return count
}

func (fw *Firewall) OnConnect(userID string) {
	count := fw.getConnCount(userID)
	atomic.AddInt64(count, 1)
}

func (fw *Firewall) OnDisconnect(userID string) {
	count := fw.getConnCount(userID)
	atomic.AddInt64(count, -1)
}

func (fw *Firewall) TrackBandwidth(userID string, bytes int64) bool {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	tracker, ok := fw.userBandwidth[userID]
	if !ok {
		tracker = &bandwidthTracker{
			windowStart: time.Now(),
			limit:       fw.config.MaxBandwidthDefault,
		}
		fw.userBandwidth[userID] = tracker
	}

	if time.Since(tracker.windowStart) > time.Second {
		tracker.bytesUsed = 0
		tracker.windowStart = time.Now()
	}

	tracker.bytesUsed += bytes

	if tracker.limit > 0 && tracker.bytesUsed > tracker.limit {
		return false
	}
	return true
}

func (fw *Firewall) SetUserBandwidthLimit(userID string, limit int64) {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	tracker, ok := fw.userBandwidth[userID]
	if !ok {
		tracker = &bandwidthTracker{
			windowStart: time.Now(),
		}
		fw.userBandwidth[userID] = tracker
	}
	tracker.limit = limit
}
