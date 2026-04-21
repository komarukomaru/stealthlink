// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

package transport

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"sort"
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
	Address     string `json:"address"`
	PSK         string `json:"psk"`
	SNI         string `json:"sni"`
	Weight      int    `json:"weight"`
	Transport   string `json:"transport"`
	SecretPath  string `json:"secret_path,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
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
	stats   map[string]*serverHealthStats
}

type serverHealthStats struct {
	latencyEWMA         time.Duration
	successCount        int
	failureCount        int
	consecutiveFailures int
	lastFailure         time.Time
	lastSuccess         time.Time
	cooldownUntil       time.Time
}

type serverAttemptGroup struct {
	Base     ServerEntry
	Variants []ServerEntry
}

func NewServerSelector(servers []ServerEntry) *ServerSelector {
	normalizeServerEntries(servers)

	return &ServerSelector{
		servers: servers,
		rng:     rand.New(rand.NewSource(time.Now().UnixNano())),
		stats:   make(map[string]*serverHealthStats),
	}
}

func (ss *ServerSelector) SelectServer() *ServerEntry {
	ss.mu.Lock()
	defer ss.mu.Unlock()

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

	normalizeServerEntries(servers)
	ss.servers = servers
}

func (ss *ServerSelector) GetServers() []ServerEntry {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	result := make([]ServerEntry, len(ss.servers))
	copy(result, ss.servers)
	return result
}

func (ss *ServerSelector) RankServerGroups(preferredTransport string) []serverAttemptGroup {
	ss.mu.RLock()
	defer ss.mu.RUnlock()

	type scoredVariant struct {
		server ServerEntry
		score  int64
		order  int
	}

	type scoredGroup struct {
		group serverAttemptGroup
		score int64
	}

	now := time.Now()
	preferred := normalizeTransportPreference(preferredTransport)
	scoredGroups := make([]scoredGroup, 0, len(ss.servers))

	for _, base := range ss.servers {
		variants := buildTransportVariants(base, preferred)
		if len(variants) == 0 {
			continue
		}

		scoredVariants := make([]scoredVariant, 0, len(variants))
		for idx, variant := range variants {
			scoredVariants = append(scoredVariants, scoredVariant{
				server: variant,
				score:  ss.candidateScoreLocked(variant, now),
				order:  idx,
			})
		}

		sort.SliceStable(scoredVariants, func(i, j int) bool {
			if scoredVariants[i].score == scoredVariants[j].score {
				return scoredVariants[i].order < scoredVariants[j].order
			}
			return scoredVariants[i].score < scoredVariants[j].score
		})

		group := serverAttemptGroup{
			Base:     base,
			Variants: make([]ServerEntry, 0, len(scoredVariants)),
		}
		for _, variant := range scoredVariants {
			group.Variants = append(group.Variants, variant.server)
		}

		scoredGroups = append(scoredGroups, scoredGroup{
			group: group,
			score: scoredVariants[0].score,
		})
	}

	sort.SliceStable(scoredGroups, func(i, j int) bool {
		if scoredGroups[i].score == scoredGroups[j].score {
			return scoredGroups[i].group.Base.Weight > scoredGroups[j].group.Base.Weight
		}
		return scoredGroups[i].score < scoredGroups[j].score
	})

	result := make([]serverAttemptGroup, 0, len(scoredGroups))
	for _, group := range scoredGroups {
		result = append(result, group.group)
	}
	return result
}

func (ss *ServerSelector) ReportDialResult(server ServerEntry, latency time.Duration, err error) {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	stats := ss.ensureStatsLocked(server)
	now := time.Now()

	if err == nil {
		stats.successCount++
		stats.consecutiveFailures = 0
		stats.lastSuccess = now
		stats.cooldownUntil = time.Time{}
		if latency > 0 {
			if stats.latencyEWMA == 0 {
				stats.latencyEWMA = latency
			} else {
				stats.latencyEWMA = (stats.latencyEWMA*3 + latency) / 4
			}
		}
		return
	}

	stats.failureCount++
	stats.consecutiveFailures++
	stats.lastFailure = now
	stats.cooldownUntil = now.Add(cooldownForFailures(stats.consecutiveFailures))
}

func (ss *ServerSelector) ensureStatsLocked(server ServerEntry) *serverHealthStats {
	key := serverStatsKey(server)
	stats := ss.stats[key]
	if stats == nil {
		stats = &serverHealthStats{}
		ss.stats[key] = stats
	}
	return stats
}

func (ss *ServerSelector) candidateScoreLocked(server ServerEntry, now time.Time) int64 {
	weight := server.Weight
	if weight <= 0 {
		weight = 1
	}

	score := int64(2000 / weight)
	stats := ss.stats[serverStatsKey(server)]
	if stats == nil {
		return score + 250
	}

	if stats.latencyEWMA > 0 {
		score += int64(stats.latencyEWMA / time.Millisecond)
	} else {
		score += 150
	}

	score += int64(stats.failureCount * 50)
	score += int64(stats.consecutiveFailures * 750)

	if !stats.cooldownUntil.IsZero() && now.Before(stats.cooldownUntil) {
		score += 5000 + int64(time.Until(stats.cooldownUntil)/time.Millisecond)
	}

	if stats.successCount > stats.failureCount {
		score -= int64((stats.successCount - stats.failureCount) * 25)
	}

	return score
}

func normalizeServerEntries(servers []ServerEntry) {
	for i := range servers {
		if servers[i].Weight <= 0 {
			servers[i].Weight = 1
		}
		servers[i].Transport = normalizeStoredTransport(servers[i].Transport)
	}
}

func normalizeStoredTransport(transport string) string {
	switch normalizeTransportPreference(transport) {
	case "tls":
		return "tls"
	case "quic":
		return "quic"
	case "auto":
		return "auto"
	default:
		return ""
	}
}

func normalizeTransportPreference(transport string) string {
	switch strings.ToLower(strings.TrimSpace(transport)) {
	case "tls":
		return "tls"
	case "quic":
		return "quic"
	case "any", "auto":
		return "auto"
	default:
		return ""
	}
}

func buildTransportVariants(base ServerEntry, preferredTransport string) []ServerEntry {
	primary := normalizeTransportPreference(base.Transport)
	if primary == "" || primary == "auto" {
		primary = normalizeTransportPreference(preferredTransport)
	}
	if primary == "" {
		primary = "tls"
	}

	order := []string{"tls", "quic"}
	if primary == "quic" {
		order = []string{"quic", "tls"}
	}

	variants := make([]ServerEntry, 0, len(order))
	seen := make(map[string]struct{}, len(order))
	for _, transport := range order {
		if _, ok := seen[transport]; ok {
			continue
		}
		seen[transport] = struct{}{}

		variant := base
		variant.Transport = transport
		if variant.Weight <= 0 {
			variant.Weight = 1
		}
		variants = append(variants, variant)
	}
	return variants
}

func serverStatsKey(server ServerEntry) string {
	transport := normalizeTransportPreference(server.Transport)
	if transport != "quic" {
		transport = "tls"
	}
	return server.Address + "|" + transport
}

func cooldownForFailures(consecutiveFailures int) time.Duration {
	if consecutiveFailures <= 0 {
		return 0
	}

	cooldown := 2 * time.Second
	for i := 1; i < consecutiveFailures; i++ {
		cooldown *= 2
		if cooldown >= time.Minute {
			return time.Minute
		}
	}
	return cooldown
}
