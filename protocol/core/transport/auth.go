// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

package transport

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

type UserRecord struct {
	ID           string          `json:"id"`
	PSK          string          `json:"psk"`
	MaxBandwidth int64           `json:"max_bandwidth"`
	AllowedPorts []PortRange     `json:"allowed_ports"`
	ExpiresAt    string          `json:"expires_at"`
	Upstream     *UpstreamConfig `json:"upstream,omitempty"`
	pskBytes     [32]byte
	expiresAt    time.Time
}

type UpstreamConfig struct {
	Address     string `json:"address"`
	PSK         string `json:"psk"`
	SNI         string `json:"sni"`
	SecretPath  string `json:"secret_path"`
	Fingerprint string `json:"fingerprint"` // https://github.com/komarukomaru/stealthlink/issues/2
}

type PortRange struct {
	From uint16 `json:"from"`
	To   uint16 `json:"to"`
}

type AuthManager struct {
	mu     sync.RWMutex
	users  map[string]*UserRecord
	pskMap map[[32]byte]*UserRecord

	rateMu    sync.Mutex
	authRates map[string]*rateEntry
}

type rateEntry struct {
	count   int
	resetAt time.Time
}

type AuthSession struct {
	User     *UserRecord
	RemoteIP string
}

func NewAuthManager(users []*UserRecord) *AuthManager {
	am := &AuthManager{
		users:     make(map[string]*UserRecord),
		pskMap:    make(map[[32]byte]*UserRecord),
		authRates: make(map[string]*rateEntry),
	}
	for _, u := range users {
		am.AddUser(u)
	}
	return am
}

func (am *AuthManager) AddUser(u *UserRecord) {
	am.mu.Lock()
	defer am.mu.Unlock()

	pskHash := sha256.Sum256([]byte(u.PSK))
	u.pskBytes = pskHash

	if u.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, u.ExpiresAt)
		if err == nil {
			u.expiresAt = t
		}
	}

	am.users[u.ID] = u
	am.pskMap[pskHash] = u
}

func (am *AuthManager) RemoveUser(id string) {
	am.mu.Lock()
	defer am.mu.Unlock()
	if u, ok := am.users[id]; ok {
		delete(am.pskMap, u.pskBytes)
		delete(am.users, id)
	}
}

func (am *AuthManager) checkRateLimit(remoteIP string) bool {
	am.rateMu.Lock()
	defer am.rateMu.Unlock()

	now := time.Now()
	entry, ok := am.authRates[remoteIP]
	if !ok || now.After(entry.resetAt) {
		am.authRates[remoteIP] = &rateEntry{count: 1, resetAt: now.Add(time.Minute)}
		return true
	}
	entry.count++
	return entry.count <= 1000
}

func (am *AuthManager) cleanRateLimits() {
	am.rateMu.Lock()
	defer am.rateMu.Unlock()
	now := time.Now()
	for ip, entry := range am.authRates {
		if now.After(entry.resetAt) {
			delete(am.authRates, ip)
		}
	}
}

func (am *AuthManager) ValidateAuth(authData []byte, remoteAddr net.Addr) (*AuthSession, error) {
	remoteIP := ""
	if addr, ok := remoteAddr.(*net.TCPAddr); ok {
		remoteIP = addr.IP.String()
	} else if addr, ok := remoteAddr.(*net.UDPAddr); ok {
		remoteIP = addr.IP.String()
	} else {
		remoteIP = remoteAddr.String()
	}

	if !am.checkRateLimit(remoteIP) {
		return nil, fmt.Errorf("rate limited")
	}

	if len(authData) < 56 {
		return nil, fmt.Errorf("auth data too short")
	}

	clientHMAC := authData[:32]
	nonce := authData[32:56]

	now := time.Now()
	currentMinute := now.Unix() / 60
	prevMinute := currentMinute - 1

	am.mu.RLock()
	defer am.mu.RUnlock()

	for _, user := range am.users {
		if !user.expiresAt.IsZero() && now.After(user.expiresAt) {
			continue
		}

		for _, minute := range []int64{currentMinute, prevMinute} {
			timeBuf := make([]byte, 8)
			binary.BigEndian.PutUint64(timeBuf, uint64(minute))

			mac := hmac.New(sha256.New, user.pskBytes[:])
			mac.Write(timeBuf)
			mac.Write(nonce)
			expected := mac.Sum(nil)

			if hmac.Equal(clientHMAC, expected) {
				return &AuthSession{
					User:     user,
					RemoteIP: remoteIP,
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("invalid credentials")
}

func GenerateAuthPayload(psk string) ([]byte, error) {
	pskHash := sha256.Sum256([]byte(psk))

	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	currentMinute := time.Now().Unix() / 60
	timeBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBuf, uint64(currentMinute))

	mac := hmac.New(sha256.New, pskHash[:])
	mac.Write(timeBuf)
	mac.Write(nonce)
	hmacResult := mac.Sum(nil)

	payload := make([]byte, 56)
	copy(payload[:32], hmacResult)
	copy(payload[32:], nonce)

	return payload, nil
}

func EncodeAuthFrame(psk string) (Frame, error) {
	payload, err := GenerateAuthPayload(psk)
	if err != nil {
		return Frame{}, err
	}
	return Frame{Type: FrameAuth, Payload: payload}, nil
}

func EncodeAuthResponse(status byte, config []byte) Frame {
	payload := make([]byte, 1+len(config))
	payload[0] = status
	if len(config) > 0 {
		copy(payload[1:], config)
	}
	return Frame{Type: FrameAuthResp, Payload: payload}
}

const (
	AuthStatusOK          byte = 0x00
	AuthStatusDenied      byte = 0x01
	AuthStatusExpired     byte = 0x02
	AuthStatusRateLimited byte = 0x03
)
