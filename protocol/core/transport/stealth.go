// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

package transport

import (
	"crypto/rand"
	"math/big"
	"sync"
	"time"
)

type StealthConfig struct {
	Enabled              bool `json:"enabled"`
	DecoyStreams         bool `json:"decoy_streams"`
	ProtocolPolymorphism bool `json:"protocol_polymorphism"`
	AdaptiveThrottling   bool `json:"adaptive_throttling"`
	DecoyInterval        time.Duration
}

func DefaultStealthConfig() StealthConfig {
	return StealthConfig{
		Enabled:              true,
		DecoyStreams:         true,
		ProtocolPolymorphism: true,
		AdaptiveThrottling:   true,
		DecoyInterval:        5 * time.Second,
	}
}

type StealthEngine struct {
	config   StealthConfig
	writer   *FrameWriter
	mu       sync.Mutex
	stopChan chan struct{}

	sessionParams *SessionParams

	latencyHistory []time.Duration
	throttled      bool
}

type SessionParams struct {
	FramePaddingMin  int
	FramePaddingMax  int
	FlushInterval    time.Duration
	BatchSize        int
	DummyMinInterval time.Duration
	DummyMaxInterval time.Duration
}

func NewStealthEngine(writer *FrameWriter, config StealthConfig) *StealthEngine {
	se := &StealthEngine{
		config:   config,
		writer:   writer,
		stopChan: make(chan struct{}),
	}

	if config.ProtocolPolymorphism {
		se.sessionParams = se.generateSessionParams()
	} else {
		se.sessionParams = &SessionParams{
			FramePaddingMin:  16,
			FramePaddingMax:  128,
			FlushInterval:    2 * time.Millisecond,
			BatchSize:        64 * 1024,
			DummyMinInterval: 2 * time.Second,
			DummyMaxInterval: 8 * time.Second,
		}
	}

	if config.DecoyStreams {
		go se.decoyLoop()
	}

	return se
}

func (se *StealthEngine) generateSessionParams() *SessionParams {
	return &SessionParams{
		FramePaddingMin:  stealthRandInt(8, 32),
		FramePaddingMax:  stealthRandInt(64, 512),
		FlushInterval:    time.Duration(stealthRandInt(1, 5)) * time.Millisecond,
		BatchSize:        stealthRandInt(32, 128) * 1024,
		DummyMinInterval: time.Duration(stealthRandInt(1, 4)) * time.Second,
		DummyMaxInterval: time.Duration(stealthRandInt(5, 15)) * time.Second,
	}
}

func (se *StealthEngine) GetSessionParams() *SessionParams {
	return se.sessionParams
}

func (se *StealthEngine) decoyLoop() {
	decoyPatterns := [][]int{
		{64, 128, 256},
		{512, 128, 64, 32},
		{1024, 256, 128},
		{128, 256, 512, 1024, 256},
		{32, 64, 128, 64, 32},
	}

	for {
		interval := stealthRandDuration(
			se.sessionParams.DummyMinInterval,
			se.sessionParams.DummyMaxInterval,
		)

		select {
		case <-time.After(interval):
			if se.throttled {
				continue
			}

			patternIdx := stealthRandInt(0, len(decoyPatterns)-1)
			pattern := decoyPatterns[patternIdx]

			for _, size := range pattern {
				padding := make([]byte, size)
				rand.Read(padding)

				se.mu.Lock()
				se.writer.WriteTypedFrame(Frame{
					Type:    FramePadding,
					Payload: padding,
				})
				se.mu.Unlock()

				jitter := stealthRandDuration(10*time.Millisecond, 100*time.Millisecond)
				time.Sleep(jitter)
			}

		case <-se.stopChan:
			return
		}
	}
}

func (se *StealthEngine) RecordLatency(d time.Duration) {
	se.mu.Lock()
	defer se.mu.Unlock()

	se.latencyHistory = append(se.latencyHistory, d)
	if len(se.latencyHistory) > 50 {
		se.latencyHistory = se.latencyHistory[len(se.latencyHistory)-50:]
	}

	if !se.config.AdaptiveThrottling || len(se.latencyHistory) < 10 {
		return
	}

	recent := se.latencyHistory[len(se.latencyHistory)-5:]
	older := se.latencyHistory[:len(se.latencyHistory)-5]

	recentAvg := avgDuration(recent)
	olderAvg := avgDuration(older)

	if recentAvg > olderAvg*3 && recentAvg > 500*time.Millisecond {
		if !se.throttled {
			se.throttled = true
			se.sessionParams.DummyMinInterval *= 3
			se.sessionParams.DummyMaxInterval *= 3
		}
	} else if se.throttled && recentAvg < olderAvg*2 {
		se.throttled = false
		se.sessionParams = se.generateSessionParams()
	}
}

func (se *StealthEngine) IsThrottled() bool {
	se.mu.Lock()
	defer se.mu.Unlock()
	return se.throttled
}

func (se *StealthEngine) Stop() {
	select {
	case <-se.stopChan:
	default:
		close(se.stopChan)
	}
}

func avgDuration(ds []time.Duration) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	var sum time.Duration
	for _, d := range ds {
		sum += d
	}
	return sum / time.Duration(len(ds))
}

func stealthRandInt(min, max int) int {
	if min >= max {
		return min
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	return min + int(n.Int64())
}

func stealthRandDuration(min, max time.Duration) time.Duration {
	if min >= max {
		return min
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max-min)))
	return min + time.Duration(n.Int64())
}
