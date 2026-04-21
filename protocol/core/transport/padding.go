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

type PaddingConfig struct {
	Enabled         bool `json:"enabled"`
	MinPaddingBytes int  `json:"min_padding_bytes"`
	MaxPaddingBytes int  `json:"max_padding_bytes"`
	DummyInterval   time.Duration
	TimingJitter    time.Duration
	NormalizeSize   bool `json:"normalize_size"`
}

func DefaultPaddingConfig() PaddingConfig {
	return PaddingConfig{
		Enabled:         true,
		MinPaddingBytes: 16,
		MaxPaddingBytes: 256,
		DummyInterval:   2 * time.Second,
		TimingJitter:    3 * time.Millisecond,
		NormalizeSize:   true,
	}
}

type PaddingEngine struct {
	config   PaddingConfig
	writer   *FrameWriter
	stopChan chan struct{}
	mu       sync.Mutex
}

func NewPaddingEngine(writer *FrameWriter, config PaddingConfig) *PaddingEngine {
	pe := &PaddingEngine{
		config:   config,
		writer:   writer,
		stopChan: make(chan struct{}),
	}
	if config.Enabled {
		go pe.dummyTrafficLoop()
	}
	return pe
}

func (pe *PaddingEngine) dummyTrafficLoop() {
	if pe.config.DummyInterval <= 0 {
		return
	}

	for {
		jitter := randomDuration(0, pe.config.DummyInterval/2)
		interval := pe.config.DummyInterval + jitter

		select {
		case <-time.After(interval):
			pe.sendDummyFrame()
		case <-pe.stopChan:
			return
		}
	}
}

func (pe *PaddingEngine) sendDummyFrame() {
	size := randomInt(pe.config.MinPaddingBytes, pe.config.MaxPaddingBytes)
	padding := make([]byte, size)
	rand.Read(padding)

	pe.mu.Lock()
	defer pe.mu.Unlock()

	pe.writer.WriteTypedFrame(Frame{
		Type:    FramePadding,
		Payload: padding,
	})
}

func (pe *PaddingEngine) WrapFrame(f Frame) Frame {
	if !pe.config.Enabled {
		return f
	}

	paddingSize := randomInt(pe.config.MinPaddingBytes, pe.config.MaxPaddingBytes)
	padding := make([]byte, paddingSize)
	rand.Read(padding)

	newPayload := make([]byte, 2+len(f.Payload)+paddingSize)
	newPayload[0] = f.Type
	newPayload[1] = byte(paddingSize)
	copy(newPayload[2:], f.Payload)
	copy(newPayload[2+len(f.Payload):], padding)

	return Frame{
		Type:    f.Type,
		Payload: newPayload,
	}
}

func (pe *PaddingEngine) AddTimingJitter() {
	if !pe.config.Enabled || pe.config.TimingJitter <= 0 {
		return
	}
	jitter := randomDuration(0, pe.config.TimingJitter)
	time.Sleep(jitter)
}

var commonSizes = []int{64, 128, 256, 512, 576, 1024, 1460, 4096, 8192, 16384}

func NormalizePacketSize(data []byte) []byte {
	dataLen := len(data)

	targetSize := commonSizes[len(commonSizes)-1]
	for _, s := range commonSizes {
		if s >= dataLen {
			targetSize = s
			break
		}
	}

	if targetSize <= dataLen {
		return data
	}

	padded := make([]byte, targetSize)
	copy(padded, data)
	rand.Read(padded[dataLen:])
	return padded
}

func (pe *PaddingEngine) Stop() {
	select {
	case <-pe.stopChan:
	default:
		close(pe.stopChan)
	}
}

func randomInt(min, max int) int {
	if min >= max {
		return min
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	return min + int(n.Int64())
}

func randomDuration(min, max time.Duration) time.Duration {
	if min >= max {
		return min
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max-min)))
	return min + time.Duration(n.Int64())
}
