// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

package transport

import (
	"hash/fnv"
	"math"
	"sync"
	"time"
)

type BloomFilter struct {
	bitset []uint64
	m      uint64
	k      uint
	mu     sync.RWMutex
}

func NewBloomFilter(capacity uint64, falsePositiveRate float64) *BloomFilter {
	m := uint64(math.Ceil(-float64(capacity) * math.Log(falsePositiveRate) / (math.Pow(math.Log(2), 2))))
	k := uint(math.Ceil(float64(m) / float64(capacity) * math.Log(2)))

	return &BloomFilter{
		bitset: make([]uint64, (m+63)/64),
		m:      m,
		k:      k,
	}
}

func (bf *BloomFilter) Add(data []byte) {
	bf.mu.Lock()
	defer bf.mu.Unlock()

	h1, h2 := hash(data)
	for i := uint(0); i < bf.k; i++ {
		pos := (h1 + uint64(i)*h2) % bf.m
		bf.bitset[pos/64] |= 1 << (pos % 64)
	}
}

func (bf *BloomFilter) Contains(data []byte) bool {
	bf.mu.RLock()
	defer bf.mu.RUnlock()

	h1, h2 := hash(data)
	for i := uint(0); i < bf.k; i++ {
		pos := (h1 + uint64(i)*h2) % bf.m
		if bf.bitset[pos/64]&(1<<(pos%64)) == 0 {
			return false
		}
	}
	return true
}

func hash(data []byte) (uint64, uint64) {
	h := fnv.New64a()
	h.Write(data)
	h1 := h.Sum64()

	h.Write([]byte{1})
	h2 := h.Sum64()
	return h1, h2
}

type ReplayFilter struct {
	current  *BloomFilter
	previous *BloomFilter
	capacity uint64
	fpRate   float64
	mu       sync.RWMutex
	stopChan chan struct{}
}

func NewReplayFilter(capacity uint64, interval time.Duration) *ReplayFilter {
	rf := &ReplayFilter{
		current:  NewBloomFilter(capacity, 0.0001),
		capacity: capacity,
		fpRate:   0.0001,
		stopChan: make(chan struct{}),
	}
	go rf.autoRotate(interval)
	return rf
}

func (rf *ReplayFilter) CheckAndAdd(data []byte) bool {
	rf.mu.RLock()
	if rf.current.Contains(data) {
		rf.mu.RUnlock()
		return true
	}
	if rf.previous != nil && rf.previous.Contains(data) {
		rf.mu.RUnlock()
		return true
	}
	rf.mu.RUnlock()

	rf.mu.Lock()
	defer rf.mu.Unlock()
	if rf.current.Contains(data) {
		return true
	}
	if rf.previous != nil && rf.previous.Contains(data) {
		return true
	}

	rf.current.Add(data)
	return false
}

func (rf *ReplayFilter) autoRotate(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rf.rotate()
		case <-rf.stopChan:
			return
		}
	}
}

func (rf *ReplayFilter) rotate() {
	rf.mu.Lock()
	defer rf.mu.Unlock()
	rf.previous = rf.current
	rf.current = NewBloomFilter(rf.capacity, rf.fpRate)
}

func (rf *ReplayFilter) Stop() {
	close(rf.stopChan)
}
