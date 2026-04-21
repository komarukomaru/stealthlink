// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

package transport

import (
	"crypto/rand"
	"testing"
	"time"
)

func TestReplayFilter(t *testing.T) {
	rf := NewReplayFilter(1000, time.Minute)
	defer rf.Stop()

	data := make([]byte, 32)
	rand.Read(data)

	if rf.CheckAndAdd(data) {
		t.Fatal("first check should return false")
	}

	if !rf.CheckAndAdd(data) {
		t.Fatal("second check should return true")
	}

	other := make([]byte, 32)
	rand.Read(other)
	if rf.CheckAndAdd(other) {
		t.Fatal("other data should return false")
	}
}

func TestReplayFilterRotation(t *testing.T) {
	interval := 100 * time.Millisecond
	rf := NewReplayFilter(1000, interval)
	defer rf.Stop()

	data1 := []byte("block1")
	rf.CheckAndAdd(data1)

	if !rf.CheckAndAdd(data1) {
		t.Fatal("datashould be present")
	}

	time.Sleep(interval + 50*time.Millisecond)
	if !rf.CheckAndAdd(data1) {
		t.Fatal("data should still be present in previous filter")
	}

	time.Sleep(interval + 50*time.Millisecond)

	if rf.CheckAndAdd(data1) {
		t.Fatal("data should represent expired after 2 rotations")
	}
}

func TestBloomFilter(t *testing.T) {
	bf := NewBloomFilter(100, 0.01)

	data := []byte("hello")
	if bf.Contains(data) {
		t.Fatal("empty filter should not contain data")
	}

	bf.Add(data)
	if !bf.Contains(data) {
		t.Fatal("filter should contain added data")
	}

	count := 0
	for i := 0; i < 1000; i++ {
		d := make([]byte, 8)
		rand.Read(d)
		if bf.Contains(d) {
			count++
		}
	}
	if count > 50 {
		t.Errorf("too many false positives: %d", count)
	}
}
