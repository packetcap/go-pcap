//go:build linux

package pcap

import (
	"sync"
	"testing"
)

func TestStatsAccumulatesResetOnReadKernelCounters(t *testing.T) {
	deltas := []Statistics{
		{Packets: 10, Drops: 3},
		{Packets: 7, Drops: 2},
	}
	handle := &Handle{
		statsReader: func(int) (Statistics, error) {
			next := deltas[0]
			deltas = deltas[1:]
			return next, nil
		},
	}

	first, err := handle.Stats()
	if err != nil {
		t.Fatalf("first Stats: %v", err)
	}
	second, err := handle.Stats()
	if err != nil {
		t.Fatalf("second Stats: %v", err)
	}

	if first != (Statistics{Packets: 10, Drops: 3}) {
		t.Fatalf("first Stats = %+v, want cumulative packets=10 drops=3", first)
	}
	if second != (Statistics{Packets: 17, Drops: 5}) {
		t.Fatalf("second Stats = %+v, want cumulative packets=17 drops=5", second)
	}
	if second.Packets < first.Packets || second.Drops < first.Drops {
		t.Fatalf("cumulative Stats decreased: first=%+v second=%+v", first, second)
	}
}

func TestStatsSerializesConcurrentReaders(t *testing.T) {
	var readerMu sync.Mutex
	calls := 0
	handle := &Handle{
		statsReader: func(int) (Statistics, error) {
			readerMu.Lock()
			defer readerMu.Unlock()
			calls++
			return Statistics{Packets: 1, Drops: 1}, nil
		},
	}

	const readers = 32
	var wg sync.WaitGroup
	wg.Add(readers)
	for range readers {
		go func() {
			defer wg.Done()
			if _, err := handle.Stats(); err != nil {
				t.Errorf("Stats: %v", err)
			}
		}()
	}
	wg.Wait()

	final, err := handle.Stats()
	if err != nil {
		t.Fatalf("final Stats: %v", err)
	}
	if final != (Statistics{Packets: readers + 1, Drops: readers + 1}) {
		t.Fatalf("final Stats = %+v, want packets=%d drops=%d", final, readers+1, readers+1)
	}
	if calls != readers+1 {
		t.Fatalf("kernel reader calls = %d, want %d", calls, readers+1)
	}
}
