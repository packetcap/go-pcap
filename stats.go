package pcap

import (
	"fmt"
	"sync"
)

// Statistics reports cumulative packet-socket receive counters for one Handle.
// Packets and Drops never decrease during the lifetime of that Handle.
type Statistics struct {
	Packets uint64
	Drops   uint64
}

// StatsUnavailableError reports that the current capture backend cannot expose
// kernel packet statistics.
type StatsUnavailableError struct {
	Platform string
}

func (e *StatsUnavailableError) Error() string {
	return fmt.Sprintf("capture statistics unavailable on %s", e.Platform)
}

type statisticsAccumulator struct {
	mu     sync.Mutex
	totals Statistics
}

func (a *statisticsAccumulator) add(delta Statistics) Statistics {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.totals.Packets += delta.Packets
	a.totals.Drops += delta.Drops
	return a.totals
}
