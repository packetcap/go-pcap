package pcap

import (
	"sync"
	"testing"
)

func TestStatisticsAccumulatorAddsResetOnReadDeltas(t *testing.T) {
	var accumulator statisticsAccumulator

	first := accumulator.add(Statistics{Packets: 10, Drops: 3})
	second := accumulator.add(Statistics{Packets: 7, Drops: 2})

	if first != (Statistics{Packets: 10, Drops: 3}) {
		t.Fatalf("first cumulative statistics = %+v, want packets=10 drops=3", first)
	}
	if second != (Statistics{Packets: 17, Drops: 5}) {
		t.Fatalf("second cumulative statistics = %+v, want packets=17 drops=5", second)
	}
	if second.Packets < first.Packets || second.Drops < first.Drops {
		t.Fatalf("cumulative statistics decreased: first=%+v second=%+v", first, second)
	}
}

func TestStatisticsAccumulatorSerializesConcurrentReaders(t *testing.T) {
	var accumulator statisticsAccumulator

	const readers = 32
	var wg sync.WaitGroup
	wg.Add(readers)
	for range readers {
		go func() {
			defer wg.Done()
			accumulator.add(Statistics{Packets: 1, Drops: 1})
		}()
	}
	wg.Wait()

	final := accumulator.add(Statistics{})
	if final != (Statistics{Packets: readers, Drops: readers}) {
		t.Fatalf("final cumulative statistics = %+v, want packets=%d drops=%d", final, readers, readers)
	}
}
