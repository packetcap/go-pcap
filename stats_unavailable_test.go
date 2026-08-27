//go:build darwin || freebsd

package pcap

import (
	"errors"
	"testing"
)

func TestStatsReturnsTypedUnavailableErrorOutsideLinux(t *testing.T) {
	_, err := (&Handle{}).Stats()
	if err == nil {
		t.Fatal("Stats returned nil error, want typed unavailable error")
	}
	var unavailable *StatsUnavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("Stats error = %T %v, want *StatsUnavailableError", err, err)
	}
}
