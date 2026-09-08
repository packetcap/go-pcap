//go:build linux

package pcap

import (
	"bytes"
	"testing"
	"time"

	"golang.org/x/net/bpf"
	syscall "golang.org/x/sys/unix"
)

// TestSetFilterDrainsPreAttachFrames proves the D-09/CAP2-07 attach-race
// mitigation: any frame that queued on the socket before setFilter's
// total-filter+drain+real-filter sequence runs is never delivered
// afterwards, even once the real filter accepts everything.
//
// This exercises the total-filter/drain/real-filter sequence directly on an
// unprivileged UDP socket rather than a real AF_PACKET capture (which needs
// CAP_NET_RAW) — SO_ATTACH_FILTER and the drain mechanics operate identically
// on any socket type; the mechanism under test is exactly the code path
// setFilter runs for the real AF_PACKET handle.
func TestSetFilterDrainsPreAttachFrames(t *testing.T) {
	preSentinel := []byte("PRE-FILTER-SENTINEL-DO-NOT-DELIVER")
	postSentinel := []byte("POST-FILTER-SENTINEL-OK")

	rfd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	defer syscall.Close(rfd)

	if err := syscall.Bind(rfd, &syscall.SockaddrInet4{Port: 0, Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	sa, err := syscall.Getsockname(rfd)
	if err != nil {
		t.Fatalf("getsockname: %v", err)
	}
	addr, ok := sa.(*syscall.SockaddrInet4)
	if !ok {
		t.Fatalf("unexpected sockaddr type %T", sa)
	}

	sfd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("sender socket: %v", err)
	}
	defer syscall.Close(sfd)

	// Simulate the attach-race window: frames arrive on the raw socket
	// while it is live but before any filter — total or real — has been
	// attached (mirrors the AF_PACKET socket()/bind() window in openLive).
	for i := 0; i < 5; i++ {
		if err := syscall.Sendto(sfd, preSentinel, 0, addr); err != nil {
			t.Fatalf("sendto (pre-filter): %v", err)
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		n, err := pendingBytes(rfd)
		if err != nil {
			t.Fatalf("checking pending bytes: %v", err)
		}
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for pre-filter datagrams to queue")
		}
		time.Sleep(time.Millisecond)
	}

	// Now run the exact sequence setFilter uses: total filter, drain,
	// real filter. The real filter here accepts everything (RetConstant
	// with a generous snap) so a leak would show up as a delivered read.
	h := &Handle{fd: rfd}
	realFilter, err := bpf.Assemble([]bpf.Instruction{bpf.RetConstant{Val: 1500}})
	if err != nil {
		t.Fatalf("assembling accept-all real filter: %v", err)
	}
	h.filter = realFilter
	if err := h.setFilter(); err != nil {
		t.Fatalf("setFilter: %v", err)
	}

	// A frame sent AFTER the real filter is attached must be delivered —
	// proves the drain didn't also blackhole legitimate post-attach traffic.
	if err := syscall.Sendto(sfd, postSentinel, 0, addr); err != nil {
		t.Fatalf("sendto (post-filter): %v", err)
	}

	buf := make([]byte, 256)
	deadline = time.Now().Add(2 * time.Second)
	var got [][]byte
	for time.Now().Before(deadline) {
		if err := syscall.SetNonblock(rfd, true); err != nil {
			t.Fatalf("set nonblock: %v", err)
		}
		n, _, err := syscall.Recvfrom(rfd, buf, 0)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				time.Sleep(time.Millisecond)
				continue
			}
			t.Fatalf("recvfrom: %v", err)
		}
		msg := make([]byte, n)
		copy(msg, buf[:n])
		got = append(got, msg)
	}

	for _, msg := range got {
		if bytes.Equal(msg, preSentinel) {
			t.Fatalf("pre-attach-race frame was delivered after setFilter's drain sequence: %q", msg)
		}
	}
	found := false
	for _, msg := range got {
		if bytes.Equal(msg, postSentinel) {
			found = true
		}
	}
	if !found {
		t.Fatalf("post-filter frame was never delivered — drain sequence over-blocked legitimate traffic; got=%q", got)
	}
}

// pendingBytes reports how many bytes are queued and unread on fd via
// SIOCINQ, used only to synchronize the test on kernel delivery of the
// pre-filter sentinel datagrams before the drain sequence runs.
func pendingBytes(fd int) (int, error) {
	v, err := syscall.IoctlGetInt(fd, syscall.SIOCINQ)
	if err != nil {
		return 0, err
	}
	return v, nil
}
