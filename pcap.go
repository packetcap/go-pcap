package pcap

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
)

type Packet struct {
	B     []byte
	Info  gopacket.CaptureInfo
	Error error
}

// Listen simple one-step command to open, listen and send packets over a returned channel
func Listen(iface string, snaplen int32, promiscuous, syscalls bool, timeout time.Duration) (chan Packet, error) {
	h, err := openLive(iface, snaplen, promiscuous, timeout, syscalls)
	if err != nil {
		return nil, fmt.Errorf("failed to open interface for listening: %v", err)
	}
	c := make(chan Packet, 50)
	go func() {
		for {
			b, ci, err := h.ReadPacketData()
			c <- Packet{
				B:     b,
				Info:  ci,
				Error: err,
			}
		}
	}()
	return c, nil
}
