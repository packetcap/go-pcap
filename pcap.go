package pcap

import (
	"encoding/binary"
	"fmt"
	"time"
	"unsafe"

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

// getEndianness discover the endianness of our current system
func getEndianness() (binary.ByteOrder, error) {
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)

	switch buf {
	case [2]byte{0xCD, 0xAB}:
		return binary.LittleEndian, nil
	case [2]byte{0xAB, 0xCD}:
		return binary.BigEndian, nil
	default:
		return nil, fmt.Errorf("Could not determine native endianness.")
	}
}

func htons(in uint16) uint16 {
	return (in<<8)&0xff00 | in>>8
}

