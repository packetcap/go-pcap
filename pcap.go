package pcap

import (
	"encoding/binary"
	"errors"
	"time"
	"unsafe"

	"github.com/google/gopacket"
)

// Packet a single packet returned by a listen call
type Packet struct {
	B     []byte
	Info  gopacket.CaptureInfo
	Error error
}

// OpenLive open a live capture. Returns a Handle that implements https://godoc.org/github.com/google/gopacket#PacketDataSource
// so you can pass it there.
func OpenLive(device string, snaplen int32, promiscuous bool, timeout time.Duration) (handle *Handle, _ error) {
	return openLive(device, snaplen, promiscuous, timeout, defaultSyscalls)
}

// Listen simple one-step command to listen and send packets over a returned channel
func (h Handle) Listen() chan Packet {
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
	return c
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
		return nil, errors.New("could not determine native endianness")
	}
}

func htons(in uint16) uint16 {
	return (in<<8)&0xff00 | in>>8
}
