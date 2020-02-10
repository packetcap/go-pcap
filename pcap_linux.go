package pcap

import (
	"fmt"
	syscall "golang.org/x/sys/unix"
	"net"
	"time"

	"github.com/google/gopacket"
)

const (
	//defaultFrameSize = 4096
	defaultFrameSize = 65632
	//defaultBlockNumbers = 128
	defaultBlockNumbers = 32
	//defaultBlockSize = defaultFrameSize * defaultBlockNumbers
	defaultBlockSize = 131072
	//defaultFramesPerBlock = defaultBlockSize / defaultFrameSize
	defaultFramesPerBlock = 32
)

type Packet struct {
	B     []byte
	Info  gopacket.CaptureInfo
	Error error
}
type Handle struct {
	syscalls    bool
	promiscuous bool
	index       int
	snaplen     int32
	fd          int
	ring        []byte
}

func (h *Handle) ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	if h.syscalls {
		return h.readPacketDataSyscall()
	}
	return h.readPacketDataMmap()
}

func (h *Handle) readPacketDataSyscall() (data []byte, ci gopacket.CaptureInfo, err error) {
	b := make([]byte, h.snaplen)
	read, _, err := syscall.Recvfrom(h.fd, b, 0)
	if err != nil {
		return nil, ci, fmt.Errorf("error reading: %v", err)
	}
	// TODO: add CaptureInfo, specifically:
	//    capture timestamp
	//    original packet length
	ci = gopacket.CaptureInfo{
		CaptureLength:  read,
		InterfaceIndex: h.index,
	}
	return b, ci, nil
}

func (h *Handle) readPacketDataMmap() (data []byte, ci gopacket.CaptureInfo, err error) {
	// we do not have this worked out yet
	return nil, gopacket.CaptureInfo{}, nil
}

func htons(in uint16) uint16 {
	return (in<<8)&0xff00 | in>>8
}

// OpenLive open a live capture. Returns a Handle that implements https://godoc.org/github.com/google/gopacket#PacketDataSource
// so you can pass it there
func OpenLive(device string, snaplen int32, promiscuous bool, timeout time.Duration) (handle *Handle, _ error) {
	return openLive(device, snaplen, promiscuous, timeout, false)
}

func openLive(iface string, snaplen int32, promiscuous bool, timeout time.Duration, syscalls bool) (handle *Handle, _ error) {
	h := Handle{
		snaplen:  snaplen,
		syscalls: syscalls,
	}
	// set up the socket - remember to switch to network socket order for the protocol int
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("failed opening raw socket: %v", err)
	}
	h.fd = fd
	if iface != "" {
		// get our interface
		in, err := net.InterfaceByName(iface)
		if err != nil {
			return nil, fmt.Errorf("unknown interface %s: %v", iface, err)
		}
		h.index = in.Index

		// create the sockaddr_ll
		sa := syscall.SockaddrLinklayer{
			Protocol: syscall.ETH_P_ALL,
			Ifindex:  in.Index,
		}
		// bind to it
		if err = syscall.Bind(fd, &sa); err != nil {
			return nil, fmt.Errorf("failed to bind")
		}
		if promiscuous {
			h.promiscuous = true
			mreq := syscall.PacketMreq{
				Ifindex: int32(in.Index),
				Type:    syscall.PACKET_MR_PROMISC,
			}
			if err = syscall.SetsockoptPacketMreq(fd, syscall.SOL_PACKET, syscall.PACKET_ADD_MEMBERSHIP, &mreq); err != nil {
				return nil, fmt.Errorf("failed to set promiscuous for %s: %v", iface, err)
			}
		}
	}
	if !syscalls {
		if err = syscall.SetsockoptInt(fd, syscall.SOL_PACKET, syscall.PACKET_VERSION, syscall.TPACKET_V1); err != nil {
			return nil, fmt.Errorf("failed to set TPACKET_V1: %v", err)
		}
		// set up the ring
		tpreq := syscall.TpacketReq{
			Block_size: defaultBlockSize,
			Block_nr:   defaultBlockNumbers,
			Frame_size: defaultFrameSize,
			Frame_nr:   defaultFramesPerBlock,
		}
		if err = syscall.SetsockoptTpacketReq(fd, syscall.SOL_PACKET, syscall.PACKET_RX_RING, &tpreq); err != nil {
			return nil, fmt.Errorf("failed to set tpacket req: %v", err)
		}
		totalSize := int(tpreq.Block_size * tpreq.Block_nr)
		var offset int64
		data, err := syscall.Mmap(fd, offset, totalSize, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
		if err != nil {
			return nil, fmt.Errorf("error mmapping: %v", err)
		}
		h.ring = data
	}
	return &h, nil
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
