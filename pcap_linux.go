package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
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
	EthHlen               = 0x10
)

type Handle struct {
	syscalls        bool
	promiscuous     bool
	index           int
	snaplen         int32
	fd              int
	ring            []byte
	framePtr        int
	framesPerBuffer uint32
	frameIndex      uint32
	frameSize       uint32
	frameNumbers    uint32
	blockSize       uint32
	pollfd          []syscall.PollFd
}

func (h Handle) ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	if h.syscalls {
		return h.readPacketDataSyscall()
	}
	return h.readPacketDataMmap()
}

func (h Handle) readPacketDataSyscall() (data []byte, ci gopacket.CaptureInfo, err error) {
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

func (h Handle) readPacketDataMmap() (data []byte, ci gopacket.CaptureInfo, err error) {
	// we check the bit setting on the pointer
	if h.pollfd == nil {
		h.pollfd = []syscall.PollFd{{Fd: int32(h.fd)}}
	}
	if h.ring[h.framePtr]&syscall.TP_STATUS_USER != syscall.TP_STATUS_USER {
		val, err := syscall.Poll(h.pollfd, -1)
		if err != nil {
			return nil, ci, fmt.Errorf("error polling socket: %v", err)
		}
		if val == -1 {
			return nil, ci, errors.New("negative error polling socket")
		}
		// socket was ready, so read from the mmap now
	}
	// read the header
	b := h.ring[h.framePtr:]
	buf := bytes.NewBuffer(b[:syscall.SizeofTpacketHdr])
	hdr := syscall.TpacketHdr{}
	// is this really bigendian?
	err = binary.Read(buf, binary.BigEndian, &hdr)
	if err != nil {
		return nil, ci, fmt.Errorf("error reading header: %v", err)
	}
	// read the sockeraddr_ll
	buf = bytes.NewBuffer(b[syscall.SizeofTpacketHdr : syscall.SizeofTpacketHdr+syscall.SizeofSockaddrLinklayer])
	sall := syscall.SockaddrLinklayer{}
	err = binary.Read(buf, binary.BigEndian, &sall)
	if err != nil {
		return nil, ci, fmt.Errorf("error reading header: %v", err)
	}
	// we do not do anything with this for now, because we leave it to the decoder
	/*
		l2content := b[hdr.Mac:hdr.Net]
		l3content := b[hdr.Net:]
	*/

	ci = gopacket.CaptureInfo{
		Length:         int(hdr.Len),
		CaptureLength:  int(hdr.Snaplen),
		Timestamp:      time.Unix(int64(hdr.Sec), int64(hdr.Usec*1000)),
		InterfaceIndex: sall.Ifindex,
	}
	data = b[:hdr.Snaplen]

	// indicate we are done with this frame, send back to the kernel
	h.ring[h.framePtr] = syscall.TP_STATUS_KERNEL

	// Increment frame index, wrapping around if end of buffer is reached.
	h.frameIndex = h.frameIndex + 1%h.frameNumbers
	// figure out which block has the next frame in the ring
	bufferIndex := h.frameIndex / h.framesPerBuffer
	bufferIndex = bufferIndex + h.blockSize

	// find the the frame within that buffer
	frameIndexDiff := h.frameIndex % h.framesPerBuffer
	h.framePtr = int(bufferIndex + frameIndexDiff*h.frameSize)

	return nil, ci, nil
}

func htons(in uint16) uint16 {
	return (in<<8)&0xff00 | in>>8
}

func tpacketAlign(base int32) int32 {
	return (base + syscall.TPACKET_ALIGNMENT - 1) &^ (syscall.TPACKET_ALIGNMENT - 1)
}

// OpenLive open a live capture. Returns a Handle that implements https://godoc.org/github.com/google/gopacket#PacketDataSource
// so you can pass it there.
func OpenLive(device string, snaplen int32, promiscuous bool, timeout time.Duration) (handle *Handle, _ error) {
	// TODO: change this from syscalls (last arg true) to mmap (last arg false) when mmap works
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
		var (
			frameSize           = uint32(tpacketAlign(syscall.TPACKET_HDRLEN+EthHlen) + tpacketAlign(snaplen))
			pageSize            = syscall.Getpagesize()
			blockSize           = uint32(pageSize)
			blockNumbers uint32 = defaultBlockNumbers
		)
		for {
			if blockSize > frameSize {
				break
			}
			blockSize = blockSize << 1
		}
		// we use the default - for now

		framesPerBuffer := blockSize / frameSize
		frameNumbers := blockNumbers * framesPerBuffer

		tpreq := syscall.TpacketReq{
			Block_size: blockSize,
			Block_nr:   blockNumbers,
			Frame_size: frameSize,
			Frame_nr:   frameNumbers,
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
		h.framesPerBuffer = framesPerBuffer
		h.blockSize = blockSize
		h.frameSize = frameSize
		h.frameNumbers = frameNumbers
		h.ring = data
	}
	return &h, nil
}
