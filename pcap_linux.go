package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	syscall "golang.org/x/sys/unix"
	"net"
	"time"
	"unsafe"

	"github.com/google/gopacket"
	log "github.com/sirupsen/logrus"
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

var (
	packetSALLSize           int32
	alignedTpacketHdrSize    int32
	alignedTpacketSALLSize   int32
	alignedTpacketAllHdrSize int32
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
	endian          binary.ByteOrder
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
	logger := log.WithFields(log.Fields{
		"func":   "readPacketDataMmap",
		"method": "mmap",
	})
	logger.Debug("started")
	// we check the bit setting on the pointer
	logger.Debugf("checking for packet at position %d", h.framePtr)
	if h.ring[h.framePtr]&syscall.TP_STATUS_USER != syscall.TP_STATUS_USER {
		val, err := syscall.Poll(h.pollfd, -1)
		if err != nil {
			logger.Errorf("error polling socket: %v", err)
			return nil, ci, fmt.Errorf("error polling socket: %v", err)
		}
		if val == -1 {
			logger.Error("negative return value from polling socket")
			return nil, ci, errors.New("negative return value from polling socket")
		}
		// socket was ready, so read from the mmap now
	}
	// read the header
	b := h.ring[h.framePtr:]
	buf := bytes.NewBuffer(b[:alignedTpacketHdrSize])
	hdr := syscall.TpacketHdr{}
	err = binary.Read(buf, h.endian, &hdr)
	if err != nil {
		logger.Errorf("error reading tpacket header: %v", err)
		return nil, ci, fmt.Errorf("error reading header: %v", err)
	}
	// read the sockaddr_ll
	// unfortunately, we cannot do binary.Read() because syscall.SockaddrLinklayer has an embedded slice
	// so we have to read it manually
	sall, err := parseSocketAddrLinkLayer(b[alignedTpacketHdrSize:alignedTpacketAllHdrSize], h.endian)
	if err != nil {
		logger.Errorf("error parsing sockaddr_ll: %v", err)
		return nil, ci, fmt.Errorf("error parsing sockaddr_ll: %v", err)
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
		InterfaceIndex: int(sall.Ifindex),
	}
	data = b[alignedTpacketAllHdrSize : uint32(alignedTpacketAllHdrSize)+hdr.Snaplen]

	// indicate we are done with this frame, send back to the kernel
	logger.Debugf("returning frame at pos %d to kernel", h.framePtr)
	h.ring[h.framePtr] = syscall.TP_STATUS_KERNEL

	// Increment frame index, wrapping around if end of buffer is reached.
	logger.Debugf("original frameIndex: %d", h.frameIndex)
	h.frameIndex = (h.frameIndex + 1) % h.frameNumbers
	logger.Debugf("updated frameIndex: %d", h.frameIndex)
	// figure out which block has the next frame in the ring
	bufferIndex := h.frameIndex / h.framesPerBuffer
	logger.Debugf("calculated bufferIndex: %d", bufferIndex)
	bufferIndex = bufferIndex * h.blockSize
	logger.Debugf("re-calculated bufferIndex: %d", bufferIndex)

	// find the the frame within that buffer
	frameIndexDiff := h.frameIndex % h.framesPerBuffer
	logger.Debugf("frameIndexDiff: %d", frameIndexDiff)
	h.framePtr = int(bufferIndex + frameIndexDiff*h.frameSize)
	logger.Debugf("h.frameSize %d, frameIndexDiff %d, frameIndexDiff*h.frameSize %d, bufferIndex %d", h.frameSize, frameIndexDiff, frameIndexDiff*h.frameSize, bufferIndex)
	logger.Debugf("final framePtr: %d", h.framePtr)

	return data, ci, nil
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
	return openLive(device, snaplen, promiscuous, timeout, false)
}

func openLive(iface string, snaplen int32, promiscuous bool, timeout time.Duration, syscalls bool) (handle *Handle, _ error) {
	logger := log.WithFields(log.Fields{
		"func":        "openLive",
		"iface":       iface,
		"snaplen":     snaplen,
		"promiscuous": promiscuous,
		"timeout":     timeout,
		"syscalls":    syscalls,
	})
	logger.Debug("started")
	h := Handle{
		snaplen:  snaplen,
		syscalls: syscalls,
	}
	// we need to know our endianness
	endianness, err := getEndianness()
	if err != nil {
		return nil, err
	}
	h.endian = endianness

	// because syscall package does not provide this
	sall := syscall.SockaddrLinklayer{}
	packetSALLSize = int32(unsafe.Sizeof(sall))
	alignedTpacketHdrSize = tpacketAlign(syscall.SizeofTpacketHdr)
	alignedTpacketSALLSize = tpacketAlign(packetSALLSize)
	alignedTpacketAllHdrSize = alignedTpacketHdrSize + alignedTpacketSALLSize

	// set up the socket - remember to switch to network socket order for the protocol int
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		logger.Errorf("failed opening raw socket: %v", err)
		return nil, fmt.Errorf("failed opening raw socket: %v", err)
	}
	h.fd = fd
	h.pollfd = []syscall.PollFd{{Fd: int32(h.fd), Events: syscall.POLLIN}}
	if iface != "" {
		// get our interface
		in, err := net.InterfaceByName(iface)
		if err != nil {
			logger.Errorf("unknown interface %s: %v", iface, err)
			return nil, fmt.Errorf("unknown interface %s: %v", iface, err)
		}
		h.index = in.Index

		// create the sockaddr_ll
		sa := syscall.SockaddrLinklayer{
			Protocol: htons(syscall.ETH_P_ALL),
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
				logger.Errorf("failed to set promiscuous for %s: %v", iface, err)
				return nil, fmt.Errorf("failed to set promiscuous for %s: %v", iface, err)
			}
		}
	}
	if !syscalls {
		if err = syscall.SetsockoptInt(fd, syscall.SOL_PACKET, syscall.PACKET_VERSION, syscall.TPACKET_V1); err != nil {
			logger.Errorf("failed to set TPACKET_V1: %v", err)
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
		logger.Debugf("creating mmap buffer with tpreq %#v", tpreq)
		if err = syscall.SetsockoptTpacketReq(fd, syscall.SOL_PACKET, syscall.PACKET_RX_RING, &tpreq); err != nil {
			logger.Errorf("failed to set tpacket req: %v", err)
			return nil, fmt.Errorf("failed to set tpacket req: %v", err)
		}
		totalSize := int(tpreq.Block_size * tpreq.Block_nr)
		var offset int64
		data, err := syscall.Mmap(fd, offset, totalSize, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
		if err != nil {
			logger.Errorf("error mmapping: %v", err)
			return nil, fmt.Errorf("error mmapping: %v", err)
		}
		logger.Infof("mmap buffer created with size %d", len(data))
		h.framesPerBuffer = framesPerBuffer
		h.blockSize = blockSize
		h.frameSize = frameSize
		h.frameNumbers = frameNumbers
		h.ring = data
	}
	return &h, nil
}

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

// parseSocketAddrLinkLayer parse byte data to get a RawSockAddrLinkLayer
func parseSocketAddrLinkLayer(b []byte, endian binary.ByteOrder) (*syscall.RawSockaddrLinklayer, error) {
	if len(b) < int(packetSALLSize) {
		return nil, fmt.Errorf("bytes of length %d shorter than mandated %d", len(b), packetSALLSize)
	}
	var addr [8]byte
	copy(addr[:], b[11:19])
	sall := syscall.RawSockaddrLinklayer{
		Family:   endian.Uint16(b[0:2]),
		Protocol: endian.Uint16(b[2:4]),
		Ifindex:  int32(endian.Uint32(b[4:8])),
		Hatype:   endian.Uint16(b[8:10]),
		Pkttype:  b[10],
		Halen:    b[11],
		Addr:     addr,
	}
	return &sall, nil
}
