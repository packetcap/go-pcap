package pcap

import (
	"encoding/binary"
	"errors"
	"fmt"
	syscall "golang.org/x/sys/unix"
	"time"
	"unsafe"

	"github.com/google/gopacket"
	log "github.com/sirupsen/logrus"
)

const (
	enable = 1
)

var (
)

type Handle struct {
	syscalls        bool
	promiscuous     bool
	index           int
	snaplen         int32
	fd              int
	buf            []byte
	endian          binary.ByteOrder
}

func (h *Handle) ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	if h.syscalls {
		return h.readPacketDataSyscall()
	}
	return h.readPacketDataMmap()
}

func (h *Handle) readPacketDataSyscall() (data []byte, ci gopacket.CaptureInfo, err error) {
	// must memset the buffer
	h.buf = make([]byte, len(h.buf), len(h.buf))
	read, err := syscall.Read(h.fd, h.buf)
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
	return h.buf[:], ci, nil
}

func (h *Handle) readPacketDataMmap() (data []byte, ci gopacket.CaptureInfo, err error) {
	logger := log.WithFields(log.Fields{
		"func":   "readPacketDataMmap",
		"method": "mmap",
	})
	logger.Debug("started")
	return data, ci, nil
}

// OpenLive open a live capture. Returns a Handle that implements https://godoc.org/github.com/google/gopacket#PacketDataSource
// so you can pass it there.
func OpenLive(device string, snaplen int32, promiscuous bool, timeout time.Duration) (handle *Handle, _ error) {
	return openLive(device, snaplen, promiscuous, timeout, true)
}

func openLive(iface string, snaplen int32, promiscuous bool, timeout time.Duration, syscalls bool) (handle *Handle, _ error) {
	var (
		fd int = -1
		err error
	)
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

	// open the bpf device
	for i := 0; i< 255; i++ {
		dev := fmt.Sprintf("/dev/bpf%d", i)
		fd, err = syscall.Open(dev, syscall.O_RDWR, 0000)
		if fd > -1 {
			break
		}
		if err != nil && err == syscall.EBUSY {
			continue
		}
		return nil, fmt.Errorf("error opening device %s: %v", dev, err)
	}
	if fd <= -1 {
		return nil, errors.New("failed to get valid bpf device")
	}
	h.fd = fd

	// set the options
	if err = SetBpfInterface(fd, iface); err != nil {
		return nil, fmt.Errorf("failed to set the BPF interface: %v", err)
	}
	if err = SetBpfHeadercmpl(fd, enable); err != nil {
		return nil, fmt.Errorf("failed to set the BPF header complete option: %v", err)
	}
	if err = SetBpfMonitor(fd, enable); err != nil {
		return nil, fmt.Errorf("failed to set the BPF monitor option: %v", err)
	}
	if err = SetBpfImmediate(fd, enable); err != nil {
		return nil, fmt.Errorf("failed to set the BPF immediate return option: %v", err)
	}
	size, err := BpfBuflen(fd)
	if err != nil {
		return nil, fmt.Errorf("failed to read buffer length: %v", err)
	}
	h.buf = make([]byte, size, size)

	return &h, nil
}

// because they deprecated all of the below from "syscall" and redirected to "golang.org/x/net/bpf" but did not
// create a replacement. Sigh.

type ivalue struct {
	name  [syscall.IFNAMSIZ]byte
	value int16
}

func SetBpfInterface(fd int, name string) error {
	var iv ivalue
	copy(iv.name[:], []byte(name))
	return ioctlPtr(fd, syscall.BIOCSETIF, unsafe.Pointer(&iv))
}

func SetBpfHeadercmpl(fd, m int) error {
	return ioctlPtr(fd, syscall.BIOCSHDRCMPLT, unsafe.Pointer(&m))
}

func SetBpfImmediate(fd, m int) error {
	return ioctlPtr(fd, syscall.BIOCIMMEDIATE, unsafe.Pointer(&m))
}

func SetBpfMonitor(fd, m int) error {
	return ioctlPtr(fd, syscall.BIOCSSEESENT, unsafe.Pointer(&m))
}
func BpfBuflen(fd int) (int, error) {
	return syscall.IoctlGetInt(fd, syscall.BIOCGBLEN)
}
func ioctlPtr(fd, arg int, valPtr unsafe.Pointer) error {
	_, _, errno := syscall.RawSyscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(arg), uintptr(valPtr))
	if errno != 0 {
		return fmt.Errorf("error: %d", errno)
	}
	return nil
}
