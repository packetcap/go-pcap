//go:build darwin || freebsd

package pcap

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	"github.com/gopacket/gopacket"
	log "github.com/sirupsen/logrus"
)

const (
	enable = 1
	// defaultSyscalls default setting for using syscalls
	defaultSyscalls = true
)

type Handle struct {
	context     context.Context
	syscalls    bool
	close       sync.Once
	closed      atomic.Bool
	promiscuous bool //nolint: unused
	timeout     time.Duration
	index       int
	snaplen     int32
	fd          int
	buf         []byte
	endian      binary.ByteOrder
	filter      []bpf.RawInstruction
	linkType    uint32
}

type BpfProgram struct {
	Len    uint32
	Filter *bpf.RawInstruction
}

func (h *Handle) ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	if h.syscalls {
		return h.readPacketDataSyscall()
	}
	return h.readPacketDataMmap()
}

func (h *Handle) readPacketDataSyscall() (data []byte, ci gopacket.CaptureInfo, err error) {
	// must memset the buffer
	h.buf = make([]byte, len(h.buf))

	var pipefd [2]int
	if err := unix.Pipe(pipefd[:]); err != nil {
		return nil, ci, fmt.Errorf("pipe: %w", err)
	}
	rfd := pipefd[0]
	wfd := pipefd[1]

	defer unix.Close(rfd)
	defer unix.Close(wfd)

	// Make pipe non-blocking
	_ = unix.SetNonblock(rfd, true)
	_ = unix.SetNonblock(wfd, true)

	// Goroutine to signal cancellation
	done := make(chan struct{})
	go func() {
		select {
		case <-h.context.Done():
			// Write any value to wake poll
			_, _ = unix.Write(wfd, []byte{1})
		case <-done:
		}
	}()
	defer close(done)

	// pollfd to handle events, like idle timeout or context message
	pfd := []unix.PollFd{
		{
			Fd:     int32(h.fd),
			Events: unix.POLLIN,
		},
		{
			Fd:     int32(rfd),
			Events: unix.POLLIN,
		},
	}

	ms := -1
	if h.timeout > 0 {
		ms = int(h.timeout.Milliseconds())
	}
	n, err := unix.Poll(pfd, ms)
	if err != nil {
		if err == unix.EINTR {
			return nil, ci, h.context.Err()
		}
		return nil, ci, err
	}
	if n == 0 {
		return nil, ci, context.DeadlineExceeded
	}
	// Context canceled → eventfd readable
	if pfd[1].Revents&unix.POLLIN != 0 {
		return nil, ci, h.context.Err()
	}

	read, err := unix.Read(h.fd, h.buf)
	if err != nil {
		return nil, ci, fmt.Errorf("error reading: %v", err)
	}
	if read <= 0 {
		return nil, ci, fmt.Errorf("read no packets")
	}
	// separate the header and packet body
	hdr := unix.BpfHdr{}
	buf := bytes.NewBuffer(h.buf[:unix.SizeofBpfHdr])
	err = binary.Read(buf, h.endian, &hdr)
	if err != nil {
		return nil, ci, fmt.Errorf("error reading bpf header: %v", err)
	}
	// TODO: add CaptureInfo, specifically:
	//    capture timestamp
	ci = gopacket.CaptureInfo{
		CaptureLength:  int(hdr.Caplen),
		Length:         int(hdr.Datalen),
		InterfaceIndex: h.index,
	}
	return h.buf[hdr.Hdrlen : uint32(hdr.Hdrlen)+hdr.Caplen], ci, nil
}

func (h *Handle) readPacketDataMmap() (data []byte, ci gopacket.CaptureInfo, err error) {
	return nil, ci, errors.New("mmap unsupported on Darwin")
}

// Close close sockets and release resources
// Close is idempotent, and uses sync.Once to ensure it only runs once.
func (h *Handle) Close() {
	// close the socket
	h.close.Do(func() {
		_ = unix.Close(h.fd)
		h.closed.Store(true)
	})
}

// set a classic BPF filter on the listener. filter must be compliant with
// tcpdump syntax.
func (h *Handle) setFilter() error {
	/*
	 * Try to install the kernel filter.
	 */
	prog := BpfProgram{
		Len:    uint32(len(h.filter)),
		Filter: (*bpf.RawInstruction)(unsafe.Pointer(&h.filter[0])),
	}
	if err := ioctlPtr(h.fd, unix.BIOCSETF, unsafe.Pointer(&prog)); err != nil {
		return fmt.Errorf("unable to set filter: %v", err)
	}

	return nil
}

func openLive(ctx context.Context, iface string, snaplen int32, promiscuous bool, timeout time.Duration, syscalls bool) (handle *Handle, _ error) {
	var (
		fd  = -1
		err error
	)
	logger := log.WithFields(log.Fields{
		"iface":       iface,
		"snaplen":     snaplen,
		"promiscuous": promiscuous,
		"timeout":     timeout,
		"syscalls":    syscalls,
	})
	logger.Debug("started")
	h := Handle{
		context:  ctx,
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
	for i := 0; i < 255; i++ {
		dev := fmt.Sprintf("/dev/bpf%d", i)
		fd, err = unix.Open(dev, unix.O_RDWR, 0000)
		if fd > -1 {
			break
		}
		if err != nil && err == unix.EBUSY {
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
	h.buf = make([]byte, size)

	linkType, err := getLinkType(fd)
	if err != nil {
		return nil, fmt.Errorf("failed to get link type: %v", err)
	}
	h.linkType = linkType

	h.timeout = timeout

	return &h, nil
}

// because they deprecated all of the below from "syscall" and redirected to "golang.org/x/net/bpf" but did not
// create a replacement. Sigh.

type ivalue struct {
	name  [unix.IFNAMSIZ]byte
	value int16
}

func SetBpfInterface(fd int, name string) error {
	var iv ivalue
	copy(iv.name[:], []byte(name))
	return ioctlPtr(fd, unix.BIOCSETIF, unsafe.Pointer(&iv))
}

func SetBpfHeadercmpl(fd, m int) error {
	return unix.IoctlSetPointerInt(fd, unix.BIOCSHDRCMPLT, m)
}

func SetBpfImmediate(fd, m int) error {
	return unix.IoctlSetPointerInt(fd, unix.BIOCIMMEDIATE, m)
}

func SetBpfMonitor(fd, m int) error {
	return unix.IoctlSetPointerInt(fd, unix.BIOCSSEESENT, m)
}
func BpfBuflen(fd int) (int, error) {
	return unix.IoctlGetInt(fd, unix.BIOCGBLEN)
}
func ioctlPtr(fd, arg int, valPtr unsafe.Pointer) error {
	//nolint:staticcheck // unix.SYS_IOCTL is deprecated, but golang does not provide a better alternative
	// as of this writing for passing pointers
	_, _, errno := unix.RawSyscall(unix.SYS_IOCTL, uintptr(fd), uintptr(arg), uintptr(valPtr))
	if errno != 0 {
		return fmt.Errorf("error: %d", errno)
	}
	return nil
}
func getLinkType(fd int) (uint32, error) {
	linkType, err := unix.IoctlGetInt(fd, unix.BIOCGDLT)
	if err != nil {
		return 0xffffffff, fmt.Errorf("failed to get link type: %v", err)
	}
	return uint32(linkType), nil
}

// LinkType return the link type, compliant with pcap-linktype(7) and http://www.tcpdump.org/linktypes.html.
// For now, we just support Null and Ethernet; some day we may support more
func (h *Handle) LinkType() uint32 {
	return h.linkType
}
