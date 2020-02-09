package main

import (
	"fmt"
	syscall "golang.org/x/sys/unix"
	"log"
	"net"
	"os"
	"time"
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
	b    []byte
	read int
	from syscall.Sockaddr
}

func htons(in uint16) uint16 {
	return (in<<8)&0xff00 | in>>8
}

func listen(iface string, promiscuous, syscalls bool, c chan Packet) error {
	// set up the socket - remember to switch to network socket order for the protocol int
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return fmt.Errorf("failed opening raw socket: %v", err)
	}
	if iface != "" {
		// get our interface
		in, err := net.InterfaceByName(iface)
		if err != nil {
			return fmt.Errorf("unknown interface %s: %v", iface, err)
		}

		// create the sockaddr_ll
		sa := syscall.SockaddrLinklayer{
			Protocol: syscall.ETH_P_ALL,
			Ifindex:  in.Index,
		}
		// bind to it
		if err = syscall.Bind(fd, &sa); err != nil {
			return fmt.Errorf("failed to bind")
		}
		if promiscuous {
			mreq := syscall.PacketMreq{
				Ifindex: int32(in.Index),
				Type:    syscall.PACKET_MR_PROMISC,
			}
			if err = syscall.SetsockoptPacketMreq(fd, syscall.SOL_PACKET, syscall.PACKET_ADD_MEMBERSHIP, &mreq); err != nil {
				return fmt.Errorf("failed to set promiscuous for %s: %v", iface, err)
			}
		}
	}
	if syscalls {
		for {
			b := make([]byte, 65536)
			read, from, err := syscall.Recvfrom(fd, b, 0)
			if err != nil {
				return fmt.Errorf("error reading: %v", err)
			}
			c <- Packet{
				b:    b,
				read: read,
				from: from,
			}
		}
	} else {
		if err = syscall.SetsockoptInt(fd, syscall.SOL_PACKET, syscall.PACKET_VERSION, syscall.TPACKET_V1); err != nil {
			return fmt.Errorf("failed to set TPACKET_V1: %v", err)
		}
		// set up the ring
		tpreq := syscall.TpacketReq{
			Block_size: defaultBlockSize,
			Block_nr:   defaultBlockNumbers,
			Frame_size: defaultFrameSize,
			Frame_nr:   defaultFramesPerBlock,
		}
		if err = syscall.SetsockoptTpacketReq(fd, syscall.SOL_PACKET, syscall.PACKET_RX_RING, &tpreq); err != nil {
			return fmt.Errorf("failed to set tpacket req: %v", err)
		}
		totalSize := int(tpreq.Block_size * tpreq.Block_nr)
		var offset int64
		data, err := syscall.Mmap(fd, offset, totalSize, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
		if err != nil {
			return fmt.Errorf("error mmapping: %v", err)
		}
		time.Sleep(5 * time.Second)
		c <- Packet{b: data[0:50]}
	}
	return nil
}

func main() {
	var iface string
	if len(os.Args) >= 2 {
		iface = os.Args[1]
	}
	c := make(chan Packet, 50)
	go func() {
		for p := range c {
			fmt.Printf("packet size %d from %#v\n", p.read, p.from)
		}
	}()
	if err := listen(iface, true, true, c); err != nil {
		log.Fatal(err)
	}
}
