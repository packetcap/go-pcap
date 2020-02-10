package main

import (
	"fmt"
	"log"
	"os"

	"github.com/deitch/pcap"
)

func main() {
	var (
		iface string
		c chan pcap.Packet
		err error
	)
	if len(os.Args) >= 2 {
		iface = os.Args[1]
	}
	c = make(chan pcap.Packet, 50)
	go func() {
		for p := range c {
			fmt.Printf("packet size %d from %#v\n", p.Read, p.From)
		}
	}()
	if err = pcap.Listen(iface, true, true, c); err != nil {
		log.Fatal(err)
	}
}
