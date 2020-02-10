package main

import (
	"fmt"
	"log"

	"github.com/deitch/pcap"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/spf13/cobra"
)

var (
	useGopacket bool
)

func main() {
	rootCmd.Execute()
}

var rootCmd = &cobra.Command{
	Use:   "pcap",
	Short: "Capture packets for all interfaces (default) or a given interface, when passed as first argument",
	Long:  `Capture packets for all interfaces (default) or a given interface, when passed as first argument`,
	Run: func(cmd *cobra.Command, args []string) {
		var (
			iface  string
			err    error
			c      chan pcap.Packet
			handle *pcap.Handle
		)
		if len(args) >= 1 {
			iface = args[0]
		}
		fmt.Printf("capturing from interface %s\n", iface)
		if useGopacket {
			if handle, err = pcap.OpenLive(iface, 1600, true, 0); err != nil {
				log.Fatal(err)
			}
			packetSource := gopacket.NewPacketSource(handle, layers.LinkTypeEthernet)
			for p := range packetSource.Packets() {
				fmt.Printf("packet size %d, first bytes %#v\n", p.Metadata().CaptureLength, p.Data()[:50])
			}
		} else {
			if c, err = pcap.Listen(iface, 65536, true, true, 0); err != nil {
				log.Fatal(err)
			}
			for p := range c {
				fmt.Printf("packet size %d, first bytes %#v\n", p.Info.CaptureLength, p.B[:50])
			}
		}
	},
}

func init() {
	rootCmd.Flags().BoolVar(&useGopacket, "gopacket", false, "use gopacket interface instead of simple pcap.Listen")
}
