package main

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/packetcap/go-pcap"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	useGopacket bool
	debug       bool
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
			count  int
		)
		if len(args) >= 1 {
			iface = args[0]
		}
		if debug {
			log.SetLevel(log.DebugLevel)
		}

		fmt.Printf("capturing from interface %s\n", iface)
		if useGopacket {
			if handle, err = pcap.OpenLive(iface, 1600, true, 0); err != nil {
				log.Fatal(err)
			}
			packetSource := gopacket.NewPacketSource(handle, layers.LinkTypeEthernet)
			for packet := range packetSource.Packets() {
				processPacket(packet, count)
				count++
			}
		} else {
			if c, err = pcap.Listen(iface, 65536, true, true, 0); err != nil {
				log.Fatal(err)
			}
			for packet := range c {
				processPacket(gopacket.NewPacket(packet.B, layers.LayerTypeEthernet, gopacket.Default), count)
				count++
			}
		}
	},
}

func init() {
	rootCmd.Flags().BoolVar(&useGopacket, "gopacket", false, "use gopacket interface instead of simple pcap.Listen")
	rootCmd.Flags().BoolVar(&debug, "debug", false, "print lots of debugging messages")
}

func processPacket(packet gopacket.Packet, count int) {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		fmt.Printf("%d: TCP packet ", count)
		// Get actual TCP data from this layer
		tcp, _ := tcpLayer.(*layers.TCP)
		fmt.Printf("From src port %d to dst port %d\n", tcp.SrcPort, tcp.DstPort)
	}
	// Iterate over all layers, printing out each layer type
	for i, layer := range packet.Layers() {
		fmt.Printf("%d: PACKET LAYER %d: %s\n", count, i, layer.LayerType())
	}

	data := packet.Data()
	if len(data) > 50 {
		data = data[:50]
	}
	fmt.Printf("%d: packet size %d, first bytes %d\n", count, packet.Metadata().CaptureLength, data)
}
