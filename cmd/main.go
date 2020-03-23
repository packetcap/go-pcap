package main

import (
	"fmt"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/packetcap/go-pcap"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	useGopacket bool
	useSyscalls bool
	debug       bool
	iface       string
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
			err    error
			handle *pcap.Handle
			count  int
			filter string
		)
		if len(args) >= 1 {
			filter = strings.Join(args, " ")
		}
		if debug {
			log.SetLevel(log.DebugLevel)
		}

		fmt.Printf("capturing from interface %s\n", iface)
		if handle, err = pcap.OpenLive(iface, 1600, true, 0, useSyscalls); err != nil {
			log.Fatal(err)
		}
		if err := handle.SetBPFFilter(filter); err != nil {
			log.Fatalf("unexpected error setting filter: %v", err)
		}
		if useGopacket {
			packetSource := gopacket.NewPacketSource(handle, layers.LinkType(handle.LinkType()))
			for packet := range packetSource.Packets() {
				processPacket(packet, count)
				count++
			}
		} else {
			for packet := range handle.Listen() {
				processPacket(gopacket.NewPacket(packet.B, layers.LayerTypeEthernet, gopacket.Default), count)
				count++
			}
		}
	},
}

func init() {
	rootCmd.Flags().BoolVar(&useGopacket, "gopacket", false, "use gopacket interface instead of simple pcap.Listen")
	rootCmd.Flags().BoolVar(&useSyscalls, "syscalls", pcap.DefaultSyscalls, "use syscalls instead of mmap when mmap is available; the default varies by platform")
	rootCmd.Flags().BoolVar(&debug, "debug", false, "print lots of debugging messages")
	rootCmd.Flags().StringVarP(&iface, "interface", "i", "", "interface from which to capture, default to all")
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
