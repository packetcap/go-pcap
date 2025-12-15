package pcap

import (
	"context"
	"net"
	"path"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	log "github.com/sirupsen/logrus"
)

const (
	tstMsg = "The quick brown fox jumps over the lazy dog!"
)

func enableLogs() {

	log.SetReportCaller(true)
	log.SetLevel(log.TraceLevel)
	log.SetFormatter(&log.TextFormatter{
		DisableTimestamp: true,
		PadLevelText:     true,
		QuoteEmptyFields: true,
		ForceColors:      true, // If you run an IDE in no pty mode then you probably want to also force color mode
		CallerPrettyfier: func(f *runtime.Frame) (string, string) {
			s := strings.Split(f.Function, ".")
			funcName := s[len(s)-1] + "()"
			_, filename := path.Split(f.File)
			return funcName, filename + ":" + strconv.Itoa(f.Line)
		},
	})
}

func Test_simpleMsg(t *testing.T) {
	enableLogs()
	localhost := net.ParseIP("127.0.0.1")
	keepGoing := atomic.Bool{}
	keepGoing.Store(true)
	wg := &sync.WaitGroup{}
	dstPorts := runPublisher(t, localhost, wg, &keepGoing)
	filter := ""
	// Right now adding these filters causes a race condition caught by 'go test -race' and doesn't exit
	//filter = fmt.Sprintf("dst port %d", dstPorts)
	//filter = fmt.Sprintf("udp and dst port %d", dstPorts)
	//filter = fmt.Sprintf("udp and dst port %d and dst host %s", dstPorts, localhost.String())

	iface := ""
	t.Logf("capturing from interface '%s' and port %d\n", iface, dstPorts)
	var err error
	var handle *Handle
	if handle, err = OpenLive(context.Background(), iface, 1600, true, 0, true); err != nil {
		t.Log(err)
	}
	if err = handle.SetBPFFilter(filter); err != nil {
		t.Fatalf("unexpected error setting filter: %v", err)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(5 * time.Second)
		handle.Close()
		t.Logf("Finished closing the handle")
	}()
	packetSource := gopacket.NewPacketSource(handle, layers.LinkType(handle.LinkType()))
	var count int
	for range packetSource.Packets() {
		count++
	}
	t.Logf("We got %d packets", count)
	keepGoing.Store(false)
	wg.Wait()
}

func runPublisher(t *testing.T, dstAddr net.IP, wg *sync.WaitGroup, keepGoing *atomic.Bool) (port uint16) {
	// Create a UDP connection here with port 0 so the OS can assign us an open port
	localhostAddr, err := net.ResolveUDPAddr("udp", dstAddr.String()+":0")
	if err != nil {
		t.Fatal(err)
	}
	sendUDP, err := net.DialUDP("udp", nil, localhostAddr)
	if err != nil {
		t.Fatal(err)
	}
	// Get the port number that the OS assigned to us.
	port = uint16(sendUDP.LocalAddr().(*net.UDPAddr).Port)

	wg.Add(1)
	go func() {
		// This thread will just be sending out messages to our localhost till we are told to stop
		defer wg.Done()
		for keepGoing.Load() {
			_, err = sendUDP.Write([]byte(tstMsg))
			if err != nil {
				// Ignoring connection refused, we just want to send the messages
				if !strings.Contains(err.Error(), "connection refused") {
					t.Errorf("Failed to set/send message:%s\n", err.Error())
				}
			}
			time.Sleep(500 * time.Microsecond)
		}
		t.Log("Done publishing")
	}()

	return port
}
