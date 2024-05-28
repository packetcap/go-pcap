package filter

import (
	"net"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type Handler interface {
	serveDNS(*udpConnection, *layers.DNS)
}

// DNSServer is the contains the runtime information
type DNSServer struct {
	port    int
	handler Handler
}

// NewDNSServer - Creates new DNSServer
func NewDNSServer(port int, records map[string]map[string]string) *DNSServer {
	return &DNSServer{
		port: port,
		handler: &serveMux{
			records: records,
		},
	}
}

type serveMux struct {
	records map[string]map[string]string
}

func (srv *serveMux) serveDNS(u *udpConnection, request *layers.DNS) {
	if len(request.Questions) < 1 {
		return
	}

	var response string
	if recs, ok := srv.records[string(request.Questions[0].Name)]; ok {
		if data, ok := recs[request.Questions[0].Type.String()]; ok {
			response = data
		}
	}

	respond(u, request, request.Questions[0].Type, response)
}

// StartToServe - creates a UDP connection and uses the connection to serve DNS
func (dns *DNSServer) StartAndServe() string {
	addr := net.UDPAddr{
		Port: dns.port,
		IP:   net.ParseIP("127.0.0.1"),
	}
	l, _ := net.ListenUDP("udp", &addr)
	dnsServerAddr := l.LocalAddr().String()
	udpConnection := &udpConnection{conn: l}
	go dns.serve(udpConnection)
	return dnsServerAddr
}

func (dns *DNSServer) serve(u *udpConnection) {
	for {
		tmp := make([]byte, 1024)
		n, addr, _ := u.conn.ReadFrom(tmp)
		u.addr = addr
		packet := gopacket.NewPacket(tmp[:n], layers.LayerTypeDNS, gopacket.Default)
		dnsPacket := packet.Layer(layers.LayerTypeDNS)
		tcp, _ := dnsPacket.(*layers.DNS)
		dns.handler.serveDNS(u, tcp)
	}
}

// nolint: unused
type handlerConvert func(*udpConnection, *layers.DNS)

// nolint: unused
func (f handlerConvert) serveDNS(w *udpConnection, r *layers.DNS) {
	f(w, r)
}

type udpConnection struct {
	conn net.PacketConn
	addr net.Addr
}

func (udp *udpConnection) Write(b []byte) error {
	_, _ = udp.conn.WriteTo(b, udp.addr)
	return nil
}

func respond(w *udpConnection, r *layers.DNS, answerType layers.DNSType, ip string) {
	replyMess := r
	var err error
	a := net.ParseIP(ip)
	if a != nil {
		dnsAnswer := layers.DNSResourceRecord{
			Type:  answerType,
			IP:    a,
			Name:  []byte(r.Questions[0].Name),
			Class: layers.DNSClassIN,
		}
		replyMess.Answers = append(replyMess.Answers, dnsAnswer)
	}
	replyMess.QR = true
	replyMess.ANCount = 1
	replyMess.OpCode = layers.DNSOpCodeNotify
	replyMess.AA = true
	replyMess.ResponseCode = layers.DNSResponseCodeNoErr
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{} // See SerializeOptions for more details.
	err = replyMess.SerializeTo(buf, opts)
	if err != nil {
		panic(err)
	}
	_ = w.Write(buf.Bytes())
}
