package pcap

/*
 MacOS uses a /dev/bpf* device; look it up from there, e.g. https://github.com/c-bata/xpcap/blob/master/sniffer.c#L50
 Linux uses a raw socket. For Linux single capture, i.e. via syscalls, see http://www.microhowto.info/howto/capture_ethernet_frames_using_an_af_packet_socket_in_c.html
  For Linux multiple capture via an mmapped ring buffer, see http://www.microhowto.info/howto/capture_ethernet_frames_using_an_af_packet_ring_buffer_in_c.html

Particular reference is at https://www.kernel.org/doc/Documentation/networking/packet_mmap.txt
*/
