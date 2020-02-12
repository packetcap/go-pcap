package pcap

/*
 MacOS uses a /dev/bpf* device instead of a raw socket. Some good examples:
  https://github.com/c-bata/xpcap/blob/master/sniffer.c#L50
  https://gist.github.com/2opremio/6fda363ab384b0d85347956fb79a3927
 Linux uses a raw socket. 
  Canonical reference is at https://www.kernel.org/doc/Documentation/networking/packet_mmap.txt
  For syscall-based capture: see http://www.microhowto.info/howto/capture_ethernet_frames_using_an_af_packet_socket_in_c.html
  For mmap-based capture: see http://www.microhowto.info/howto/capture_ethernet_frames_using_an_af_packet_ring_buffer_in_c.html

*/
