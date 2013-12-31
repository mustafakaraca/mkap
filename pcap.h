#ifndef _PCAP_H__
#define _PCAP_H__

#define TCPDUMP_MAGIC		0xA1B2C3D4
#define PCAP_VERSION_MAJOR	2
#define PCAP_VERSION_MINOR	4

#define LINKTYPE_ETHERNET	1
#define LINKTYPE_IEEE802_11	105
#define LINKTYPE_PRISM_HEADER	119
#define LINKTYPE_RADIOTAP_HDR	127
#define LINKTYPE_RAW_IP		12

struct pcap_global_header {
	u_int32_t magic;
	u_int16_t version_major;
	u_int16_t version_minor;
	int32_t   thiszone;
	u_int32_t sigfigs;
	u_int32_t snaplen;
	u_int32_t linktype;
};

struct pcap_packet_header {
	u_int32_t ts_sec;
	u_int32_t ts_usec;
	u_int32_t incl_len;
	u_int32_t orig_len;
};

#endif

