#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <poll.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <linux/filter.h>
#include <errno.h>

#include "pcap.h"

#define LISTEN_PORT 54321

#ifndef ARPHRD_ETHER
#define ARPHRD_ETHER    1               /* Ethernet 10/100Mbps.  */
#endif
#ifndef ARPHRD_PPP
#define ARPHRD_PPP      512
#endif
#ifndef ARPHRD_IEEE80211
#define ARPHRD_IEEE80211 801            /* IEEE 802.11.  */
#endif
#ifndef ARPHRD_IEEE80211_PRISM
#define ARPHRD_IEEE80211_PRISM 802      /* IEEE 802.11 + Prism2 header.  */
#endif
#ifndef ARPHRD_IEEE80211_RADIOTAP
#define ARPHRD_IEEE80211_RADIOTAP 803   /* IEEE 802.11 + radiotap header.  */
#endif

static int signal_interrupt = 0;

static void signal_handler(int s)
{
	switch(s){
	case SIGINT:
		signal_interrupt = 1;
		signal(SIGINT, signal_handler);
		break;
	default:
		/* do nothing */
		break;
	}
	return;
}

static int create_capture_socket(char *ifname)
{
	int sock_raw;
	struct ifreq ifr;
	struct sockaddr_ll sll;
	struct packet_mreq mrq;
	int fdflags;

	/* Open raw socket */
	sock_raw = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock_raw < 0){
		perror("create_capture_socket: socket : ");
		return -1;
	}
	if (!ifname)
		return sock_raw;

	/* Get interface index */
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
	if (ioctl(sock_raw, SIOCGIFINDEX, &ifr) < 0){
		perror("create_capture_socket: ioctl(SIOCGIFINDEX) :");
		goto err1;
	}
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifr.ifr_ifindex;
	sll.sll_protocol = htons(ETH_P_ALL);

	/* bind the raw socket to the interface specified */
	if (bind(sock_raw, (struct sockaddr *)&sll, sizeof(sll)) < 0){
		perror("create_capture_socket: bind()");
		goto err1;
	}

	fdflags = fcntl(sock_raw, F_GETFL);
	if (fdflags < 0){
		perror("create_capture_socket: fcntl(F_GETFL):");
		goto err1;
	}
	if (fcntl(sock_raw, F_SETFL, fdflags | O_NONBLOCK) < 0){
		perror("create_capture_socket: fcntl(F_SETFL)");
	}
	return sock_raw;

err1:
	while((close(sock_raw) < 1) && (errno == EINTR));	
	return -1;
}

static int get_arptype(char *ifname, int sockfd)
{
	struct ifreq ifr;
	
	if (!ifname)
		return ARPHRD_ETHER;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0){
		perror("get_arptype: ioctl (SIOCGIFHWADDR):");
		return -1;
	}

	return ifr.ifr_hwaddr.sa_family;
}

static int get_tcp_sock()
{
	int serversock, clientsock, yes;
	struct sockaddr_in addr;

	serversock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (serversock < 0)
		return -1;
	yes = 1;
	setsockopt(serversock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(LISTEN_PORT);
	addr.sin_addr.s_addr = INADDR_ANY;
	if (bind(serversock, (struct sockaddr *)&addr, sizeof(addr)))
		goto err;
	if (listen(serversock, 3))
		goto err;
	clientsock = accept(serversock, NULL, NULL);
	close(serversock);
	return clientsock;

err:
	close(serversock);
	return -1;
}

static int attach_mkap_conn_filter(int sock, unsigned int linktype)
{
	struct sock_filter raw_ip_patch = BPF_STMT(BPF_LDX|BPF_W|BPF_IMM, 0);
	struct sock_filter filter_instr[] = {
		/* check ether_type */
		BPF_STMT(BPF_LDX|BPF_W|BPF_IMM, 14),
		BPF_STMT(BPF_LD|BPF_H|BPF_ABS, 12),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0x8100, 0, 2),
		BPF_STMT(BPF_LDX|BPF_W|BPF_IMM, 18),
		BPF_STMT(BPF_LD|BPF_H|BPF_ABS, 16),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, ETH_P_IP, 0, 12),
		/* check for tcp */
		BPF_STMT(BPF_LD|BPF_B|BPF_IND, 9),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, IPPROTO_TCP, 0, 10),

		/* calculate tcp offset */
		BPF_STMT(BPF_LD|BPF_B|BPF_IND, 0),
		BPF_STMT(BPF_ALU|BPF_AND|BPF_K, 0x0F),
		BPF_STMT(BPF_ALU|BPF_MUL|BPF_K, 4),
		BPF_STMT(BPF_ALU|BPF_ADD|BPF_X, 0),
		BPF_STMT(BPF_ST, 0),
		BPF_STMT(BPF_LDX|BPF_W|BPF_MEM, 0),

		/* check src port */
		BPF_STMT(BPF_LD|BPF_H|BPF_IND, 0),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, LISTEN_PORT, 3, 0),
		BPF_STMT(BPF_LD|BPF_H|BPF_IND, 2),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, LISTEN_PORT, 1, 0),

		BPF_STMT(BPF_RET|BPF_K, 0x00FFFFFF),
		BPF_STMT(BPF_RET|BPF_K, 0),
	};
	struct sock_fprog filter_prog;

	memset(&filter_prog, 0, sizeof(filter_prog));
	filter_prog.len = sizeof(filter_instr) / sizeof(filter_instr[0]);
	filter_prog.filter = filter_instr;

	if (linktype == LINKTYPE_RAW_IP) {
		/* patch the filter for raw ip */
		filter_instr[5] = raw_ip_patch;
		filter_prog.len -= 5;
		filter_prog.filter = &filter_instr[5];
	}

	return setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &filter_prog, sizeof(filter_prog));
}

static int check_mkap_conn(unsigned char *buffer, int len, unsigned int linktype)
{
	struct ether_header *ethh;
	struct iphdr *iph;
	struct tcphdr *tcph;
	int ipoffset = 0;
	unsigned short ether_type;

	if (linktype == LINKTYPE_ETHERNET) {
		ipoffset += sizeof(*ethh);
		if (len < (ipoffset + sizeof(*iph)))
			return 0;
		ethh = (struct ether_header *)buffer;
		ether_type = ethh->ether_type;
		if (ether_type == htons(0x8100)) {
			ipoffset += 4;
			if (len < (ipoffset + sizeof(*iph)))
				return 0;
			ether_type = *(unsigned short *)(buffer + sizeof(*ethh) + 2);
		}
		if (ether_type != htons(ETHERTYPE_IP))
			return 0;
	} else if (linktype == LINKTYPE_RAW_IP) {
		if (len < sizeof(*iph))
			return 0;
	}
	iph = (struct iphdr *)(buffer + ipoffset);
	if (iph->protocol != IPPROTO_TCP)
		return 0;
	if (len < (ipoffset + iph->ihl * 4 + sizeof(*tcph)))
		return 0;
	tcph = (struct tcphdr *)(buffer + ipoffset + iph->ihl * 4);
	if (tcph->dest != htons(LISTEN_PORT) && tcph->source != htons(LISTEN_PORT))
		return 0;
	return 1;
}

int main(int argc, char **argv)
{
	FILE *fp;
	int sock_raw;
	unsigned char recvbuffer[65536];
	int n, opt, sock;
	struct pcap_global_header pcap_global;
	struct pcap_packet_header pcap_packet;
	struct timeval tv;
	struct pollfd rawpfd;
	char *ifname = NULL;
	char *filename = NULL;

	while ((opt = getopt(argc, argv, "i:f:h")) != -1) {
		switch (opt) {
		case 'i':
			ifname = optarg;
			break;
		case 'f':
			filename = optarg;
			break;
		case 'h':
		default:
			printf(	"usage: mkap [-f filename] [-i interface]\n"
				"\t-i: specify a specific interface to listen. if not specified capture all ethernet traffic.\n"
				"\t-f: specify a file to dump the traffic. if not specified, listen for a tcp connection from\n"
				"\t    port %d and dump the traffic to that connection\n", LISTEN_PORT);
			exit(0);
		}
	}

	sock_raw = create_capture_socket(ifname);
	if (sock_raw < 0){
		printf("cannot open specified interface\n");
		exit(1);
	}

	pcap_global.magic = TCPDUMP_MAGIC;
	pcap_global.version_major = PCAP_VERSION_MAJOR;
	pcap_global.version_minor = PCAP_VERSION_MINOR;
	pcap_global.thiszone = 0;
	pcap_global.sigfigs = 0;
	pcap_global.snaplen = 65535;

	switch(get_arptype(ifname, sock_raw)){
	case ARPHRD_ETHER:
		printf("linktype: ARPHRD_ETHER\n");
		pcap_global.linktype = LINKTYPE_ETHERNET;
		break;
	case ARPHRD_PPP:
		printf("linktype: ARPHRD_PPP\n");
		pcap_global.linktype = LINKTYPE_RAW_IP;
		break;
#if 0
	case ARPHRD_IEEE80211:
		printf("linktype: ARPHRD_IEEE80211\n");
		pcap_global.linktype = LINKTYPE_IEEE802_11;
		break;
	case ARPHRD_IEEE80211_PRISM:
		printf("linktype: ARPHRD_IEEE80211_PRISM\n");
		pcap_global.linktype = LINKTYPE_PRISM_HEADER;
		break;
	case ARPHRD_IEEE80211_RADIOTAP:
		printf("linktype ARPHRD_IEEE80211_RADIOTAP\n");
		pcap_global.linktype = LINKTYPE_RADIOTAP_HDR;
		break;
#endif
	case -1:
		printf("cannot get interface arp type\n");
		exit(1);
	default:
		printf("unsupported linktype %d\n", get_arptype(ifname, sock_raw));
		exit(1);
	}

	if (filename) {
		fp = fopen(filename, "wb");
	} else {
		attach_mkap_conn_filter(sock_raw, pcap_global.linktype);
		sock = get_tcp_sock();
		if (sock < 0) {
			printf("get_tcp_sock() failed\n");
			exit(1);
		}
		fp = fdopen(sock, "wb");
	}
	if (fp == NULL){
		printf("Cannot open specified file\n");
		exit(1);
	}

	if (fwrite(&pcap_global, 1, sizeof(pcap_global), fp) != sizeof(pcap_global)){
		printf("error on writing PCAP file header\n");
		exit(1);
	}
	fflush(fp);

	signal(SIGINT, signal_handler);
	rawpfd.fd = sock_raw;
	rawpfd.events = POLLIN;

	for(;;){
		if (signal_interrupt){
			fprintf(stderr, "SIGINT received\n");
			exit(1);
		}
		n = poll(&rawpfd, 1, 1000);
		if (n == 0) /* timeout */
			continue;
		if (n < 0){
			if (errno == EINTR){
				continue;
			} else {
				perror("main: poll():");
				exit(1);
			}
		}
		if (!(rawpfd.revents & POLLIN)) {
			fprintf(stderr, "Unexpected behaviour\n");
			exit(1);
		}
		n = read(sock_raw, recvbuffer, 65536);
		if (n < 0){
			if(errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK){
				continue;
			} else {
				perror("read():");
				exit(1);
			}
		}
		if(n == 0){
			printf("raw socket closed\n");
			exit(0);
		}
		if (filename == NULL) {
			if (check_mkap_conn(recvbuffer, n, pcap_global.linktype))
				continue;
		}
		if (gettimeofday(&tv, NULL) < 0){
			perror("main: gettimeofday():");
			exit(1);
		}
		pcap_packet.ts_sec = tv.tv_sec;
		pcap_packet.ts_usec = tv.tv_usec;
		pcap_packet.incl_len = pcap_packet.orig_len = n;
		if (fwrite(&pcap_packet, 1, sizeof(pcap_packet), fp) != sizeof(pcap_packet)){
			printf("error on writing packet header\n");
			exit(1);
		}

		if (fwrite(recvbuffer, 1, n, fp) != n){
			printf("error on writing to capture file\n");
			exit(1);
		}
		fflush(fp);
	}
	return 0;
}
