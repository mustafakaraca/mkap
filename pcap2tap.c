#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <byteswap.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_tun.h>
#include <errno.h>

#include "pcap.h"


static int open_tap_dev()
{
	int fd;
	char tmp_dev[32];

	system("modprobe tun");
	fd = open("/dev/net/tun", O_RDWR);
	if (fd >= 0)
		return fd;

	snprintf(tmp_dev, sizeof(tmp_dev), "/tmp/__tmp_tap_dev_%d", getpid());
	if (mknod(tmp_dev, 0644|S_IFCHR, makedev(10, 200))) {
		perror("mknod()");
		return -1;
	}
	fd = open(tmp_dev, O_RDWR);
	unlink(tmp_dev);
	return fd;
}

static int get_ioctl_sock()
{
	static int s = -1;

	if (s < 0) {
		s = socket(PF_INET, SOCK_DGRAM, 0);
		if (s < 0)
			return -1;
	}
	return s;
}

static int set_unset_dev_flags(char *ifname, int flags, int set)
{
	struct ifreq ifr;
	int s;

	s = get_ioctl_sock();
	if (s < 0)
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
	ifr.ifr_name[IFNAMSIZ - 1] = 0;
	if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0)
		return -1;
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
	ifr.ifr_name[IFNAMSIZ - 1] = 0;
	if (set)
		ifr.ifr_flags |= flags;
	else
		ifr.ifr_flags &= ~flags;
	if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0)
		return -1;
	return 0;
}

static int setup_tap_dev(int linktype)
{
	int fd;
	struct ifreq ifr;
	char ifname[IFNAMSIZ];

	fd = open_tap_dev();
	if (fd < 0)
		return -1;
	memset(&ifr, 0, sizeof(ifr));
	if (linktype == ARPHRD_PPP)
		ifr.ifr_flags = IFF_TUN;
	else
		ifr.ifr_flags = IFF_TAP;
	ifr.ifr_flags |= IFF_NO_PI;

	if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
		perror("ioctl(TUNSETIFF)");
		goto err;
	}
	printf("tap dev: %s opened\n", ifr.ifr_name);

	strncpy(ifname, ifr.ifr_name, IFNAMSIZ - 1);
	ifname[IFNAMSIZ - 1] = 0;

	if (set_unset_dev_flags(ifname, IFF_UP, 0)) {
		perror("set_unset_dev_flags(unset IFF_UP)");
		goto err;
	}
	if (ioctl(fd, TUNSETLINK, linktype)) {
		perror("ioctl(TUNSETLINK)");
		goto err;
	}
	if (set_unset_dev_flags(ifname, IFF_UP, 1)) {
		perror("set_unset_dev_flags(set IFF_UP)");
		goto err;
	}
	return fd;
err:
	close(fd);
	return -1;
}

int main(int argc, char *argv[])
{
	int tap_fd, swap, arp_type, n;
	struct pcap_global_header gheader;
	struct pcap_packet_header pheader;
	unsigned char pktbuf[65536];

	if (fread(&gheader, 1, sizeof(gheader), stdin) != sizeof(gheader)) {
		perror("fread(gheader)");
		return -1;
	}
	if (gheader.magic == TCPDUMP_MAGIC) {
		swap = 0;
	} else if (gheader.magic == bswap_32(TCPDUMP_MAGIC)) {
		swap = 1;
	} else {
		printf("bad magic\n");
		return -1;
	}
	if (swap) {
		gheader.magic = bswap_32(gheader.magic);
		gheader.version_major = bswap_16(gheader.version_major);
		gheader.version_minor = bswap_16(gheader.version_minor);
		gheader.thiszone = bswap_32(gheader.thiszone);
		gheader.snaplen = bswap_32(gheader.snaplen);
		gheader.linktype = bswap_32(gheader.linktype);
	}
	if (gheader.version_major != PCAP_VERSION_MAJOR || gheader.version_minor != PCAP_VERSION_MINOR) {
		printf("pcap version does not match\n");
		return -1;
	}
	switch (gheader.linktype) {
	case LINKTYPE_ETHERNET:
		arp_type = ARPHRD_ETHER;
		break;
	case LINKTYPE_RAW_IP:
		arp_type = ARPHRD_PPP;
		break;
	case LINKTYPE_IEEE802_11:
		arp_type = ARPHRD_IEEE80211;
		break;
	case LINKTYPE_PRISM_HEADER:
		arp_type = ARPHRD_IEEE80211_PRISM;
		break;
	case LINKTYPE_RADIOTAP_HDR:
		arp_type = ARPHRD_IEEE80211_RADIOTAP;
		break;
	default:
		printf("unrecognized linktype\n");
		return -1;
	}

	tap_fd = setup_tap_dev(arp_type);
	if (tap_fd < 0) {
		perror("setup_tap_dev()");
		return -1;
	}
	printf("interface setup complete. writing packets\n");
	for (;;) {
		if (fread(&pheader, 1, sizeof(pheader), stdin) != sizeof(pheader)) {
			perror("fread(pheader)");
			break;
		}
		if (swap) {
			pheader.ts_sec = bswap_32(pheader.ts_sec);
			pheader.ts_usec = bswap_32(pheader.ts_usec);
			pheader.incl_len = bswap_32(pheader.incl_len);
			pheader.orig_len = bswap_32(pheader.orig_len);
		}
		if (fread(pktbuf, 1, pheader.incl_len, stdin) != pheader.incl_len) {
			perror("fread(pkt)");
			break;
		}
		if (pheader.incl_len != pheader.orig_len) {
			printf("skipping short packet.\n");
			continue;
		}
		if ((n = write(tap_fd, pktbuf, pheader.incl_len)) != pheader.incl_len)
			fprintf(stderr, "write(): %d-%s\n", n, strerror(errno));
	}
	return 0;
}
