/*
 mnetmon Copyright (C) <2014> <matthias holl>

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program. If not, see <http://www.gnu.org/licenses/>


 mnetmon.c

 network monitor,sniffer

 by mah00

 www.mahoosoft.com

 pcap.h
 apt-get install libpcap-dev

 linux:

 gcc -o mnetmon mnetmon-1.0.8.c -lpcap

 sudo ./mnetmon

 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <pcap.h>
#define puffer 300000
enum {
	net, net2
};

void mnetmonDUMP(u_char *arg, const struct pcap_pkthdr* netmonPKThdr,
		const u_char* mpacket) {
	int cap = 0;
	static int count = 0;
	for (cap = 0; cap < netmonPKThdr->len; cap++) {
		if (isprint(mpacket[cap]))
			printf("%c ", mpacket[cap]);
		else
			printf(" . ", mpacket[cap]);
		if ((cap % 20 == 0 && cap != 0) || cap == netmonPKThdr->len - 1)
			printf("\n");
	}
}
static const char *call[] = { "/proc/net/nf_conntrack", "/proc/net/dev" };
static void callinfo(const int a) {
	FILE *mahoofile;
	char buffer[puffer];
	size_t bytes_read;
	if ((mahoofile = fopen(call[a], "r")) == NULL ) {
		return;
	}
	bytes_read = fread(buffer, 1, sizeof(buffer), mahoofile);
	fclose(mahoofile);
	if (bytes_read == 0 || bytes_read == sizeof(buffer))
		return;
	buffer[bytes_read] = '\0';
	printf("%s", buffer);
	return;
}
int main(int argc, char **argv) {
	struct mtree *re;
	unsigned int p;
	int mchoice, r;
	int cap2;
	char *device;
	char erbf[PCAP_ERRBUF_SIZE];
	pcap_t* desc;
	const u_char *mpacket;
	struct pcap_pkthdr netmonHDR;
	struct ether_header *netmonETH;
	struct bpf_program netmonA;
	bpf_u_int32 netmonm;
	bpf_u_int32 netmonn;
	do {
		printf("\n");
		printf("This is free software! GNU General Public License \n");
		printf("This program comes with ABSOLUTELY NO WARRANTY \n");
		printf("mnetmon Copyright (C) 2014 by Matthias Holl \n");
		printf("\n");
		printf("mnetmon 1.0.8 \n");
		printf("\n");
		printf(" -1- network monitor\n");
		printf(" -2- sniffer promiscuous mode \n");
		printf(" -0- quit\n");
		printf("your choice ->");
		scanf("%d", &mchoice);
		printf("\n");
		if (mchoice == 1) {
			while (1) {
				sleep(5);
				callinfo(net);
				callinfo(net2);
			}
		} else if (mchoice == 2) {
			device = pcap_lookupdev(erbf);
			if (device == NULL ) {
				fprintf(stderr, "%s\n", erbf);
				exit(1);
			}
			pcap_lookupnet(device, &netmonn, &netmonm, erbf);
			desc = pcap_open_live(device, BUFSIZ, 1, -1, erbf);
			if (desc == NULL ) {
				exit(1);
			}
			if (pcap_compile(desc, &netmonA, argv[1], 0, netmonn) == -1) {
				fprintf(stderr, "error\n");
				exit(1);
			}
			if (pcap_setfilter(desc, &netmonA) == -1) {
				fprintf(stderr, "filter error\n");
				exit(1);
			}
			pcap_loop(desc, -1, mnetmonDUMP, NULL );
			return EXIT_SUCCESS;
		} else if (mchoice == 3) {
			device = pcap_lookupdev(erbf);
			if (device == NULL ) {
				fprintf(stderr, "%s\n", erbf);
				exit(1);
			}
			pcap_lookupnet(device, &netmonn, &netmonm, erbf);
			desc = pcap_open_live(device, BUFSIZ, 1, -1, erbf);
			if (desc == NULL ) {
				exit(1);
			}
			if (pcap_compile(desc, &netmonA, argv[1], 0, netmonn) == -1) {
				fprintf(stderr, "error\n");
				exit(1);
			}
			if (pcap_setfilter(desc, &netmonA) == -1) {
				fprintf(stderr, "filter error\n");
				exit(1);
			}

		}
	} while (mchoice != 0);
	return EXIT_SUCCESS;
}
