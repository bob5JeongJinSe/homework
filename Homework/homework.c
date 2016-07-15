
#ifdef _MSC_VER
/*
* we do not want the warnings about the old deprecated and unsecure CRT functions
* since these examples can be compiled under *nix as well
*/
#define _CRT_SECURE_NO_WARNINGS
#endif
#pragma comment(lib,"Ws2_32.lib")
#include <stdlib.h>
#include <stdio.h>

#include<winsock2.h>
#include <pcap.h>

#define LINE_LEN 16
#define FILTER "tcp && ip"

struct het {
	u_char dmac[6];
	u_char smac[6];
};
struct iphet {
	unsigned char dip[4];
	unsigned char sip[4];

};
//qweqweqweqweqweqweqweqweqweqwe//
struct ip_header
{
	unsigned char ip_header_len : 4;
	unsigned char ip_version : 4;
	unsigned char ip_tos;
	unsigned short ip_total_length;
	unsigned short ip_id;
	unsigned char ip_frag_offset : 5;
	unsigned char ip_more_fragment : 1;
	unsigned char ip_dont_fragment : 1;
	unsigned char ip_reserved_zero : 1;
	unsigned char ip_frag_offset1;
	unsigned char ip_ttl;
	unsigned char ip_protocol;
	unsigned short ip_checksum;
	struct in_addr ip_srcaddr;
	struct in_addr ip_destaddr;
};


struct tcp_header
{
	unsigned short source_port;
	unsigned short dest_port;
	unsigned int sequence;
	unsigned int acknowledge;
	unsigned char ns : 1;
	unsigned char reserved_part1 : 3;
	unsigned char data_offset : 4;
	unsigned char fin : 1;
	unsigned char syn : 1;
	unsigned char rst : 1;
	unsigned char psh : 1;
	unsigned char ack : 1;
	unsigned char urg : 1;
	unsigned char ecn : 1;
	unsigned char cwr : 1;
	unsigned short window;
	unsigned short checksum;
	unsigned short urgent_pointer;
};
//asdasdasdasdasdasd//

int main(int argc, char **argv)
{
	pcap_if_t *alldevs, *d;
	pcap_t *fp;
	u_int inum, i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	int res;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	struct bpf_program fcode;
	bpf_u_int32 NetMask;
	struct het heternet;

	printf("pktdump_ex: prints the packets of the network using WinPcap.\n");
	printf("   Usage: pktdump_ex [-s source]\n\n"
		"   Examples:\n"
		"      pktdump_ex -s file.acp\n"
		"      pktdump_ex -s \\Device\\NPF_{C8736017-F3C3-4373-94AC-9A34B7DAD998}\n\n");

	if (argc < 3)
	{
		printf("\nNo adapter selected: printing the device list:\n");
		/* The user didn't provide a packet source: Retrieve the local device list */
		if (pcap_findalldevs(&alldevs, errbuf) == -1)
		{
			fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
			exit(1);
		}

		/* Print the list */
		for (d = alldevs; d; d = d->next)
		{
			printf("%d. %s\n    ", ++i, d->name);

			if (d->description)
				printf(" (%s)\n", d->description);
			else
				printf(" (No description available)\n");
		}

		if (i == 0)
		{
			printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
			return -1;
		}

		printf("Enter the interface number (1-%d):", i);
		scanf("%d", &inum);

		if (inum < 1 || inum > i)
		{
			printf("\nInterface number out of range.\n");

			/* Free the device list */
			pcap_freealldevs(alldevs);
			return -1;
		}

		/* Jump to the selected adapter */
		for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

		/* Open the adapter */
		if ((fp = pcap_open_live(d->name,	// name of the device
			65536,							// portion of the packet to capture. 
											// 65536 grants that the whole packet will be captured on all the MACs.
			1,								// promiscuous mode (nonzero means promiscuous)
			1000,							// read timeout
			errbuf							// error buffer
		)) == NULL)
		{
			fprintf(stderr, "\nError opening adapter\n");
			return -1;
		}
	}
	else
	{
		/* Do not check for the switch type ('-s') */
		if ((fp = pcap_open_live(argv[2],	// name of the device
			65536,							// portion of the packet to capture. 
											// 65536 grants that the whole packet will be captured on all the MACs.
			1,								// promiscuous mode (nonzero means promiscuous)
			1000,							// read timeout
			errbuf							// error buffer
		)) == NULL)
		{
			fprintf(stderr, "\nError opening adapter\n");
			return -1;
		}
	}

	if (FILTER != NULL)
	{
		// We should loop through the adapters returned by the pcap_findalldevs_ex()
		// in order to locate the correct one.
		//
		// Let's do things simpler: we suppose to be in a C class network ;-)
		NetMask = 0xffffff;

		//compile the filter
		if (pcap_compile(fp, &fcode, FILTER, 1, NetMask) < 0)
		{
			fprintf(stderr, "\nError compiling filter: wrong syntax.\n");

			pcap_close(fp);
			return -3;
		}
	}

	/* Read the packets */
	while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
	{

		if (res == 0)
			/* Timeout elapsed */
			continue;

		/* print pkt timestamp and pkt len */
		printf("%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);

		/* Print the packet */
		for (i = 1; (i < header->caplen + 1); i++)
		{
			printf("%.2x ", pkt_data[i - 1]);
			if ((i % LINE_LEN) == 0) printf("\n");
		}
		printf("\n\n");

		// print
		memcpy(&heternet, pkt_data, 12);
		//memcpy(&hip, &pkt_data[26], 8);
		//memcpy(&hport, &pkt_data[34], 4);


		printf("목적지 MAC ");
		for (int i = 0; i < 6; i++) {
			printf("%.2x ", heternet.dmac[i]);
		}
		printf("\n\n");

		printf("출발지 MAC 주소 ");
		for (int i = 0; i < 6; i++) {
			printf("%.2x ", heternet.smac[i]);
		}
		printf("\n\n");

		pkt_data += 15;
		struct ip_header *ip = (struct ip_header *)pkt_data;
		//printf("s_ip: %s", inet_ntoa(ip->ip_srcaddr));


		pkt_data += ip->ip_header_len;
		// 2. 구조체 객체 생성( struct 구조체이름 객체이름 )
		// 3. memcpy() 호출
		//
		// ip는 inet_ntoa() 함수 사용
		// port ntohs() 함수


		printf("\n\n");
	}

	if (res == -1)
	{
		printf("Error reading the packets: %s\n", pcap_geterr(fp));
		return -1;
	}

	pcap_close(fp);
	return 0;
}
