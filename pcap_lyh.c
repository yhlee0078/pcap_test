#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <pcap.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#define PROMISCUOUS 1
#define NONPROMISCUOUS 0



/*
	struct ether_header
	struct ip
	struct tcphdr

 */
void show_mac_addr(struct ether_header *ether_hdr)
{
	int i;

	printf("ETH.smac : ");
	for(i = 0; i<ETH_ALEN; i++)
	{
		printf("%.2X ", ether_hdr->ether_shost[i]);
	}
	printf("\n");

	printf("ETH.dmac :");
	for(i = 0; i<ETH_ALEN; i++)
	{
		printf("%.2X ", ether_hdr->ether_dhost[i]);
	}
	printf("\n");
}

void show_ip_addr(struct ip *ip_hdr)
{
	printf("ip.src : %s\n", inet_ntoa(ip_hdr->ip_src));
	printf("ip.dst : %s\n", inet_ntoa(ip_hdr->ip_src));
}
void show_tcp_port(struct tcphdr *tcp_hdr)
{
	printf("tcp.sport : %d\n", ntohs(tcp_hdr->th_sport));
	printf("tcp.dport : %d\n", ntohs(tcp_hdr->th_dport));
}

void show_tcp_payload(const u_char *payload, int len)
{
	int i;
	printf("TCP payloads : ");
	for(i=0; i<len; i++)
	{
		printf("%02X ", *(payload+i));
	}

	printf("\n");
}




int main(int argc, char *argv[])
{
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	struct pcap_pkthdr hdr;
	const u_char *packet;
	struct ether_header *ether_hdr;
	struct ip *ip_hdr;
	struct tcphdr *tcp_hdr;
	int i;

	if(argc != 2)
	{
		printf("usage : ./pcap_lyh <dev>\n");
		exit(-1);
	}

	dev = argv[1];
	// opening the specific device
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "Couldn't open device %s\n", dev, errbuf);
	}
	else
	{
		fprintf(stdout, "Device %s opened\n", dev);
	}

	while(1)
	{
		packet = pcap_next(handle, &hdr);
		if(packet == NULL)
		{
			printf("no packet at all\n");
			continue;
		}

		else // packet captured
		{
			printf("pkt len : %d\n", hdr.len);

			ether_hdr = (struct ethhdr *)packet;
			
			show_mac_addr(ether_hdr); // ether.smac, ether.dmac

			if(ntohs(ether_hdr->ether_type) == ETHERTYPE_IP)
			{
				packet = packet + sizeof(struct ethhdr); // eth - ip - tcp
				ip_hdr = (struct ip *)packet;
				printf("IP Packet OK\n");
				
				show_ip_addr(ip_hdr);

				if(ip_hdr->ip_p = IPPROTO_TCP)
				{
					packet = packet + (ip_hdr->ip_hl)*4;
					tcp_hdr = (struct tcphdr *)packet;

					show_tcp_port(tcp_hdr);

					printf("a");

					packet += (tcp_hdr->th_off)*4; // for payload(data)

					int payload_size = ntohs(ip_hdr->ip_len) - ((ip_hdr->ip_hl)*4 +(tcp_hdr->th_off)*4);

					if(payload_size > 10)
					{
						printf("Upper 10 payloads\n");
						show_tcp_payload(packet, 10);
					}
					else
					{
						printf("size <= 10.. still show you\n");
						show_tcp_payload(packet, payload_size);	
					}


				}
				else
				{
					printf("Not a TCP Packet\n");
					continue;
				}
			}
			else
			{
				printf("Not a IP Packet\n");
				continue;
			}

			
		}

	}
	

	


}
