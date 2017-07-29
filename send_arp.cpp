#include <pcap.h> 
#include <stdio.h>
#include <stdlib.h> 
#include <string.h> 

#include <arpa/inet.h>

#include <sys/socket.h>
#include <sys/ioctl.h>

#include <netinet/if_ether.h>

#include <net/ethernet.h>
#include <net/if_arp.h>
#include <net/if.h>

#define ETHER_HEAD_LEN 14
#define ARP_LEN 28
#define IP_SIZE 4 
int main(int argc, char *argv[]){

	if (argc != 4){ 
		printf("USAGE: send_arp <interface> <sender IP> <target IP>\n"); 
		exit(1); 
	} 

	struct ether_header 	header;
	struct ether_arp arp;

	struct sockaddr_in sender_ip;
	struct sockaddr_in target_ip;

	header.ether_type=htons(ETH_P_ARP);

	arp.arp_hrd = htons(ARPHRD_ETHER);
	arp.arp_pro = htons(ETH_P_IP);
	arp.arp_hln=ETHER_ADDR_LEN;
	arp.arp_pln=sizeof(in_addr_t);
	arp.arp_op = htons(ARPOP_REQUEST);
 
	inet_aton(argv[2], &sender_ip.sin_addr);
	inet_aton(argv[3], &target_ip.sin_addr);

	pcap_t *p;
	char errbuf[PCAP_ERRBUF_SIZE] = { 0x00, };
	u_char packet[ETHER_HEAD_LEN + ARP_LEN];

	/*  Get My MAC Address
		coded by https://stackoverflow.com/questions/1779715/how-to-get-mac-address-of-your-machine-using-a-c-program */
	struct ifreq ifr;
	u_int8_t mac[ETH_ALEN];
	u_int8_t broadcast[ETH_ALEN] = {0x00, };

	memset(&ifr, 0, sizeof(ifr));
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, argv[1], sizeof(ifr.ifr_name));

	if ((ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) && fd != -1){
		memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
		printf("MAC Device : %s\n", argv[1]);
		printf("Mac : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n" , mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	}
	else{
		printf("Get MAC address failure\n");
		exit(1);
	}
	/*																												*/

	/* Find target MAC */
	// Initialize ethernet interface 
	memcpy(header.ether_shost, mac, ETH_ALEN);
	memcpy(header.ether_dhost, broadcast, ETH_ALEN);
	header.ether_type = htons(ETHERTYPE_ARP);

	// Initialize ARP protocol
	arp.arp_hrd = htons(0x1);
	arp.arp_pro = htons(0x0800);
	arp.arp_hln = ETH_ALEN; // 1byte
	arp.arp_pln = IP_SIZE;
	arp.arp_op = htons(0x1); // request
	memcpy(arp.arp_sha, mac, ETH_ALEN);
	memcpy(arp.arp_spa, &sender_ip.sin_addr, IP_SIZE); // sender -> boradcast
	memcpy(arp.arp_tha, broadcast, ETH_ALEN);
	memcpy(arp.arp_tpa, &target_ip.sin_addr, IP_SIZE);


	// Initialize packet
	memcpy(packet, &header, ETHER_HEAD_LEN);
	memcpy(packet + ETHER_HEAD_LEN, &arp, ARP_LEN);

	// Ready device
	p = pcap_open_live(argv[1], 1024, 0, 0, errbuf);

	if(errbuf[0] == '\0'){
		printf("pcap_open_live failed\n");
		printf("%s", errbuf);
		exit(1);
	}

	// Send packet
	pcap_sendpacket(p, packet, ETHER_HEAD_LEN + ARP_LEN)

	return 0;
}