#include <pcap.h> 
#include <stdio.h>
#include <stdlib.h> 
#include <string.h> 
#include <unistd.h>

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

	struct ether_header header;
	struct ether_arp arp;

	struct sockaddr_in sender_ip;
	struct sockaddr_in target_ip;

	header.ether_type = htons(ETH_P_ARP);

	arp.arp_hrd = htons(ARPHRD_ETHER);
	arp.arp_pro = htons(ETH_P_IP);
	arp.arp_hln = ETHER_ADDR_LEN;
	arp.arp_pln = sizeof(in_addr_t);
	arp.arp_op = htons(ARPOP_REQUEST);
	inet_aton(argv[2], &sender_ip.sin_addr);
	inet_aton(argv[3], &target_ip.sin_addr);

	pcap_t *p;
	char errbuf[PCAP_ERRBUF_SIZE] = { 0x00, };
	u_char packet[ETHER_HEAD_LEN + ARP_LEN];
	struct bpf_program fp;

	/*  Get My MAC Address
		coded by https://stackoverflow.com/questions/1779715/how-to-get-mac-address-of-your-machine-using-a-c-program */
	struct ifreq ifr;
	u_int8_t mac[ETH_ALEN];
	u_int8_t target_mac[ETH_ALEN] = {0x00, }; // for inet_ntop
	u_int8_t broadcast[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	memset(&ifr, 0, sizeof(ifr));
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, argv[1], sizeof(ifr.ifr_name));

	if ((ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) && fd != -1){
		memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
		printf("MAC Device : %s\n", argv[1]);
		printf("Mac : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n\n" , mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	}
	else{
		printf("Get MAC address failure\n");
		exit(1);
	}

	/* Find target MAC start */

	// Initialize ethernet interface 
	memcpy(header.ether_shost, mac, ETH_ALEN);
	memcpy(header.ether_dhost, broadcast, ETH_ALEN);
	header.ether_type = htons(ETHERTYPE_ARP);

	// Initialize ARP protocol
	memcpy(arp.arp_sha, mac, ETH_ALEN);
	memcpy(arp.arp_spa, &target_ip.sin_addr, IP_SIZE); // sender -> boradcast
	memcpy(arp.arp_tha, broadcast, ETH_ALEN);
	memcpy(arp.arp_tpa, &sender_ip.sin_addr, IP_SIZE);


	// Initialize packet
	memcpy(packet, &header, ETHER_HEAD_LEN);
	memcpy(packet + ETHER_HEAD_LEN, &arp, ARP_LEN);

	// Ready device to request arp
	p = pcap_open_live(argv[1], 94, 0, 100, errbuf);

	if (p == NULL){
		printf("pcap_open_live returned null. device ready failed\n");
		printf("errbuf : %s\n", errbuf);
		exit(1);
	}

	// Send packet
	if (pcap_sendpacket(p, packet, sizeof(packet)) == -1){
		printf("pcap_sendpacket failed\n");
		exit(1);
	}
	else
		printf("ARP requset sended\n");

	/* I tried dynamic cast such as in_addr to bpf_u_int32 didn't work. 
	   So we'll use pcap_lookupnet to get net, mask. 
	   If you have a better idea than mine, Feel free and just tell me your thought. */   

	bpf_u_int32 net, mask;
	struct pcap_pkthdr *recv_header;
	u_int8_t *recv_packet;
	struct ether_header *recv_ether;
	struct ether_arp *recv_arp;

	//lookup device
	if( pcap_lookupnet(argv[1], &net, &mask, errbuf) == -1){
		printf("pcap_lookupnet failed\n");
		printf("errvbuf : %s\n", errbuf);
	}

	// Configure filter to capture only ARP 
	if(pcap_compile(p, &fp, "arp", 0, net) == -1){
		printf("pcap_compile failed\n");
		exit(1);
	}
	if(pcap_setfilter(p, &fp) == -1){
		printf("pcap_setfilter failed\n");
		exit(1);
	}

	// Recv reply data
	if(pcap_next_ex(p, &recv_header, (const u_char **)&recv_packet) != 1){
		printf("pcap_next_ex failed\n");	
		exit(1);
	}
	else
		printf("ARP reply data arrived\n");


	// Initialize Recv data
	recv_ether = (struct ether_header *)recv_packet;
	recv_arp = (struct ether_arp *)(recv_packet + ETHER_HEAD_LEN);
	memcpy(target_mac, &recv_arp->arp_sha, ETH_ALEN);


	if ( ntohs(recv_ether->ether_type) != ETHERTYPE_ARP ) {
		printf("Seems like filter dosen't work. Terminating...\n");
		exit(1);
	}
	else
		printf("Ether type : ARP\n");
	
	if ( ntohs(recv_arp->arp_op) != 0x2 ){
		printf("Seems like not ARP reply packet. Terminating...\n");
		exit(1);
	}
	else
		printf("Op code : 0x2 (reply)\n");

	printf("Target MAC : %x:%x:%x:%x:%x:%x\n", target_mac[0], target_mac[1], target_mac[2], target_mac[3], target_mac[4], target_mac[5]);


	return 0;
}