#include <pcap.h> 
#include <stdlib.h> 
#include <string.h> 
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>

int main(int argc, char *argv[]){

	struct ether_header header;
	struct ether_arp arp;

	struct in_addr sender_ip;
	struct in_addr target_ip;

	if (argc != 4){ 
		printf("USAGE: send_arp <interface> <sender IP> <target IP>\n"); 
		exit(1); 
	} 

	if ((descr = pcap_open_live(argv[1], 100, 1,  512, errbuf))==NULL){
		fprintf(stderr, "ERROR: %s\n", errbuf);
		exit(1);
	}

	header.etyer_type=htons(ETH_P_ARP);

	arp.arp_hrd = htons(ARPHRD_ETHER);
	arp.arp_pro = htons(ETH_P_IP);
	arp.arp_hln=ETHER_ADDR_LEN;
	arp.arp_pln=sizeof(in_addr_t);
	arp.arp_op = htons(ARPOP_REQUEST);
 
	sender_ip = inet_aton(argv[2]);
	target_ip = inet_aton(argv[3]);

	return 0;
}