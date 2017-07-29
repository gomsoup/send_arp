#include <pcap.h> 
#include <stdlib.h> 
#include <string.h> 
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>

int main(int argc, char *argv[]){

	struct ether_header header;
	struct ether_arp arp;

	struct in_addr sender_ip;
	struct in_addr target_ip;


/*  coded by https://stackoverflow.com/questions/1779715/how-to-get-mac-address-of-your-machine-using-a-c-program */
	struct ifreq ifr;
	u_int8_t mac[ETH_ALEN];

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
//////

	if (argc != 4){ 
		printf("USAGE: send_arp <interface> <sender IP> <target IP>\n"); 
		exit(1); 
	} 

	header.ether_type=htons(ETH_P_ARP);

	arp.arp_hrd = htons(ARPHRD_ETHER);
	arp.arp_pro = htons(ETH_P_IP);
	arp.arp_hln=ETHER_ADDR_LEN;
	arp.arp_pln=sizeof(in_addr_t);
	arp.arp_op = htons(ARPOP_REQUEST);
 
	inet_aton(argv[2], &sender_ip);
	inet_aton(argv[3], &target_ip);

//	printf("%s", sender_ip);
//	printf("%s", target_ip);

	return 0;
}