#include <iostream>
#include <string>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <pcap.h>

#include <errno.h>

#include <sys/time.h>
#include <sys/socket.h>

#include <net/ethernet.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#include <arpa/inet.h>

#define PROMISCUOUS 1
#define NONPRIMISCUOUS 0
#define ETHER_HEAD_LENGTH 14
#define IP4_HEAD_LENGTH 20
#define ARPOP_REQUEST 1 

using namespace std;


class pcapClass{
public:
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[100] = "port 80";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr *header;	/* The header that pcap gives us */
	const u_char *packet;
	int res;

	void propertiesForDevice(){
		if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1){
			fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
			exit(2);
		}
	}

	void openSessionPromiscuous(){
		handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
		if(handle == NULL){
			fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
			exit(2);
		}
	}

	void filterApplyAndCompile(){
		if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1){
			fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
			exit(2);
		}
	}

	void pcapGetPacket(){
		res = pcap_next_ex(handle, &header, &packet);
		cout << "Jacked a packet with legnth of [" << header->len << "]" << endl;
	}

	void pcapInitClass(char *dummy){
		dev = dummy;
		openSessionPromiscuous();
		filterApplyAndCompile();
	}
};


class etherClass: public pcapClass{
public:
	struct ether_header *ep;
	u_short ether_type;
	
	char destMAC[6];
	char srcMAC[6];

	void etherInitClass(){
		ep = (struct ether_header *) packet;
		ether_type = ntohs(ep->ether_type);
		
		cout << "Ethernet Data" << endl;

		cout << "Src MAC      : " ;
		for(int i=0; i<ETH_ALEN; i++){
			printf("%.2X ", ep->ether_shost[i]);
		}
		cout << endl;

		cout << "Dest MAC     : ";
		for(int i=0; i<ETH_ALEN; i++){
			printf("%.2X ", ep->ether_dhost[i]);
		}
		cout << endl;
		cout << "Ethernet type : " << ether_type << endl << endl;
	}


};


class ipClass: public etherClass{
public:
	bool is_ip;
	bool is_arp;

	u_int ip_v;
	u_int ip_hl;
	u_int ip_id;
	u_int ip_ttl;
	u_char ip_src[INET_ADDRSTRLEN];
	u_char ip_dst[INET_ADDRSTRLEN];
	const u_char *ipPacket;
	struct ip *iph;

	void ipInitClass(){
		if (ether_type == ETHERTYPE_IP){
			is_ip = true;
			ipPacket = packet; 
			ipPacket+=sizeof(struct ether_header);
			iph = (struct ip*)ipPacket;

			ip_v = iph->ip_v;
			ip_hl = iph->ip_hl;
			ip_id = ntohs(iph->ip_id);
			ip_ttl = iph->ip_ttl;
			
			inet_ntop(AF_INET, &iph->ip_src, ip_src, INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &iph->ip_dst, ip_dst, INET_ADDRSTRLEN);
		}
		else{
			is_ip = false;
			cout << "This is not IP Packet" << endl;
			cout << "Ethernet type : " << ether_type << endl << endl;	
		}
	}
	
	void printIPSpec(){
		cout << "IP Data" << endl;
		cout << "Version     : " << ip_v << endl;
		cout << "Header Len  : " << ip_hl << endl;
		cout << "ID          : " << ip_id << endl;
		cout << "TTL         : " << ip_ttl << endl;
		cout << "Src Address : " << ip_src << endl;
		cout << "Dst Address : " << ip_dst << endl;
	}
}



class tcpClass: public ipClass{
public:
	struct tcphdr *tcph;
	u_char *tcpdata;
	int data_size;
	int tcp_src;
	int tcp_dst;
	bool is_tcp;
	const char *payload;
	int size_payload;
	int cnt;

	void tcpInitClass(){
		if (iph->ip_p == IPPROTO_TCP){
			is_tcp = true;
			tcph = (struct tcphdr *)(ipPacket + ip_hl*4);
			tcpdata = (u_char *)(ipPacket + ip_hl*4 + tcph->doff *4);

			tcp_src = ntohs(tcph->source);
			tcp_dst = ntohs(tcph->dest);
		}
		else {
			is_tcp = false;
			cout << "This is not TCP Packet" << endl;
			cout << "Ethernet type : " << ether_type << endl << endl;	

		}
	}
	
	void printTCPSpec(){
		int cnt = 1;

		cout << "-----------------------TCP Data-----------------------" << endl;
		
		for(int i= ip_hl*4 + tcph->doff *4 ; i< ntohs(iph->ip_len); i++){
			printf("%02x ", *(tcpdata++));
			if (cnt % 16 == 0) cout << endl;
			cnt++;
		}
		cout << endl;
		cout << "------------------------------------------------------" <<endl;
		cout << "Src Port    : " << tcp_src << endl;
		cout << "Dst Port    : " << tcp_dst << endl << endl;
	}
};

int main(int argc, char *argv[]){
	tcpClass t;


	if(argc < 2){
		cout << "can't find dummy interface in given argument" << endl;
		exit(1);
	}

	t.pcapInitClass(argv[1]);
	
	while(1){
		t.pcapGetPacket();

		if(t.header->len != 0){
			t.etherInitClass();
			t.ipInitClass();

			if(t.is_ip){
				t.printIPSpec();
				cout << endl;

				t.tcpInitClass();
				
				if(t.is_tcp){
					t.printTCPSpec();
					cout << endl;
				}
			}
		}

		t.header->len =0;
	}	
	return 0;
}
