all: send_arp

send_arp: send_arp.cpp
	g++ -o send_arp send_arp.cpp -lpcap -std=c++11 -g
