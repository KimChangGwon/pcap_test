#include <cstdio>
#include <cstdlib>
#include <string.h>
#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include "header_def.h"

#define ERRBUF_SIZE 4096
#define ETH_HDR_SIZE 14

using namespace std;

void print_error(char *, char *);
void cbfunc(unsigned char*, const pcap_pkthdr*, const unsigned char*);
void ethernet_analyzer(unsigned char *);
void IP_analyzer(unsigned char * IP_packet);
void TCP_analyzer(unsigned char * TCP_packet);

int overall_size;

int main(void)
{
	pcap_t * packet_handle;		
	char * dev;
	char * errbuf = new char[ERRBUF_SIZE];
	struct pcap_pkthdr * header;
	const u_char * packet;
	
	dev = pcap_lookupdev(errbuf);		//device name. no need to input device name from user
	printf("network interface : %s\n", dev);
	if(dev == NULL) print_error("couldn't find device", errbuf);
	
	packet_handle = pcap_open_live(dev, 4096, 1, 200, errbuf); //packet handle, maximun 4096 bytes, 200 ms time limit
	if(packet_handle == NULL) print_error("cannot get packet handle", errbuf); 

	pcap_loop(packet_handle, 0, cbfunc, NULL); //used pcap_loop, instead of pcap_next. this function can define callback function in which the captured packet will be compiled
						   //and second argument, 0, has a same meaning 'infinite loop' as pcap_next function in while loop
						   //The last parameter, NULL, is for user argument that can be used in callback function, but is not defined
	pcap_close(packet_handle);
	return 0;
}

void print_error(char * errorPoint, char * errorBuf){
	fprintf(stderr, "<<<< %s >>>> \n%s", errorPoint, errorBuf);
	exit(1);
}

void cbfunc(unsigned char * usr_args, const struct pcap_pkthdr * packet_header, const unsigned char * packet){
	printf("PACKET RECEVIED : %d BYTES\n", packet_header->len);
	overall_size = packet_header->len;
	ethernet_analyzer((unsigned char*)packet);
}

void ethernet_analyzer(unsigned char * ETH_packet)
{
	printf("\n-------------- ETHERNET ---------------\n");
	const int DST_MACADDR_LEN = 6;
	const int SRC_MACADDR_LEN = 6;
	const short ETH_TYPE = ntohs(ETH_packet[DST_MACADDR_LEN + SRC_MACADDR_LEN]); //re-ordering from network-order to host-order, short type
	
	printf("<<<< DESTINATION MAC ADDRESS >>>>\n");
	for(int a = 0; a<DST_MACADDR_LEN; a=a+1) printf(a == DST_MACADDR_LEN-1?"%02X":"%02X:", ETH_packet[a]);
	puts("");
	
	printf("<<<< SOURCE MAC ADDRESS >>>>\n");
	for(int a = DST_MACADDR_LEN; a < DST_MACADDR_LEN + SRC_MACADDR_LEN;a = a + 1) printf(a==DST_MACADDR_LEN+SRC_MACADDR_LEN -1 ? "%02X":"%02X:", ETH_packet[a]);
	puts("");

	printf("---------------------------------------\n");
	switch(ETH_TYPE){
		case 0x0800:
			IP_analyzer(ETH_packet + ETH_HDR_SIZE);		
			break;
		default :
			printf("L3 is NOT IPv4 Protocol\n"); 
	}	
		
	return;
}

void IP_analyzer(unsigned char * IP_packet){
	printf("\n---------------- IPv4 -----------------\n");
	
	struct new_iphdr * IP_HDR;	
	IP_HDR = (struct new_iphdr *) IP_packet;		
	printf("Source IP Address : %s\n", inet_ntoa(*(struct in_addr*)&(IP_HDR->srcIP)));
	printf("Destination IP Address : %s\n", inet_ntoa(*(struct in_addr*) &(IP_HDR->destIP)));
	printf("---------------------------------------\n");
	
	if(IP_HDR->Protocol_ID == 0x06) {
		int IP_hdrlen = ((IP_HDR->version_and_hdrlen)&0xF)*4;
		TCP_analyzer(IP_packet + IP_hdrlen); 
	}
	else puts("L4 is NOT TCP Protocol\n");
}

void TCP_analyzer(unsigned char * TCP_packet){
	printf("\n---------------- TCP -----------------\n");
	struct new_tcphdr * TCP_HDR;
	TCP_HDR = (struct new_tcphdr *) TCP_packet;
	printf("Source Port# : %hu\n", ntohs(TCP_HDR->srcport));
	printf("Destination Port# : %hu\n", ntohs(TCP_HDR->dstport));		
	printf("---------------------------------------\n");

	int header_size = (TCP_HDR->data_offset) * 4;
	int data_length = overall_size - ETH_HDR_SIZE - sizeof(struct new_iphdr) - header_size;
	if(data_length >0){
		printf("\n---------------- DATA -----------------\n");
		for(int a = header_size; a < header_size + (data_length < 32? data_length : 32); a = a + 1) {
			printf("%02X   ", TCP_packet[a]);
			if((a - header_size + 1) % 8 == 0) puts("");
		}
		puts("\n");
	}	
	else puts("\nNO DATA\n");
}
