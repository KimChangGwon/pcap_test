#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "header_def.h"

#define ERRBUF_SIZE 4096
#define ETH_HDR_SIZE 14
#define MACADDR_LEN 6
#define printMacSrc 0
#define printMacDst 1
#define printPortSrc 2
#define printPortDst 3


void print_error(int8_t *, int8_t *);
void cbfunc(uint8_t*, const struct pcap_pkthdr*, const uint8_t*);
void ethernet_analyzer(uint8_t *);
void IP_analyzer(uint8_t * IP_packet);
void TCP_analyzer(uint8_t * TCP_packet, int32_t TCP_length);
void PrintMac(uint8_t * packet, int32_t flag);

int32_t overall_size;

int32_t main(void)
{
	pcap_t * packet_handle;		
	int8_t * dev;
	int8_t errbuf[ERRBUF_SIZE];
	struct pcap_pkthdr * header;
	const u_int8_t * packet;
	
	dev = pcap_lookupdev(errbuf);		//device name. no need to input device name from user
	printf("network interface : %s\n", dev);
	if(dev == NULL) print_error("couldn't find device", errbuf);
	
	packet_handle = pcap_open_live(dev, ERRBUF_SIZE, 1, 200, errbuf); //packet handle, maximun 4096 bytes, 200 ms time limit
	if(packet_handle == NULL) print_error("cannot get packet handle", errbuf); 

	pcap_loop(packet_handle, 0, cbfunc, NULL); //used pcap_loop, instead of pcap_next. this function can define callback function in which the captured packet will be compiled
						   //and second argument, 0, has a same meaning 'infinite loop' as pcap_next function in while loop
						   //The last parameter, NULL, is for user argument that can be used in callback function, but is not defined
	pcap_close(packet_handle);
	return 0;
}

void print_error(int8_t * errorPoint, int8_t * errorBuf){
	fprintf(stderr, "<<<< %s >>>> \n%s", errorPoint, errorBuf);
	exit(1);
}

void cbfunc(uint8_t * usr_args, const struct pcap_pkthdr * packet_header, const uint8_t * packet){
	printf("PACKET RECEVIED : %d BYTES\n", packet_header->len);
	overall_size = packet_header->len;
	ethernet_analyzer((uint8_t*)packet);
}

void PrintMac(uint8_t * packet, int32_t flag){	
	switch(flag){
		case printMacSrc:
			printf("<<<< SOURCE MAC ADDRESS >>>>\n");
			for(int32_t a = 0; a<MACADDR_LEN; a=a+1) printf(a == MACADDR_LEN-1?"%02X":"%02X:", packet[a]);
			break;	
		case printMacDst:
			printf("<<<< DESTINATION MAC ADDRESS >>>>\n");
			for(int32_t a = MACADDR_LEN; a < MACADDR_LEN + MACADDR_LEN;a = a + 1) printf(a==MACADDR_LEN+MACADDR_LEN -1 ? "%02X":"%02X:", packet[a]);
			break;
	}
	puts("");
	printf("---------------------------------------\n");
}

void PrintIP(int8_t * port, int32_t flag){
	switch(flag){
		case printPortSrc:
			printf("Source IP Address : %s\n", port);		
			break;
		case printPortDst:
			printf("Destination IP Address : %s\n", port);
			break;
	}
	printf("---------------------------------------\n");
}

void ethernet_analyzer(uint8_t * ETH_packet)
{
	printf("\n-------------- ETHERNET ---------------\n");
	const short ETH_TYPE = ntohs(ETH_packet[MACADDR_LEN + MACADDR_LEN]); //re-ordering from network-order to host-order, short type
	
	PrintMac(ETH_packet, printMacSrc);
	PrintMac(ETH_packet, printMacDst);	
	
	switch(ETH_TYPE){
		case ETHERTYPE_IP:
			IP_analyzer(ETH_packet + ETH_HDR_SIZE);		
			break;
		default :
			printf("L3 is NOT IPv4 Protocol\n"); 
	}	
		
	return;
}

void IP_analyzer(uint8_t * IP_packet){
	printf("\n---------------- IPv4 -----------------\n");
	
	struct new_iphdr * IP_HDR;	
	IP_HDR = (struct new_iphdr *) IP_packet;		
	
	PrintIP(inet_ntoa(*(struct in_addr*)&(IP_HDR->srcIP)), printPortSrc);
	PrintIP(inet_ntoa(*(struct in_addr*)&(IP_HDR->destIP)), printPortDst);

	if(IP_HDR->Protocol_ID == IPPROTO_TCP){
		int32_t IP_hdrlen = ((IP_HDR->version_and_hdrlen)&0xF) << 2;
		int32_t TCP_length = ntohs(IP_HDR->total_len) - IP_hdrlen;
		TCP_analyzer(IP_packet + IP_hdrlen, TCP_length); 
	}
	else puts("L4 is NOT TCP Protocol\n");
}

void TCP_analyzer(uint8_t * TCP_packet, int32_t TCP_length){
	printf("\n---------------- TCP -----------------\n");
	struct new_tcphdr * TCP_HDR;
	TCP_HDR = (struct new_tcphdr *) TCP_packet;
	printf("Source Port# : %hu\n", ntohs(TCP_HDR->srcport));
	printf("Destination Port# : %hu\n", ntohs(TCP_HDR->dstport));		
	printf("---------------------------------------\n");

	int32_t header_size = (TCP_HDR->data_offset) * 4;
	int32_t data_length = TCP_length - header_size;
	printf("data_length : %d\n", data_length);
	if(data_length >0){
		printf("\n---------------- DATA -----------------\n");
		for(int32_t a = header_size; a < header_size + (data_length < 32? data_length : 32); a = a + 1) {
			printf("%02X   ", TCP_packet[a]);
			if((a - header_size + 1) % 8 == 0) puts("");
		}
		puts("\n");
	}	
	else puts("\nNO DATA\n");
}
