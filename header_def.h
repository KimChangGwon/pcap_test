#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PUSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

#pragma pack(1)
struct new_iphdr{
	unsigned char version_and_hdrlen;
	unsigned char service_type;
	unsigned short total_len;
	unsigned short identification;
	unsigned short Offset;
	unsigned char TTL;
	unsigned char Protocol_ID;
	unsigned short checksum;
	unsigned int srcIP;
	unsigned int destIP;
};
#pragma pack()

#pragma pcak(1)
struct new_tcphdr{
	unsigned short srcport;
	unsigned short dstport;
	unsigned int seqnum;
	unsigned int acknum;
	unsigned char reserved:4;
	unsigned char data_offset:4;
	unsigned char flags;
	unsigned short window;
	unsigned short checksum;
	unsigned short urgent;
};
#pragma pack()
