#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PUSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

#pragma pack(1)
struct new_iphdr{
	uint8_t version_and_hdrlen;
	uint8_t service_type;
	uint16_t total_len;
	uint16_t identification;
	uint16_t Offset;
	uint8_t TTL;
	uint8_t Protocol_ID;
	uint16_t checksum;
	uint32_t srcIP;
	uint32_t destIP;
};
#pragma pack()

#pragma pcak(1)
struct new_tcphdr{
	uint16_t srcport;
	uint16_t dstport;
	uint32_t seqnum;
	uint32_t acknum;
	uint8_t reserved:4;
	uint8_t data_offset:4;
	uint8_t flags;
	uint16_t window;
	uint16_t checksum;
	uint16_t urgent;
};
#pragma pack()
