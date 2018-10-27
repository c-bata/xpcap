#ifndef _PCAP_TCP
#define _PCAP_TCP

typedef struct {
	unsigned short srcPort;
	unsigned short dstPort;
	unsigned int sequenceNum;
	unsigned int acknowledgmentNum;
	unsigned int header: 4;
	unsigned int reserved: 6;
	struct CodeBit {
		unsigned int urg: 1;
		unsigned int ack: 1;
		unsigned int psh: 1;
		unsigned int rst: 1;
		unsigned int syn: 1;
		unsigned int fin: 1;
	} codeBit;
	unsigned short windowSize;
    unsigned short checkSum;
	unsigned short urgentPointer;
} TCPHeader;

#endif /* _PCAP_TCP */
