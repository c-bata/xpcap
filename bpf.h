#ifndef _PCAP_BPF
#define _PCAP_BPF

typedef struct {
    char deviceName[11];
    char interfaceName[16];
    unsigned int bufferLength;
} BpfOption;

typedef struct {
    int fd;
    char deviceName[11];
    unsigned int bufferLength;
    unsigned int readBytesConsumed;
    char *buffer;
} BpfSniffer;

void printBpfOptions(BpfOption option);

void printBpfSnifferParams(BpfSniffer sniffer);

int newBpfSniffer(BpfOption option, BpfSniffer *sniffer);

int closeBpfSniffer(BpfSniffer *sniffer);

#endif /* _PCAP_BPF */
