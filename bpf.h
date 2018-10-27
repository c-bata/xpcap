#ifndef XPCAP_BPF_H
#define XPCAP_BPF_H

typedef struct {
    char deviceName[11];
    char interfaceName[16];
    unsigned int bufferLength;
} BpfOption;

typedef struct {
    int fd;
    char deviceName[11];
    unsigned int bufferLength;
    unsigned int lastReadLength;
    unsigned int readBytesConsumed;
    char *buffer;
} BpfSniffer;

typedef struct {
    char *data;
} CapturedInfo;

void
printBpfOptions(BpfOption option);

void
printBpfSnifferParams(BpfSniffer sniffer);

int
newBpfSniffer(BpfOption option, BpfSniffer *sniffer);

int
readBpfPacketData(BpfSniffer *sniffer, CapturedInfo *info);

int
closeBpfSniffer(BpfSniffer *sniffer);

#endif /* XPCAP_BPF_H */
