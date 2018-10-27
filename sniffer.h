#ifndef XPCAP_SNIFFER_H
#define XPCAP_SNIFFER_H

typedef struct {
    char deviceName[11];
    char interfaceName[16];
    unsigned int bufferLength;
} SnifferParams;

typedef struct {
    int fd;
    char deviceName[11];
    unsigned int bufferLength;
    char *buffer;
#ifdef __MACH__
    unsigned int lastReadLength;
    unsigned int readBytesConsumed;
#endif
} Sniffer;

typedef struct {
    char *data;
} CapturedInfo;

int
new_sniffer(SnifferParams params, Sniffer *sniffer);

int
close_sniffer(Sniffer *sniffer);

#ifdef __MACH__
int
read_bpf_packet_data(Sniffer *sniffer, CapturedInfo *info);
#endif

#endif //XPCAP_SNIFFER_H

