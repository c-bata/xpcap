#ifndef XPCAP_SNIFFER_H
#define XPCAP_SNIFFER_H

typedef struct {
    char device[11];
    char ifr_name[16];
    unsigned int buf_len;
} SnifferParams;

typedef struct {
    int fd;
    char device[11];
    unsigned int buf_len;
    char *buffer;
#ifdef __MACH__
    unsigned int last_read_len;
    unsigned int read_bytes_consumed;
#endif
} Sniffer;

typedef struct {
    char *data;
#ifdef __MACH__
    struct bpf_hdr *bpf_hdr;
#endif
} CapturedInfo;

int
new_sniffer(SnifferParams params, Sniffer *sniffer);

int
close_sniffer(Sniffer *sniffer);

int
read_new_packets(Sniffer *sniffer);

#ifdef __MACH__
int
parse_bpf_packets(Sniffer *sniffer, CapturedInfo *info);
#endif

#endif //XPCAP_SNIFFER_H

