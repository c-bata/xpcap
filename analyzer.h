#ifndef XPCAP_ANALYZER_H
#define XPCAP_ANALYZER_H

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <unistd.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sysexits.h>


typedef struct {
    int port;
    int verbose;
} AnalyzerOption;

void
analyze_packet(uint8_t *ptr, size_t len, AnalyzerOption params);

#endif //XPCAP_ANALYZER_H
