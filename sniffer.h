#ifndef XPCAP_SNIFFER_H
#define XPCAP_SNIFFER_H

#ifdef __MACH__
#include "sniffer_darwin.h"
#elif __linux__
#include "sniffer_linux.h"
#endif

int
new_sniffer(SnifferParams params, Sniffer *sniffer);

int
close_sniffer(Sniffer *sniffer);

int
read_new_packets(Sniffer *sniffer);

#endif //XPCAP_SNIFFER_H

