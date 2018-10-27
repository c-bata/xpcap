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

#include "bpf.h"
#include "printer.h"

int
main()
{
    BpfOption option;
    strcpy(option.interfaceName, "en0");
    option.bufferLength = 32767;
    printBpfOptions(option);

    BpfSniffer sniffer;
    if (newBpfSniffer(option, &sniffer) == -1)
        return 1;

    printBpfSnifferParams(sniffer);

    CapturedInfo info;
    int dataLength;
    while((dataLength = readBpfPacketData(&sniffer, &info)) != -1) {
        print_separator();
        printf("Payload length: %d\n", dataLength);
        struct ether_header* eh = (struct ether_header*)info.data;
        print_ether_header(eh);

        if (ntohs(eh->ether_type) == ETHERTYPE_IP) {
            printf("  type: IPv4, %x\n", eh->ether_type);

            struct ip* ip = (struct ip*)((long)eh + sizeof(struct ether_header));
            print_ip(ip);

            if (ip->ip_p == IPPROTO_TCP) {
                struct tcphdr* tcp = (struct tcphdr*)((long)ip + (ip->ip_hl * 4));
                print_tcphdr(tcp);
            }
        } else {
            printf("  type: Other, %x\n", eh->ether_type);
        }
    }
    closeBpfSniffer(&sniffer);
    return 0;
}
