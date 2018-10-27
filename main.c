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
#include <netinet/in.h>
#include <net/if.h>

#include "ethernet.h"
#include "ip.h"
#include "tcp.h"
#include "bpf.h"

int main()
{
    BpfOption option;
    strcpy(option.interfaceName, "en0");
    option.bufferLength = 32767;
    printBpfOptions(option);

    BpfSniffer sniffer;
    if (newBpfSniffer(option, &sniffer) == -1)
        return 1;

    printBpfSnifferParams(sniffer);
    int status = 0;

    int readBytes = 0;
    struct bpf_hdr* bpfPacket;

    while (1) {
        memset(sniffer.buffer, 0, sniffer.bufferLength);

        readBytes = (int) read(sniffer.fd, sniffer.buffer, sniffer.bufferLength);

        if (readBytes == -1) {
            perror("read()");
            status = errno;
            break;
        }
        if (readBytes > 0) {
            char *ptr = 0;

            while((int)ptr + (int)sizeof(sniffer.buffer) < readBytes) {
                bpfPacket = (struct bpf_hdr*)((long)sniffer.buffer + (long)ptr);

                printf("--------------------------------------------------\n");
                printf(" Ethernet Frame\n");
                EthernetHeader* ethHeader = (EthernetHeader*)((long)sniffer.buffer + (long)ptr + bpfPacket->bh_hdrlen);
                printf("  src mac address: %x:%x:%x:%x:%x:%x\n",
                       ethHeader->srcAddress[0],
                       ethHeader->srcAddress[1],
                       ethHeader->srcAddress[2],
                       ethHeader->srcAddress[3],
                       ethHeader->srcAddress[4],
                       ethHeader->srcAddress[5]);

                printf("  dst mac address: %x:%x:%x:%x:%x:%x\n",
                       ethHeader->dstAddress[0],
                       ethHeader->dstAddress[1],
                       ethHeader->dstAddress[2],
                       ethHeader->dstAddress[3],
                       ethHeader->dstAddress[4],
                       ethHeader->dstAddress[5]);

                if (ethHeader->type == TYPE_IPV4) {
                    printf("  type: IPv4, %x\n", ethHeader->type);

                    IpHeader* ip = (IpHeader*)((long)ethHeader + sizeof(EthernetHeader));

                    printf(" IP Frame\n");
                    printf("  headerLength: %d\n", ip->headerLength * 4);
                    printf("  version: %d\n", ip->version);
                    printf("  ttl: %d\n", ip->ttl);
                    printf("  dst ip: %d.%d.%d.%d\n",
                           ip->dstAddress[0],
                           ip->dstAddress[1],
                           ip->dstAddress[2],
                           ip->dstAddress[3]);
                    printf("  src ip: %d.%d.%d.%d\n",
                           ip->srcAddress[0],
                           ip->srcAddress[1],
                           ip->srcAddress[2],
                           ip->srcAddress[3]);

                    if (ip->protocol == IP_PROTOCOL_TCP) {
                        TCPHeader* tcp = (TCPHeader*)((long)ip + (ip->headerLength * 4));
                        printf(" TCP Frame\n");
                        printf("  dst port: %d\n", tcp->dstPort);
                        printf("  src port: %d\n", tcp->srcPort);
                    }
                } else {
                    printf("  type: Other, %x\n", ethHeader->type);
                }

                ptr += BPF_WORDALIGN(bpfPacket->bh_hdrlen + bpfPacket->bh_caplen);
            }
        }
    }
    closeBpfSniffer(&sniffer);
    return status;
}