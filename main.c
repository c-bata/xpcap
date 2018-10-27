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

#include "bpf.h"
#include "printer.h"

struct  {
    char *device;
    int arp,icmp,tcp,udp;
    int port;
} g_param = {"", 1, 1, 1, 1, 0};

int
is_target_port(uint16_t port1, uint16_t port2)
{
    int flag;
    if (g_param.port == 0) {
        flag = 1;
    } else if (g_param.port > 0) {
        if (g_param.port == port1 || g_param.port == port2) {
            flag = 1;
        } else {
            flag = 0;
        }
    } else {
        if (-g_param.port == port1 || -g_param.port == port2) {
            flag = 0;
        } else {
            flag = 1;
        }
    }
    return(flag);
}

void
analyze_packet(uint8_t *ptr, size_t len)
{
    struct ether_header eh;
    struct ether_arp ether_arp;
    struct ip ip;
    struct ip6_hdr ip6_hdr;
    struct tcphdr tcphdr;
    struct udphdr udphdr;
    struct icmp icmp;
    uint8_t  *hptr;
    int size;
    int lest;

    (void) memcpy(&eh, ptr, sizeof(struct ether_header));
    ptr += sizeof(struct ether_header);
    len -= sizeof(struct ether_header);
    if (ntohs(eh.ether_type) == ETHERTYPE_ARP
        || ntohs(eh.ether_type) == ETHERTYPE_REVARP) {

        if (g_param.arp) {

            (void) memcpy(&ether_arp, ptr, sizeof(struct ether_arp));
            print_separator();
            printf("[ARP]\n");
            print_ether_header(&eh);
            print_ether_arp(&ether_arp);
            print_separator();
            printf("\n");
        }
    } else if (ntohs(eh.ether_type) == ETHERTYPE_IP) {
        (void) memcpy(&ip, ptr, sizeof(struct ip));
        ptr += sizeof(struct ip);
        len = ntohs(ip.ip_len) - sizeof(struct ip);
        if (ip.ip_p == IPPROTO_TCP) {

            if (g_param.tcp) {

                (void) memcpy(&tcphdr, ptr, sizeof(struct tcphdr));
                ptr += sizeof(struct tcphdr);
                len -= sizeof(struct tcphdr);
#ifdef __MACH__
                if (is_target_port(ntohs(tcphdr.th_sport), ntohs(tcphdr.th_dport))) {
#elif __linux__
                if (is_target_port(ntohs(tcphdr.source), ntohs(tcphdr.dest))) {
#endif
                    print_separator();
                    printf("[TCP]\n");
                    print_ether_header(&eh);
                    print_ip(&ip);
                    print_tcphdr(&tcphdr);
#ifdef __MACH__
                    lest = tcphdr.th_off * 4 - sizeof(struct tcphdr);
#elif __linux__
                    lest = tcphdr.doff * 4 - sizeof(struct tcphdr);
#endif
                    if (lest > 0) {
                        print_tcp_optpad(ptr, lest);
                    }
                    ptr += lest;
                    len -= lest;
                    if (len > 0) {
                        print_data(ptr, len);
                    }
                    print_separator();
                    printf("\n");
                }
            }
        } else if(ip.ip_p == IPPROTO_UDP) {
            if (g_param.udp){
                (void) memcpy(&udphdr, ptr, sizeof(struct udphdr));
                ptr += sizeof(struct udphdr);
                len -= sizeof(struct udphdr);
                lest = tcphdr.th_off * 4 - sizeof(struct tcphdr);
#ifdef __MACH__
                if (is_target_port(ntohs(udphdr.uh_sport), ntohs(udphdr.uh_dport))) {
#elif __linux__
                if (is_target_port(ntohs(udphdr.source), ntohs(udphdr.dest))) {
#endif
                    print_separator();
                    printf("[UDP]\n");
                    print_ether_header(&eh);
                    print_ip(&ip);
                    print_udphdr(&udphdr);
                    if (len > 0) {
                        /* データあり */
                        print_data(ptr, len);
                    }
                    print_separator();
                    printf("\n");
                }
            }
        } else if(ip.ip_p == IPPROTO_ICMP) {
            if (g_param.icmp){
                hptr = ptr;
                size = len;
                (void) memcpy(&icmp, ptr, sizeof(struct icmp));
                ptr += sizeof(struct icmp);
                len -= sizeof(struct icmp);
                print_separator();
                printf("[ICMP]\n");
                print_ether_header(&eh);
                print_ip(&ip);
                print_icmp(&icmp, hptr, size);
                print_separator();
                printf("\n");
            }
        }
    } else if (ntohs(eh.ether_type) == 0x86DD) {
        (void) memcpy(&ip6_hdr, ptr, sizeof(struct ip6_hdr));
        ptr += sizeof(struct ip6_hdr);
        len -= sizeof(struct ip6_hdr);
        if (ip6_hdr.ip6_nxt == IPPROTO_TCP) {
            if (g_param.tcp) {
                (void) memcpy(&tcphdr, ptr, sizeof(struct tcphdr));
                ptr += sizeof(struct tcphdr);
                len -= sizeof(struct tcphdr);
#ifdef __MACH__
                if (is_target_port(ntohs(tcphdr.th_sport), ntohs(tcphdr.th_dport))) {
#elif __linux__
                if (is_target_port(ntohs(tcphdr.source), ntohs(tcphdr.dest))) {
#endif
                    print_separator();
                    printf("[TCP6]\n");
                    print_ether_header(&eh);
                    print_ipv6(&ip6_hdr);
                    print_tcphdr(&tcphdr);
#ifdef __MACH__
                    lest = tcphdr.th_off * 4 - sizeof(struct tcphdr);
#elif __linux__
                    lest = tcphdr.doff * 4 - sizeof(struct tcphdr);
#endif
                    if (lest > 0) {
                        print_tcp_optpad(ptr, lest);
                    }
                    ptr += lest;
                    len -= lest;
                    if (len > 0) {
                        print_data(ptr, len);
                    }
                    print_separator();
                    printf("\n");
                }
            }
        } else if (ip6_hdr.ip6_nxt == IPPROTO_UDP) {
            if (g_param.udp){
                (void) memcpy(&udphdr, ptr, sizeof(struct udphdr));
                ptr += sizeof(struct udphdr);
                len -= sizeof(struct udphdr);
#ifdef __MACH__
                if (is_target_port(ntohs(udphdr.uh_sport), ntohs(udphdr.uh_dport))) {
#elif __linux__
                if (is_target_port(ntohs(udphdr.source), ntohs(udphdr.dest))) {
#endif
                    print_separator();
                    printf("[UDP6]\n");
                    print_ether_header(&eh);
                    print_ipv6(&ip6_hdr);
                    print_udphdr(&udphdr);
                    if (len > 0) {
                        print_data(ptr, len);
                    }
                    print_separator();
                    printf("\n");
                }
            }
        }
    }
}

int
main(int argc, char *argv[])
{
    int i;
    if (argc <= 1) {
        (void) fprintf(stderr, "pdump device [-tcp] [-udp] [-arp]"
                               "[-icmp] [port-no] [-port-no]\n");
        return (EX_USAGE);
    }

    g_param.device = argv[1];
    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-tcp") == 0) {
            g_param.tcp = 0;
        } else if(strcmp(argv[i], "-udp") == 0) {
            g_param.udp = 0;
        } else if(strcmp(argv[i], "-arp") == 0) {
            g_param.arp = 0;
        } else if(strcmp(argv[i], "-icmp") == 0) {
            g_param.icmp = 0;
        } else {
            g_param.port = atoi(argv[i]);
        }
    }

    fprintf(stderr,
            "tcp = %d, udp = %d, arp = %d, icmp = %d, port = %d\n",
            g_param.tcp,
            g_param.udp,
            g_param.arp,
            g_param.icmp,
            g_param.port);

    BpfOption option;
    strcpy(option.interfaceName, g_param.device);
    option.bufferLength = 32767;
    printBpfOptions(option);

    BpfSniffer sniffer;
    if (newBpfSniffer(option, &sniffer) == -1)
        return 1;

    printBpfSnifferParams(sniffer);

    CapturedInfo info;
    int dataLength;
    while((dataLength = readBpfPacketData(&sniffer, &info)) != -1) {
        analyze_packet((uint8_t *) info.data, (size_t) dataLength);
    }
    closeBpfSniffer(&sniffer);
    return 0;
}
