#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "printer.h"
#include "analyzer.h"

void
show_summary(uint8_t *ptr, size_t len)
{
    print_separator()
    struct ether_header* eh = (struct ether_header*)ptr;
    printf(" Ethernet Frame\n");
    printf("  src mac address: %x:%x:%x:%x:%x:%x\n",
           eh->ether_shost[0],
           eh->ether_shost[1],
           eh->ether_shost[2],
           eh->ether_shost[3],
           eh->ether_shost[4],
           eh->ether_shost[5]);

    printf("  dst mac address: %x:%x:%x:%x:%x:%x\n",
           eh->ether_dhost[0],
           eh->ether_dhost[1],
           eh->ether_dhost[2],
           eh->ether_dhost[3],
           eh->ether_dhost[4],
           eh->ether_dhost[5]);

    if (ntohs(eh->ether_type) == ETHERTYPE_IP) {
        printf("  type: IPv4, %x\n", eh->ether_type);

        struct ip* ip = (struct ip*)((long)eh + sizeof(struct ether_header));
        printf(" IP Frame\n");
        printf("  headerLength: %d\n", ip->ip_hl * 4);
        printf("  version: %d\n", ip->ip_v);
        printf("  protocol: %d\n", ip->ip_p);
        printf("  ttl: %d\n", ip->ip_ttl);
        printf("  dst ip: %s\n", inet_ntoa(ip->ip_dst));
        printf("  src ip: %s\n", inet_ntoa(ip->ip_src));

        if (ip->ip_p == IPPROTO_TCP) {
            struct tcphdr* tcp = (struct tcphdr*)((long)ip + (ip->ip_hl * 4));
            printf(" TCP Packet\n");
            printf("  dst port: %d\n", tcp->th_dport);
            printf("  src port: %d\n", tcp->th_sport);
        }
    } else {
        printf("  type: Other, %x\n", eh->ether_type);
    }
}

int
is_target_port(uint16_t port1, uint16_t port2, int port)
{
    int flag;
    if (port == 0) {
        flag = 1;
    } else if (port > 0) {
        if (port == port1 || port == port2) {
            flag = 1;
        } else {
            flag = 0;
        }
    } else {
        if (-port == port1 || -port == port2) {
            flag = 0;
        } else {
            flag = 1;
        }
    }
    return(flag);
}

void
analyze_packet_verbose(uint8_t *ptr, size_t len, int port)
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
        (void) memcpy(&ether_arp, ptr, sizeof(struct ether_arp));
        print_separator();
        printf("[ARP]\n");
        print_ether_header(&eh);
        print_ether_arp(&ether_arp);
        print_separator();
        printf("\n");
    } else if (ntohs(eh.ether_type) == ETHERTYPE_IP) {
        (void) memcpy(&ip, ptr, sizeof(struct ip));
        ptr += sizeof(struct ip);
        len = ntohs(ip.ip_len) - sizeof(struct ip);
        if (ip.ip_p == IPPROTO_TCP) {
            (void) memcpy(&tcphdr, ptr, sizeof(struct tcphdr));
            ptr += sizeof(struct tcphdr);
            len -= sizeof(struct tcphdr);
#ifdef __MACH__
            if (is_target_port(ntohs(tcphdr.th_sport), ntohs(tcphdr.th_dport), port)) {
#elif __linux__
            if (is_target_port(ntohs(tcphdr.source), ntohs(tcphdr.dest), port)) {
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
        } else if(ip.ip_p == IPPROTO_UDP) {
            (void) memcpy(&udphdr, ptr, sizeof(struct udphdr));
            ptr += sizeof(struct udphdr);
            len -= sizeof(struct udphdr);
#ifdef __MACH__
            if (is_target_port(ntohs(udphdr.uh_sport), ntohs(udphdr.uh_dport), port)) {
#elif __linux__
            if (is_target_port(ntohs(udphdr.source), ntohs(udphdr.dest), port)) {
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
        } else if(ip.ip_p == IPPROTO_ICMP) {
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
    } else if (ntohs(eh.ether_type) == 0x86DD) {
        (void) memcpy(&ip6_hdr, ptr, sizeof(struct ip6_hdr));
        ptr += sizeof(struct ip6_hdr);
        len -= sizeof(struct ip6_hdr);
        if (ip6_hdr.ip6_nxt == IPPROTO_TCP) {
            (void) memcpy(&tcphdr, ptr, sizeof(struct tcphdr));
            ptr += sizeof(struct tcphdr);
            len -= sizeof(struct tcphdr);
#ifdef __MACH__
            if (is_target_port(ntohs(tcphdr.th_sport), ntohs(tcphdr.th_dport), port)) {
#elif __linux__
            if (is_target_port(ntohs(tcphdr.source), ntohs(tcphdr.dest), port)) {
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
        } else if (ip6_hdr.ip6_nxt == IPPROTO_UDP) {
            (void) memcpy(&udphdr, ptr, sizeof(struct udphdr));
            ptr += sizeof(struct udphdr);
            len -= sizeof(struct udphdr);
#ifdef __MACH__
            if (is_target_port(ntohs(udphdr.uh_sport), ntohs(udphdr.uh_dport), port)) {
#elif __linux__
            if (is_target_port(ntohs(udphdr.source), ntohs(udphdr.dest), port)) {
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

void
analyze_packet(uint8_t *ptr, size_t len, AnalyzerOption opt)
{
    if (opt.verbose) {
        analyze_packet_verbose(ptr, len, opt.port);
    } else {
        show_summary(ptr, len);
    }
}
