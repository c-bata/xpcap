#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netdb.h>

#include <ctype.h>
#include <errno.h>
#include <ifaddrs.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "printer.h"

void
print_data(const uint8_t *data, size_t size)
{
    int i, j;
    (void) printf("data--------------------------------------------------------"
                  "--------------------\n");
    for (i = 0; i < size; i++) {
        for (j = 0; j < 16; j++) {
            if (j != 0) {
                (void) printf(" ");
            }
            if (i + j < size) {
                (void) printf("%02X", *(data + j));
            } else {
                (void) printf("  ");
            }
        }
        (void) printf("    ");
        for (j = 0; j < 16; j++) {
            if (i < size) {
                if (isascii(*data) && isprint(*data)) {
                    (void) printf("%c", *data);
                } else {
                    (void) printf(".");
                }
                data++;
                i++;
            } else {
                (void) printf(" ");
            }
        }
        (void) printf("\n");
    }
}

void
print_ether_header(struct ether_header *eh)
{
    int i;
    printf("ether_header------------------------------------------------"
           "--------------------\n");
    printf("ether_dhost = ");
    for (i = 0; i<ETHER_ADDR_LEN; i++) {
        if (i != 0) {
            printf(":");
        }
        printf("%02X", eh->ether_dhost[i]);
    }
    printf("\n");
    printf("ether_shost = ");
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        if (i != 0) {
            printf(":");
        }
        printf("%02X", eh->ether_shost[i]);
    }
    printf("\n");
    printf("ether_type = %02X", ntohs(eh->ether_type));
    switch(ntohs(eh->ether_type)){
        case ETHERTYPE_PUP:
            printf("(Xerox PUP)\n");
            break;
        case ETHERTYPE_IP:
            printf("(IP)\n");
            break;
        case ETHERTYPE_ARP:
            printf("(Address resolution)\n");
            break;
        case ETHERTYPE_REVARP:
            printf("(Reverse ARP)\n");
            break;
        case 0x86DD:
            printf("(IPv6)\n");
            break;
        default:
            printf("(unknown)\n");
            break;
    }
}

void
print_ether_arp(struct ether_arp *ether_arp)
{
    static char *hrd[] = {
            "From KA9Q: NET/ROM pseudo.",
            "Ethernet 10/100Mbps.",
            "Experimental Ethernet.",
            "AX.25 Level 2.",
            "PROnet token ring.",
            "Chaosnet.",
            "IEEE 802.2 Ethernet/TR/TB.",
            "ARCnet.",
            "APPLEtalk.",
            "undefine",
            "undefine",
            "undefine",
            "undefine",
            "undefine",
            "undefine",
            "Frame Relay DLCI.",
            "undefine",
            "undefine",
            "undefine",
            "ATM.",
            "undefine",
            "undefine",
            "undefine",
            "Metricom STRIP (new IANA id)."
    };
    static char *op[] = {
            "undefined",
            "ARP request.",
            "ARP reply.",
            "RARP request.",
            "RARP reply.",
            "undefined",
            "undefined",
            "undefined",
            "InARP request.",
            "InARP reply.",
            "(ATM)ARP NAK."
    };
    int i;
    printf("ether_arp---------------------------------------------------"
           "--------------------\n");
    printf("arp_hrd = %u", ntohs(ether_arp->arp_hrd));
    if (ntohs(ether_arp->arp_hrd) <= 23) {
        printf("(%s), ", hrd[ntohs(ether_arp->arp_hrd)]);
    } else {
        printf("(undefined), ");
    }
    printf("arp_pro = %u", ntohs(ether_arp->arp_pro));
    switch(ntohs(ether_arp->arp_pro)){
        case ETHERTYPE_PUP:
            printf("(Xerox POP)\n");
            break;
        case ETHERTYPE_IP:
            printf("(IP)\n");
            break;
        case ETHERTYPE_ARP:
            printf("(Address resolution)\n");
            break;
        case ETHERTYPE_REVARP:
            printf("(Reverse ARP)\n");
            break;
        default:
            printf("(unknown)\n");
            break;
    }
    printf("arp_hln = %u, ", ether_arp->arp_hln);
    printf("arp_pln = %u, ", ether_arp->arp_pln);
    printf("arp_op = %u", ntohs(ether_arp->arp_op));
    if (ntohs(ether_arp->arp_op) <= 10) {
        printf("(%s)\n", op[ntohs(ether_arp->arp_op)]);
    } else {
        printf("(undefine)\n");
    }
    printf("arp_sha = ");
    for (i = 0; i<ether_arp->arp_hln; i++) {
        if (i != 0) {
            printf(":");
        }
        printf("%02X", ether_arp->arp_sha[i]);
    }
    printf("\n");
    printf("arp_spa = ");
    for (i = 0; i < ether_arp->arp_pln; i++) {
        if (i != 0) {
            printf(".");
        }
        printf("%u", ether_arp->arp_spa[i]);
    }
    printf("\n");
    printf("arp_tha = ");
    for (i = 0; i < ether_arp->arp_hln; i++) {
        if (i != 0) {
            printf(":");
        }
        printf("%02X", ether_arp->arp_tha[i]);
    }
    printf("\n");
    printf("arp_tpa = ");
    for (i = 0; i < ether_arp->arp_pln; i++) {
        if (i != 0) {
            printf(".");
        }
        printf("%u", ether_arp->arp_tpa[i]);
    }
    printf("\n");
}

void
print_ip(struct ip *ip)
{
    static char *proto[] = {
            "undefined",
            "ICMP",
            "IGMP",
            "undefined",
            "IPIP",
            "undefined",
            "TCP",
            "undefined",
            "EGP",
            "undefined",
            "undefined",
            "undefined",
            "PUP",
            "undefined",
            "undefined",
            "undefined",
            "undefined",
            "UDP"
    };
    printf("ip----------------------------------------------------------"
           "--------------------\n");
    printf("ip_v = %u, ", ip->ip_v);
    printf("ip_hl = %u, ", ip->ip_hl);
    printf("ip_tos = %x, ", ip->ip_tos);
    printf("ip_len = %d\n", ntohs(ip->ip_len));
    printf("ip_id = %u, ", ntohs(ip->ip_id));
    printf("ip_off = %x, %d\n",
           (ntohs(ip->ip_off))>>13&0x07,
           ntohs(ip->ip_off)&0x1FFF);
    printf("ip_ttl = %u, ", ip->ip_ttl);
    printf("ip_p = %u", ip->ip_p);
    if (ip->ip_p <= 17) {
        printf("(%s), ", proto[ip->ip_p]);
    } else {
        printf("(undefined), ");
    }
    printf("ip_sum = %u\n", ntohs(ip->ip_sum));
    printf("ip_src = %s\n", inet_ntoa(ip->ip_src));
    printf("ip_dst = %s\n", inet_ntoa(ip->ip_dst));
}

void
print_ipv6(struct ip6_hdr *ip6_hdr)
{
    char buf[256];
    static char *proto[] = {
            "undefined",
            "ICMP",
            "IGMP",
            "undefined",
            "IPIP",
            "undefined",
            "TCP",
            "undefined",
            "EGP",
            "undefined",
            "undefined",
            "undefined",
            "PUP",
            "undefined",
            "undefined",
            "undefined",
            "undefined",
            "UDP"
    };
    printf("ip6---------------------------------------------------------"
           "--------------------\n");
    printf("ip6_vfc = %u\n", ip6_hdr->ip6_vfc);
    printf("ip6_flow = %u\n", ip6_hdr->ip6_flow);
    printf("ip6_plen = %u\n", ip6_hdr->ip6_plen);
    if (ip6_hdr->ip6_nxt <= 17) {
        printf("(%s), ", proto[ip6_hdr->ip6_nxt]);
    } else {
        printf("(undefined), ");
    }
    printf("ip6_hlim = %u\n", ip6_hdr->ip6_hlim);
    printf("ip6_src = %s\n", inet_ntop(AF_INET6,
                                       &ip6_hdr->ip6_src,
                                       buf,
                                       sizeof(buf)));
    printf("ip6_dst = %s\n", inet_ntop(AF_INET6,
                                       &ip6_hdr->ip6_dst,
                                       buf,
                                       sizeof(buf)));
}

void
print_tcphdr(struct tcphdr *tcphdr)
{
    printf("tcphdr------------------------------------------------------"
           "--------------------\n");
#ifdef __MACH__
    printf("source: %d\n", tcphdr->th_sport);
    printf("destination: %d\n", tcphdr->th_dport);
    printf("sequence number: %d\n", tcphdr->th_seq);
    printf("ack number = %u\n", ntohl(tcphdr->th_ack));
    printf("data offset = %u, ", tcphdr->th_off);
    printf("control flag = %u, ", tcphdr->th_flags);
    printf("window = %u, ", tcphdr->th_win);
    printf("checksum = %u, ", tcphdr->th_sum);
    printf("urgent pointer = %u\n", tcphdr->th_urp);
#elif __linux__
    printf("source = %u, ", ntohs(tcphdr->source));
    printf("dest = %u\n", ntohs(tcphdr->dest));
    printf("seq = %u\n", ntohl(tcphdr->seq));
    printf("ack_seq = %u\n", ntohl(tcphdr->ack_seq));
    printf("doff = %u, ", tcphdr->doff);
    printf("urg = %u, ", tcphdr->urg);
    printf("ack = %u, ", tcphdr->ack);
    printf("psh = %u, ", tcphdr->psh);
    printf("rst = %u, ", tcphdr->rst);
    printf("syn = %u, ", tcphdr->syn);
    printf("fin = %u, ", tcphdr->fin);
    printf("th_win = %u\n", ntohs(tcphdr->window));
    printf("th_sum = %u, ", ntohs(tcphdr->check));
    printf("th_urp = %u\n", ntohs(tcphdr->urg_ptr));
#endif
}

void
print_tcp_optpad(unsigned char *data, int size)
{
    int i;
    printf("option, pad = ");
    for (i = 0; i < size; i++) {
        if (i != 0) {
            printf(", ");
        }
        printf("%x", *data); data++;
    }
    printf("\n");
}

void
print_udphdr(struct udphdr *udphdr)
{
    printf("udphdr------------------------------------------------------"
           "--------------------\n");
#ifdef __MACH__
    printf("source = %u, ", ntohs(udphdr->uh_sport));
    printf("dest = %u\n", ntohs(udphdr->uh_dport));
    printf("len = %u, ", ntohs(udphdr->uh_ulen));
    printf("check = %u\n", ntohs(udphdr->uh_sum));
#elif __linux__
    printf("source = %u, ", ntohs(udphdr->source));
    printf("dest = %u\n", ntohs(udphdr->dest));
    printf("len = %u, ", ntohs(udphdr->len));
    printf("check = %u\n", ntohs(udphdr->check));
#endif
}

void
print_icmp(struct icmp *icmp, unsigned char *hptr, int size)
{
    static char *type[] = {
            "Echo Reply",
            "undefined",
            "undefined",
            "Destination Unreachable",
            "Source Quench",
            "Redirect",
            "undefined",
            "undefined",
            "Echo Request",
            "Router Adverisement",
            "Router Selection",
            "Time Exceeded for Datagram",
            "Parameter Problem on Datagram",
            "Timestamp Request",
            "Timestamp Reply",
            "Information Request",
            "Information Reply",
            "Address Mask Request",
            "Address Mask Reply"
    };
    struct tcphdr tcphdr;
    struct udphdr udphdr;
    printf("icmp--------------------------------------------------------"
           "--------------------\n");
    printf("icmp_type = %u", icmp->icmp_type);
    if (icmp->icmp_type <= 18) {
        printf("(%s), ", type[icmp->icmp_type]);
    } else {
        printf("(undefined), ");
    }
    printf("icmp_code = %u, ", icmp->icmp_code);
    printf("icmp_cksum = %u\n", ntohs(icmp->icmp_cksum));
    if (icmp->icmp_type == 0 || icmp->icmp_type == 8) {
        printf("icmp_id = %u, ", ntohs(icmp->icmp_id));
        printf("icmp_seq = %u\n", ntohs(icmp->icmp_seq));
        print_data(hptr+8, size-8);
    } else if (icmp->icmp_type == 3) {
        if (icmp->icmp_code == 4) {
            printf("icmp_pmvoid = %u\n", ntohs(icmp->icmp_pmvoid));
            printf("icmp_nextmtu = %u\n", ntohs(icmp->icmp_nextmtu));
        } else {
            printf("icmp_void = %u\n", ntohs(icmp->icmp_void));
        }
    } else if (icmp->icmp_type == 5) {
        printf("icmp_gwaddr = %s\n", inet_ntoa(icmp->icmp_gwaddr));
    } else if (icmp->icmp_type == 11) {
        printf("icmp_void = %u\n", ntohs(icmp->icmp_void));
    }
    if (icmp->icmp_type == 3 || icmp->icmp_type == 5 || icmp->icmp_type == 11) {
        print_ip(&icmp->icmp_ip);
        if (icmp->icmp_ip.ip_p == IPPROTO_TCP) {
            hptr += 8;
            hptr += sizeof(struct ip);
            (void) memcpy(&tcphdr, hptr, sizeof(struct tcphdr));
            print_tcphdr(&tcphdr);
        } else if(icmp->icmp_ip.ip_p == IPPROTO_UDP) {
            hptr += 8;
            hptr += sizeof(struct ip);
            memcpy(&udphdr, hptr, sizeof(struct udphdr));
            print_udphdr(&udphdr);
        }
    }
}
