#ifndef XPCAP_PRINTER_H
#define XPCAP_PRINTER_H

#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>

#define print_separator() { \
	(void) printf("================================="  \
	"===============================================\n"); }

void
print_data(const uint8_t *data, size_t size);

void
print_ether_header(struct ether_header *eh);

void
print_ether_arp(struct ether_arp *ether_arp);

void
print_ip(struct ip *ip);

void
print_ipv6(struct ip6_hdr *ip6_hdr);

void
print_tcphdr(struct tcphdr *tcphdr);

void
print_tcp_optpad(unsigned char *data, int size);

void
print_udphdr(struct udphdr *udphdr);

void
print_icmp(struct icmp *icmp, unsigned char *hptr, int size);

#endif //XPCAP_PRINTER_H
