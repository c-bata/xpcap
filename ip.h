#ifndef _PCAP_IP
#define _PCAP_IP

#define IP_PROTOCOL_ICMP    1
#define IP_PROTOCOL_IGMP    2
#define IP_PROTOCOL_IPINIP  3
#define IP_PROTOCOL_TCP     6
#define IP_PROTOCOL_UDP     17

typedef struct {
    unsigned char  flag;
    unsigned char  length;
    unsigned short data;
} IpOption;

typedef struct {
    unsigned char headerLength: 4;
    unsigned char version: 4;
    unsigned char tos;
    unsigned short totalLength;
    unsigned short id;
    unsigned short fragment;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short checkSum;
    unsigned char srcAddress[4];
    unsigned char dstAddress[4];
    IpOption option;
} IpHeader;

#endif /* _PCAP_IP */
