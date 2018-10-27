#ifndef _PCAP_ETHERNET
#define _PCAP_ETHERNET

#define TYPE_IPV4        0x0008
#define TYPE_ARP         0x0608
#define TYPE_RARP        0x3580
#define TYPE_APPLE_TALK  0x9b80
#define TYPE_IEEE8021Q   0x0081
#define TYPE_NETWARE_IPX 0x3781

typedef struct {
    unsigned char dstAddress[6];
    unsigned char srcAddress[6];
    unsigned short type;
} EthernetHeader;

#endif /* _PCAP_ETHERNET */
