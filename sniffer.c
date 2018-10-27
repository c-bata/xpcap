#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/errno.h>
#include <sys/uio.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#ifdef __MACH__
#include <net/bpf.h>
#elif __linux__
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <linux/if.h>
#endif

#include "sniffer.h"

#ifdef __MACH__
int
pick_bpf_device(Sniffer *sniffer)
{
    char dev[11] = {0};
    for (int i = 0; i < 99; ++i) {
        sprintf(dev, "/dev/bpf%i", i);
        sniffer->fd = open(dev, O_RDWR);
        if (sniffer->fd != -1) {
            strcpy(sniffer->deviceName, dev);
            return 0;
        }
    }
    return -1;
}

int
new_bpf_sniffer(SnifferParams params, Sniffer *sniffer)
{
    if (strlen(params.deviceName) == 0) {
        if (pick_bpf_device(sniffer) == -1)
            return -1;
    } else {
        sniffer->fd = open(params.deviceName, O_RDWR);
        if (sniffer->fd != -1)
            return -1;
    }

    if (params.bufferLength == 0) {
        /* Get Buffer Length */
        if (ioctl(sniffer->fd, BIOCGBLEN, &sniffer->bufferLength) == -1) {
            perror("ioctl BIOCGBLEN");
            return -1;
        }
    } else {
        /* Set Buffer Length */
        /* The buffer must be set before the file is attached to an interface with BIOCSETIF. */
        if (ioctl(sniffer->fd, BIOCSBLEN, &params.bufferLength) == -1) {
            perror("ioctl BIOCSBLEN");
            return -1;
        }
        sniffer->bufferLength = params.bufferLength;
    }

    struct ifreq if_req;
    strcpy(if_req.ifr_name, params.interfaceName);
    if(ioctl(sniffer->fd, BIOCSETIF, &if_req) > 0) {
        perror("ioctl BIOCSETIF");
        return -1;
    }

    unsigned int enable = 1;
    if (ioctl(sniffer->fd, BIOCIMMEDIATE, &enable) == -1) {
        perror("ioctl BIOCIMMEDIATE");
        return -1;
    }

    if (ioctl(sniffer->fd, BIOCPROMISC, NULL) == -1) {
        perror("ioctl BIOCPROMISC");
        return -1;
    }

    sniffer->readBytesConsumed = 0;
    sniffer->lastReadLength = 0;
    sniffer->buffer = malloc(sizeof(char) * sniffer->bufferLength);
    return 0;
}
#elif __linux__
int
new_raw_socket_sniffer(SnifferParams params, Sniffer *sniffer)
{
    struct ifreq if_req;
    struct sockaddr_ll sa;
    int soc;

    if ((soc = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
        perror("socket");
        return -1;
    }

    strcpy(if_req.ifr_name, params.interfaceName);
    if (ioctl(soc, SIOCGIFINDEX, &if_req) == -1) {
        perror("ioctl SIOCGIFINDEX");
        close(soc);
        return -1;
    }

    sa.sll_family = PF_PACKET;
    sa.sll_protocol = htons(ETH_P_ALL);
    sa.sll_ifindex = if_req.ifr_ifindex;
    if (bind(soc, (struct sockaddr *) &sa, sizeof(sa)) == -1) {
        perror("bind");
        (void) close(soc);
        return (-1);
    }

    if (ioctl(soc, SIOCGIFFLAGS, &if_req) == -1) {
        perror("ioctl");
        (void) close(soc);
        return (-1);
    }

    if_req.ifr_flags = if_req.ifr_flags|IFF_PROMISC|IFF_UP;
    if (ioctl(soc, SIOCSIFFLAGS, &if_req) == -1) {
        perror("ioctl");
        (void) close(soc);
        return (-1);
    }

    sniffer->fd = soc;
    sniffer->buffer = malloc(sizeof(char) * sniffer->bufferLength);
    if (params.bufferLength > 0) {
        sniffer->bufferLength = params.bufferLength;
    } else {
        sniffer->bufferLength = 4096;
    }
    return 0;
}
#endif

int
new_sniffer(SnifferParams params, Sniffer *sniffer)
{
#ifdef __MACH__
    return new_bpf_sniffer(params, sniffer);
#elif __linux__
    return new_raw_socket_sniffer(params, sniffer);
#endif
}

#ifdef __MACH__
int
read_bpf_packet_data(Sniffer *sniffer, CapturedInfo *info)
{
    struct bpf_hdr *bpfPacket;
    if (sniffer->readBytesConsumed + sizeof(sniffer->buffer) >= sniffer->lastReadLength) {
        sniffer->readBytesConsumed = 0;
        memset(sniffer->buffer, 0, sniffer->bufferLength);

        ssize_t lastReadLength = read(sniffer->fd, sniffer->buffer, sniffer->bufferLength);
        if (lastReadLength == -1) {
            sniffer->lastReadLength = 0;
            perror("read bpf packet:");
            return -1;
        }
        sniffer->lastReadLength = (unsigned int) lastReadLength;
    }

    bpfPacket = (struct bpf_hdr*)((long)sniffer->buffer + (long)sniffer->readBytesConsumed);
    info->data = sniffer->buffer + (long)sniffer->readBytesConsumed + bpfPacket->bh_hdrlen;
    sniffer->readBytesConsumed += BPF_WORDALIGN(bpfPacket->bh_hdrlen + bpfPacket->bh_caplen);
    return bpfPacket->bh_datalen;
}
#endif

int
close_sniffer(Sniffer *sniffer)
{
    free(sniffer->buffer);
    if (close(sniffer->fd) == -1)
        return -1;
    return 0;
}

