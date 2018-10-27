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

#include "bpf.h"

void
printBpfOptions(BpfOption option)
{
    fprintf(stderr, "BpfOption:\n");
    fprintf(stderr, "  BPF Device: %s\n", option.deviceName);
    fprintf(stderr, "  Network Interface: %s\n", option.interfaceName);
    fprintf(stderr, "  Buffer Length: %d\n", option.bufferLength);
}

void
printBpfSnifferParams(BpfSniffer sniffer)
{
    fprintf(stderr, "BpfSniffer:\n");
    fprintf(stderr, "  Opened BPF Device: %s\n", sniffer.deviceName);
    fprintf(stderr, "  Buffer Length: %d\n", sniffer.bufferLength);
}

int
pickBpfDevice(BpfSniffer *sniffer)
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

void
initBpfSniffer(BpfSniffer *sniffer)
{
    sniffer->readBytesConsumed = 0;
    sniffer->lastReadLength = 0;
    sniffer->buffer = malloc(sizeof(char) * sniffer->bufferLength);
}

int
newBpfSniffer(BpfOption option, BpfSniffer *sniffer)
{
    if (strlen(option.deviceName) == 0) {
        if (pickBpfDevice(sniffer) == -1)
            return -1;
    } else {
        sniffer->fd = open(option.deviceName, O_RDWR);
        if (sniffer->fd != -1)
            return -1;
    }

    if (option.bufferLength == 0) {
        /* Get Buffer Length */
        if (ioctl(sniffer->fd, BIOCGBLEN, &sniffer->bufferLength) == -1) {
            perror("ioctl BIOCGBLEN");
            return -1;
        }
    } else {
        /* Set Buffer Length */
        /* The buffer must be set before the file is attached to an interface with BIOCSETIF. */
        if (ioctl(sniffer->fd, BIOCSBLEN, &option.bufferLength) == -1) {
            perror("ioctl BIOCSBLEN");
            return -1;
        }
        sniffer->bufferLength = option.bufferLength;
    }

    struct ifreq interface;
    strcpy(interface.ifr_name, option.interfaceName);
    if(ioctl(sniffer->fd, BIOCSETIF, &interface) > 0) {
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

    initBpfSniffer(sniffer);
    return 0;
}

int
readBpfPacketData(BpfSniffer *sniffer, CapturedInfo *info)
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

int
closeBpfSniffer(BpfSniffer *sniffer)
{
    free(sniffer->buffer);

    if (close(sniffer->fd) == -1)
        return -1;
    return 0;
}
