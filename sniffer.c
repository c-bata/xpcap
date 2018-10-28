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
            strcpy(sniffer->device, dev);
            return 0;
        }
    }
    return -1;
}

int
new_bpf_sniffer(SnifferParams params, Sniffer *sniffer)
{
    if (strlen(params.device) == 0) {
        if (pick_bpf_device(sniffer) == -1)
            return -1;
    } else {
        sniffer->fd = open(params.device, O_RDWR);
        if (sniffer->fd != -1)
            return -1;
    }

    if (params.buf_len == 0) {
        /* Get Buffer Length */
        if (ioctl(sniffer->fd, BIOCGBLEN, &sniffer->buf_len) == -1) {
            perror("ioctl BIOCGBLEN");
            return -1;
        }
    } else {
        /* Set Buffer Length */
        /* The buffer must be set before the file is attached to an interface with BIOCSETIF. */
        if (ioctl(sniffer->fd, BIOCSBLEN, &params.buf_len) == -1) {
            perror("ioctl BIOCSBLEN");
            return -1;
        }
        sniffer->buf_len = params.buf_len;
    }

    struct ifreq if_req;
    strcpy(if_req.ifr_name, params.interface);
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

    sniffer->read_bytes_consumed = 0;
    sniffer->last_read_len = 0;
    sniffer->buffer = malloc(sizeof(char) * sniffer->buf_len);
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

    strcpy(if_req.ifr_name, params.interface);
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
    sniffer->buffer = malloc(sizeof(char) * sniffer->buf_len);
    if (params.buf_len > 0) {
        sniffer->buf_len = params.buf_len;
    } else {
        sniffer->buf_len = 4096;
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

int
read_new_packets(Sniffer *sniffer)
{
    memset(sniffer->buffer, 0, sniffer->buf_len);

    ssize_t len;
#ifdef __MACH__
    sniffer->read_bytes_consumed = 0;
    if ((len = read(sniffer->fd, sniffer->buffer, sniffer->buf_len)) == -1){
        sniffer->last_read_len = 0;
        perror("read:");
        return -1;
    }
    sniffer->last_read_len = (unsigned int) len;
#elif __linux__
    if ((len = recv(sniffer->fd, sniffer->buffer, sniffer->buf_len, 0)) == -1){
        perror("recv:");
        return -1;
    }
#endif
    return (int) len;
}

#ifdef __MACH__
int
parse_bpf_packets(Sniffer *sniffer, CapturedInfo *info)
{
    if (sniffer->read_bytes_consumed + sizeof(sniffer->buffer) >= sniffer->last_read_len) {
        return 0;
    }

    info->bpf_hdr = (struct bpf_hdr*)((long)sniffer->buffer + (long)sniffer->read_bytes_consumed);
    info->data = sniffer->buffer + (long)sniffer->read_bytes_consumed + info->bpf_hdr->bh_hdrlen;
    sniffer->read_bytes_consumed += BPF_WORDALIGN(info->bpf_hdr->bh_hdrlen + info->bpf_hdr->bh_caplen);
    return info->bpf_hdr->bh_datalen;
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

