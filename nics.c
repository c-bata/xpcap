#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <netdb.h>

static void show_interface(int fd, const char *name) {
    int family;
    struct ifreq ifreq;
    char host[128];
    memset(&ifreq, 0, sizeof ifreq);
    strncpy(ifreq.ifr_name, name, IFNAMSIZ);
    if(ioctl(fd, SIOCGIFADDR, &ifreq)!=0) {
        /* perror(name); */
        return; /* ignore */
    }
    switch(family=ifreq.ifr_addr.sa_family) {
        case AF_UNSPEC:
            return; /* ignore */
        case AF_INET:
        case AF_INET6:
            getnameinfo(&ifreq.ifr_addr, sizeof ifreq.ifr_addr, host, sizeof host, 0, 0, NI_NUMERICHOST);
            break;
        default:
            sprintf(host, "unknown (family: %d)", family);
    }
    printf("%-24s%s\n", name, host);
}

static void list_interfaces(int fd, void (*show)(int fd, const char *name)) {
    struct ifreq *ifreq;
    struct ifconf ifconf;
    char buf[16384];
    unsigned i;
    size_t len;

    ifconf.ifc_len=sizeof buf;
    ifconf.ifc_buf=buf;
    if(ioctl(fd, SIOCGIFCONF, &ifconf)!=0) {
        perror("ioctl(SIOCGIFCONF)");
        exit(EXIT_FAILURE);
    }

    ifreq=ifconf.ifc_req;
    for(i=0;i<ifconf.ifc_len;) {
        /* some systems have ifr_addr.sa_len and adjust the length that
         * way, but not mine. weird */
#ifndef linux
        len=IFNAMSIZ + ifreq->ifr_addr.sa_len;
#else
        len=sizeof *ifreq;
#endif
        if(show) {
            show(fd, ifreq->ifr_name);
        } else {
            printf("%s\n", ifreq->ifr_name);
        }
        ifreq=(struct ifreq*)((char*)ifreq+len);
        i+=len;
    }
}

void show_all_interfaces(int family) {
    int fd;

    fd=socket(family, SOCK_DGRAM, 0);
    if(fd<0) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }
    list_interfaces(fd, show_interface);
    close(fd);
}

int main() {
    printf("IPv4\n");
    show_all_interfaces(PF_INET); /* IPv4 */
    printf("IPv6\n");
    show_all_interfaces(PF_INET6); /* IPv6 */
    return EXIT_SUCCESS;
}
