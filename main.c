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
#include "analyzer.h"

struct  {
    char *device;
    int port;
    int verbose;
} cli_param = {"", 0, 0};


int
main(int argc, char *argv[])
{
    int i;
    if (argc <= 1) {
        fprintf(stderr, "pdump device [-v] [port-no]\n");
        return EX_USAGE;
    }

    cli_param.device = argv[1];
    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0) {
            cli_param.verbose = 0;
        } else {
            cli_param.port = atoi(argv[i]);
        }
    }

    fprintf(stderr,
            "verbose = %d, port = %d", cli_param.verbose, cli_param.port);

    BpfOption option;
    strcpy(option.interfaceName, cli_param.device);
    option.bufferLength = 32767;
    printBpfOptions(option);

    BpfSniffer sniffer;
    if (newBpfSniffer(option, &sniffer) == -1)
        return EXIT_FAILURE;

    printBpfSnifferParams(sniffer);

    CapturedInfo info;
    int dataLength;
    while((dataLength = readBpfPacketData(&sniffer, &info)) != -1) {
        AnalyzerOption opt;
        opt.verbose = cli_param.verbose;
        opt.port = cli_param.port;
        analyze_packet((uint8_t *) info.data, (size_t) dataLength, opt);
    }
    closeBpfSniffer(&sniffer);
    return EXIT_SUCCESS;
}
