#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sysexits.h>
#include <signal.h>

#include "sniffer.h"
#include "analyzer.h"

static int g_gotsig = 0;

struct  {
    char *device;
    int port;
    int verbose;
} cli_param = {"", 0, 0};

void
sig_int_handler(int sig)
{
    g_gotsig = sig;
}

void
capture_loop(Sniffer *sniffer)
{
#ifdef __MACH__
    CapturedInfo info;
    int dataLength;
    while((dataLength = readBpfPacketData(sniffer, &info)) != -1) {
        if (g_gotsig) {
            break;
        }
        AnalyzerOption opt;
        opt.verbose = cli_param.verbose;
        opt.port = cli_param.port;
        analyze_packet((uint8_t *) info.data, (size_t) dataLength, opt);
    }
#elif __linux__
    uint8_t buf[2048];
    struct timeval timeout;
    fd_set mask;
    int width;
    ssize_t len;
    while (g_gotsig == 0) {
        FD_ZERO(&mask);
        FD_SET(sniffer->fd, &mask);
        width = sniffer->fd + 1;

        timeout.tv_sec = 3;
        timeout.tv_usec = 0;
        switch (select(width, (fd_set *) &mask, NULL, NULL, &timeout)) {
            case -1:
                /* Error */
                perror("select");
                break;
            case 0:
                /* Timeout */
                break;
            default:
                /* Ready */
                if (FD_ISSET(sniffer->fd, &mask)){
                    if ((len = recv(sniffer->fd, buf, sizeof(buf), 0)) == -1){
                        perror("read");
                    } else {
                        AnalyzerOption opt;
                        opt.verbose = cli_param.verbose;
                        opt.port = cli_param.port;
                        analyze_packet(buf, len, opt);
                    }
                }
                break;
        }
    }
#endif
}

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
    fprintf(stderr, "++++++++++++++++++++++++++++++++++++++++\n");
    fprintf(stderr, "device = %s, verbose = %d, port = %d\n",
            cli_param.device, cli_param.verbose, cli_param.port);
    fprintf(stderr, "++++++++++++++++++++++++++++++++++++++++\n\n");

    signal(SIGINT, sig_int_handler);

    SnifferParams params;
    strcpy(params.interfaceName, cli_param.device);
    params.bufferLength = 4096;

    Sniffer sniffer;
    if (newSniffer(params, &sniffer) == -1)
        return EXIT_FAILURE;

    capture_loop(&sniffer);
    closeSniffer(&sniffer);
    return EXIT_SUCCESS;
}
