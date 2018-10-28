#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sysexits.h>
#include <signal.h>
#include <sys/select.h>

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
    AnalyzerOption opt;
    opt.verbose = cli_param.verbose;
    opt.port = cli_param.port;

    struct timeval timeout;
    fd_set mask;
    int width, len, ready;
    while (g_gotsig == 0) {
        FD_ZERO(&mask);
        FD_SET(sniffer->fd, &mask);
        width = sniffer->fd + 1;

        timeout.tv_sec = 8;
        timeout.tv_usec = 0;
        ready = select(width, &mask, NULL, NULL, &timeout);
        if (ready == -1) {
            perror("select");
            break;
        } else if (ready == 0) {
            fprintf(stderr, "select timeout");
            break;
        }

        if (FD_ISSET(sniffer->fd, &mask)){
            if ((len = read_new_packets(sniffer)) == -1) {
                perror("read");
                continue;
            }

#ifdef __MACH__
            CapturedInfo info;
            while((len = parse_bpf_packets(sniffer, &info)) > 0)
                analyze_packet((uint8_t *) info.data, (size_t) len, opt);
#elif __linux__
            analyze_packet((uint8_t *) sniffer->buffer, (size_t) len, opt);
#endif
        }
    }
}

int
main(int argc, char *argv[])
{
    int i;
    if (argc <= 1) {
        fprintf(stderr, "xpcap <device> [-v] [--port port-no]\n");
        return EX_USAGE;
    }

    int skip = 0;
    cli_param.device = argv[1];
    for (i = 2; i < argc; i++) {
        if (skip) {
            skip = 0;
            continue;
        }

        if (strcmp(argv[i], "-v") == 0) {
            cli_param.verbose = 1;
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0) {
            if (i+1 >= argc) {
                fprintf(stderr, "should specify port number after -p or --port option\n");
                return EX_USAGE;
            }
            cli_param.port = atoi(argv[i+1]);
            skip = 1;
        } else {
            fprintf(stderr, "xpcap <device> [-v] [--port port-no]\n");
            return EX_USAGE;
        }
    }

    fprintf(stderr, "device = %s, verbose = %d, port = %d\n",
            cli_param.device, cli_param.verbose, cli_param.port);

    signal(SIGINT, sig_int_handler);

    SnifferParams params;
    strcpy(params.interface, cli_param.device);
    params.buf_len = 4096;

    Sniffer sniffer;
    if (new_sniffer(params, &sniffer) == -1)
        return EXIT_FAILURE;

    capture_loop(&sniffer);
    close_sniffer(&sniffer);
    return EXIT_SUCCESS;
}
