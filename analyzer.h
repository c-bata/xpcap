#ifndef XPCAP_ANALYZER_H
#define XPCAP_ANALYZER_H

#include <stdlib.h>

typedef struct {
    int port;
    int verbose;
} AnalyzerOption;

void
analyze_packet(uint8_t *ptr, size_t len, AnalyzerOption params);

#endif //XPCAP_ANALYZER_H
