typedef struct {
    char device[11];
    char interface[16];
    unsigned int buf_len;
} SnifferParams;

struct Sniffer_t {
    int fd;
    char device[11];
    unsigned int buf_len;
    char *buffer;
    unsigned int last_read_len;
    unsigned int read_bytes_consumed;
};

typedef struct Sniffer_t Sniffer;

struct CapturedInfo_t {
    char *data;
    struct bpf_hdr *bpf_hdr;
};

typedef struct CapturedInfo_t CapturedInfo;

int
parse_bpf_packets(Sniffer *sniffer, CapturedInfo *info);
