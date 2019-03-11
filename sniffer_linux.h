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
};

typedef struct Sniffer_t Sniffer;

struct CapturedInfo_t {
    char *data;
};

typedef struct CapturedInfo_t CapturedInfo;
