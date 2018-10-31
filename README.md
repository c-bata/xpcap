# XPCAP: cross(X)-platform Packet CAPture

Cross-platform packet capture, supports Linux, macOS(BSD) without depending on libpcap.

![xpcap](https://user-images.githubusercontent.com/5564044/47612189-e411a780-dab8-11e8-94ad-bac70e443e2e.gif)

Supported Protocols are ARP, IPv4, IPv6, TCP, UDP and ICMP.

## How works

The packet capture tool receives and analyzes all packets flowing through the network.
[Promiscuous mode](https://en.wikipedia.org/wiki/Promiscuous_mode) allows a network device to intercept and read each network packet regardless of the target address. Most of NICs (Network Interface Cards) are support it.

Because software and hardware work in cooperation, the layer being handled is low and there are differences between each systems. [libpcap](https://en.wikipedia.org/wiki/Pcap) created by the author of tcpdump absorbs differences in UNIX systems. It has also been ported to Windows, and it called WinPcap. But xpcap supports Linux and macOS without having to depend on libpcap for my study purpose.

### RAW Socket

When reading ethernet frames on Linux environments, we need to use RAW Socket.

1. Open socket descriptor with `PF_PACKET` as  a protocol family, `SOCK_RAW` as a socket type and `htons(ETH_P_ALL)` as a protocol.
    * `int soc = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))`
2. Retrieving information about network interface from the interface name.
    * `ioctl(soc, SIOCGIFINDEX, &if_req)`
3. Binding the socket descriptor to the interface.
    * `bind(soc, (struct sockaddr *) &sa, sizeof(sa))`
4. Get flags of the interface:
    * `ioctl(soc, SIOCGIFFLAGS, &if_req)`
5. Enable promiscuous mode and set the interface up.
    * ioctl(soc, SIOCSIFFLAGS, &if_req)`

After that, you reading ethernet frames via `recv(2)`  when socket descriptor is ready.
If using `select(2)` to watch socket descriptor, the source code is below:

```
struct timeval timeout;
fd_set mask;
int width, len, ready;
while (g_gotsig == 0) {
    FD_ZERO(&mask);
    FD_SET(soc, &mask);
    width = doc + 1;

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
        if ((len = recv(soc, buffer, >buf_len, 0)) == -1){
            perror("recv:");
            return -1;
        }
    }
}
```

There are many materials and texts which describes how to capture packets in Linux environment using RAW Socket. But BPF(Berkeley Packet Filters) which is the only way to read ethernet frames on BSD environment is not.


### BPF (Berkeley Packet Filter)

We need to use BPF(Berkeley Packet Filter) at BSD systems including macOS.
BPF provides virtual machine to filter packets in kernel space. And BPF devices are used to read data.

BPF devices are exists in `/dev/` directory. You need to find available BPF devices While opening them.

```
$ ls /dev/bpf?
/dev/bpf0 /dev/bpf1 /dev/bpf2 /dev/bpf3 /dev/bpf4 /dev/bpf5 /dev/bpf6 /dev/bpf7 /dev/bpf8 /dev/bpf9
```

Although it exists up to about bpf255 in my macbook, google/gopacke seems to check until bpf99. Maybe it's enough in almost situations because of the number of NIC.

[See google/gopacket bsdbpf package](https://github.com/google/gopacket/blob/a35e09f9f224786863ce609de910bc82fc4d4faf/bsdbpf/bsd_bpf_sniffer.go#L166-L177)

After found free bpf device, following operations are required to read ethernet frames.

1. Open a bpf device.
    * `fd = open(params.device, O_RDWR)`
2. Set buffer length or get buffer length.
    * `ioctl(fd, BIOCSBLEN, &params.buf_len)` : set buffer length
    * `ioctl(fd, BIOCGBLEN, &params.buf_len)` : get buffer length
3. Bind a BPF device into the interface.
    * `ioctl(fd, BIOCSETIF, &if_req)`
4. Enable promiscuous mode.
    * `ioctl(fd, BIOCPROMISC, NULL)`

After that you need to use `read(2)` because this is device file, not socket descritptor.
Return value of `read(2)` is not Ethernet frame binaries. Ethernet frame is wrapped by a BPF packet.
When parsing the header of BPF, since the data length is on, we will repeat the parsing by finding the position of the next BPF packet by using it.

```c
typedef struct {
    int fd;
    char device[11];
    unsigned int buf_len;
    char *buffer;
    unsigned int last_read_len;
    unsigned int read_bytes_consumed;
} Sniffer;

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
```

After that it's ok you just parsing ethernet frames and extract `ARP`, `ICMP`, `IP`, `IPv6`, `TCP` and `UDP` protocols.


## How to run

At first, please check your network interface devices using `ifconfig`:

```
$ ifconfig
lo0: ...
 :
en0: ...
 :
```

After that compiled xpcap via `build.sh` or `cmake` and run it:

```
$ ./build.sh
$ ./xpcap en0 -v
device = en0, verbose = 1, port = 0

================================================================================
[TCP6]
ether_header--------------------------------------------------------------------
ether_dhost = XX:XX:XX:XX:XX:XX
ether_shost = XX:XX:XX:XX:XX:XX
ether_type = 86DD(IPv6)
ip6-----------------------------------------------------------------------------
ip6_vfc = 96
ip6_flow = 2363892320
ip6_plen = 15104
(TCP), ip6_hlim = 56
ip6_src = xxxx:xxxx:xxxx:x::xxxx:xxxx
ip6_dst = yyyy:yy:yyyy:yyyy:yyyy:yyyy:yyyy:yyyy
tcphdr--------------------------------------------------------------------------
source: 47873
destination: 59083
sequence number: 1148644729
ack number = 2897299570
data offset = 5, control flag = 24, window = 49152, checksum = 54057, urgent pointer = 0
data----------------------------------------------------------------------------
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ..something..data..
================================================================================

================================================================================
[ARP]
ether_header--------------------------------------------------------------------
ether_dhost = XX:XX:XX:XX:XX:XX
ether_shost = XX:XX:XX:XX:XX:XX
ether_type = 806(Address resolution)
ether_arp-----------------------------------------------------------------------
arp_hrd = 1(Ethernet 10/100Mbps.), arp_pro = 2048(IP)
arp_hln = 6, arp_pln = 4, arp_op = 1(ARP request.)
arp_sha = 34:76:C5:77:5D:4C
arp_spa = 192.168.0.1
arp_tha = 00:00:00:00:00:00
arp_tpa = 192.168.0.8
================================================================================

================================================================================
[UDP]
ether_header--------------------------------------------------------------------
ether_dhost = XX:XX:XX:XX:XX:XX
ether_shost = XX:XX:XX:XX:XX:XX
ether_type = 800(IP)
ip------------------------------------------------------------------------------
ip_v = 4, ip_hl = 5, ip_tos = 0, ip_len = 149
ip_id = 29282, ip_off = 0, 0
ip_ttl = 255, ip_p = 17(UDP), ip_sum = 42831
ip_src = yyy.yyy.yyy.yyy
ip_dst = xxx.xxx.xxx.xxx
udphdr--------------------------------------------------------------------------
source = 5353, dest = 5353
len = 129, check = 38825
data----------------------------------------------------------------------------
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ..something..data..
================================================================================
```

If you are macOS user and want to test xpcap on Linux, please creating VM image from the Vagrantfile.


## LICENSE

MIT License.

