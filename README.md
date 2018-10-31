# XPCAP: cross(X)-platform Packet CAPture

Cross-platform packet capture, supports Linux, macOS(BSD) without depending on libpcap.
Supported Protocols are ARP, IPv4, IPv6, TCP, UDP and ICMP.

![xpcap](https://user-images.githubusercontent.com/5564044/47612189-e411a780-dab8-11e8-94ad-bac70e443e2e.gif)

See article: [How to write cross-platform packet capture using RAW Socket and BPF.](https://medium.com/@c_bata_/how-to-write-cross-platform-packet-capture-using-raw-socket-and-bpf-bab3b614bc03)

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

