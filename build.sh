#!/bin/bash
set -e
gcc -g -Wall -O0 -c bpf.c
ar rusv libbpf.a bpf.o
gcc -g -Wall -O0 -o xpcap main.c -L. -lbpf
