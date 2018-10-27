#!/bin/bash
set -e

gcc -g -Wall -O0 -c printer.c
ar rusv libprinter.a printer.o

gcc -g -Wall -O0 -c analyzer.c
ar rusv libanalyzer.a analyzer.o

gcc -g -Wall -O0 -c sniffer.c
ar rusv libsniffer.a sniffer.o

gcc -g -Wall -O0 -o xpcap main.c -L. -lanalyzer -lprinter -lsniffer
