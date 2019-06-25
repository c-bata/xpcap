cmake_minimum_required(VERSION 3.12)
project(xpcap C)

set(CMAKE_C_STANDARD 11)

add_executable(xpcap main.c printer.c analyzer.c sniffer.c)

add_executable(nics nics.c)