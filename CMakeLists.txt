cmake_minimum_required(VERSION 3.12)
project(xpcap C)

set(CMAKE_C_STANDARD 11)

add_executable(xpcap main.c bpf.c printer.c)