# Purpose
This file is a Makefile snippet used to set up a debugging environment for a software project. It defines a variable `FD_DEBUG_SBPF_TRACES` with a value of `1` and appends a preprocessor directive `-DFD_DEBUG_SBPF_TRACES=1` to both `CPPFLAGS` and `CFLAGS`, enabling debug traces for SBPF (Solana Berkeley Packet Filter) during the compilation process.
