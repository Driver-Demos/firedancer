# Purpose
This file is a Makefile snippet used in a build system to conditionally include headers and object files. It checks if the macro `FD_HAS_INT128` is defined, and if so, it adds `fd_genesis_cluster.h` to the list of headers and `fd_genesis_cluster` and `fd_disco` to the list of object files to be compiled.
