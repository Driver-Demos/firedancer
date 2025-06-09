# Purpose
This file is a Makefile snippet used in a build system to conditionally include headers and object files based on the presence of a 128-bit integer type. If the macro `FD_HAS_INT128` is defined, it adds `fd_txn_generate.h` to the headers and `fd_txn_generate` and `fd_flamenco` to the object files for compilation.
