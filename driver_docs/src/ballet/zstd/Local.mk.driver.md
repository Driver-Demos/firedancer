# Purpose
This file is a Makefile snippet used for conditional compilation and testing of a software component related to Zstandard (ZSTD) compression. It checks if the `FD_HAS_ZSTD` flag is defined, and if so, it adds the `fd_zstd.h` header, compiles the `fd_zstd` object with `fd_util`, and sets up a unit test named `test_zstd` that is subsequently executed.
