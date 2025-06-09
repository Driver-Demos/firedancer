# Purpose
This file is a Makefile snippet that conditionally includes and runs unit tests for a software project. If the `FD_HAS_SSE` flag is defined, it adds object files `fd_verify_tile` and `fd_disco`, creates a unit test named `test_tiles_verify` with dependencies on `fd_ballet`, `fd_tango`, and `fd_util`, and executes the unit test `test_tiles_verify`.
