# Purpose
This file is a Makefile snippet used for conditional compilation in a software build process. It utilizes a macro `add-hdrs` to include the header file `fd_archiver.h` and conditionally adds object files `fd_archiver_feeder`, `fd_archiver_writer`, and `fd_archiver_playback` to the build if the `FD_HAS_SSE` flag is defined, indicating support for SSE (Streaming SIMD Extensions).
