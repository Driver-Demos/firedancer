# Purpose
This Makefile snippet checks for the presence of the `libucontext.a` library file and, if found, appends `-lucontext` to the `LDFLAGS` to link against it. It also sets a preprocessor flag `FD_HAS_UCONTEXT` to indicate the availability of `ucontext` functionality, which is no longer part of POSIX but still present in some C libraries like glibc.
