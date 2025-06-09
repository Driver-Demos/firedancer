# Purpose
This file is a Makefile snippet used in a build system to conditionally add object files to the build process. If the `FD_HAS_SSE` flag is defined, it invokes a function `add-objs` to include `fd_exec_tile` and `fd_discof` in the list of objects to be compiled.
