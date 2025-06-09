# Purpose
This file snippet is a Makefile segment that conditionally adds object files to a build process. If the `FD_HAS_SSE` macro is defined, it invokes a function `add-objs` to include `fd_resolv_tile` and `fd_discof` in the list of object files to be compiled. This is typically used to manage platform-specific or feature-specific compilation.
