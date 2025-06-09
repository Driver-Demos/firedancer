# Purpose
This file snippet is a Makefile segment that conditionally adds object files to a build process. If the `FD_HAS_SSE` macro is defined, it invokes a function `add-objs` to include `fd_send_tile` and `fd_discof` in the build. This is typically used to include specific source files when certain hardware capabilities, such as SSE (Streaming SIMD Extensions), are available.
