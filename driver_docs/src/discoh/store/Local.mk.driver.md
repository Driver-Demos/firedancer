# Purpose
This file snippet is a Makefile configuration that conditionally adds object files to a build process. If the `FD_HAS_SSE` flag is defined, it invokes a function `add-objs` to include `fd_store_tile` and `fd_discoh` object files in the build. This setup is typically used to include specific optimizations or features when the SSE (Streaming SIMD Extensions) instruction set is available.
