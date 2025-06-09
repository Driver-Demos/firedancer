# Purpose
This file is a Makefile snippet that conditionally compiles the `fd_rpcserver` binary. It checks for the presence of specific features or capabilities (`FD_HAS_HOSTED`, `FD_HAS_INT128`, `FD_HAS_SSE`) before invoking the `make-bin` function with the necessary source files and libraries, including `fd_discof`, `fd_disco`, and others, along with `$(SECP256K1_LIBS)`.
