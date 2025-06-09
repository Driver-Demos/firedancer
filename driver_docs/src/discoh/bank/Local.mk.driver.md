# Purpose
This file is a Makefile snippet used for conditional compilation. It checks for the presence of specific features or capabilities (`FD_HAS_ATOMIC`, `FD_HAS_INT128`, `FD_HAS_SSE`) and, if all are defined, it adds headers and object files (`fd_bank_abi.h`, `fd_bank_abi`, `fd_bank_tile`, `fd_discoh`) to the build process using Makefile functions `add-hdrs` and `add-objs`.
