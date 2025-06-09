# Purpose
This file is a Makefile snippet used for conditional compilation. It checks for the presence of the `FD_HAS_INT128` flag to conditionally add headers and objects related to `fd_repair` and `fd_flamenco`. If the `FD_HAS_HOSTED` flag is also defined, it includes a commented-out line for building a binary named `fd_repair_tool` with specified dependencies.
