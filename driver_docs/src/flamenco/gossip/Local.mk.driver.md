# Purpose
This file is a Makefile snippet used for conditional compilation in a software build process. It checks for the presence of the `FD_HAS_HOSTED` and `FD_HAS_INT128` flags, and if both are defined, it adds headers and object files related to `fd_gossip` and `fd_flamenco`, and creates a binary named `fd_gossip_spy` with dependencies on `fd_flamenco`, `fd_ballet`, and `fd_util`.
