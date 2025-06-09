# Purpose
This file is a Makefile snippet used for conditional compilation. It checks if the `FD_HAS_LINUX` and `FD_HAS_SSE` flags are defined, and if so, it adds `fd_netlink_tile.h` to the headers and `fd_netlink_tile` and `fd_disco` to the objects for the build process. This ensures that these components are only included when both conditions are met.
