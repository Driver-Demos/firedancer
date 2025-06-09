# Purpose
This file is a Makefile snippet used for conditional compilation. It checks if the macros `FD_HAS_SSE` and `FD_HAS_ALLOCA` are defined, and if so, it adds `fd_net_tile.h` to the headers and `fd_net_tile_topo` and `fd_disco` to the objects for the build process. This ensures that these components are only included when specific hardware or compiler features are available.
