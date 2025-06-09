## Folders
- **[sock](net/sock.driver.md)**: The `sock` folder in the `firedancer` codebase contains implementations and configurations for network socket operations, including a network socket tile for UDP communication, private structures for socket management, a makefile for conditional compilation, and security policies for network operations.
- **[xdp](net/xdp.driver.md)**: The `xdp` folder in the `firedancer` codebase contains source code and configuration files for managing XDP and XSK socket operations, including a generated seccomp filter policy, implementation of traffic translation, and security policies for network operations.

## Files
- **[fd_net_tile.h](net/fd_net_tile.h.driver.md)**: The `fd_net_tile.h` file provides APIs for integrating XDP networking into a Firedancer topology using the 'net' tile, including functions for packet bounds checking and topology configuration.
- **[fd_net_tile_topo.c](net/fd_net_tile_topo.c.driver.md)**: The `fd_net_tile_topo.c` file in the `firedancer` codebase provides topology support routines for configuring network tiles, including setup for XDP and socket-based tiles, and managing network links and memory caches.
- **[Local.mk](net/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase specifies conditional inclusion of headers and objects for the network component based on the presence of `FD_HAS_SSE` and `FD_HAS_ALLOCA` flags.
