
## Files
- **[fd_udpsock.c](udpsock/fd_udpsock.c.driver.md)**: The `fd_udpsock.c` file in the `firedancer` codebase implements a UDP socket abstraction with support for sending and receiving packets, including mock Ethernet and IPv4 headers, and provides functions for managing socket memory and configuration.
- **[fd_udpsock.h](udpsock/fd_udpsock.h.driver.md)**: The `fd_udpsock.h` file defines an unprivileged, single-threaded UDP socket driver for debugging purposes, implementing the `fd_aio` abstraction and providing functions for managing UDP socket operations in the `firedancer` codebase.
- **[Local.mk](udpsock/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase specifies build instructions for the `udpsock` component, including headers, object files, and a unit test, conditioned on the `FD_HAS_HOSTED` flag.
- **[test_udpsock_echo.c](udpsock/test_udpsock_echo.c.driver.md)**: The `test_udpsock_echo.c` file in the `firedancer` codebase implements a UDP echo server that listens on a specified port, swaps the source and destination of incoming UDP packets, and sends them back to the sender.
