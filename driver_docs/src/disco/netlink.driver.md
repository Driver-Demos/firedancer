## Folders
- **[generated](netlink/generated.driver.md)**: The `generated` folder in the `firedancer` codebase contains the `netlink_seccomp.h` file, which is a generated header file defining a seccomp filter policy for netlink communication.

## Files
- **[fd_netlink_tile.c](netlink/fd_netlink_tile.c.driver.md)**: The `fd_netlink_tile.c` file in the `firedancer` codebase implements the creation, joining, and management of a netlink tile within a network topology, handling network device, route, and neighbor updates using netlink sockets.
- **[fd_netlink_tile.h](netlink/fd_netlink_tile.h.driver.md)**: The `fd_netlink_tile.h` file provides APIs for managing netlink tiles, including functions for creating and joining network topologies and handling neighbor solicitation requests.
- **[fd_netlink_tile_private.h](netlink/fd_netlink_tile_private.h.driver.md)**: The `fd_netlink_tile_private.h` file defines the `fd_netlink_tile_ctx` structure and associated constants for managing network link, route, and neighbor updates within the Firedancer project.
- **[Local.mk](netlink/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase specifies conditional inclusion of headers and objects for the `fd_netlink_tile` and `fd_disco` components based on the presence of `FD_HAS_LINUX` and `FD_HAS_SSE` flags.
- **[netlink.seccomppolicy](netlink/netlink.seccomppolicy.driver.md)**: The `netlink.seccomppolicy` file in the `firedancer` codebase defines security policies for handling file descriptors and network sockets, including logging, sending, and receiving network messages using specific file descriptors.
