## Folders
- **[generated](sock/generated.driver.md)**: The `generated` folder in the `firedancer` codebase contains the `sock_seccomp.h` file, which is a generated header file defining a seccomp filter policy for socket operations.

## Files
- **[fd_sock_tile.c](sock/fd_sock_tile.c.driver.md)**: The `fd_sock_tile.c` file in the `firedancer` codebase implements a network socket tile that handles UDP socket creation, configuration, and data transmission, including both receiving and sending messages, while integrating with the system's topology and metrics.
- **[fd_sock_tile_private.h](sock/fd_sock_tile_private.h.driver.md)**: The `fd_sock_tile_private.h` file defines the private structures and constants for managing socket tiles in the Firedancer network, including metrics, socket configurations, and transmission links.
- **[Local.mk](sock/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase specifies conditional object file additions for `fd_sock_tile` and `fd_disco` based on the presence of `FD_HAS_SSE` and `FD_HAS_ALLOCA` definitions.
- **[sock.seccomppolicy](sock/sock.seccomppolicy.driver.md)**: The `sock.seccomppolicy` file in the `firedancer` codebase defines security policies for network operations and logging, including conditions for polling, receiving, and sending messages, as well as writing and syncing log files.
