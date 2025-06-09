## Folders
- **[generated](gossip/generated.driver.md)**: The `generated` folder in the `firedancer` codebase contains a generated header file, `fd_gossip_tile_seccomp.h`, which defines a seccomp filter policy for managing system call permissions.

## Files
- **[fd_gossip_tile.c](gossip/fd_gossip_tile.c.driver.md)**: The `fd_gossip_tile.c` file implements the gossip networking protocol for a Firedancer node, handling message sending, receiving, and processing within the gossip network.
- **[fd_gossip_tile.seccomppolicy](gossip/fd_gossip_tile.seccomppolicy.driver.md)**: The `fd_gossip_tile.seccomppolicy` file defines security policies for logging in the Firedancer project, specifying how log messages are written to files and pipes, and ensuring critical logs are immediately synchronized to disk.
- **[Local.mk](gossip/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase conditionally adds the `fd_gossip_tile` object to the `fd_discof` target if `FD_HAS_SSE` is defined.
