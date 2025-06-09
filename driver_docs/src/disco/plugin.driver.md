## Folders
- **[generated](plugin/generated.driver.md)**: The `generated` folder in the `firedancer` codebase contains a single file, `fd_plugin_tile_seccomp.h`, which is a generated header file defining a seccomp filter policy for managing system call restrictions.

## Files
- **[fd_plugin.h](plugin/fd_plugin.h.driver.md)**: The `fd_plugin.h` file in the `firedancer` codebase defines message types and structures for plugin communication, including slot updates, gossip updates, vote updates, and block engine status updates.
- **[fd_plugin_tile.c](plugin/fd_plugin_tile.c.driver.md)**: The `fd_plugin_tile.c` file in the `firedancer` codebase implements a plugin tile for processing various input kinds, managing memory contexts, and handling fragments with specific callbacks during and after processing.
- **[fd_plugin_tile.seccomppolicy](plugin/fd_plugin_tile.seccomppolicy.driver.md)**: The `fd_plugin_tile.seccomppolicy` file defines security policies for logging behavior in the `firedancer` codebase, specifying conditions for writing and syncing log messages to files and pipes.
- **[Local.mk](plugin/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase specifies conditional object file additions for the `fd_plugin_tile`, `fd_disco`, and `fd_flamenco` targets based on the presence of `FD_HAS_INT128` and `FD_HAS_SSE` definitions.
