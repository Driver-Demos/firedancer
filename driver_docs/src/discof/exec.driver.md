## Folders
- **[generated](exec/generated.driver.md)**: The `generated` folder in the `firedancer` codebase contains a single generated header file, `fd_exec_tile_seccomp.h`, which defines a seccomp filter policy for restricting system calls.

## Files
- **[fd_exec_tile.c](exec/fd_exec_tile.c.driver.md)**: The `fd_exec_tile.c` file in the `firedancer` codebase implements the execution logic for a tile in a distributed system, handling tasks such as transaction execution, slot and epoch management, and account hashing, while interfacing with various runtime components and managing memory and data structures specific to the execution context.
- **[fd_exec_tile.seccomppolicy](exec/fd_exec_tile.seccomppolicy.driver.md)**: The `fd_exec_tile.seccomppolicy` file defines security policies for logging in the `firedancer` codebase, specifying conditions for writing and syncing log messages to a file or STDERR.
- **[Local.mk](exec/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase conditionally adds objects `fd_exec_tile` and `fd_discof` to the build if `FD_HAS_SSE` is defined.
