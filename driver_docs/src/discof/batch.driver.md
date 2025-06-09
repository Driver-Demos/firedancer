## Folders
- **[generated](batch/generated.driver.md)**: The `generated` folder in the `firedancer` codebase contains a single generated header file, `fd_batch_tile_seccomp.h`, which defines a seccomp filter policy for syscall filtering.

## Files
- **[fd_batch_tile.c](batch/fd_batch_tile.c.driver.md)**: The `fd_batch_tile.c` file in the `firedancer` codebase implements functionality for managing batch processing tiles, including snapshot creation and epoch account hash production, within a distributed system.
- **[fd_batch_tile.seccomppolicy](batch/fd_batch_tile.seccomppolicy.driver.md)**: The `fd_batch_tile.seccomppolicy` file in the `firedancer` codebase defines security policies for file descriptor operations related to logging and snapshot creation, including permissions for writing, syncing, truncating, seeking, and reading files.
- **[Local.mk](batch/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase conditionally adds object files `fd_batch_tile` and `fd_discof` to the build if `FD_HAS_SSE` is defined.
