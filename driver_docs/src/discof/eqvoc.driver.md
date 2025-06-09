## Folders
- **[generated](eqvoc/generated.driver.md)**: The `generated` folder in the `firedancer` codebase contains a single generated header file, `fd_eqvoc_tile_seccomp.h`, which defines a seccomp filter policy for system call restrictions.

## Files
- **[fd_eqvoc_tile.c](eqvoc/fd_eqvoc_tile.c.driver.md)**: The `fd_eqvoc_tile.c` file in the `firedancer` codebase implements the initialization and operation of an EQVOC tile, handling tasks such as managing cluster contact information, processing gossip and shred data, and setting up security policies.
- **[fd_eqvoc_tile.seccomppolicy](eqvoc/fd_eqvoc_tile.seccomppolicy.driver.md)**: The `fd_eqvoc_tile.seccomppolicy` file in the `firedancer` codebase defines security policies for logging, specifying conditions for writing log messages to files and pipes, and ensuring immediate disk synchronization for warnings and above.
- **[Local.mk](eqvoc/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase conditionally adds objects to the build process for `fd_eqvoc_tile` and `fd_discof` if `FD_HAS_SSE` is defined.
