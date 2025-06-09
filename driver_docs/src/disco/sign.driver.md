## Folders
- **[generated](sign/generated.driver.md)**: The `generated` folder in the `firedancer` codebase contains a single file, `fd_sign_tile_seccomp.h`, which is a generated header file defining a seccomp filter policy for syscall filtering.

## Files
- **[fd_sign_tile.c](sign/fd_sign_tile.c.driver.md)**: The `fd_sign_tile.c` file in the `firedancer` codebase implements a signing tile that handles cryptographic signing operations, including initialization, housekeeping, and fragment processing, using various signing types and roles.
- **[fd_sign_tile.seccomppolicy](sign/fd_sign_tile.seccomppolicy.driver.md)**: The `fd_sign_tile.seccomppolicy` file in the `firedancer` codebase defines security policies for logging, specifying conditions for writing to and syncing log files and STDERR.
- **[Local.mk](sign/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase conditionally adds object files `fd_sign_tile` and `fd_disco` to the build if `FD_HAS_SSE` is defined.
