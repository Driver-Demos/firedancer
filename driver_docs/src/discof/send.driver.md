## Folders
- **[generated](send/generated.driver.md)**: The `generated` folder in the `firedancer` codebase contains a single file, `fd_send_tile_seccomp.h`, which is a generated header file defining a seccomp filter policy for system call restrictions.

## Files
- **[fd_send_tile.c](send/fd_send_tile.c.driver.md)**: The `fd_send_tile.c` file in the `firedancer` codebase implements functionality for signing and sending transactions to the current leader, primarily for voting purposes, and includes handling of various input and output links, transaction metrics, and leader contact information.
- **[fd_send_tile.seccomppolicy](send/fd_send_tile.seccomppolicy.driver.md)**: The `fd_send_tile.seccomppolicy` file in the `firedancer` codebase defines security policies for logging, specifying conditions under which log messages are written to files or pipes and ensuring that warnings and above are immediately synchronized to disk.
- **[Local.mk](send/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase conditionally adds objects to the build process for `fd_send_tile` and `fd_discof` if SSE support is enabled.
