## Folders
- **[generated](writer/generated.driver.md)**: The `generated` folder in the `firedancer` codebase contains a single generated header file, `fd_writer_tile_seccomp.h`, which defines a seccomp filter policy for managing system call permissions in the project.

## Files
- **[fd_writer_tile.c](writer/fd_writer_tile.c.driver.md)**: The `fd_writer_tile.c` file in the `firedancer` codebase implements the functionality for a writer tile, including initialization, message processing, and integration with other components such as exec tiles and replay tiles, within a distributed system.
- **[fd_writer_tile.seccomppolicy](writer/fd_writer_tile.seccomppolicy.driver.md)**: The `fd_writer_tile.seccomppolicy` file defines security policies for logging, specifying conditions under which log messages are written to a file or STDERR and when the logfile is fsynced to disk.
- **[Local.mk](writer/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase specifies conditional object file additions for `fd_writer_tile` and `fd_discof` based on the presence of `FD_HAS_INT128` and `FD_HAS_SSE` macros.
