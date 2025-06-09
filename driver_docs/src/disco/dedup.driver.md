## Folders
- **[generated](dedup/generated.driver.md)**: The `generated` folder in the `firedancer` codebase contains a generated header file, `fd_dedup_tile_seccomp.h`, which defines a seccomp filter policy for syscall filtering.

## Files
- **[fd_dedup_tile.c](dedup/fd_dedup_tile.c.driver.md)**: The `fd_dedup_tile.c` file in the `firedancer` codebase implements a deduplication service that filters out duplicate transaction signatures from multiple input streams and presents them to consumers, ensuring efficient and secure data processing.
- **[fd_dedup_tile.seccomppolicy](dedup/fd_dedup_tile.seccomppolicy.driver.md)**: The `fd_dedup_tile.seccomppolicy` file defines security policies for logging in the Firedancer deduplication tile, specifying conditions for writing and syncing log messages to a file or STDERR.
- **[Local.mk](dedup/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase conditionally adds object files for `fd_dedup_tile` and `fd_disco` if `FD_HAS_SSE` is defined.
- **[test_dedup.c](dedup/test_dedup.c.driver.md)**: The `test_dedup.c` file in the `firedancer` codebase implements a unit test for the deduplication functionality, involving the setup and execution of multiple tiles for transmitting, deduplicating, and receiving test traffic, with configurations for various parameters such as packet size, burst characteristics, and duplication thresholds.
