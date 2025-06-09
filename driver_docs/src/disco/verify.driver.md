## Folders
- **[generated](verify/generated.driver.md)**: The `generated` folder in the `firedancer` codebase contains a single generated header file, `fd_verify_tile_seccomp.h`, which defines a seccomp filter policy for verifying system calls.

## Files
- **[fd_verify_tile.c](verify/fd_verify_tile.c.driver.md)**: The `fd_verify_tile.c` file in the `firedancer` codebase implements a verification tile that wraps around a multiplexer tile to verify transaction signatures, filter out non-matching transactions, and manage transaction processing metrics.
- **[fd_verify_tile.h](verify/fd_verify_tile.h.driver.md)**: The `fd_verify_tile.h` file in the `firedancer` codebase defines structures and functions for verifying transactions, including deduplication and signature verification, within a verification tile context.
- **[fd_verify_tile.seccomppolicy](verify/fd_verify_tile.seccomppolicy.driver.md)**: The `fd_verify_tile.seccomppolicy` file in the `firedancer` codebase defines security policies for logging, specifying conditions for writing to and syncing log files and STDERR.
- **[Local.mk](verify/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase defines build and test instructions for the `fd_verify_tile` and related unit tests, conditional on the presence of SSE support.
- **[test_verify.c](verify/test_verify.c.driver.md)**: The `test_verify.c` file in the `firedancer` codebase contains a series of test cases for verifying the functionality of transaction verification, including handling valid and invalid transactions, deduplication, and signature verification.
- **[verify_synth_load.c](verify/verify_synth_load.c.driver.md)**: The `verify_synth_load.c` file in the `firedancer` codebase implements a task for verifying synthetic load by setting up configurations, joining necessary IPC objects, and performing signature verification on synthetic messages.
