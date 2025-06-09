
## Files
- **[fd_zstd.c](zstd/fd_zstd.c.driver.md)**: The `fd_zstd.c` file in the `firedancer` codebase provides functions for handling Zstandard decompression streams, including initialization, reading, resetting, and deleting operations, while ensuring compatibility with the libzstd library.
- **[fd_zstd.h](zstd/fd_zstd.h.driver.md)**: The `fd_zstd.h` file in the `firedancer` codebase provides APIs for handling Zstandard compressed streams, focusing on streaming decompression without dynamic heap allocations or syscalls, and includes functions for managing memory and processing Zstandard frames.
- **[fd_zstd_private.h](zstd/fd_zstd_private.h.driver.md)**: The `fd_zstd_private.h` file defines a private structure for a Zstandard decompression stream with specific alignment and magic number requirements in the `firedancer` codebase.
- **[Local.mk](zstd/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase defines build and test instructions for the ZSTD component, including header and object file additions and unit test execution, conditional on `FD_HAS_ZSTD`.
- **[test_zstd.c](zstd/test_zstd.c.driver.md)**: The `test_zstd.c` file in the `firedancer` codebase contains tests for Zstandard decompression functionality, including alignment checks, decompression of test vectors, and validation of the decompression stream's behavior.
