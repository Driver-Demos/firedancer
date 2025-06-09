
## Files
- **[fd_spad.c](spad/fd_spad.c.driver.md)**: The `fd_spad.c` file in the `firedancer` codebase implements various functions for managing and verifying a shared memory allocator, including debug and sanitizer-specific implementations for memory operations.
- **[fd_spad.h](spad/fd_spad.h.driver.md)**: The `fd_spad.h` file in the `firedancer` codebase provides APIs for high-performance, persistent, inter-process shared scratch pad memories, supporting fast allocation, frame management, and integration with real-time streaming and shared memory regions.
- **[Local.mk](spad/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase specifies the headers, objects, and unit tests for the `fd_spad` component, including running the `test_spad` unit test.
- **[test_spad.c](spad/test_spad.c.driver.md)**: The `test_spad.c` file in the `firedancer` codebase contains a comprehensive suite of tests for the `fd_spad` memory allocation system, including tests for allocation, trimming, preparation, cancellation, publishing, and frame management, with additional checks for memory alignment and poisoning using AddressSanitizer.
