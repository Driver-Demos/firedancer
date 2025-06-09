
## Files
- **[fd_io.c](io/fd_io.c.driver.md)**: The `fd_io.c` file in the `firedancer` codebase provides a set of functions for performing various I/O operations, including reading, writing, seeking, truncating, and memory-mapped I/O, as well as handling buffered I/O and translating error codes and signals to human-readable strings.
- **[fd_io.h](io/fd_io.h.driver.md)**: The `fd_io.h` file in the `firedancer` codebase provides a platform-agnostic API for high-performance stream I/O operations, including buffered and memory-mapped I/O, with support for both blocking and non-blocking modes.
- **[Local.mk](io/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase specifies the headers, objects, and unit tests for the `fd_io` and `fd_util` components, and includes a command to run the `test_io` unit test.
- **[test_io.c](io/test_io.c.driver.md)**: The `test_io.c` file in the `firedancer` codebase contains a comprehensive suite of tests for file input/output operations, including creating, writing, reading, seeking, and buffered I/O, as well as error handling and memory-mapped I/O.
