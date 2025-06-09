
## Files
- **[fd_poh.c](poh/fd_poh.c.driver.md)**: The `fd_poh.c` file in the `firedancer` codebase implements functions for appending and mixing in data using SHA-256 hashing.
- **[fd_poh.h](poh/fd_poh.h.driver.md)**: The `fd_poh.h` file provides a software-based implementation of the Proof-of-History hashchain, including functions for appending recursive hash operations and mixing in a 32-byte value.
- **[Local.mk](poh/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase specifies the headers, objects, and unit tests for the `fd_poh` and `fd_ballet` components, and includes a command to run the `test_poh` unit test.
- **[test_poh.c](poh/test_poh.c.driver.md)**: The `test_poh.c` file in the `firedancer` codebase contains tests and benchmarks for the Proof of History (PoH) functions, including `fd_poh_append` and `fd_poh_mixin`, ensuring their correctness and performance.
