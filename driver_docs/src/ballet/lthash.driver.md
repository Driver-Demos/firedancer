
## Files
- **[fd_lthash.h](lthash/fd_lthash.h.driver.md)**: The `fd_lthash.h` file in the `firedancer` codebase provides APIs for a lattice-based incremental hash using Blake3, including functions for initialization, appending, finalizing, zeroing, addition, subtraction, and encoding of hash values.
- **[Local.mk](lthash/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase specifies the inclusion of the `fd_lthash.h` header and sets up a unit test for `test_lthash` with dependencies on `fd_ballet` and `fd_util`.
- **[test_lthash.c](lthash/test_lthash.c.driver.md)**: The `test_lthash.c` file in the `firedancer` codebase contains tests for the `fd_lthash` functionality, including initialization, appending, finalizing, addition, subtraction, and zeroing of hash values.
