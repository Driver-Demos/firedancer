
## Files
- **[fd_siphash13.c](siphash13/fd_siphash13.c.driver.md)**: The `fd_siphash13.c` file in the `firedancer` codebase implements a modified version of the SipHash-1-3 cryptographic hash function, providing initialization, data appending, and finalization functionalities.
- **[fd_siphash13.h](siphash13/fd_siphash13.h.driver.md)**: The `fd_siphash13.h` file provides APIs for implementing the SipHash1-3 cryptographic hash function, including initialization, data appending, and finalization functions.
- **[fuzz_siphash13.c](siphash13/fuzz_siphash13.c.driver.md)**: The `fuzz_siphash13.c` file in the `firedancer` codebase implements a fuzz testing harness for the SipHash-1-3 algorithm, ensuring the correctness of both standard and fast hashing methods.
- **[Local.mk](siphash13/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase specifies build instructions for the `siphash13` component, including header and object file additions, unit test creation and execution, and conditional fuzz test setup.
- **[test_siphash13.c](siphash13/test_siphash13.c.driver.md)**: The `test_siphash13.c` file in the `firedancer` codebase contains a test suite for the SipHash-1-3 algorithm, including validation against predefined test vectors and benchmarking of its performance.
