
## Files
- **[fd_asan.c](sanitize/fd_asan.c.driver.md)**: The `fd_asan.c` file in the `firedancer` codebase implements address sanitization functionality, including watching and checking memory addresses for poisoning status.
- **[fd_asan.h](sanitize/fd_asan.h.driver.md)**: The `fd_asan.h` file in the `firedancer` codebase provides an interface for integrating AddressSanitizer (ASan) functionality to track and manage memory regions, allowing for the detection of out-of-bounds errors in memory accesses.
- **[fd_backtrace.c](sanitize/fd_backtrace.c.driver.md)**: The `fd_backtrace.c` file provides a function to print a backtrace to a specified file descriptor using the `execinfo` library.
- **[fd_backtrace.h](sanitize/fd_backtrace.h.driver.md)**: The `fd_backtrace.h` file declares a function for printing a backtrace to a specified file descriptor.
- **[fd_fuzz.h](sanitize/fd_fuzz.h.driver.md)**: The `fd_fuzz.h` file in the `firedancer` codebase provides a header for fuzz testing utilities, including a function prototype for mutating data using LLVM's fuzzer.
- **[fd_fuzz_stub.c](sanitize/fd_fuzz_stub.c.driver.md)**: The `fd_fuzz_stub.c` file in the `firedancer` codebase provides a stub fuzz harness for build targets without a fuzz engine, allowing regression testing against existing input files but not actual fuzz exploration.
- **[fd_msan.h](sanitize/fd_msan.h.driver.md)**: The `fd_msan.h` file in the `firedancer` codebase provides functions for marking memory as uninitialized or initialized and checking memory initialization status, leveraging MemorySanitizer (MSan) to detect uninitialized memory access.
- **[fd_sanitize.h](sanitize/fd_sanitize.h.driver.md)**: The `fd_sanitize.h` file in the `firedancer` codebase provides APIs for compiler sanitizers, such as AddressSanitizer, to detect errors like out-of-bounds memory accesses and undefined behavior.
- **[Local.mk](sanitize/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase is a makefile that manages the inclusion of headers, creation of a library, and conditional compilation flags for sanitization utilities.
- **[test_fuzz_canary_canary.c](sanitize/test_fuzz_canary_canary.c.driver.md)**: The `test_fuzz_canary_canary.c` file contains a canary function intended to be detected by a canary finder as a test of the finder's effectiveness.
