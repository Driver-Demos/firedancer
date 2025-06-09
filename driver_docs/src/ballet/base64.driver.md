
## Files
- **[fd_base64.c](base64/fd_base64.c.driver.md)**: The `fd_base64.c` file in the `firedancer` codebase provides functions for encoding and decoding data using the Base64 encoding scheme.
- **[fd_base64.h](base64/fd_base64.h.driver.md)**: The `fd_base64.h` file provides functions for encoding and decoding data between binary and Base64 format, using the standard Base64 alphabet with padding as specified in RFC 4648.
- **[fuzz_base64_dec.c](base64/fuzz_base64_dec.c.driver.md)**: The `fuzz_base64_dec.c` file implements a fuzz testing harness to ensure the safety of Base64 decoding against untrusted inputs in the `firedancer` codebase.
- **[fuzz_base64_enc.c](base64/fuzz_base64_enc.c.driver.md)**: The `fuzz_base64_enc.c` file in the `firedancer` codebase implements a fuzz test to verify that decoding the result of encoding a data input with Base64 returns the original data, ensuring the encode-decode process is an identity function.
- **[Local.mk](base64/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase specifies the build configuration for the base64 module, including headers, object files, unit tests, and conditional fuzz tests.
- **[test_base64.c](base64/test_base64.c.driver.md)**: The `test_base64.c` file in the `firedancer` codebase contains unit tests and benchmarks for verifying the correctness and performance of Base64 encoding and decoding functions.
