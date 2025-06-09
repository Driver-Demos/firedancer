
## Files
- **[fd_hmac.c](hmac/fd_hmac.c.driver.md)**: The `fd_hmac.c` file in the `firedancer` codebase implements HMAC functionality using SHA-256, SHA-384, and SHA-512 hash algorithms by including a template file `fd_hmac_tmpl.c` with different hash configurations.
- **[fd_hmac.h](hmac/fd_hmac.h.driver.md)**: The `fd_hmac.h` file in the `firedancer` codebase provides APIs for computing HMAC digests using SHA-256, SHA-384, and SHA-512 algorithms for message authentication.
- **[fd_hmac_tmpl.c](hmac/fd_hmac_tmpl.c.driver.md)**: The `fd_hmac_tmpl.c` file in the `firedancer` codebase defines a template for implementing HMAC using a specified hash function, requiring definitions for the hash algorithm, its output size, and block size.
- **[fuzz_hmac.c](hmac/fuzz_hmac.c.driver.md)**: The `fuzz_hmac.c` file in the `firedancer` codebase implements a fuzz testing harness for HMAC functions using SHA-256, SHA-384, and SHA-512 algorithms.
- **[Local.mk](hmac/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase defines build and test configurations for the HMAC component, including header and object file additions, unit test creation, and conditional fuzz test setup.
- **[test_hmac.c](hmac/test_hmac.c.driver.md)**: The `test_hmac.c` file in the `firedancer` codebase contains test cases for verifying the correctness of HMAC implementations using SHA-256, SHA-384, and SHA-512 algorithms against predefined test vectors.
