
## Files
- **[fd_secp256k1.c](secp256k1/fd_secp256k1.c.driver.md)**: The `fd_secp256k1.c` file implements a function to recover a public key from a message hash and a recoverable ECDSA signature using the secp256k1 library.
- **[fd_secp256k1.h](secp256k1/fd_secp256k1.h.driver.md)**: The `fd_secp256k1.h` file provides APIs for secp256k1 signature computations, specifically including a function to recover a public key from a recoverable SECP256K1 signature.
- **[fuzz_secp256k1_recover.c](secp256k1/fuzz_secp256k1_recover.c.driver.md)**: The `fuzz_secp256k1_recover.c` file in the `firedancer` codebase implements a fuzzing test for the secp256k1 public key recovery function, verifying the ability to recover and match public keys from given message and signature inputs.
- **[Local.mk](secp256k1/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase configures the build process for secp256k1-related headers, objects, unit tests, and fuzz tests, with conditional inclusion based on the presence of the `libsecp256k1` library.
- **[test_secp256k1.c](secp256k1/test_secp256k1.c.driver.md)**: The `test_secp256k1.c` file in the `firedancer` codebase contains tests for the `fd_secp256k1_recover` function, including correctness checks against known public keys and performance benchmarks.
