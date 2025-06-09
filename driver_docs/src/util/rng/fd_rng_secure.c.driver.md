# Purpose
This C source code file provides a platform-specific implementation of a secure random number generator function, [`fd_rng_secure`](#fd_rng_secure). The function is designed to fill a buffer with cryptographically secure random bytes, and it adapts its implementation based on the operating system. For Linux and FreeBSD systems, it utilizes the `getrandom` system call to generate random data, ensuring that the operation is secure and blocking until sufficient entropy is available. On Apple systems, it uses the `CCRandomGenerateBytes` function from the CommonCrypto library to achieve the same goal. If the code is compiled on an unsupported platform, the function logs a warning and returns `NULL`, indicating that secure random number generation is not available.

The file includes necessary headers for logging and platform-specific random number generation functions. It uses conditional compilation to select the appropriate implementation based on the detected operating system. The function is marked with attributes to indicate that its return value should not be ignored, emphasizing the importance of checking for errors. This code is intended to be part of a larger system, likely as a utility function within a library, providing a consistent interface for secure random number generation across different platforms. The use of logging and error handling ensures that any issues during random number generation are reported, aiding in debugging and system reliability.
# Imports and Dependencies

---
- `fd_rng.h`
- `../log/fd_log.h`
- `assert.h`
- `errno.h`
- `sys/random.h`
- `CommonCrypto/CommonRandom.h`


# Functions

---
### fd\_rng\_secure<!-- {{#callable:fd_rng_secure}} -->
The `fd_rng_secure` function generates cryptographically secure random bytes and stores them in a provided buffer, with platform-specific implementations for Linux, FreeBSD, and Apple, and a fallback for unsupported platforms.
- **Inputs**:
    - `d`: A pointer to the buffer where the random bytes will be stored.
    - `sz`: The number of random bytes to generate and store in the buffer.
- **Control Flow**:
    - On Linux or FreeBSD, it uses the `getrandom` system call to fill the buffer with random bytes, logging a warning and returning NULL if the call fails.
    - On Apple platforms, it uses `CCRandomGenerateBytes` to fill the buffer, logging a warning and returning NULL if the function does not succeed.
    - On unsupported platforms, it logs a warning indicating that the function is not supported and returns NULL.
- **Output**: A pointer to the buffer `d` if successful, or NULL if the operation fails or is unsupported.


