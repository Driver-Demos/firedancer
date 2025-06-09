
## Files
- **[fd_hex.c](hex/fd_hex.c.driver.md)**: The `fd_hex.c` file in the `firedancer` codebase provides functions for encoding and decoding hexadecimal strings, including a lookup table for encoding and a function for converting characters to their hexadecimal values.
- **[fd_hex.h](hex/fd_hex.h.driver.md)**: The `fd_hex.h` file provides functions for encoding binary data to hexadecimal and decoding hexadecimal data back to binary, with case-insensitive decoding.
- **[fuzz_hex.c](hex/fuzz_hex.c.driver.md)**: The `fuzz_hex.c` file in the `firedancer` codebase implements a fuzz testing utility for validating and decoding hexadecimal strings, ensuring they are correctly encoded and meet specified size constraints.
- **[Local.mk](hex/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase specifies the headers, objects, and conditional fuzz test setup for the `fd_hex` and `fd_ballet` components.
