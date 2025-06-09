
## Files
- **[fd_bank_abi.c](bank/fd_bank_abi.c.driver.md)**: The `fd_bank_abi.c` file in the `firedancer` codebase contains stub implementations for various bank-related functions, all of which currently log an error message and return without performing any operations.
- **[fd_bank_abi.h](bank/fd_bank_abi.h.driver.md)**: The `fd_bank_abi.h` file in the `firedancer` codebase defines constants and function prototypes for handling bank transactions, including resolving address lookup tables and managing account data.
- **[Local.mk](bank/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase specifies conditional inclusion of headers and objects for `fd_bank_abi` and `fd_discof` based on the presence of atomic operations, 128-bit integers, and SSE support.
