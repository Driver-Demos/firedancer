
## Files
- **[fd_bank_abi.c](bank/fd_bank_abi.c.driver.md)**: The `fd_bank_abi.c` file in the `firedancer` codebase defines and implements various data structures and functions for handling and processing transaction data, including address lookups and message handling, within a bank application interface.
- **[fd_bank_abi.h](bank/fd_bank_abi.h.driver.md)**: The `fd_bank_abi.h` file in the `firedancer` codebase defines structures and functions for handling ABI-compatible transactions, including initialization, address lookup resolution, and sidecar data management for `SanitizedTransaction` objects.
- **[fd_bank_tile.c](bank/fd_bank_tile.c.driver.md)**: The `fd_bank_tile.c` file in the `firedancer` codebase implements a banking tile that processes transactions, handles microblocks and bundles, and manages transaction metrics and rebates.
- **[Local.mk](bank/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase specifies conditional inclusion of headers and objects for the `fd_bank_abi` and `fd_bank_tile` components based on the presence of atomic operations, 128-bit integers, and SSE support.
