
## Files
- **[fd_poh_tile.c](poh/fd_poh_tile.c.driver.md)**: The `fd_poh_tile.c` file in the `firedancer` codebase implements the Proof of History (PoH) mechanism for the Solana blockchain, detailing how leader slots are managed, how hashes are computed and published, and how the system handles leader transitions and slot resets.
- **[Local.mk](poh/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase conditionally adds objects to the build process for `fd_poh_tile` and `fd_discof` if `FD_HAS_SSE` is defined.
