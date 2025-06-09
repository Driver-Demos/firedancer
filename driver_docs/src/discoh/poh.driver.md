
## Files
- **[fd_poh_tile.c](poh/fd_poh_tile.c.driver.md)**: The `fd_poh_tile.c` file in the `firedancer` codebase implements the Proof of History (PoH) mechanism for the Solana blockchain, detailing how leader slots are managed, how hashes are computed and verified, and how transactions are processed and published within the network.
- **[Local.mk](poh/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase conditionally adds object files `fd_poh_tile` and `fd_discoh` to the build if `FD_HAS_SSE` is defined.
