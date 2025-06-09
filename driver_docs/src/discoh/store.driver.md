
## Files
- **[fd_store_tile.c](store/fd_store_tile.c.driver.md)**: The `fd_store_tile.c` file in the `firedancer` codebase implements the initialization and management of a storage context for processing and inserting data fragments into a blockstore, including handling memory alignment and footprint calculations.
- **[Local.mk](store/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase conditionally adds object files `fd_store_tile` and `fd_discoh` to the build if `FD_HAS_SSE` is defined.
