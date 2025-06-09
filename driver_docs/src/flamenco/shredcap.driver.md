
## Files
- **[fd_shredcap.c](shredcap/fd_shredcap.c.driver.md)**: The `fd_shredcap.c` file in the `firedancer` codebase implements functions for managing and verifying the ingestion of data from RocksDB into a capture format, including creating and verifying manifest and bank hash files, and populating a blockstore with the captured data.
- **[fd_shredcap.h](shredcap/fd_shredcap.h.driver.md)**: The `fd_shredcap.h` file defines the structure and functions for the `fd_shredcap` capture format, which is used to store and manage Solana ledger shreds for testing and replay purposes, including manifest and bank hash management.
- **[Local.mk](shredcap/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase conditionally adds headers and objects related to `fd_shredcap` and `fd_flamenco` if `FD_HAS_ROCKSDB` is defined.
