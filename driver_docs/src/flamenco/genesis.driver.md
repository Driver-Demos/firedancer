
## Files
- **[fd_genesis_create.c](genesis/fd_genesis_create.c.driver.md)**: The `fd_genesis_create.c` file in the `firedancer` codebase implements the creation of a Solana genesis block, configuring various parameters such as fee rate, rent, inflation, and accounts, and encoding the genesis data into a binary format.
- **[fd_genesis_create.h](genesis/fd_genesis_create.h.driver.md)**: The `fd_genesis_create.h` file provides a tool for creating Solana genesis blobs, which are used to bootstrap a Solana ledger, and includes a structure for specifying genesis creation options.
- **[Local.mk](genesis/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase specifies build instructions and conditional unit test execution for the `fd_genesis_create` and `fd_flamenco` components, contingent on the presence of `FD_HAS_INT128` and `FD_HAS_HOSTED` flags.
- **[test_genesis_create.c](genesis/test_genesis_create.c.driver.md)**: The `test_genesis_create.c` file in the `firedancer` codebase tests the creation of a genesis block with various configurations and options, including account funding and feature gates, while managing logging levels and memory buffers.
