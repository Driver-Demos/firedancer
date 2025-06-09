
## Files
- **[fd_genesis_cluster.c](genesis/fd_genesis_cluster.c.driver.md)**: The `fd_genesis_cluster.c` file in the `firedancer` codebase provides functions to identify and name blockchain clusters based on their genesis hash values.
- **[fd_genesis_cluster.h](genesis/fd_genesis_cluster.h.driver.md)**: The `fd_genesis_cluster.h` file defines macros for different cluster types and provides functions to identify a cluster from a base58 encoded hash and to retrieve the human-readable name of a cluster in the `firedancer` codebase.
- **[Local.mk](genesis/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase specifies conditional inclusion of headers and objects related to `fd_genesis_cluster` and `fd_disco` based on the presence of `FD_HAS_INT128`.
