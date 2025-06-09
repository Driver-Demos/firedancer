## Folders
- **[test](restart/test.driver.md)**: The `test` folder in the `firedancer` codebase contains shell scripts for restarting and configuring the Agave validator and the Firedancer application in wen-restart mode.

## Files
- **[fd_restart.c](restart/fd_restart.c.driver.md)**: The `fd_restart.c` file in the `firedancer` codebase implements functions for managing the restart process of a distributed system, including handling gossip messages, finding the heaviest fork, and managing checkpoints.
- **[fd_restart.h](restart/fd_restart.h.driver.md)**: The `fd_restart.h` file in the `firedancer` codebase provides the implementation of Solana's SIMD-0046 protocol, known as wen-restart, which automates optimistic cluster restarts, including definitions, parameters, and functions for managing the restart state and processing gossip messages.
- **[fd_restart_tile.c](restart/fd_restart_tile.c.driver.md)**: The `fd_restart_tile.c` file in the `firedancer` codebase implements the functionality for managing the restart process of a tile, including initialization, handling gossip and store messages, and verifying the heaviest fork in a distributed system.
- **[Local.mk](restart/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase specifies the inclusion of headers and object files for the `fd_restart` and `fd_restart_tile` components when both `FD_HAS_INT128` and `FD_HAS_SSE` are defined.
