
## Files
- **[fd_gossip.c](gossip/fd_gossip.c.driver.md)**: The `fd_gossip.c` file in the `firedancer` codebase implements a gossip protocol for managing network communication between nodes, including functionalities for sending and receiving messages, handling pings and pongs, managing peer connections, and maintaining data structures for tracking network state and message statistics.
- **[fd_gossip.h](gossip/fd_gossip.h.driver.md)**: The `fd_gossip.h` file in the `firedancer` codebase defines the structures, constants, and functions necessary for implementing a gossip protocol, including configuration, address management, message handling, and metrics collection.
- **[fd_gossip_spy.c](gossip/fd_gossip_spy.c.driver.md)**: The `fd_gossip_spy.c` file in the `firedancer` codebase implements a gossip protocol client that interacts with a Solana network, handling network communication, data processing, and signal management.
- **[Local.mk](gossip/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase defines build rules for the `fd_gossip` component, including headers, objects, and binaries, conditional on the presence of `FD_HAS_HOSTED` and `FD_HAS_INT128`.
