
## Files
- **[fd_pktgen_tile.c](pktgen/fd_pktgen_tile.c.driver.md)**: The `fd_pktgen_tile.c` file in the `firedancer` codebase implements a packet generator that floods a network tile with small outgoing Ethernet frames, each containing a unique sequence number to prevent network interface controllers from halting transmission due to repeated payloads.
- **[pktgen.c](pktgen/pktgen.c.driver.md)**: The `pktgen.c` file in the `firedancer` codebase implements a packet generator application that configures network topology, manages CPU affinity, and provides a command-line interface for controlling packet generation and monitoring network metrics.
- **[pktgen.h](pktgen/pktgen.h.driver.md)**: The `pktgen.h` file in the `firedancer` codebase declares an external action, `fd_action_pktgen`, for packet generation functionality.
