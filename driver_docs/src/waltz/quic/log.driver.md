
## Files
- **[fd_quic_log.c](log/fd_quic_log.c.driver.md)**: The `fd_quic_log.c` file in the `firedancer` codebase implements functions for managing QUIC log buffers, including creating, deleting, and joining transmit and receive logs.
- **[fd_quic_log.h](log/fd_quic_log.h.driver.md)**: The `fd_quic_log.h` file in the `firedancer` codebase defines the ABI for QUIC shared memory logging, including structures for log headers and error handling, as well as event identifiers for connection and allocation failure events.
- **[fd_quic_log_tx.h](log/fd_quic_log_tx.h.driver.md)**: The `fd_quic_log_tx.h` file provides internal APIs for high-performance logging of events in the Firedancer project, specifically focusing on the producer-side operations for managing and writing to shared memory log buffers.
- **[fd_quic_log_user.h](log/fd_quic_log_user.h.driver.md)**: The `fd_quic_log_user.h` file defines an ABI for extracting high-frequency logs from an `fd_quic` instance, providing structures and functions for consumer-side log access without offering APIs for writing logs.
- **[Local.mk](log/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase specifies header and object files for the QUIC log component and includes a commented-out line for a unit test.
