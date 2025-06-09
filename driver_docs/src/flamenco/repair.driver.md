
## Files
- **[fd_repair.c](repair/fd_repair.c.driver.md)**: The `fd_repair.c` file in the `firedancer` codebase implements functionality for managing and repairing peer connections, including setting configurations, handling inflight requests, and managing peer statistics and cache files.
- **[fd_repair.h](repair/fd_repair.h.driver.md)**: The `fd_repair.h` file in the `firedancer` codebase defines structures, constants, and functions for managing a repair protocol, including handling peer addresses, inflight requests, and metrics for network packet repairs.
- **[fd_repair_tool.c](repair/fd_repair_tool.c.driver.md)**: The `fd_repair_tool.c` file in the `firedancer` codebase implements a network repair tool that handles communication and data repair processes, including sending and receiving packets, resolving host addresses, and managing repair configurations.
- **[Local.mk](repair/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase is a makefile that conditionally adds headers and objects for `fd_repair` and `fd_flamenco` based on the presence of `FD_HAS_INT128` and optionally includes a binary target for `fd_repair_tool` if `FD_HAS_HOSTED` is defined.
