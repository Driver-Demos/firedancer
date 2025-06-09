
## Files
- **[fd_cnc.c](cnc/fd_cnc.c.driver.md)**: The `fd_cnc.c` file in the `firedancer` codebase provides functions for managing and interacting with a command-and-control (CNC) structure, including operations for creating, joining, leaving, deleting, and opening command sessions, as well as handling signals and errors.
- **[fd_cnc.h](cnc/fd_cnc.h.driver.md)**: The `fd_cnc.h` file in the `firedancer` codebase provides APIs for managing out-of-band command-and-control signals for high-performance application threads, including state transitions, signal handling, and memory management for `fd_cnc_t` objects.
- **[Local.mk](cnc/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase specifies the headers, objects, and unit tests for the `fd_cnc` and `fd_tango` components.
- **[test_cnc.c](cnc/test_cnc.c.driver.md)**: The `test_cnc.c` file in the `firedancer` codebase contains a unit test for the command and control (CNC) system, verifying its functionality through various signal handling and state transitions, including booting, running, and halting states.
