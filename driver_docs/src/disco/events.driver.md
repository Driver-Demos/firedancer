
## Files
- **[fd_circq.c](events/fd_circq.c.driver.md)**: The `fd_circq.c` file implements a circular queue data structure with functions for creating, joining, leaving, deleting, pushing, and popping messages, as well as verifying and evicting messages within the queue.
- **[fd_circq.h](events/fd_circq.h.driver.md)**: The `fd_circq.h` file defines a fixed-size circular buffer structure for storing a queue of messages, with operations to push and pop messages while managing metadata within the buffer itself.
- **[Local.mk](events/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase specifies the headers, object files, and unit tests for the `fd_circq` and related components within the `disco/events` directory.
- **[test_circq.c](events/test_circq.c.driver.md)**: The `test_circq.c` file contains a series of test functions to validate the functionality of a circular queue implementation in the `firedancer` codebase.
