
## Files
- **[fd_fseq.c](fseq/fd_fseq.c.driver.md)**: The `fd_fseq.c` file in the `firedancer` codebase implements functions for managing a shared memory region that contains a sequence number, including creating, joining, leaving, and deleting the sequence.
- **[fd_fseq.h](fseq/fd_fseq.h.driver.md)**: The `fd_fseq.h` file in the `firedancer` codebase provides APIs for managing sequence numbers as persistent shared memory objects, primarily for flow control in communications, including functions for creating, joining, leaving, querying, and updating these sequence numbers.
- **[Local.mk](fseq/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase specifies the headers, object files, and unit tests for the `fd_fseq` and `fd_tango` components, and includes a command to run the `test_fseq` unit test.
- **[test_fseq.c](fseq/test_fseq.c.driver.md)**: The `test_fseq.c` file in the `firedancer` codebase contains a series of unit tests for the `fd_fseq` functionality, including alignment checks, memory allocation, and sequence update operations.
