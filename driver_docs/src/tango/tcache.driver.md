
## Files
- **[fd_tcache.c](tcache/fd_tcache.c.driver.md)**: The `fd_tcache.c` file in the `firedancer` codebase provides functions for managing a transactional cache, including creating, joining, leaving, and deleting cache instances with alignment and validation checks.
- **[fd_tcache.h](tcache/fd_tcache.h.driver.md)**: The `fd_tcache.h` file in the `firedancer` codebase defines a cache system for deduplicating traffic by storing and managing a history of unique 64-bit tags, optimized for performance in memory-efficient environments.
- **[Local.mk](tcache/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase specifies the headers, objects, and unit tests for the `fd_tcache` component, and includes commands to build and run the `test_tcache` unit test.
- **[test_tcache.c](tcache/test_tcache.c.driver.md)**: The `test_tcache.c` file in the `firedancer` codebase contains unit tests for the `tcache` component, verifying its alignment, footprint, mapping, querying, removal, reset, and insertion functionalities, as well as benchmarking its performance.
