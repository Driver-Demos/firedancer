
## Files
- **[fd_scratch.c](scratch/fd_scratch.c.driver.md)**: The `fd_scratch.c` file in the `firedancer` codebase implements thread-local scratch memory management functions and a virtual function table for memory allocation and deallocation.
- **[fd_scratch.h](scratch/fd_scratch.h.driver.md)**: The `fd_scratch.h` file in the `firedancer` codebase provides APIs for high-performance scratch pad memory allocation, including functions for managing memory frames, allocations, and alignment, with support for both simple and complex temporary memory usage scenarios.
- **[Local.mk](scratch/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase is a makefile script that adds headers and objects for `fd_scratch`, creates a unit test for `test_scratch`, and runs the unit test.
- **[test_scratch.c](scratch/test_scratch.c.driver.md)**: The `test_scratch.c` file in the `firedancer` codebase contains a comprehensive test suite for validating the functionality and safety of the scratch memory allocation system, including alignment, allocation, deallocation, and memory safety checks.
