
## Files
- **[fd_fibre.c](fibre/fd_fibre.c.driver.md)**: The `fd_fibre.c` file in the `firedancer` codebase implements cooperative threading using fibers, including functions for fiber initialization, scheduling, context switching, and inter-fiber communication through pipes.
- **[fd_fibre.h](fibre/fd_fibre.h.driver.md)**: The `fd_fibre.h` file in the `firedancer` codebase defines the structures and functions for managing fibres, including initialization, execution, scheduling, and inter-fibre communication through pipes.
- **[Local.mk](fibre/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase is a makefile script that conditionally builds and tests the `fd_fibre` library and its unit tests if both `FD_HAS_HOSTED` and `FD_HAS_LINUX` are defined.
- **[test_fibre.c](fibre/test_fibre.c.driver.md)**: The `test_fibre.c` file in the `firedancer` codebase contains tests for the `fd_fibre` library, including functions to test fibre scheduling, waiting mechanisms, and pipe communication between producer and consumer fibres.
