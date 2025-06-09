
## Files
- **[fd_tempo.c](tempo/fd_tempo.c.driver.md)**: The `fd_tempo.c` file in the `firedancer` codebase implements functions for modeling and measuring the performance of wallclock and tickcount operations, as well as setting and retrieving the ticks per nanosecond ratio.
- **[fd_tempo.h](tempo/fd_tempo.h.driver.md)**: The `fd_tempo.h` file in the `firedancer` codebase provides APIs for measuring time and tick intervals, including models for wallclock and tickcount, functions for setting and estimating tick rates, and utilities for managing timing intervals in asynchronous processes.
- **[Local.mk](tempo/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase specifies the headers, object files, and unit tests for the `tempo` component, including the `fd_tempo.h` header and `test_tempo` unit test.
- **[test_tempo.c](tempo/test_tempo.c.driver.md)**: The `test_tempo.c` file in the `firedancer` codebase contains a series of tests for the `fd_tempo` module, including wallclock and tickcount models, tick per nanosecond calculations, and various asynchronous timing functions.
