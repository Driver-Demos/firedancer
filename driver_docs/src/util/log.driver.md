
## Files
- **[fd_dtrace.h](log/fd_dtrace.h.driver.md)**: The `fd_dtrace.h` file in the `firedancer` codebase provides conditional wrappers for software-defined trace points, utilizing system trace capabilities if available on Linux.
- **[fd_log.c](log/fd_log.c.driver.md)**: The `fd_log.c` file in the `firedancer` codebase provides a comprehensive logging utility that includes functionalities for setting application and thread identifiers, managing log levels, handling signals, and formatting log messages with optional colorization and deduplication.
- **[fd_log.h](log/fd_log.h.driver.md)**: The `fd_log.h` file in the `firedancer` codebase provides a comprehensive logging system that supports multiple log levels, hexdump capabilities, and runtime configuration, producing both ephemeral and permanent log message streams for applications.
- **[Local.mk](log/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase specifies the headers, object files, and unit tests for the logging utility component.
- **[test_log.c](log/test_log.c.driver.md)**: The `test_log.c` file in the `firedancer` codebase is a comprehensive test suite for the logging functionality, including assertions, log level settings, hexdump logging, and wallclock tests, ensuring the logging system behaves as expected under various conditions.
