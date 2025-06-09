## Folders
- **[commands](fddev/commands.driver.md)**: The `commands` folder in the `firedancer` codebase contains files and a subfolder for managing blockstore configuration and implementing commands for testing validator TPS benchmarks and spawning development validator threads.
- **[tests](fddev/tests.driver.md)**: The `tests` folder in the `firedancer` codebase contains a test suite implementation for the `fddev` application, focusing on configuration, workspace setup, readiness, and device management.

## Files
- **[dev1.c](fddev/dev1.c.driver.md)**: The `dev1.c` file in the `firedancer` codebase defines the `dev1` command, which is responsible for configuring and running a single tile in a development environment, handling signals, and managing command-line arguments.
- **[dev1.h](fddev/dev1.h.driver.md)**: The `dev1.h` file in the `firedancer` codebase declares an external action, `fd_action_dev1`, and includes a shared configuration header.
- **[Local.mk](fddev/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase defines build and run targets for the `fddev` application, including integration tests and conditional compilation based on system capabilities.
- **[main.c](fddev/main.c.driver.md)**: The `main.c` file in the `firedancer` codebase contains the entry point for the application, calling the `fd_dev_main` function with command-line arguments and default configuration settings.
- **[main.h](fddev/main.h.driver.md)**: The `main.h` file in the `firedancer` codebase defines constants, callback arrays, configuration stages, tile operations, and actions for the `fddev` application.
