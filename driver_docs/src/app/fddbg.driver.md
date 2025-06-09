
## Files
- **[Local.mk](fddbg/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase defines a makefile rule to build the `fddbg` binary using `main` and `fd_util` if both `FD_HAS_HOSTED` and `FD_HAS_LINUX` are defined.
- **[main.c](fddbg/main.c.driver.md)**: The `main.c` file in the `firedancer` codebase implements a wrapper to enable debugging with elevated capabilities in VS Code by managing process capabilities and executing GDB with the necessary permissions.
