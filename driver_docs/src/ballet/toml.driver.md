
## Files
- **[fd_toml.c](toml/fd_toml.c.driver.md)**: The `fd_toml.c` file in the `firedancer` codebase implements a backtracking recursive descent parser for TOML files, handling various data types and structures, and providing error handling and memory management functionalities.
- **[fd_toml.h](toml/fd_toml.h.driver.md)**: The `fd_toml.h` file in the `firedancer` codebase provides APIs for parsing TOML configuration files, including error handling and mapping TOML types to `fd_pod` types, while noting certain deviations from the TOML specification.
- **[fuzz_toml.c](toml/fuzz_toml.c.driver.md)**: The `fuzz_toml.c` file in the `firedancer` codebase implements a fuzz testing interface for parsing TOML data using the LLVM fuzzer.
- **[Local.mk](toml/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase specifies the headers, objects, and conditional fuzz test setup for the TOML component in the `ballet` module.
