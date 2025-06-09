## Folders
- **[config](firedancer/config.driver.md)**: The `config` folder in the `firedancer` codebase contains the `default.toml` file, which provides detailed configuration settings for a Firedancer instance, covering aspects such as user permissions, file paths, logging, network interfaces, tile management, and development options.

## Files
- **[.gitignore](firedancer/.gitignore.driver.md)**: The `.gitignore` file in the `firedancer` codebase specifies that `version.h` and `version2.h` should be ignored by Git.
- **[callbacks.c](firedancer/callbacks.c.driver.md)**: The `callbacks.c` file in the `firedancer` codebase defines callback functions for various components such as `runtime_pub`, `blockstore`, `fec_sets`, `txncache`, and `exec_spad`, handling their footprint, alignment, and initialization processes.
- **[config.c](firedancer/config.driver.md.c)**: The `config.c` file in the `firedancer` codebase imports a default configuration from a TOML file using the `FD_IMPORT_BINARY` macro.
- **[config.h](firedancer/config.driver.md.h)**: The `config.h` file in the `firedancer` codebase declares external variables for the default configuration and its size, and includes a utility header.
- **[Local.mk](firedancer/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase is a makefile that manages the generation and updating of version headers and the conditional compilation of the `firedancer` application based on various feature flags.
- **[main.c](firedancer/main.c.driver.md)**: The `main.c` file in the `firedancer` codebase initializes the Firedancer application by setting up topology callbacks, configuration stages, tiles, and actions, and includes a main function to execute the application with default configurations.
- **[topology.c](firedancer/topology.c.driver.md)**: The `topology.c` file in the `firedancer` codebase is responsible for setting up and initializing the network topology, including configuring various tiles, workspaces, and links for the Firedancer application.
- **[topology.h](firedancer/topology.h.driver.md)**: The `topology.h` file declares a function for initializing topology configurations in the Firedancer application.
- **[version.c](firedancer/version.c.driver.md)**: The `version.c` file in the `firedancer` codebase defines versioning information for the application, including major, minor, and patch versions, as well as commit reference strings and numbers.
- **[version.mk](firedancer/version.mk.driver.md)**: The `version.mk` file in the `firedancer` codebase defines and exports versioning information and the current Git commit hash for the Firedancer application.
