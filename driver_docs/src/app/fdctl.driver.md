## Folders
- **[commands](fdctl/commands.driver.md)**: The `commands` folder in the `firedancer` codebase contains source and header files for implementing and declaring functions related to starting and configuring the Agave component of a Firedancer validator.
- **[config](fdctl/config.driver.md)**: The `config` folder in the `firedancer` codebase contains various TOML configuration files tailored for benchmarking different CPU architectures, setting up development environments, and configuring Solana testnet environments.

## Files
- **[.gitignore](fdctl/.gitignore.driver.md)**: The `.gitignore` file in the `firedancer/src/app/fdctl/` directory specifies that `version.h` and `version2.h` should be ignored by Git.
- **[config.c](fdctl/config.driver.md.c)**: The `config.c` file in the `firedancer` codebase imports a default configuration from a TOML file using the `FD_IMPORT_BINARY` macro.
- **[config.h](fdctl/config.driver.md.h)**: The `config.h` file in the `firedancer` codebase declares external constants for the default configuration and its size for the `fdctl` application.
- **[Local.mk](fdctl/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase is a Makefile that manages versioning, builds, and dependencies for the `fdctl` application, including handling Rust toolchain updates and ensuring submodules are up to date.
- **[main.c](fdctl/main.c.driver.md)**: The `main.c` file in the `firedancer` codebase sets up the main application logic for the `fdctl` binary, including configuration stages, topology callbacks, tile execution, and available actions.
- **[topology.c](fdctl/topology.c.driver.md)**: The `topology.c` file in the `firedancer` codebase is responsible for initializing and configuring the network topology, including setting up tiles, links, and CPU affinities based on the provided configuration.
- **[topology.h](fdctl/topology.h.driver.md)**: The `topology.h` file in the `firedancer` codebase declares a function for initializing topology configurations.
- **[version.c](fdctl/version.c.driver.md)**: The `version.c` file in the `firedancer` codebase defines versioning information for the `fdctl` application, including major, minor, and patch versions, as well as commit reference details.
- **[version.mk](fdctl/version.mk.driver.md)**: The `version.mk` file in the `firedancer` codebase specifies the major, minor, and patch version numbers for the `fdctl` application.
- **[with-version.mk](fdctl/with-version.mk.driver.md)**: The `with-version.mk` file in the `firedancer` codebase defines and exports versioning information for the Firedancer application, including major, minor, and patch versions, as well as the current commit hash.
