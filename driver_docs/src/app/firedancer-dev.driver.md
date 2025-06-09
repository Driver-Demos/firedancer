## Folders
- **[commands](firedancer-dev/commands.driver.md)**: The `commands` folder in the `firedancer` codebase contains C files that implement various commands for simulating, benchmarking, and managing network topologies and protocols, including backtesting, development, gossip, and simulation functionalities.
- **[config](firedancer-dev/config.driver.md)**: The `config` folder in the `firedancer` codebase contains TOML files that provide various configuration settings for the Firedancer application, including layout, gossip, blockstore, tiles, consensus, paths, logging, memory management, and runtime limits.

## Files
- **[Local.mk](firedancer-dev/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase defines the build configuration for the `firedancer-dev` application, including dependencies and conditions for enabling the build based on system capabilities.
- **[main.c](firedancer-dev/main.c.driver.md)**: The `main.c` file in the `firedancer` codebase initializes and runs the Firedancer application by setting up various topology callbacks, configuration stages, tiles, and actions, and then calling the `fd_dev_main` function with the necessary parameters.
