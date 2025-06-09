## Folders
- **[configure](commands/configure.driver.md)**: The `configure` folder in the `firedancer` codebase contains source files that implement and define the command-line interface and various system configurations necessary for running Firedancer, including network device settings, huge page filesystems, CPU hyperthreading, and kernel parameters.
- **[monitor](commands/monitor.driver.md)**: The `monitor` folder in the `firedancer` codebase contains source files and a generated header for implementing a terminal-based monitoring tool, utility functions for data formatting and terminal output, and security policies for monitoring system calls and process supervision.
- **[run](commands/run.driver.md)**: The `run` folder in the `firedancer` codebase contains source files and security policies for managing the initialization, configuration, and execution of the Firedancer application, including process supervision and seccomp filter policies.

## Files
- **[help.c](commands/help.c.driver.md)**: The `help.c` file in the `firedancer` codebase implements a command function that displays usage information and available subcommands for the application.
- **[help.h](commands/help.h.driver.md)**: The `help.h` file declares the function `help_cmd_fn` and the external variable `fd_action_help` for handling help commands in the `firedancer` application.
- **[keys.c](commands/keys.c.driver.md)**: The `keys.c` file in the `firedancer` codebase provides functionality for generating new keypairs and printing public keys, with command handling for these operations.
- **[keys.h](commands/keys.h.driver.md)**: The `keys.h` file in the `firedancer` codebase declares functions and an external action related to command handling for keys, including argument parsing and command execution.
- **[mem.c](commands/mem.c.driver.md)**: The `mem.c` file defines a command function `mem_cmd_fn` that prints workspace memory and tile topology information, and registers it as an action named "mem" in the `firedancer` codebase.
- **[mem.h](commands/mem.h.driver.md)**: The `mem.h` file in the `firedancer` codebase declares a function prototype for `mem_cmd_fn` and an external action `fd_action_mem` related to memory commands.
- **[netconf.c](commands/netconf.c.driver.md)**: The `netconf.c` file in the `firedancer` codebase implements a command function to print network configuration details, including interfaces, IPv4 routes, and neighbor tables.
- **[netconf.h](commands/netconf.h.driver.md)**: The `netconf.h` file declares a function for network configuration commands and an external action related to network configuration in the Firedancer application.
- **[ready.c](commands/ready.c.driver.md)**: The `ready.c` file in the `firedancer` codebase implements a command function that waits for all non-agave tiles to be ready by checking their status and logs the readiness of the tiles.
- **[ready.h](commands/ready.h.driver.md)**: The `ready.h` file in the `firedancer` codebase declares the `ready_cmd_fn` function and the `fd_action_ready` external action for handling readiness commands.
- **[set_identity.c](commands/set_identity.c.driver.md)**: The `set_identity.c` file in the `firedancer` codebase implements a state machine to manage the process of switching the identity key of a validator, ensuring a seamless transition without data corruption.
- **[set_identity.h](commands/set_identity.h.driver.md)**: The `set_identity.h` file declares the `set_identity_cmd_fn` function and the `fd_action_set_identity` action for setting identity configurations in the Firedancer application.
- **[version.c](commands/version.c.driver.md)**: The `version.c` file in the `firedancer` codebase defines a command to display the current software version and commit reference.
- **[version.h](commands/version.h.driver.md)**: The `version.h` file in the `firedancer` codebase declares the `version_cmd_fn` function and the `fd_action_version` action for handling version-related commands.
