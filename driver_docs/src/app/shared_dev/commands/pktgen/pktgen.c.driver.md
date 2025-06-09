# Purpose
This C source code file is designed to implement a packet generator (pktgen) functionality within a network application. The primary purpose of this code is to configure and manage a network topology for packet generation, monitor network metrics, and provide a command-line interface for controlling the packet generation process. The code includes functions for setting up CPU affinities, initializing network topologies, and configuring various network parameters. It also includes a real-time status rendering function that displays network statistics such as packet rates and buffer statuses. The code is structured to run within a single process, utilizing global variables to share state, and it provides a simple REPL (Read-Eval-Print Loop) interface for user interaction.

The file imports several headers from different directories, indicating its reliance on external libraries and modules for network configuration, metrics collection, and topology management. It defines a public API through the `fd_action_pktgen` structure, which includes function pointers for argument parsing and command execution, making it suitable for integration into a larger application. The code is designed to be executed as part of a broader system, likely as a module within a network testing or simulation framework. The use of external interfaces and configuration options suggests that this file is part of a modular system where different components can be configured and executed independently.
# Imports and Dependencies

---
- `../dev.h`
- `../../../shared/commands/configure/configure.h`
- `../../../shared/commands/run/run.h`
- `../../../../disco/net/fd_net_tile.h`
- `../../../../disco/metrics/fd_metrics.h`
- `../../../../disco/topo/fd_topob.h`
- `../../../../disco/topo/fd_cpu_topo.h`
- `../../../../util/net/fd_ip4.h`
- `../../../../util/tile/fd_tile_private.h`
- `stdio.h`
- `unistd.h`
- `sys/ioctl.h`
- `poll.h`


# Global Variables

---
### CALLBACKS
- **Type**: `fd_topo_obj_callbacks_t *[]`
- **Description**: `CALLBACKS` is a global variable that is an array of pointers to `fd_topo_obj_callbacks_t` structures. This array is declared as an external variable, indicating that it is defined elsewhere in the program or in another module.
- **Use**: `CALLBACKS` is used to pass a set of callback functions to the `fd_topob_finish` function, which finalizes the topology setup.


---
### fd\_pktgen\_active
- **Type**: `uint`
- **Description**: The `fd_pktgen_active` is a global variable of type `uint` that indicates the current operational mode of the packet generator (pktgen) in the Firedancer application. It is used to determine whether the pktgen is in 'send+recv' mode or just 'recv' mode, which is reflected in the status rendering function.
- **Use**: This variable is used to control and check the operational mode of the packet generator, toggling between active and inactive states based on user commands.


---
### pktgen\_cmd\_fn
- **Type**: `function`
- **Description**: `pktgen_cmd_fn` is a function that configures and initializes the packet generator topology using the provided configuration. It sets up network tiles, metrics, and other necessary components for the packet generator to function.
- **Use**: This function is used to initialize and configure the packet generator's topology and settings based on the provided configuration.


---
### fd\_action\_pktgen
- **Type**: `action_t`
- **Description**: The `fd_action_pktgen` is a global variable of type `action_t` that represents an action configuration for a packet generator. It is initialized with specific attributes such as a name, command arguments, a function to execute, permissions, and a description. This configuration is used to define the behavior and properties of the packet generator action within the system.
- **Use**: This variable is used to configure and execute the packet generator action, which floods an interface with invalid Ethernet frames.


# Functions

---
### pktgen\_topo<!-- {{#callable:pktgen_topo}} -->
The `pktgen_topo` function configures the topology for a packet generator based on the provided configuration, including CPU affinity and network tile setup.
- **Inputs**:
    - `config`: A pointer to a `config_t` structure containing configuration details for the packet generator, including CPU affinity and network settings.
- **Control Flow**:
    - Retrieve the CPU affinity setting from the configuration and determine if it is set to 'auto'.
    - Initialize an array to map tiles to CPUs and parse the CPU affinity string if not set to 'auto'.
    - Initialize the CPU topology and check for any invalid CPU indices specified in the affinity string.
    - Verify that the number of CPUs specified in the affinity string matches the expected count (exactly three CPUs).
    - Reset the topology and configure shared memory page size based on the configuration.
    - Set up workspaces and network tiles, linking them according to the parsed CPU affinity.
    - Configure the packet generator tile, including setting a fake destination IP address.
    - Create network links for packet generation and reception, including a dummy RX link.
    - Finalize the network tile setup and apply automatic layout if the affinity is set to 'auto'.
    - Finish the topology setup and print the configuration to the log.
- **Output**: The function does not return a value; it modifies the topology configuration in place based on the provided settings.


---
### pktgen\_cmd\_args<!-- {{#callable:pktgen_cmd_args}} -->
The `pktgen_cmd_args` function is a placeholder function intended to handle command-line arguments for a packet generator, but currently does nothing with its parameters.
- **Inputs**:
    - `pargc`: A pointer to an integer representing the count of command-line arguments.
    - `pargv`: A pointer to an array of strings representing the command-line arguments.
    - `args`: A pointer to an `args_t` structure, presumably intended to hold parsed command-line arguments or configuration options.
- **Control Flow**:
    - The function takes three parameters: `pargc`, `pargv`, and `args`, which are intended to handle command-line arguments.
    - Currently, the function does not perform any operations on these parameters, as indicated by the use of `(void)` to suppress unused variable warnings.
    - The function is marked with a `FIXME` comment, suggesting that configuration options should be added in the future.
- **Output**: The function does not return any value or produce any output.


---
### render\_status<!-- {{#callable:render_status}} -->
The `render_status` function displays network metrics and statistics on the terminal, updating the display at regular intervals.
- **Inputs**:
    - `net_metrics`: A pointer to an array of volatile unsigned long integers representing various network metrics.
- **Control Flow**:
    - The function begins by saving the current cursor position and moving the cursor to the top of the terminal, clearing a line to prevent buffer spamming.
    - It prints the current mode of the packet generator, either 'send+recv' or 'recv', based on the global variable `fd_pktgen_active`.
    - Static variables are initialized to store previous metric values and calculated rates, with a check to initialize the timestamp if it's the first run.
    - The current time is fetched, and if the elapsed time since the last update exceeds 10 milliseconds, it calculates the differences in network metrics since the last update.
    - It computes the busy ratio, packet per second rates, and bits per second rates for both received and transmitted packets, as well as dropped packets.
    - The function updates the static variables with the current metric values for use in the next iteration.
    - It retrieves current idle and busy buffer counts for both RX and TX from the `net_metrics`.
    - The function prints the calculated statistics, including network busy percentage, RX and TX packet rates, and buffer statuses, to the terminal.
    - Finally, it restores the cursor position and flushes the output to ensure the display is updated.
- **Output**: The function does not return a value; it outputs network statistics directly to the terminal.


# Function Declarations (Public API)

---
### fdctl\_tile\_run<!-- {{#callable_declaration:fdctl_tile_run}} -->
Retrieves a tile configuration by name.
- **Description**: Use this function to obtain the configuration of a specific tile by its name. It searches through a predefined list of tiles and returns the configuration of the tile that matches the provided name. This function is useful when you need to access or modify the settings of a particular tile in a network topology. Ensure that the tile name provided exists in the list; otherwise, an error is logged, and a default-initialized tile configuration is returned.
- **Inputs**:
    - `tile`: A pointer to a constant `fd_topo_tile_t` structure representing the tile to be searched for. The `name` field of this structure is used to match against the list of available tiles. The pointer must not be null, and the `name` field must be a valid string.
- **Output**: Returns an `fd_topo_run_tile_t` structure containing the configuration of the matching tile. If no match is found, a default-initialized `fd_topo_run_tile_t` is returned.
- **See also**: [`fdctl_tile_run`](../../../shared/boot/fd_boot.c.driver.md#fdctl_tile_run)  (Implementation)


