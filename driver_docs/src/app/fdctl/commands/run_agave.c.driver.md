# Purpose
The provided C source code file is designed to facilitate the startup and configuration of the "Agave" component of a Firedancer validator, which is likely part of a larger distributed system or blockchain network. The file includes various headers and libraries that suggest it is part of a larger codebase, with dependencies on shared utilities and network functionalities. The primary function of this file is to configure and launch the Agave process with specific parameters and settings derived from a configuration structure (`config_t`). This configuration includes network settings, consensus parameters, ledger management, gossip protocol settings, RPC configurations, and snapshot management, all of which are crucial for the operation of a validator node in a distributed network.

The code defines several functions and macros to handle the setup and execution of the Agave process. It includes functions for memory space management, setting environment variables, and configuring process affinity to specific CPU cores. The [`agave_boot`](#agave_boot) function constructs a command-line argument list for the Agave process based on the configuration, while [`agave_main`](#agave_main) handles the main execution logic, including setting up the process environment and invoking the main validator function. The `run_agave_cmd_fn` function is responsible for creating a new process using the `clone` system call, effectively isolating the Agave process in its own PID namespace if sandboxing is enabled. The file concludes with the definition of an `action_t` structure, `fd_action_run_agave`, which encapsulates the command's metadata and execution function, indicating that this file is part of a command-line interface or a larger application framework.
# Imports and Dependencies

---
- `../../shared/commands/run/run.h`
- `../../../util/net/fd_ip4.h`
- `../../../util/tile/fd_tile_private.h`
- `sched.h`
- `stdlib.h`
- `errno.h`
- `unistd.h`
- `pthread.h`
- `sys/wait.h`


# Global Variables

---
### fd\_log\_private\_shared\_lock
- **Type**: `int*`
- **Description**: `fd_log_private_shared_lock` is a global pointer to an integer, which is likely used as a lock or synchronization mechanism in a shared memory context. It is declared as an external variable, indicating that its definition is located in another translation unit.
- **Use**: This variable is used to control or synchronize access to shared resources, as seen in the `agave_main` function where it is checked and modified to manage debugging and synchronization states.


---
### \_fd\_ext\_larger\_max\_cost\_per\_block
- **Type**: `int`
- **Description**: The variable `_fd_ext_larger_max_cost_per_block` is a static integer that represents the maximum cost per block in a development or benchmarking context. It is used to potentially increase the cost limits for blocks during testing or development phases, allowing for consensus-breaking changes in a controlled environment.
- **Use**: This variable is used to store the maximum cost per block value from the configuration for development and benchmarking purposes.


---
### \_fd\_ext\_larger\_shred\_limits\_per\_block
- **Type**: `int`
- **Description**: The variable `_fd_ext_larger_shred_limits_per_block` is a static integer that is used to store the larger shred limits per block for development and benchmarking purposes. It is initialized in the `agave_boot` function using a value from the configuration structure.
- **Use**: This variable is used to configure the maximum shred limits per block in a development or benchmarking environment.


---
### \_fd\_ext\_disable\_status\_cache
- **Type**: `int`
- **Description**: The `_fd_ext_disable_status_cache` is a static integer variable that is used to store a configuration setting related to the status cache in a development or benchmarking context. It is initialized with a value from the `config` structure, specifically from `config->development.bench.disable_status_cache`. This suggests that it is used to control whether the status cache is disabled during certain operations, likely for testing or performance evaluation purposes.
- **Use**: This variable is used to store and manage the configuration setting for disabling the status cache in a development or benchmarking environment.


---
### run\_agave\_cmd\_fn
- **Type**: `function`
- **Description**: The `run_agave_cmd_fn` is a function that initiates the execution of the Agave component of a Firedancer validator. It sets the logging thread name to 'agave' and then creates a new process using the `clone` system call to run the `agave_main` function. This function is responsible for setting up the environment and executing the Agave validator logic.
- **Use**: This function is used to start the Agave process in a separate PID namespace, ensuring isolation from other processes.


---
### fd\_action\_run\_agave
- **Type**: `action_t`
- **Description**: The `fd_action_run_agave` is a global variable of type `action_t` that represents an action to start the Agave side of a Firedancer validator. It is initialized with a name, a function pointer to `run_agave_cmd_fn`, and a description of its purpose. The `args` and `perm` fields are set to `NULL`, indicating that this action does not require additional arguments or permissions.
- **Use**: This variable is used to define and execute the action of starting the Agave component of a Firedancer validator.


# Functions

---
### clone\_labs\_memory\_space\_tiles<!-- {{#callable:clone_labs_memory_space_tiles}} -->
The `clone_labs_memory_space_tiles` function preloads shared memory for specific workspaces and runs a single process for the Agave tiles using the provided configuration.
- **Inputs**:
    - `config`: A pointer to a `config_t` structure containing configuration details, including topology and workspace information.
- **Control Flow**:
    - Iterates over each workspace in the configuration's topology.
    - Checks the name of each workspace to determine the appropriate shared memory join mode.
    - Joins the workspace in read-only mode if its name is 'pack_bank' or 'shred_store'.
    - Joins the workspace in read-write mode if its name matches any of the specified names like 'bank_poh', 'bank_pack', etc.
    - Runs a single process for the Agave tiles using the `fd_topo_run_single_process` function with the provided configuration.
- **Output**: The function does not return a value; it performs operations on shared memory and runs a process based on the configuration.


---
### fd\_ext\_larger\_max\_cost\_per\_block<!-- {{#callable:fd_ext_larger_max_cost_per_block}} -->
The function `fd_ext_larger_max_cost_per_block` returns the value of the static variable `_fd_ext_larger_max_cost_per_block`, which is used to configure a consensus-breaking development-only cost limit per block.
- **Inputs**: None
- **Control Flow**:
    - The function is defined to return an integer value.
    - It directly returns the value of the static variable `_fd_ext_larger_max_cost_per_block`.
- **Output**: The function returns an integer representing the maximum cost per block, as configured in a development environment.


---
### fd\_ext\_larger\_shred\_limits\_per\_block<!-- {{#callable:fd_ext_larger_shred_limits_per_block}} -->
The function `fd_ext_larger_shred_limits_per_block` returns the value of a static integer variable `_fd_ext_larger_shred_limits_per_block`.
- **Inputs**: None
- **Control Flow**:
    - The function is defined to return an integer value.
    - It directly returns the value of the static variable `_fd_ext_larger_shred_limits_per_block`.
- **Output**: The function returns an integer value representing the larger shred limits per block, which is stored in the static variable `_fd_ext_larger_shred_limits_per_block`.


---
### fd\_ext\_disable\_status\_cache<!-- {{#callable:fd_ext_disable_status_cache}} -->
The `fd_ext_disable_status_cache` function returns the value of the static variable `_fd_ext_disable_status_cache`, which indicates whether the status cache is disabled.
- **Inputs**: None
- **Control Flow**:
    - The function is defined to return an integer value.
    - It directly returns the value of the static variable `_fd_ext_disable_status_cache`.
- **Output**: The function returns an integer value representing the state of the `_fd_ext_disable_status_cache` variable.


---
### agave\_boot<!-- {{#callable:agave_boot}} -->
The `agave_boot` function initializes and configures the Agave validator by setting up command-line arguments and environment variables based on the provided configuration, and then executes the validator process.
- **Inputs**:
    - `config`: A pointer to a `config_t` structure containing various configuration settings for the Agave validator.
- **Control Flow**:
    - Initialize index variables and buffers for command-line arguments.
    - Define macros for adding arguments to the `argv` array with different formats.
    - Add initial command-line arguments for logging and control.
    - Configure network settings by adding relevant arguments based on the `config` structure.
    - Set up consensus-related arguments, including identity, vote accounts, and consensus options.
    - Configure ledger-related settings, including paths and size limits.
    - Set up gossip-related arguments, including entry points and ports.
    - Configure RPC settings, including ports and API options.
    - Set up snapshot-related arguments, including paths and retention limits.
    - Determine the number of handler threads based on configuration and system capabilities.
    - Terminate the `argv` array with a NULL pointer to mark the end of arguments.
    - Set environment variables for metrics configuration if specified.
    - Log the configured command-line arguments for the Agave validator.
    - Set CPU affinity for the process based on the configuration to optimize performance.
    - Set global variables for development and benchmarking options.
    - Call `fd_ext_validator_main` to execute the Agave validator with the configured arguments.
- **Output**: The function does not return a value; it sets up and executes the Agave validator process.


---
### agave\_main<!-- {{#callable:agave_main}} -->
The `agave_main` function initializes and boots the Agave component of a Firedancer validator, handling debugging, memory space setup, and user ID switching.
- **Inputs**:
    - `args`: A pointer to a `config_t` structure containing configuration settings for the Agave component.
- **Control Flow**:
    - Check if debugging is enabled for the tile and handle debugger attachment or wait for a shared lock release.
    - Call [`clone_labs_memory_space_tiles`](#clone_labs_memory_space_tiles) to preload shared memory for Agave tiles.
    - Retrieve the current process ID and set it for logging purposes.
    - Discover the stack for logging purposes and log the booting process.
    - Switch the user and group ID to those specified in the configuration.
    - Call [`agave_boot`](#agave_boot) to start the Agave component with the provided configuration.
- **Output**: Returns 0 upon successful execution, indicating the Agave component has been initialized and booted.
- **Functions called**:
    - [`clone_labs_memory_space_tiles`](#clone_labs_memory_space_tiles)
    - [`agave_boot`](#agave_boot)


# Function Declarations (Public API)

---
### fdctl\_tile\_run<!-- {{#callable_declaration:fdctl_tile_run}} -->
Retrieves a tile configuration by name.
- **Description**: Use this function to obtain the configuration of a specific tile by its name. It searches through a predefined list of tiles and returns the configuration of the tile that matches the provided name. This function should be called when you need to access the configuration details of a tile within the system. If the tile is not found, an error is logged, and a default configuration is returned.
- **Inputs**:
    - `tile`: A pointer to a `fd_topo_tile_t` structure representing the tile to be searched. The `name` field of this structure is used to identify the tile. The pointer must not be null, and the `name` field must be a valid string.
- **Output**: Returns an `fd_topo_run_tile_t` structure containing the configuration of the tile if found. If the tile is not found, a default-initialized `fd_topo_run_tile_t` is returned.
- **See also**: [`fdctl_tile_run`](../../shared/boot/fd_boot.c.driver.md#fdctl_tile_run)  (Implementation)


