# Purpose
This C source code file is designed to configure and execute a benchmarking topology for a system, likely related to network or distributed computing environments. The file includes several headers that suggest it is part of a larger project, with dependencies on shared commands, topology management, and utilities for shared memory and tile management. The primary functionality revolves around setting up a benchmark topology ([`add_bench_topo`](#add_bench_topo) function) and executing commands related to configuration and running the system ([`bench_cmd_fn`](#bench_cmd_fn) function). The code handles CPU affinity settings, network configurations, and initializes various components necessary for running a benchmark, such as setting up network namespaces and joining shared memory workspaces.

The file is not a standalone executable but rather a component of a larger system, likely intended to be compiled and linked with other parts of the project. It defines functions that are used to manipulate configurations and execute specific tasks, such as setting up the benchmark topology and running the system in a single process. The code also includes error handling and logging to ensure that configurations are correctly applied and that the system is set up as intended. The presence of external variables and functions, such as `CALLBACKS` and [`fdctl_tile_run`](#fdctl_tile_run), indicates that this file interacts with other parts of the system, making it a crucial component in the broader context of the project's execution and configuration management.
# Imports and Dependencies

---
- `../dev.h`
- `../../../shared/commands/configure/configure.h`
- `../../../shared/commands/run/run.h`
- `../../../../disco/topo/fd_topob.h`
- `../../../../disco/topo/fd_cpu_topo.h`
- `../../../../util/shmem/fd_shmem_private.h`
- `../../../../util/tile/fd_tile_private.h`
- `unistd.h`
- `stdio.h`
- `sched.h`
- `fcntl.h`
- `pthread.h`
- `linux/capability.h`
- `linux/futex.h`
- `sys/syscall.h`
- `sys/wait.h`
- `sys/socket.h`
- `arpa/inet.h`


# Global Variables

---
### CALLBACKS
- **Type**: `fd_topo_obj_callbacks_t *`
- **Description**: CALLBACKS is an external array of pointers to fd_topo_obj_callbacks_t structures. These structures likely contain function pointers or callback functions related to topology objects in the system.
- **Use**: CALLBACKS is used to store and manage callback functions for topology objects, facilitating dynamic behavior in the topology management system.


---
### fd\_log\_private\_shared\_lock
- **Type**: `int *`
- **Description**: `fd_log_private_shared_lock` is a pointer to an integer that is declared as an external global variable. It is likely used to manage or synchronize access to shared resources in a multi-threaded or multi-process environment.
- **Use**: This variable is used to control or indicate the locking state of a shared resource, as seen in the code where it is set to 0, potentially indicating an unlocked state.


# Functions

---
### bench\_cmd\_args<!-- {{#callable:bench_cmd_args}} -->
The `bench_cmd_args` function checks for the presence of the `--no-quic` flag in the command-line arguments and updates the `no_quic` field in the `args` structure accordingly.
- **Inputs**:
    - `pargc`: A pointer to an integer representing the count of command-line arguments.
    - `pargv`: A pointer to an array of strings representing the command-line arguments.
    - `args`: A pointer to an `args_t` structure where the `no_quic` field will be updated based on the presence of the `--no-quic` flag.
- **Control Flow**:
    - The function calls `fd_env_strip_cmdline_contains` with `pargc`, `pargv`, and the string `--no-quic` to check if the flag is present in the command-line arguments.
    - The result of the check (a boolean value) is assigned to `args->load.no_quic`.
- **Output**: The function does not return a value; it modifies the `args` structure in place.


---
### add\_bench\_topo<!-- {{#callable:add_bench_topo}} -->
The `add_bench_topo` function configures a benchmark topology by setting up tiles and their CPU affinities, linking them, and handling auto-affinity if specified.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology to be configured.
    - `affinity`: A string specifying the CPU affinity for the tiles, or 'auto' for automatic configuration.
    - `benchg_tile_cnt`: The number of 'benchg' tiles to be configured.
    - `benchs_tile_cnt`: The number of 'benchs' tiles to be configured.
    - `accounts_cnt`: The number of accounts for the 'benchg' tiles.
    - `transaction_mode`: An integer representing the transaction mode for the 'benchg' tiles.
    - `contending_fraction`: A float representing the fraction of contending transactions for the 'benchg' tiles.
    - `cu_price_spread`: A float representing the price spread for the 'benchg' tiles.
    - `conn_cnt`: The number of connections for the 'benchs' tiles.
    - `send_to_port`: The port number to which 'benchs' tiles will send data.
    - `send_to_ip_addr`: The IP address to which 'benchs' tiles will send data.
    - `rpc_port`: The RPC port for the 'bencho' tile.
    - `rpc_ip_addr`: The RPC IP address for the 'bencho' tile.
    - `no_quic`: An integer flag indicating whether QUIC is disabled (non-zero) or enabled (zero).
    - `reserve_agave_cores`: An integer flag indicating whether to reserve cores for Agave (non-zero) or not (zero).
- **Control Flow**:
    - Initialize the workspace for the benchmark topology and create initial links for 'bencho_out' and 'benchg_s'.
    - Determine if the affinity is set to 'auto' and initialize CPU parsing structures.
    - Parse the CPU affinity string if not 'auto' and validate the parsed CPU indices against available CPUs.
    - Check if the number of CPUs specified in the affinity string matches the required number of tiles and log errors or warnings if not.
    - Create and configure the 'bencho' tile with RPC settings.
    - Iterate over 'benchg_tile_cnt' to create and configure 'benchg' tiles with account, mode, and transaction settings.
    - Iterate over 'benchs_tile_cnt' to create and configure 'benchs' tiles with connection and network settings.
    - Link the 'bencho' tile output to 'bencho_out' and connect 'benchg' and 'benchs' tiles appropriately.
    - If auto-affinity is specified, recompute the topology layout automatically.
    - Finalize the topology configuration with `fd_topob_finish`.
- **Output**: The function does not return a value; it modifies the `fd_topo_t` structure pointed to by `topo` to reflect the configured benchmark topology.


---
### bench\_cmd\_fn<!-- {{#callable:bench_cmd_fn}} -->
The `bench_cmd_fn` function configures and initializes a benchmarking environment based on the provided arguments and configuration settings, ensuring proper CPU affinity and network setup before executing the benchmark.
- **Inputs**:
    - `args`: A pointer to an `args_t` structure containing command-line arguments, specifically whether QUIC is disabled.
    - `config`: A pointer to a `config_t` structure containing configuration settings for the benchmarking environment, including network, RPC, and CPU affinity settings.
- **Control Flow**:
    - Determine the destination port based on whether QUIC is disabled using `fd_ushort_if` function.
    - Set the RPC port in the configuration, defaulting to 8899 if not already set.
    - If the configuration is not for Firedancer, enable the full API for Frankendancer.
    - Check if CPU affinity settings are consistent across different configuration sections and log an error if they are not.
    - Call [`add_bench_topo`](#add_bench_topo) to set up the benchmark topology with the specified parameters.
    - Initialize a `configure_args` structure and populate its stages from the `STAGES` array.
    - Call `configure_cmd_fn` to apply the configuration settings.
    - Update the configuration for development using [`update_config_for_dev`](../dev.c.driver.md#update_config_for_dev).
    - Initialize Firedancer and set up network namespaces with `run_firedancer_init` and `fdctl_setup_netns`.
    - If the network provider is 'xdp', install XDP using `fd_topo_install_xdp`.
    - Unlock the shared log lock for index 1.
    - Join workspaces in read-write mode using `fd_topo_join_workspaces`.
    - Run the topology in a single process mode using `fd_topo_run_single_process`.
- **Output**: The function does not return a value; it performs configuration and initialization tasks for a benchmarking environment.
- **Functions called**:
    - [`add_bench_topo`](#add_bench_topo)
    - [`update_config_for_dev`](../dev.c.driver.md#update_config_for_dev)


# Function Declarations (Public API)

---
### fdctl\_tile\_run<!-- {{#callable_declaration:fdctl_tile_run}} -->
Retrieves a tile configuration by its name.
- **Description**: Use this function to obtain the configuration of a specific tile identified by its name. It searches through a predefined list of tiles and returns the configuration of the tile that matches the provided name. This function should be called when you need to access the configuration details of a tile for further operations. Ensure that the tile name provided is valid and exists in the list of tiles; otherwise, an error is logged, and a default configuration is returned.
- **Inputs**:
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing the tile to be searched. The `name` field of this structure must not be null and should contain the name of the tile to be found. The caller retains ownership of this pointer.
- **Output**: Returns an `fd_topo_run_tile_t` structure containing the configuration of the tile if found. If the tile is not found, logs an error and returns a default-initialized `fd_topo_run_tile_t`.
- **See also**: [`fdctl_tile_run`](../../../shared/boot/fd_boot.c.driver.md#fdctl_tile_run)  (Implementation)


---
### update\_config\_for\_dev<!-- {{#callable_declaration:update_config_for_dev}} -->
Updates the configuration for development environment.
- **Description**: This function updates the configuration object by setting the expected shred version for shred and store tiles based on the genesis file if available. It should be called when the configuration needs to be prepared for a development environment, ensuring that shred versions are correctly set. The function assumes that the configuration object is properly initialized and contains valid paths and topology information. It does not handle null pointers or invalid configurations, so the caller must ensure the input is valid.
- **Inputs**:
    - `config`: A pointer to a fd_config_t structure representing the configuration to be updated. Must not be null and should be properly initialized with valid paths and topology information. The function will modify this structure to set the expected shred versions.
- **Output**: None
- **See also**: [`update_config_for_dev`](../dev.c.driver.md#update_config_for_dev)  (Implementation)


