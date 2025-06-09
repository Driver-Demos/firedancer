# Purpose
The provided C source code file is designed to facilitate the development and debugging of a software system called "Firedancer." It achieves this by running the entire system within a single process, which simplifies the debugging process. The code includes functions for handling command-line arguments, configuring the system, and managing process signals. It also integrates various components from shared libraries, such as configuration, run, and monitor commands, which are essential for the system's operation. The file is not a standalone executable but rather a component that is likely part of a larger application, given its reliance on external headers and libraries.

Key technical components of the code include functions for processing command-line arguments ([`dev_cmd_args`](#dev_cmd_args)), setting up permissions ([`dev_cmd_perm`](#dev_cmd_perm)), and updating configuration settings ([`update_config_for_dev`](#update_config_for_dev)). The code also handles signal management to ensure proper termination of processes ([`install_parent_signals`](#install_parent_signals) and [`parent_signal`](#parent_signal)). Additionally, it includes logic for running the Firedancer system in a threaded mode ([`run_firedancer_threaded`](#run_firedancer_threaded)) and managing child processes for monitoring and execution. The file defines internal functions and uses external interfaces, such as those for logging and system utilities, to support its operations. Overall, the code provides a focused functionality aimed at enhancing the development and debugging workflow for the Firedancer system.
# Imports and Dependencies

---
- `../../platform/fd_sys_util.h`
- `../../shared/genesis_hash.h`
- `../../shared/commands/configure/configure.h`
- `../../shared/commands/run/run.h`
- `../../shared/commands/monitor/monitor.h`
- `stdio.h`
- `unistd.h`
- `sched.h`
- `fcntl.h`
- `pthread.h`
- `sys/wait.h`


# Global Variables

---
### firedancer\_pid
- **Type**: `pid_t`
- **Description**: The `firedancer_pid` is a global variable of type `pid_t` that stores the process ID of the Firedancer process. It is used to manage and control the lifecycle of the Firedancer process, particularly in signal handling and process termination scenarios.
- **Use**: This variable is used to store the process ID of the Firedancer process for managing its execution and termination.


---
### monitor\_pid
- **Type**: `pid_t`
- **Description**: The `monitor_pid` is a global variable of type `pid_t` that stores the process ID of the monitor process. It is used to manage and control the lifecycle of the monitor process within the application.
- **Use**: `monitor_pid` is used to store the process ID of the monitor process, allowing the application to send signals to it or check its status.


---
### fd\_log\_private\_path
- **Type**: `char[1024]`
- **Description**: The `fd_log_private_path` is a global character array with a size of 1024, initialized as an empty string at the start. It is used to store the file path for logging purposes within the application.
- **Use**: This variable is used to hold the path to the log file, which is referenced in logging operations to specify where log messages should be written.


---
### fd\_log\_private\_shared\_lock
- **Type**: `int*`
- **Description**: `fd_log_private_shared_lock` is a global pointer to an integer, which is used as a lock mechanism for logging operations. It is declared as an external variable, indicating that its definition is likely in another file.
- **Use**: This variable is used to manage access to shared resources during logging, ensuring that logging operations are synchronized across different parts of the program.


# Functions

---
### dev\_cmd\_args<!-- {{#callable:dev_cmd_args}} -->
The `dev_cmd_args` function processes command-line arguments to configure development settings in the `args_t` structure.
- **Inputs**:
    - `pargc`: A pointer to an integer representing the count of command-line arguments.
    - `pargv`: A pointer to an array of strings representing the command-line arguments.
    - `args`: A pointer to an `args_t` structure where the parsed command-line options will be stored.
- **Control Flow**:
    - Initialize `args->dev.parent_pipefd` to -1.
    - Check for the presence of the `--monitor` flag in the command-line arguments and set `args->dev.monitor` accordingly.
    - Check for the presence of the `--no-configure` flag and set `args->dev.no_configure` accordingly.
    - Check for the presence of the `--no-init-workspaces` flag and set `args->dev.no_init_workspaces` accordingly.
    - Check for the presence of either `--no-agave` or `--no-solana` flags and set `args->dev.no_agave` accordingly.
    - Retrieve the value associated with the `--debug-tile` flag, if present, and copy it into `args->dev.debug_tile`.
- **Output**: The function does not return a value; it modifies the `args_t` structure pointed to by `args` to reflect the parsed command-line options.


---
### dev\_cmd\_perm<!-- {{#callable:dev_cmd_perm}} -->
The `dev_cmd_perm` function configures and runs command permissions based on the provided arguments and configuration.
- **Inputs**:
    - `args`: A pointer to an `args_t` structure containing command-line arguments and configuration flags.
    - `chk`: A pointer to an `fd_cap_chk_t` structure used for capability checking.
    - `config`: A constant pointer to a `config_t` structure containing configuration settings.
- **Control Flow**:
    - Check if the `no_configure` flag in `args` is not set using `FD_LIKELY` macro.
    - If the `no_configure` flag is not set, initialize a `configure_args` structure with the command `CONFIGURE_CMD_INIT`.
    - Iterate over the `STAGES` array and populate the `stages` field of `configure_args` with its elements.
    - Call `configure_cmd_perm` with `configure_args`, `chk`, and `config` to configure command permissions.
    - Call `run_cmd_perm` with `NULL`, `chk`, and `config` to run command permissions.
- **Output**: The function does not return a value; it performs operations based on the input arguments and configuration.


---
### parent\_signal<!-- {{#callable:parent_signal}} -->
The `parent_signal` function handles signals by terminating specific processes and logging the event before exiting the program.
- **Inputs**:
    - `sig`: The signal number that triggered the function.
- **Control Flow**:
    - Check if `firedancer_pid` is set and send a SIGINT signal to the process with that PID.
    - Check if `monitor_pid` is set and send a SIGKILL signal to the process with that PID.
    - Set a local lock variable to 0 and assign its address to `fd_log_private_shared_lock`.
    - Log the received signal and the log file path if the log file descriptor is valid, otherwise just log the signal.
    - If the received signal is SIGINT, exit the program with a status code of 128 plus SIGINT, otherwise exit with status code 0.
- **Output**: The function does not return a value; it performs process termination and exits the program.


---
### install\_parent\_signals<!-- {{#callable:install_parent_signals}} -->
The `install_parent_signals` function sets up signal handlers for SIGTERM and SIGINT signals to execute the `parent_signal` function when these signals are received.
- **Inputs**: None
- **Control Flow**:
    - A `sigaction` structure `sa` is initialized with `parent_signal` as the handler and no flags.
    - The `sigaction` function is called to associate the `SIGTERM` signal with the `sa` structure, and if it fails, an error is logged.
    - The `sigaction` function is called again to associate the `SIGINT` signal with the `sa` structure, and if it fails, an error is logged.
- **Output**: The function does not return any value; it sets up signal handlers for the process.


---
### update\_config\_for\_dev<!-- {{#callable:update_config_for_dev}} -->
The `update_config_for_dev` function updates the expected shred version in a configuration based on the genesis file if it is not already set.
- **Inputs**:
    - `config`: A pointer to an `fd_config_t` structure that contains configuration details, including paths and topology information.
- **Control Flow**:
    - Constructs the path to the genesis file using the ledger path from the configuration.
    - Computes the shred version from the genesis file using `compute_shred_version`.
    - Iterates over each shred tile in the configuration's topology layout.
    - For each shred tile, it finds the tile ID and checks if the expected shred version is zero.
    - If the expected shred version is zero, it updates it with the computed shred version.
    - Finds the store tile ID and checks if the expected shred version is zero.
    - If the expected shred version for the store tile is zero, it updates it with the computed shred version.
- **Output**: The function does not return a value; it modifies the `config` structure in place.


---
### run\_firedancer\_threaded<!-- {{#callable:run_firedancer_threaded}} -->
The `run_firedancer_threaded` function initializes and runs the Firedancer application in a single process with threading support, handling signal installation, workspace setup, and optional execution of a main function.
- **Inputs**:
    - `config`: A pointer to a `config_t` structure containing configuration settings for the Firedancer application.
    - `init_workspaces`: An integer flag indicating whether to initialize workspaces.
    - `agave_main`: A pointer to a function that takes a constant `config_t` pointer as an argument, representing an optional main function to execute if certain conditions are met.
- **Control Flow**:
    - Install signal handlers for the parent process using `install_parent_signals()`.
    - Log the topology configuration using `fd_topo_print_log()`.
    - Initialize the Firedancer application with `run_firedancer_init()` using the provided configuration and workspace initialization flag.
    - Set up network namespaces with `fdctl_setup_netns()`.
    - If debugging is enabled (`config->development.debug_tile`), set a shared lock for logging.
    - Check if the network provider is 'xdp' and install XDP using `fd_topo_install_xdp()` if true.
    - Join all workspaces in read-write mode using `fd_topo_join_workspaces()` to ensure proper memory access across threads.
    - Run the Firedancer application in a single process with threading using `fd_topo_run_single_process()`.
    - If `agave_main` is provided and `config->development.no_agave` is false, execute the `agave_main` function.
    - Enter an infinite loop with `pause()` to keep the process running indefinitely, as threads will not exit normally.
- **Output**: The function does not return a value; it runs the Firedancer application in a threaded mode and keeps the process alive indefinitely.
- **Functions called**:
    - [`install_parent_signals`](#install_parent_signals)


---
### dev\_cmd\_fn<!-- {{#callable:dev_cmd_fn}} -->
The `dev_cmd_fn` function configures and runs a development environment for the Firedancer application, handling various command-line arguments and conditions to determine the execution flow.
- **Inputs**:
    - `args`: A pointer to an `args_t` structure containing command-line arguments and options for the development environment.
    - `config`: A pointer to a `config_t` structure that holds configuration settings for the Firedancer application.
    - `agave_main`: A function pointer to a function that takes a constant `config_t` pointer, used for additional processing if required.
- **Control Flow**:
    - Check if configuration is needed and perform it using `configure_cmd_fn` if not disabled by `args->dev.no_configure`.
    - Update the configuration for development using [`update_config_for_dev`](#update_config_for_dev).
    - If `args->dev.no_agave` is set, disable Agave in the configuration.
    - If a debug tile is specified in `args->dev.debug_tile`, adjust the configuration to disable sandboxing and set the appropriate debug tile ID.
    - If monitoring is not enabled (`args->dev.monitor` is false), run Firedancer using either `run_firedancer` or [`run_firedancer_threaded`](#run_firedancer_threaded) based on the `no_clone` configuration setting.
    - If monitoring is enabled, set up signal handling, create a non-blocking pipe, and fork the process to run Firedancer and a monitor process.
    - In the child process, redirect standard error to the pipe and run Firedancer.
    - In the parent process, set up monitoring arguments and fork a monitor process to handle output from the pipe.
    - Wait for any child process to exit and handle unexpected exits by logging errors and killing remaining processes.
    - Exit the process group with the appropriate exit code.
- **Output**: The function does not return a value; it performs its operations through side effects on the `config` structure and by running processes.
- **Functions called**:
    - [`update_config_for_dev`](#update_config_for_dev)
    - [`run_firedancer_threaded`](#run_firedancer_threaded)
    - [`install_parent_signals`](#install_parent_signals)


# Function Declarations (Public API)

---
### fdctl\_tile\_run<!-- {{#callable_declaration:fdctl_tile_run}} -->
Retrieves a tile configuration from the topology by name.
- **Description**: This function searches for a tile in the topology that matches the given tile's name and returns its configuration. It is used when you need to retrieve the configuration of a specific tile by its name from a predefined set of tiles. The function expects the tile to be present in the topology; if the tile is not found, an error is logged, and a default-initialized tile configuration is returned. This function should be called when the topology is fully initialized and populated with tiles.
- **Inputs**:
    - `tile`: A pointer to a constant `fd_topo_tile_t` structure representing the tile to be searched for. The `name` field of this structure is used to match against the names of tiles in the topology. The pointer must not be null, and the `name` field must be a valid string.
- **Output**: Returns an `fd_topo_run_tile_t` structure representing the configuration of the tile if found. If the tile is not found, logs an error and returns a default-initialized `fd_topo_run_tile_t` structure.
- **See also**: [`fdctl_tile_run`](../../shared/boot/fd_boot.c.driver.md#fdctl_tile_run)  (Implementation)


