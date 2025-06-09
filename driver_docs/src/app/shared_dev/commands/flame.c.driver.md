# Purpose
This C source code file is designed to facilitate the collection and reporting of performance data using flame graphs, a visualization tool for profiling software performance. The code is structured around a command named "flame," which is part of a larger system, as indicated by its integration with shared and platform-specific utilities. The primary functionality is encapsulated in the [`flame_cmd_fn`](#flame_cmd_fn) function, which orchestrates the setup and execution of performance data collection using the `/usr/bin/perf` tool. The code handles different scenarios for targeting specific system components, such as all tiles, specific tiles, or a particular process (e.g., "agave"), and it manages the execution of the `perf` tool to record and report flame graphs.

Key technical components include signal handling for graceful termination, process management through `fork` and `execve` for executing the `perf` tool, and the use of shared memory and topology configurations to determine the system components to profile. The code defines a public API through the `fd_action_flame` structure, which specifies the command's name, argument parsing function, execution function, permission requirements, and a description. This structure suggests that the code is part of a modular system where actions can be dynamically registered and executed, likely within a larger diagnostic or performance monitoring framework.
# Imports and Dependencies

---
- `../../shared/fd_config.h`
- `../../shared/fd_action.h`
- `../../platform/fd_sys_util.h`
- `../../../disco/metrics/fd_metrics.h`
- `errno.h`
- `stdio.h`
- `unistd.h`
- `sys/wait.h`
- `sys/random.h`


# Global Variables

---
### record\_pid
- **Type**: `int`
- **Description**: The `record_pid` is a static integer variable that stores the process ID of a child process created by the `fork()` system call. It is used to manage the lifecycle of a performance recording process initiated by the program.
- **Use**: `record_pid` is used to store the process ID of the child process running the performance recording, allowing the parent process to send signals to it or check its status.


---
### flame\_cmd\_perm
- **Type**: `function pointer`
- **Description**: The `flame_cmd_perm` is a function pointer that is part of the `fd_action_flame` structure. It points to a function that checks the permissions required to execute the flame action, specifically ensuring that the user has the necessary root capabilities to read system performance counters using `/usr/bin/perf`. This function is crucial for security and access control, ensuring that only authorized users can perform the action.
- **Use**: This variable is used to assign the permission-checking function to the `perm` field of the `fd_action_flame` structure, which is responsible for capturing a performance flamegraph.


---
### fd\_action\_flame
- **Type**: `action_t`
- **Description**: The `fd_action_flame` is a global variable of type `action_t` that represents an action to capture a performance flamegraph using the `/usr/bin/perf` tool. It is initialized with specific function pointers and metadata that define its behavior and permissions.
- **Use**: This variable is used to define and execute the 'flame' action, which involves capturing and reporting performance data as a flamegraph.


# Functions

---
### parent\_signal<!-- {{#callable:parent_signal}} -->
The `parent_signal` function handles a received signal by logging it and, if a recording process is active, sending it a SIGINT signal.
- **Inputs**:
    - `sig`: The signal number that was received and triggered this handler.
- **Control Flow**:
    - Log the received signal using `FD_LOG_NOTICE` with the signal name obtained from `fd_io_strsignal`.
    - Check if `record_pid` is set (indicating an active recording process).
    - If `record_pid` is set, attempt to send a SIGINT signal to the process with PID `record_pid` using `kill()`.
    - If the `kill()` call fails, log an error using `FD_LOG_ERR`.
- **Output**: This function does not return any value; it performs logging and sends a signal to a process if applicable.


---
### install\_parent\_signals<!-- {{#callable:install_parent_signals}} -->
The `install_parent_signals` function sets up signal handlers for SIGTERM and SIGINT to invoke the `parent_signal` function when these signals are received.
- **Inputs**: None
- **Control Flow**:
    - Initialize a `sigaction` structure `sa` with `parent_signal` as the handler and no flags.
    - Attempt to set the signal handler for SIGTERM using `sigaction`; if it fails, log an error with `FD_LOG_ERR`.
    - Attempt to set the signal handler for SIGINT using `sigaction`; if it fails, log an error with `FD_LOG_ERR`.
- **Output**: This function does not return any value; it sets up signal handlers for the process.


---
### flame\_cmd\_args<!-- {{#callable:flame_cmd_args}} -->
The `flame_cmd_args` function processes command-line arguments for the 'flame' command, updating the argument count and pointer while storing the command name in a structure.
- **Inputs**:
    - `pargc`: A pointer to an integer representing the count of command-line arguments.
    - `pargv`: A pointer to an array of strings representing the command-line arguments.
    - `args`: A pointer to an `args_t` structure where the command name will be stored.
- **Control Flow**:
    - Check if the argument count pointed to by `pargc` is zero; if so, log an error and exit with a usage message.
    - Copy the first argument from `pargv` into the `name` field of the `flame` member of the `args` structure, ensuring it does not exceed the buffer size.
    - Decrement the argument count pointed to by `pargc`.
    - Increment the argument pointer `pargv` to point to the next argument.
- **Output**: The function does not return a value; it modifies the input arguments and the `args` structure in place.


---
### flame\_cmd\_fn<!-- {{#callable:flame_cmd_fn}} -->
The `flame_cmd_fn` function sets up and executes a performance profiling session using `/usr/bin/perf` to generate a flamegraph for specified tiles or processes.
- **Inputs**:
    - `args`: A pointer to an `args_t` structure containing command-line arguments, specifically the name of the tile or process to profile.
    - `config`: A pointer to a `config_t` structure containing configuration details, including the topology of tiles.
- **Control Flow**:
    - Install signal handlers for SIGTERM and SIGINT to handle parent process signals.
    - Join the shared memory workspace in read-only mode and fill the topology configuration.
    - Initialize variables for counting tiles and storing their indices.
    - Determine the tiles to profile based on the `args->flame.name` value, which can be 'all', 'agave', or a specific tile name with an optional kind ID.
    - For 'all', populate `tile_idxs` with all tile indices; for 'agave', find the 'bank' tile index; otherwise, find the specific tile index based on the name and optional kind ID.
    - Construct a comma-separated list of thread IDs or process IDs for the selected tiles, checking if each tile is running using `kill()` with signal 0.
    - Log a notice about the perf command to be executed and fork a child process to run the perf record command with the constructed arguments.
    - Wait for the perf record process to complete, handling signals and errors appropriately.
    - Fork another child process to run the perf report command to generate the flamegraph.
    - Wait for the perf report process to complete, handling signals and errors appropriately.
    - Exit the process group.
- **Output**: The function does not return a value; it performs its operations and exits the process group after generating the flamegraph.
- **Functions called**:
    - [`install_parent_signals`](#install_parent_signals)


