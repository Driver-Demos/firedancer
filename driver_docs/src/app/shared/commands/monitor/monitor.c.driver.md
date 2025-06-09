# Purpose
The provided C code is part of a monitoring tool designed to observe and report on the performance and status of a Firedancer instance, which is likely a distributed system or application. This code is structured to be executed as a standalone program, as indicated by the presence of a `main`-like function ([`monitor_cmd_fn`](#monitor_cmd_fn)) and the setup of command-line arguments and permissions. The primary functionality of this code is to collect and display metrics related to system performance, such as transaction rates, memory usage, and process states, in a terminal-based graphical user interface (GUI). It achieves this by interfacing with various system components and utilizing system calls to gather and present data in real-time.

Key technical components of this code include the use of structures to store snapshots of system metrics (`tile_snap_t` and `link_snap_t`), functions to capture and compare these metrics over time ([`tile_snap`](#tile_snap), [`link_snap`](#link_snap)), and mechanisms to handle command-line arguments and permissions ([`monitor_cmd_args`](#monitor_cmd_args), `monitor_cmd_perm`). The code also incorporates system-level operations such as adjusting resource limits, handling signals for graceful termination, and managing terminal settings for interactive user input. Additionally, it uses a seccomp filter to enforce security policies, ensuring that only necessary system calls are permitted during execution. The code is designed to be modular, with clear separation of concerns, allowing it to be integrated into a larger system or used as a standalone monitoring tool.
# Imports and Dependencies

---
- `../../../../util/fd_util.h`
- `../../../shared_dev/commands/bench/bench.h`
- `../../fd_config.h`
- `../../../platform/fd_cap_chk.h`
- `../../../../disco/topo/fd_topo.h`
- `../../../../disco/metrics/fd_metrics.h`
- `helper.h`
- `unistd.h`
- `errno.h`
- `stdio.h`
- `stdlib.h`
- `signal.h`
- `sys/syscall.h`
- `sys/resource.h`
- `linux/capability.h`
- `sys/ioctl.h`
- `termios.h`
- `generated/monitor_seccomp.h`


# Global Variables

---
### monitor\_cmd\_perm
- **Type**: `function`
- **Description**: `monitor_cmd_perm` is a function that sets up permissions and resource limits for the monitor command in a Firedancer instance. It adjusts the memory lock limit and checks for necessary capabilities to ensure the process can run in a sandboxed environment with the required permissions.
- **Use**: This function is used to configure and verify the necessary permissions and resource limits before executing the monitor command.


---
### stop1
- **Type**: `int`
- **Description**: The `stop1` variable is a static integer initialized to 0, indicating that it is a global variable with file scope, meaning it is only accessible within the file it is declared in.
- **Use**: It is used as a flag to control the termination of the monitoring loop in the `run_monitor` function.


---
### buffer
- **Type**: `char[]`
- **Description**: The `buffer` is a static character array with a size defined by the macro `FD_MONITOR_TEXT_BUF_SZ`, which is set to 131072. It is used to store text data, likely for output or processing within the monitoring functions of the program.
- **Use**: This variable is used to temporarily hold text data that is processed or output by the monitoring functions, such as in the `run_monitor` function.


---
### buffer2
- **Type**: ``char[]``
- **Description**: `buffer2` is a static character array with a size defined by the macro `FD_MONITOR_TEXT_BUF_SZ`. It is used to temporarily store data read from a file descriptor, likely for processing or output purposes.
- **Use**: This variable is used as a temporary buffer to hold data read from a file descriptor in the `drain_to_buffer` function.


---
### termios\_backup
- **Type**: `struct termios`
- **Description**: The `termios_backup` variable is a static instance of the `struct termios` data structure, which is used to store terminal I/O settings. It is declared at the global scope, indicating that it is intended to be used throughout the file to manage terminal settings.
- **Use**: This variable is used to save the current terminal settings so they can be restored later, ensuring that any changes made to the terminal configuration during program execution can be reverted.


---
### fd\_action\_monitor
- **Type**: `action_t`
- **Description**: The `fd_action_monitor` is a global variable of type `action_t` that represents an action to monitor a locally running Firedancer instance using a terminal GUI. It is initialized with specific function pointers and parameters that define its behavior and permissions.
- **Use**: This variable is used to encapsulate the command-line action for monitoring Firedancer, including its arguments, execution function, permissions, and description.


# Data Structures

---
### tile\_snap\_t
- **Type**: `struct`
- **Members**:
    - `pid`: Stores the process ID associated with the tile.
    - `heartbeat`: Represents a heartbeat signal for monitoring the tile's activity.
    - `in_backp`: Indicates whether the tile is currently experiencing backpressure.
    - `backp_cnt`: Counts the number of times the tile has experienced backpressure.
    - `nvcsw`: Tracks the number of voluntary context switches for the tile.
    - `nivcsw`: Tracks the number of involuntary context switches for the tile.
    - `regime_ticks`: An array of 9 elements tracking time spent in different operational regimes.
- **Description**: The `tile_snap_t` structure is designed to capture a snapshot of various performance and operational metrics for a tile in a distributed system. It includes fields for tracking process ID, heartbeat signals, backpressure status and count, context switch counts, and an array to record time spent in different operational regimes. This structure is used to monitor and analyze the performance and behavior of individual tiles within the system.


---
### link\_snap\_t
- **Type**: `struct`
- **Members**:
    - `mcache_seq`: Stores the sequence number of the message cache.
    - `fseq_seq`: Stores the sequence number of the flow sequence.
    - `fseq_diag_tot_cnt`: Total count of diagnostics for the flow sequence.
    - `fseq_diag_tot_sz`: Total size of diagnostics for the flow sequence.
    - `fseq_diag_filt_cnt`: Count of filtered diagnostics for the flow sequence.
    - `fseq_diag_filt_sz`: Size of filtered diagnostics for the flow sequence.
    - `fseq_diag_ovrnp_cnt`: Count of overrun polling diagnostics for the flow sequence.
    - `fseq_diag_ovrnr_cnt`: Count of overrun reading diagnostics for the flow sequence.
    - `fseq_diag_slow_cnt`: Count of slow diagnostics for the flow sequence.
- **Description**: The `link_snap_t` structure is designed to capture a snapshot of various diagnostic metrics related to message and flow sequences in a networked system. It includes fields for tracking sequence numbers and diagnostic counts and sizes, such as total, filtered, and overrun diagnostics, which are essential for monitoring and analyzing the performance and reliability of data links.


# Functions

---
### monitor\_cmd\_args<!-- {{#callable:monitor_cmd_args}} -->
The `monitor_cmd_args` function processes command-line arguments to configure monitoring parameters for a Firedancer instance.
- **Inputs**:
    - `pargc`: A pointer to an integer representing the count of command-line arguments.
    - `pargv`: A pointer to an array of strings representing the command-line arguments.
    - `args`: A pointer to an `args_t` structure where the parsed monitoring parameters will be stored.
- **Control Flow**:
    - Initialize `drain_output_fd` to -1, indicating it is only accessible to development commands.
    - Extract and set `dt_min`, `dt_max`, `duration`, and `seed` from the command-line arguments using `fd_env_strip_cmdline_long` and `fd_env_strip_cmdline_uint`, with default values if not provided.
    - Calculate `ns_per_tic` using `fd_tempo_tick_per_ns` for calibration during initialization.
    - Check for the presence of `--bench` and `--sankey` flags in the command-line arguments and set `with_bench` and `with_sankey` accordingly.
    - Validate the extracted values: ensure `dt_min` is positive, `dt_max` is at least `dt_min`, and `duration` is non-negative, logging errors if any conditions are violated.
- **Output**: The function does not return a value but modifies the `args` structure to store the parsed and validated monitoring parameters.


---
### tile\_total\_ticks<!-- {{#callable:tile_total_ticks}} -->
The `tile_total_ticks` function calculates the total number of ticks across all regimes for a given tile snapshot.
- **Inputs**:
    - `snap`: A pointer to a `tile_snap_t` structure, which contains an array of regime tick counts for a tile.
- **Control Flow**:
    - Initialize a variable `total` to 0.
    - Iterate over the `regime_ticks` array in the `snap` structure, which has 9 elements.
    - For each element in the `regime_ticks` array, add its value to `total`.
    - Return the accumulated `total` value.
- **Output**: The function returns an `ulong` representing the sum of all regime ticks in the `regime_ticks` array of the `tile_snap_t` structure.


---
### tile\_snap<!-- {{#callable:tile_snap}} -->
The `tile_snap` function captures a snapshot of metrics for each tile in a topology, updating the provided snapshot array with current metrics data.
- **Inputs**:
    - `snap_cur`: A pointer to an array of `tile_snap_t` structures where the snapshot data for each tile will be stored.
    - `topo`: A constant pointer to an `fd_topo_t` structure representing the topology of tiles to be monitored.
- **Control Flow**:
    - Iterates over each tile in the topology using a loop indexed by `tile_idx`.
    - For each tile, retrieves the corresponding `tile_snap_t` structure from the `snap_cur` array.
    - Accesses the tile's metrics using the `fd_metrics_tile` function and updates the `heartbeat` field in the snapshot.
    - Registers the tile's metrics using `fd_metrics_register`.
    - Uses memory fence operations (`FD_COMPILER_MFENCE`) to ensure memory consistency before and after updating certain fields.
    - Updates various fields in the snapshot structure such as `pid`, `nvcsw`, `nivcsw`, `in_backp`, and `backp_cnt` using macros like `FD_MGAUGE_GET` and `FD_MCNT_GET`.
    - Iterates over a fixed range (0 to 8) to update the `regime_ticks` array in the snapshot with regime duration metrics.
- **Output**: The function does not return a value; it updates the `snap_cur` array with the current metrics for each tile.


---
### find\_producer\_out\_idx<!-- {{#callable:find_producer_out_idx}} -->
The `find_producer_out_idx` function identifies the index of a specified consumer in the list of reliable consumers for a producer's primary output.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology of tiles.
    - `producer`: A pointer to an `fd_topo_tile_t` structure representing the producer tile.
    - `consumer`: A pointer to an `fd_topo_tile_t` structure representing the consumer tile.
    - `consumer_in_idx`: An unsigned long integer representing the index of the consumer's input link.
- **Control Flow**:
    - Initialize `reliable_cons_cnt` to 0 to count reliable consumers.
    - Iterate over each tile in the topology using a loop indexed by `i`.
    - For each tile, iterate over its input links using a loop indexed by `j`.
    - For each input link, iterate over the producer's output links using a loop indexed by `k`.
    - Check if the current consumer's input link ID matches the producer's output link ID and if the link is reliable.
    - If the current consumer matches the specified consumer and input index, return the current count of reliable consumers.
    - If not, increment the `reliable_cons_cnt`.
    - If no match is found after all iterations, return `ULONG_MAX`.
- **Output**: Returns the index of the specified consumer in the list of reliable consumers, or `ULONG_MAX` if not found.


---
### link\_snap<!-- {{#callable:link_snap}} -->
The `link_snap` function captures and updates diagnostic snapshots of link metrics for each input link in a topology.
- **Inputs**:
    - `snap_cur`: A pointer to an array of `link_snap_t` structures where the current snapshot of link metrics will be stored.
    - `topo`: A constant pointer to an `fd_topo_t` structure representing the topology of the system, which contains information about tiles and links.
- **Control Flow**:
    - Initialize `link_idx` to 0 to track the current link index in the snapshot array.
    - Iterate over each tile in the topology using `tile_idx`.
    - For each tile, iterate over its input links using `in_idx`.
    - For each input link, retrieve the corresponding `link_snap_t` structure from `snap_cur` using `link_idx`.
    - Retrieve the metadata cache (`mcache`) for the current link and query its sequence number, storing it in `snap->mcache_seq`.
    - Query the forward sequence (`fseq`) for the current link and store it in `snap->fseq_seq`.
    - If the link is polled, retrieve the input metrics and store them in `in_metrics`.
    - Find the producer of the current link and ensure it is valid.
    - If the link is reliable, find the producer's output metrics and store them in `out_metrics`.
    - Use memory fences (`FD_COMPILER_MFENCE`) to ensure memory consistency.
    - If input metrics are available, update the snapshot with various diagnostic counters from `in_metrics`; otherwise, set these counters to zero.
    - If output metrics are available, update the snapshot with the slow count from `out_metrics`; otherwise, set it to zero.
    - Update the total count and size diagnostics by adding the filtered count and size.
    - Increment `link_idx` to move to the next link in the snapshot array.
- **Output**: The function does not return a value; it updates the `snap_cur` array with the current state of link metrics for each input link in the topology.
- **Functions called**:
    - [`find_producer_out_idx`](#find_producer_out_idx)


---
### write\_stdout<!-- {{#callable:write_stdout}} -->
The `write_stdout` function writes a specified buffer to the standard output (stdout) in a loop until the entire buffer is written, handling interruptions and errors appropriately.
- **Inputs**:
    - `buf`: A pointer to the buffer containing the data to be written to stdout.
    - `buf_sz`: The size of the buffer, indicating the total number of bytes to be written.
- **Control Flow**:
    - Initialize `written` to 0 and `total` to `buf_sz` to track the number of bytes written and the total bytes to write, respectively.
    - Enter a while loop that continues until `written` is less than `total`.
    - Within the loop, call `write` to write data from the buffer to stdout, starting from the current position (`buf + written`) and attempting to write the remaining bytes (`total - written`).
    - Check if the `write` call returns a negative value, indicating an error.
    - If the error is `EINTR`, continue the loop to retry the write operation.
    - If the error is not `EINTR`, log an error message and exit the loop.
    - If the write is successful, add the number of bytes written (`n`) to `written` to update the progress.
- **Output**: The function does not return a value; it writes the buffer to stdout and handles any errors internally.


---
### drain\_to\_buffer<!-- {{#callable:drain_to_buffer}} -->
The `drain_to_buffer` function reads data from a file descriptor into a buffer, processing each line and ensuring the buffer is managed correctly to handle newline characters and buffer overflows.
- **Inputs**:
    - `buf`: A pointer to a character buffer where the read data will be stored.
    - `buf_sz`: A pointer to an unsigned long representing the size of the buffer.
    - `fd`: An integer file descriptor from which data will be read.
- **Control Flow**:
    - The function enters an infinite loop to continuously read data from the file descriptor `fd` into a temporary buffer `buffer2` with a size specified by `*buf_sz`.
    - If the `read` call returns -1 and `errno` is `EAGAIN`, the loop breaks, indicating no data is available.
    - If `read` returns -1 for any other reason, an error is logged and the function exits.
    - The function searches for newline characters in the read data using `memchr`.
    - For each line found, it checks if the current buffer has enough space to store the line; if not, it writes the current buffer to stdout and resets the buffer pointers.
    - The line is copied to the buffer, and a newline character is appended, managing the buffer size accordingly.
    - The process repeats for each line until all data is processed.
- **Output**: The function does not return a value; it modifies the buffer and buffer size in place, and writes to stdout if necessary.
- **Functions called**:
    - [`write_stdout`](#write_stdout)


---
### restore\_terminal<!-- {{#callable:restore_terminal}} -->
The `restore_terminal` function restores the terminal settings to their previous state using the `termios_backup` structure.
- **Inputs**: None
- **Control Flow**:
    - The function calls `tcsetattr` with `STDIN_FILENO`, `TCSANOW`, and `&termios_backup` to restore terminal settings.
    - The function does not handle any errors explicitly, as it casts the return value of `tcsetattr` to void.
- **Output**: The function does not return any value.


---
### run\_monitor<!-- {{#callable:run_monitor}} -->
The `run_monitor` function continuously monitors and logs diagnostic snapshots of a system's topology, including tiles and links, over a specified duration, with options for output formatting and additional metrics.
- **Inputs**:
    - `config`: A pointer to a `config_t` structure containing the system's topology and configuration settings.
    - `drain_output_fd`: An integer file descriptor for draining output, typically used for logging.
    - `with_sankey`: An integer flag indicating whether to include Sankey diagram metrics in the output.
    - `dt_min`: A long integer specifying the minimum time interval between diagnostic snapshots in nanoseconds.
    - `dt_max`: A long integer specifying the maximum time interval between diagnostic snapshots in nanoseconds.
    - `duration`: A long integer specifying the total duration for monitoring in nanoseconds.
    - `seed`: An unsigned integer used to seed the random number generator for timing intervals.
    - `ns_per_tic`: A double representing the number of nanoseconds per tic, used for timing calculations.
- **Control Flow**:
    - Initialize random number generator with the provided seed.
    - Allocate memory for previous and current snapshots of tiles and links based on the topology configuration.
    - Take initial diagnostic snapshots of tiles and links and record the current time.
    - Enter a loop that continues until the specified duration has elapsed or a stop condition is met.
    - Within the loop, wait for a randomized interval between `dt_min` and `dt_max` before taking new snapshots.
    - Compare the current and previous snapshots, and format the results for output.
    - Handle terminal input to switch between different output panes or exit the loop.
    - If `with_sankey` is enabled, calculate and print additional metrics related to transaction flow.
    - Write the formatted output to the standard output.
    - Swap the current and previous snapshot buffers for the next iteration.
- **Output**: The function does not return a value; it outputs formatted diagnostic information to the terminal and logs.
- **Functions called**:
    - [`tile_snap`](#tile_snap)
    - [`link_snap`](#link_snap)
    - [`drain_to_buffer`](#drain_to_buffer)
    - [`write_stdout`](#write_stdout)
    - [`fd_getchar`](helper.c.driver.md#fd_getchar)
    - [`printf_stale`](helper.c.driver.md#printf_stale)
    - [`printf_heart`](helper.c.driver.md#printf_heart)
    - [`printf_err_cnt`](helper.c.driver.md#printf_err_cnt)
    - [`printf_err_bool`](helper.c.driver.md#printf_err_bool)
    - [`printf_pct`](helper.c.driver.md#printf_pct)
    - [`tile_total_ticks`](#tile_total_ticks)
    - [`printf_rate`](helper.c.driver.md#printf_rate)
    - [`printf_seq`](helper.c.driver.md#printf_seq)


---
### signal1<!-- {{#callable:signal1}} -->
The `signal1` function handles a signal by ignoring its argument and gracefully terminating the program.
- **Inputs**:
    - `sig`: An integer representing the signal number that triggered the handler.
- **Control Flow**:
    - The function takes an integer `sig` as an argument, which represents the signal number.
    - The function explicitly ignores the `sig` argument by casting it to void.
    - The function calls `exit(0)` to terminate the program gracefully.
- **Output**: The function does not return a value; it terminates the program with an exit status of 0.


---
### monitor\_cmd\_fn<!-- {{#callable:monitor_cmd_fn}} -->
The `monitor_cmd_fn` function sets up and runs a monitoring process for a Firedancer instance, handling signal actions, configuring file descriptors, and managing sandboxing and security policies.
- **Inputs**:
    - `args`: A pointer to an `args_t` structure containing command-line arguments and monitoring options.
    - `config`: A pointer to a `config_t` structure containing configuration settings for the Firedancer instance.
- **Control Flow**:
    - Check if benchmarking is enabled in the arguments and add the benchmark topology if necessary.
    - Set up signal handlers for SIGTERM and SIGINT to ensure graceful termination.
    - Initialize an array of allowed file descriptors, including standard input/output and any specified log file descriptors.
    - Join the topology workspaces in read-only mode.
    - Populate a seccomp filter policy for monitoring with specified file descriptors.
    - Close the log lock file descriptor from the configuration.
    - Enter a sandbox environment if sandboxing is enabled, otherwise switch user and group IDs.
    - Fill the topology configuration with necessary data.
    - Invoke the [`run_monitor`](#run_monitor) function to start the monitoring process with the specified configuration and arguments.
    - Exit the process gracefully.
- **Output**: The function does not return a value; it exits the process after setting up and running the monitoring process.
- **Functions called**:
    - [`populate_sock_filter_policy_monitor`](generated/monitor_seccomp.h.driver.md#populate_sock_filter_policy_monitor)
    - [`run_monitor`](#run_monitor)


