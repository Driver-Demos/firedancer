# Purpose
This C source code file is designed to manage and execute "tiles" within a topology, likely in a distributed or parallel computing environment. The code provides functionality to initialize, configure, and run these tiles, which are units of computation or processing. The file includes functions for setting up logging, handling debugger attachment, and managing thread execution for tiles. It also includes mechanisms for sandboxing processes, which involves setting resource limits and security policies to isolate the execution environment of each tile. The code is structured to handle both privileged and unprivileged initialization of tiles, and it supports the use of dynamic analysis tools by providing alternative stack management functions.

The file is not a standalone executable but rather a component of a larger system, as indicated by its inclusion of multiple headers and its focus on providing specific functionalities related to tile management. It defines several internal functions and structures, such as [`fd_topo_run_tile`](#fd_topo_run_tile) and `fd_topo_run_thread_args_t`, which are used to manage the lifecycle of tiles, including their initialization, execution, and resource management. The code also includes provisions for integrating with eXpress Data Path (XDP) for network packet processing, suggesting its use in high-performance networking applications. Overall, the file is a specialized component that facilitates the execution and management of computational tiles within a larger distributed system.
# Imports and Dependencies

---
- `fd_topo.h`
- `../metrics/fd_metrics.h`
- `../../waltz/xdp/fd_xdp1.h`
- `../../util/tile/fd_tile_private.h`
- `unistd.h`
- `signal.h`
- `errno.h`
- `pthread.h`
- `sys/syscall.h`
- `linux/futex.h`
- `sys/resource.h`
- `sys/prctl.h`
- `sys/stat.h`
- `sys/mman.h`
- `net/if.h`


# Data Structures

---
### fd\_topo\_run\_thread\_args\_t
- **Type**: `struct`
- **Members**:
    - `topo`: A pointer to an fd_topo_t structure, representing the topology.
    - `tile`: A pointer to an fd_topo_tile_t structure, representing a specific tile in the topology.
    - `tile_run`: An fd_topo_run_tile_t structure, containing run-time configuration for the tile.
    - `uid`: An unsigned integer representing the user ID for the thread.
    - `gid`: An unsigned integer representing the group ID for the thread.
    - `done_futex`: A pointer to an integer used as a futex for synchronization.
    - `copied`: A volatile integer indicating whether the structure has been copied.
    - `stack_lo`: A pointer to the lower bound of the stack memory for the thread.
    - `stack_hi`: A pointer to the upper bound of the stack memory for the thread.
- **Description**: The `fd_topo_run_thread_args_t` structure is used to encapsulate the arguments required to run a thread in a specific topology context. It includes pointers to the topology and tile structures, run-time configuration for the tile, user and group IDs for permission management, a futex for synchronization, and pointers defining the stack boundaries for the thread. This structure is essential for managing the execution of threads within a defined topology, ensuring proper resource allocation and synchronization.


# Functions

---
### initialize\_logging<!-- {{#callable:initialize_logging}} -->
The `initialize_logging` function sets up logging for a specific tile by configuring CPU, thread, and stack settings, and logs a notice about the tile's booting process.
- **Inputs**:
    - `tile_name`: A constant character pointer representing the name of the tile.
    - `tile_kind_id`: An unsigned long integer representing the kind ID of the tile.
    - `pid`: An unsigned long integer representing the process ID.
    - `tid`: An unsigned long integer representing the thread ID.
- **Control Flow**:
    - Call `fd_log_cpu_set` with a NULL argument to set the CPU for logging.
    - Set the private thread ID for logging using `fd_log_private_tid_set` with the given `pid`.
    - Declare a character array `thread_name` of size 20 to store the formatted thread name.
    - Use `fd_cstr_printf_check` to format the `thread_name` with the `tile_name` and `tile_kind_id`, and check for success with `FD_TEST`.
    - Set the thread name for logging using `fd_log_thread_set` with the formatted `thread_name`.
    - Discover the private stack for logging using `fd_log_private_stack_discover` with predefined stack size and stack pointers.
    - Log a notice message indicating the booting of the tile with its name, process ID, and thread ID using `FD_LOG_NOTICE`.
- **Output**: The function does not return any value; it performs logging setup and outputs a notice log message.


---
### check\_wait\_debugger<!-- {{#callable:check_wait_debugger}} -->
The `check_wait_debugger` function checks if a debugger should attach to a process and waits for a signal to proceed if required.
- **Inputs**:
    - `pid`: The process ID of the tile for which the debugger check is being performed.
    - `wait`: A pointer to a volatile integer that indicates whether the process should wait before proceeding.
    - `debugger`: A pointer to a volatile integer that indicates whether a debugger should attach to the process.
- **Control Flow**:
    - Check if the `debugger` pointer is non-null using `FD_UNLIKELY` macro.
    - If `debugger` is non-null, log a warning message indicating that the process is waiting for a debugger to attach.
    - Attempt to stop the process using `kill(getpid(), SIGSTOP)` and log an error if it fails.
    - Set the value pointed to by `debugger` to 1, indicating that the debugger has attached.
    - Check if the `wait` pointer is non-null using `FD_UNLIKELY` macro.
    - If `wait` is non-null, enter a loop that continuously checks the value pointed to by `wait` using `FD_VOLATILE` and pauses using `FD_SPIN_PAUSE` until the value becomes non-zero.
- **Output**: The function does not return a value; it modifies the values pointed to by `wait` and `debugger` as side effects.


---
### fd\_topo\_run\_tile<!-- {{#callable:fd_topo_run_tile}} -->
The `fd_topo_run_tile` function initializes and runs a tile within a topology, potentially within a sandboxed environment, handling various setup tasks such as logging, memory mapping, and security configurations.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology in which the tile is to be run.
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing the tile to be run.
    - `sandbox`: An integer flag indicating whether the tile should be run in a sandboxed environment.
    - `keep_controlling_terminal`: An integer flag indicating whether to keep the controlling terminal.
    - `dumpable`: An integer flag indicating whether the process should be dumpable.
    - `uid`: A `uint` representing the user ID to be used in the sandbox.
    - `gid`: A `uint` representing the group ID to be used in the sandbox.
    - `allow_fd`: An integer representing a file descriptor that is allowed in the sandbox.
    - `wait`: A volatile integer pointer used to indicate whether the function should wait for a debugger.
    - `debugger`: A volatile integer pointer used to indicate whether a debugger is attached.
    - `tile_run`: A pointer to an `fd_topo_run_tile_t` structure containing function pointers and configuration for running the tile.
- **Control Flow**:
    - Set the thread name using the tile's name and kind ID, and log an error if setting the name fails.
    - Retrieve the process ID (PID) and thread ID (TID) after a potential clone operation.
    - Check if the function should wait for a debugger to attach and initialize logging with the tile's details.
    - Preload shared memory by joining tile workspaces before entering a sandbox.
    - If a privileged initialization function is provided, call it with the topology and tile.
    - Prepare an array of allowed file descriptors, including any specified by `allow_fd`, and populate it using a provided function if available.
    - Prepare a seccomp filter array and populate it using a provided function if available.
    - Determine the file descriptor limit using a provided function if available, otherwise use a default value.
    - If sandboxing is enabled, enter the sandbox with the specified configurations, otherwise switch the user and group IDs.
    - Join all inter-process communication objects in the tile's workspaces after entering the sandbox.
    - Register the tile's metrics and set process and thread IDs in the metrics gauge.
    - If an unprivileged initialization function is provided, call it with the topology and tile.
    - Run the tile using the provided run function and log an error if the run loop returns.
- **Output**: The function does not return a value; it performs its operations and logs an error if the tile run loop returns unexpectedly.
- **Functions called**:
    - [`check_wait_debugger`](#check_wait_debugger)
    - [`initialize_logging`](#initialize_logging)
    - [`fd_topo_join_tile_workspaces`](fd_topo.c.driver.md#fd_topo_join_tile_workspaces)
    - [`fd_topo_fill_tile`](fd_topo.c.driver.md#fd_topo_fill_tile)


---
### run\_tile\_thread\_main<!-- {{#callable:run_tile_thread_main}} -->
The `run_tile_thread_main` function initializes a thread to run a tile in a topology, ensuring stack safety and synchronization with a futex.
- **Inputs**:
    - `_args`: A pointer to `fd_topo_run_thread_args_t` structure containing arguments for running the tile thread, including topology, tile, user and group IDs, done futex, and stack boundaries.
- **Control Flow**:
    - The function begins by copying the input arguments from `_args` to a local `args` variable and sets a memory fence to ensure memory operations are completed before proceeding.
    - It marks the `copied` field in the original `_args` structure to indicate that the arguments have been copied.
    - The function uses `madvise` to prevent the stack from being copied during a fork operation, logging an error if this fails.
    - It calls [`fd_topo_run_tile`](#fd_topo_run_tile) to execute the tile with the provided arguments, including topology, tile, user and group IDs, and tile run configuration.
    - If a `done_futex` is provided, the function enters a loop to atomically compare and swap the futex value until it matches the tile ID, pausing between attempts.
    - After successfully updating the futex, it uses a syscall to wake any threads waiting on the futex, logging an error if this fails.
    - If no `done_futex` is provided, it logs an error indicating that [`fd_topo_run_tile`](#fd_topo_run_tile) returned unexpectedly.
- **Output**: The function returns `NULL` after completing the tile execution and synchronization operations.
- **Functions called**:
    - [`fd_topo_run_tile`](#fd_topo_run_tile)


---
### fd\_topo\_tile\_stack\_join\_anon<!-- {{#callable:fd_topo_tile_stack_join_anon}} -->
The function `fd_topo_tile_stack_join_anon` allocates a private anonymous memory region for a stack with guard regions to prevent memory corruption during fork operations.
- **Inputs**: None
- **Control Flow**:
    - Initialize the stack size `sz` to twice the size of `FD_TILE_PRIVATE_STACK_SZ` and set memory protection `prot` to read and write, and flags `flags` to private, anonymous, and stack.
    - Attempt to allocate memory using `mmap` with huge pages if AddressSanitizer (ASAN) and MemorySanitizer (MSAN) are not enabled.
    - If the initial `mmap` call fails, attempt to allocate memory again without huge pages.
    - If the second `mmap` call fails, log an error and terminate the program.
    - Create a lower guard region by mapping a page with no access permissions just below the allocated stack memory.
    - Create an upper guard region by mapping a page with no access permissions just above the allocated stack memory.
- **Output**: Returns a pointer to the allocated stack memory.


---
### fd\_topo\_tile\_stack\_join<!-- {{#callable:fd_topo_tile_stack_join}} -->
The `fd_topo_tile_stack_join` function joins a shared memory stack for a tile, setting up guard regions to protect the stack boundaries.
- **Inputs**:
    - `app_name`: The name of the application, used to construct the shared memory stack name.
    - `tile_name`: The name of the tile, used to construct the shared memory stack name.
    - `tile_kind_id`: The kind identifier for the tile, used to construct the shared memory stack name.
- **Control Flow**:
    - If the macro `FD_HAS_MSAN` is defined, the function returns the result of `fd_topo_tile_stack_join_anon()` to handle memory sanitization needs.
    - A stack name is constructed using `app_name`, `tile_name`, and `tile_kind_id` and checked for formatting errors.
    - The function attempts to join a shared memory segment with the constructed name in read-write mode using `fd_shmem_join`.
    - If joining the shared memory fails, an error is logged and the function exits.
    - The function releases a portion of the shared memory to make space for guard regions using `fd_shmem_release`.
    - The stack pointer is adjusted to account for the released memory space.
    - Guard regions are created at the low and high ends of the stack using `mmap` with `PROT_NONE` to prevent access, ensuring stack overflow protection.
    - If any `mmap` operation fails, an error is logged and the function exits.
- **Output**: The function returns a pointer to the joined shared memory stack with guard regions set up.
- **Functions called**:
    - [`fd_topo_tile_stack_join_anon`](#fd_topo_tile_stack_join_anon)


---
### fd\_topo\_install\_xdp<!-- {{#callable:fd_topo_install_xdp}} -->
The `fd_topo_install_xdp` function installs an XDP (eXpress Data Path) program on a network interface specified in the topology and binds it to a given address, managing file descriptors for the XDP socket and program link.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure representing the network topology.
    - `bind_addr`: An unsigned integer representing the address to bind the XDP program to.
- **Control Flow**:
    - Finds the index of the first tile with the name 'net' in the topology using [`fd_topo_find_tile`](fd_topo.h.driver.md#fd_topo_find_tile) and checks if it is valid.
    - Retrieves the network tile from the topology using the found index.
    - Creates an array of UDP port candidates from the network tile's configuration.
    - Retrieves the network interface index using `if_nametoindex` and logs an error if it fails.
    - Calls `fd_xdp_install` to install the XDP program on the network interface with the specified bind address and UDP ports, storing the result in `xdp_fds`.
    - Duplicates the file descriptor for the XDP socket map to a fixed value (123462) and closes the original, logging errors if any operation fails.
    - Duplicates the file descriptor for the XDP program link to a fixed value (123463) and closes the original, logging errors if any operation fails.
    - Updates the `xdp_fds` structure with the new file descriptor values and returns it.
- **Output**: Returns an `fd_xdp_fds_t` structure containing file descriptors for the XDP socket map and program link.
- **Functions called**:
    - [`fd_topo_find_tile`](fd_topo.h.driver.md#fd_topo_find_tile)


---
### run\_tile\_thread<!-- {{#callable:run_tile_thread}} -->
The `run_tile_thread` function initializes and runs a thread for a specific tile in a topology, setting up its stack, CPU affinity, and priority, and then launching the thread with specific arguments.
- **Inputs**:
    - `topo`: A pointer to the topology structure (`fd_topo_t`) that contains information about the system's tiles.
    - `tile`: A pointer to the tile structure (`fd_topo_tile_t`) that represents the specific tile to be run.
    - `tile_run`: A structure (`fd_topo_run_tile_t`) containing the run configuration and functions for the tile.
    - `uid`: The user ID under which the thread should run.
    - `gid`: The group ID under which the thread should run.
    - `done_futex`: A pointer to an integer used as a futex for synchronization, indicating when the thread is done.
    - `floating_cpu_set`: A constant pointer to a CPU set structure (`fd_cpuset_t`) used when the tile's CPU index is not specified.
    - `floating_priority`: The priority to be set for the thread if the tile's CPU index is not specified.
- **Control Flow**:
    - Check if the tile is meant for a thread pool and return immediately if so.
    - Join the stack for the tile using [`fd_topo_tile_stack_join`](#fd_topo_tile_stack_join).
    - Initialize thread attributes and set the stack for the thread.
    - Determine the CPU affinity and priority based on the tile's CPU index.
    - Set the thread's CPU affinity using `fd_cpuset_setaffinity`.
    - Prepare the arguments for the thread function `run_tile_thread_main`.
    - Create the thread using `pthread_create` with the prepared attributes and arguments.
    - Wait for the thread to signal that it has copied its arguments by spinning on `args.copied`.
- **Output**: The function does not return a value; it sets up and starts a thread for a tile, handling errors internally.
- **Functions called**:
    - [`fd_topo_tile_stack_join`](#fd_topo_tile_stack_join)


---
### fd\_topo\_run\_single\_process<!-- {{#callable:fd_topo_run_single_process}} -->
The `fd_topo_run_single_process` function manages the execution of tiles in a topology, adjusting CPU affinity and priority, and running each tile in a separate thread.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology containing the tiles to be run.
    - `agave`: An integer flag indicating whether to run only agave tiles (1), non-agave tiles (0), or all tiles (any other value).
    - `uid`: A user ID to switch to after running the tiles.
    - `gid`: A group ID to switch to after running the tiles.
    - `tile_run`: A function pointer that takes a constant pointer to an `fd_topo_tile_t` and returns an `fd_topo_run_tile_t` structure, which contains the run configuration for a tile.
    - `done_futex`: A pointer to an integer used as a futex for synchronization purposes, indicating when a tile has completed execution.
- **Control Flow**:
    - Save the current CPU affinity and priority to restore them later.
    - Iterate over each tile in the topology.
    - Check if the tile should be run based on the `agave` flag and the tile's `is_agave` property.
    - For each tile to be run, obtain the run configuration using the `tile_run` function pointer.
    - Call [`run_tile_thread`](#run_tile_thread) to execute the tile in a separate thread, passing the necessary parameters including the saved CPU affinity and priority.
    - Switch the process's user and group ID to the specified `uid` and `gid`.
    - Restore the original process priority and CPU affinity.
- **Output**: The function does not return a value; it performs its operations as side effects, primarily running tiles in separate threads and managing process attributes.
- **Functions called**:
    - [`run_tile_thread`](#run_tile_thread)


