# Purpose
This C source code file is designed to manage and monitor context switch metrics for a set of processes, referred to as "tiles," within a system. The code is structured to be part of a larger application, likely a performance monitoring or resource management tool, as it includes functionality to track voluntary and involuntary context switches for each tile. The file defines a structure `fd_cswtch_ctx_t` to maintain context-specific data, such as the number of tiles, file descriptors for status monitoring, and metrics pointers. The code includes functions for initializing this context in both privileged and unprivileged modes, suggesting it is intended to operate in environments with varying levels of access control.

The file also integrates with a broader system through the use of external headers and includes, such as `fd_metrics.h`, `fd_stem.h`, and `fd_topo.h`, indicating its reliance on external libraries or modules for metrics and topology management. The code defines several static functions to handle initialization, context switching, and reporting, and it uses system calls to interact with the `/proc` filesystem to gather process status information. Additionally, the file sets up security policies and file descriptor management, which are crucial for maintaining the integrity and performance of the monitoring system. The `fd_tile_cswtch` structure at the end of the file encapsulates the functionality provided by this code, making it a modular component that can be integrated into a larger application framework.
# Imports and Dependencies

---
- `../metrics/fd_metrics.h`
- `../stem/fd_stem.h`
- `../topo/fd_topo.h`
- `fcntl.h`
- `errno.h`
- `sys/types.h`
- `time.h`
- `unistd.h`
- `generated/fd_cswtch_tile_seccomp.h`
- `../../disco/stem/fd_stem.c`


# Global Variables

---
### fd\_tile\_cswtch
- **Type**: `fd_topo_run_tile_t`
- **Description**: The `fd_tile_cswtch` is a global variable of type `fd_topo_run_tile_t`, which is a structure used to define the configuration and behavior of a tile in a topology. This structure includes function pointers for initialization, running, and resource management specific to context switching metrics collection.
- **Use**: This variable is used to configure and manage a tile responsible for collecting and reporting context switch metrics in a distributed system.


# Data Structures

---
### fd\_cswtch\_ctx\_t
- **Type**: `struct`
- **Members**:
    - `next_report_nanos`: Stores the time in nanoseconds for the next report to be generated.
    - `tile_cnt`: Represents the count of tiles being monitored.
    - `first_seen_died`: An array that records the first time a tile was detected as dead.
    - `status_fds`: An array of file descriptors for reading the status of each tile.
    - `metrics`: An array of pointers to metrics data for each tile.
- **Description**: The `fd_cswtch_ctx_t` structure is designed to manage context switch metrics for a set of tiles in a system. It keeps track of the timing for the next report, the number of tiles, and maintains arrays to monitor the status and metrics of each tile. The structure is used to facilitate the collection and reporting of context switch data, ensuring that the system can respond to changes in tile status efficiently.


# Functions

---
### scratch\_align<!-- {{#callable:scratch_align}} -->
The `scratch_align` function returns a constant alignment value of 128 bytes.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended for use only within the file it is defined and suggests inlining for performance.
    - The function does not take any parameters.
    - It simply returns the constant value 128UL, which represents an alignment size in bytes.
- **Output**: The function returns an unsigned long integer value of 128, representing the alignment size.


---
### scratch\_footprint<!-- {{#callable:scratch_footprint}} -->
The `scratch_footprint` function calculates the memory footprint required for a context switch context structure, aligned to a specific boundary.
- **Inputs**:
    - `tile`: A pointer to a `fd_topo_tile_t` structure, which is not used in the function.
- **Control Flow**:
    - The function begins by initializing a layout variable `l` with `FD_LAYOUT_INIT`.
    - It then appends the size and alignment of the `fd_cswtch_ctx_t` structure to `l` using `FD_LAYOUT_APPEND`.
    - Finally, it finalizes the layout with `FD_LAYOUT_FINI`, aligning it to the value returned by `scratch_align()`, and returns the result.
- **Output**: The function returns an `ulong` representing the calculated memory footprint for the context switch context structure, aligned to the specified boundary.
- **Functions called**:
    - [`scratch_align`](#scratch_align)


---
### before\_credit<!-- {{#callable:before_credit}} -->
The `before_credit` function checks the current time against a scheduled report time, updates context switch metrics for each tile, and handles process status checks.
- **Inputs**:
    - `ctx`: A pointer to a `fd_cswtch_ctx_t` structure containing context information such as next report time, tile count, file descriptors, and metrics.
    - `mux`: A pointer to a `fd_stem_context_t` structure, which is not used in this function.
    - `charge_busy`: A pointer to an integer that is set to 1 if the function performs any work, indicating that the system is busy.
- **Control Flow**:
    - Retrieve the current wall clock time using `fd_log_wallclock()`.
    - If the current time is less than the next scheduled report time, calculate the difference, sleep for the minimum of this difference or 2 milliseconds, and return.
    - Update the next report time by adding a predefined interval.
    - Set `charge_busy` to 1 to indicate that the function is performing work.
    - Iterate over each tile in the context (`ctx->tile_cnt`).
    - For each tile, reset the file descriptor offset using `lseek` and read the status file into a buffer.
    - If the read fails due to a missing process, handle the process death by logging a warning if necessary and continue to the next tile.
    - Parse the buffer for voluntary and involuntary context switch metrics, updating the context's metrics array.
    - Log an error if expected metrics are not found in the buffer.
- **Output**: The function does not return a value but updates the `charge_busy` flag and the context's metrics for each tile.


---
### privileged\_init<!-- {{#callable:privileged_init}} -->
The `privileged_init` function initializes context switching metrics for a set of tiles in a topology by opening status file descriptors for each tile's process and thread IDs.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology of tiles.
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing the specific tile to initialize.
- **Control Flow**:
    - Retrieve the local address of the tile object using `fd_topo_obj_laddr` and store it in `scratch`.
    - Initialize a scratch allocator with `FD_SCRATCH_ALLOC_INIT` using the `scratch` pointer.
    - Allocate memory for a `fd_cswtch_ctx_t` context structure using `FD_SCRATCH_ALLOC_APPEND`.
    - Check if the number of tiles in the topology is less than `FD_TILE_MAX` using `FD_TEST`.
    - Set the `tile_cnt` in the context to the number of tiles in the topology.
    - Iterate over each tile in the topology to initialize metrics and status file descriptors.
    - For each tile, retrieve the metrics object address and join it using `fd_metrics_join`.
    - Determine the process ID (PID) and thread ID (TID) for the current tile; if the tile matches the current tile ID, use `fd_sandbox_getpid` and `fd_sandbox_gettid`, otherwise retrieve from metrics.
    - Construct the path to the status file in `/proc` using `fd_cstr_printf_check`.
    - Open the status file for reading and store the file descriptor in `ctx->status_fds`.
    - Store the metrics pointer in `ctx->metrics`.
    - If opening the status file fails, log an error and exit.
- **Output**: The function does not return a value; it initializes the context structure for context switching metrics.


---
### unprivileged\_init<!-- {{#callable:unprivileged_init}} -->
The `unprivileged_init` function initializes a context for unprivileged operations by setting up a scratch memory area and preparing a context switch tracking structure.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology configuration.
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing the specific tile configuration.
- **Control Flow**:
    - Retrieve a scratch memory address using `fd_topo_obj_laddr` with the topology and tile object ID.
    - Initialize the scratch memory allocation using `FD_SCRATCH_ALLOC_INIT`.
    - Allocate memory for a `fd_cswtch_ctx_t` context structure within the scratch space using `FD_SCRATCH_ALLOC_APPEND`.
    - Set all elements of the `first_seen_died` array in the context to zero using `memset`.
    - Set the `next_report_nanos` field in the context to the current wall clock time using `fd_log_wallclock`.
    - Finalize the scratch memory allocation with `FD_SCRATCH_ALLOC_FINI` and check for overflow against the calculated scratch footprint.
    - Log an error if the scratch memory allocation exceeds the available footprint.
- **Output**: The function does not return a value; it initializes a context structure in the provided scratch memory space.
- **Functions called**:
    - [`scratch_footprint`](#scratch_footprint)


---
### populate\_allowed\_seccomp<!-- {{#callable:populate_allowed_seccomp}} -->
The `populate_allowed_seccomp` function populates a seccomp filter policy for a given tile and returns the instruction count of the policy.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure representing the topology, which is not used in this function.
    - `tile`: A pointer to a constant `fd_topo_tile_t` structure representing the tile, which is not used in this function.
    - `out_cnt`: An unsigned long integer representing the count of output seccomp filter instructions.
    - `out`: A pointer to a `struct sock_filter` array where the seccomp filter policy will be populated.
- **Control Flow**:
    - The function begins by explicitly ignoring the `topo` and `tile` parameters, indicating they are not used in the function body.
    - It calls the [`populate_sock_filter_policy_fd_cswtch_tile`](generated/fd_cswtch_tile_seccomp.h.driver.md#populate_sock_filter_policy_fd_cswtch_tile) function with `out_cnt`, `out`, and the file descriptor obtained from `fd_log_private_logfile_fd()` to populate the seccomp filter policy.
    - The function returns the value of `sock_filter_policy_fd_cswtch_tile_instr_cnt`, which presumably represents the number of instructions in the seccomp filter policy.
- **Output**: The function returns an unsigned long integer representing the number of instructions in the seccomp filter policy.
- **Functions called**:
    - [`populate_sock_filter_policy_fd_cswtch_tile`](generated/fd_cswtch_tile_seccomp.h.driver.md#populate_sock_filter_policy_fd_cswtch_tile)


---
### populate\_allowed\_fds<!-- {{#callable:populate_allowed_fds}} -->
The `populate_allowed_fds` function populates an array with file descriptors that are allowed for a specific tile in a topology, including standard error, a log file, and status descriptors for each tile.
- **Inputs**:
    - `topo`: A pointer to a `fd_topo_t` structure representing the topology of the system.
    - `tile`: A pointer to a `fd_topo_tile_t` structure representing the specific tile within the topology.
    - `out_fds_cnt`: An unsigned long integer representing the maximum number of file descriptors that can be stored in the `out_fds` array.
    - `out_fds`: A pointer to an integer array where the allowed file descriptors will be stored.
- **Control Flow**:
    - Retrieve a scratch memory address using `fd_topo_obj_laddr` with the given topology and tile object ID.
    - Initialize a scratch allocator with `FD_SCRATCH_ALLOC_INIT`.
    - Allocate memory for a `fd_cswtch_ctx_t` context structure using `FD_SCRATCH_ALLOC_APPEND`.
    - Check if `out_fds_cnt` is less than the required number of file descriptors (2 plus the number of tiles in the context), and log an error if so.
    - Initialize `out_cnt` to 0 and set the first file descriptor in `out_fds` to 2 (standard error).
    - If a log file descriptor is available, add it to `out_fds`.
    - Iterate over each tile in the context and add its status file descriptor to `out_fds`.
    - Return the total number of file descriptors added to `out_fds`.
- **Output**: Returns the number of file descriptors that were successfully populated into the `out_fds` array.


