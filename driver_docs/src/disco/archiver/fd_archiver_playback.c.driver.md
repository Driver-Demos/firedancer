# Purpose
The provided C source code file is designed to implement an "archiver playback tile" within a larger system, likely a distributed or networked application. This component is responsible for reading data from an archive file and replaying it with precise timing to simulate the original data capture conditions. The replayed data is then forwarded to various receiver tiles, such as those handling shred, quic, gossip, and repair functionalities. The code ensures that the timing of the data replay matches the original capture by introducing artificial delays, thereby maintaining the integrity of the data flow and processing sequence as it was initially recorded.

Key technical components of this file include the definition of data structures for managing playback statistics and context, functions for initializing both privileged and unprivileged contexts, and mechanisms for handling data fragments during playback. The code also includes functions for setting up security policies and managing file descriptors, which are crucial for maintaining system security and resource management. The file is part of a larger system, as indicated by the inclusion of other headers and the use of external functions and macros. It defines a public API in the form of the `fd_tile_archiver_playback` structure, which encapsulates the functionality of the playback tile and provides an interface for integrating this component into the broader system.
# Imports and Dependencies

---
- `../tiles.h`
- `fd_archiver.h`
- `errno.h`
- `fcntl.h`
- `string.h`
- `sys/mman.h`
- `sys/stat.h`
- `unistd.h`
- `linux/unistd.h`
- `sys/socket.h`
- `linux/if_xdp.h`
- `generated/archiver_playback_seccomp.h`
- `../../util/pod/fd_pod_format.h`
- `../stem/fd_stem.c`


# Global Variables

---
### fd\_tile\_archiver\_playback
- **Type**: `fd_topo_run_tile_t`
- **Description**: The `fd_tile_archiver_playback` is a global variable of type `fd_topo_run_tile_t`, which is a structure that defines the configuration and behavior of a tile in a topology. This specific instance is configured for an archiver playback tile, which is responsible for consuming data from an archive file, adding artificial delays to mimic original capture timings, and forwarding data to receiver tiles.
- **Use**: This variable is used to configure and manage the execution of the archiver playback tile within the system's topology.


# Data Structures

---
### fd\_archiver\_playback\_stats
- **Type**: `struct`
- **Members**:
    - `net_shred_out_cnt`: Counts the number of network shred output fragments.
    - `net_quic_out_cnt`: Counts the number of network QUIC output fragments.
    - `net_gossip_out_cnt`: Counts the number of network gossip output fragments.
    - `net_repair_out_cnt`: Counts the number of network repair output fragments.
- **Description**: The `fd_archiver_playback_stats` structure is designed to keep track of various network output fragment counts during the playback process in an archiver system. It includes counters for different types of network outputs such as shred, QUIC, gossip, and repair, which are essential for monitoring and analyzing the performance and behavior of the archiver playback tile.


---
### fd\_archiver\_playback\_stats\_t
- **Type**: `struct`
- **Members**:
    - `net_shred_out_cnt`: Counts the number of network shred output fragments.
    - `net_quic_out_cnt`: Counts the number of network QUIC output fragments.
    - `net_gossip_out_cnt`: Counts the number of network gossip output fragments.
    - `net_repair_out_cnt`: Counts the number of network repair output fragments.
- **Description**: The `fd_archiver_playback_stats_t` structure is designed to keep track of various network output fragment counts during the playback of archived data. It includes counters for different types of network outputs such as shred, QUIC, gossip, and repair, which are essential for monitoring and analyzing the playback performance and ensuring the correct distribution of data fragments to the respective receiver tiles.


---
### fd\_archiver\_playback\_out\_ctx\_t
- **Type**: `struct`
- **Members**:
    - `mem`: A pointer to an fd_wksp_t structure, representing a memory workspace.
    - `mtu`: An unsigned long representing the maximum transmission unit size.
    - `chunk0`: An unsigned long representing the initial chunk index in the data cache.
    - `wmark`: An unsigned long representing the watermark for the data cache.
    - `chunk`: An unsigned long representing the current chunk index in the data cache.
- **Description**: The `fd_archiver_playback_out_ctx_t` structure is used to manage the context for output operations in the archiver playback process. It holds information about the memory workspace, maximum transmission unit, and data cache management, including initial and current chunk indices and watermark. This structure is essential for handling data fragments during playback, ensuring they are correctly managed and transmitted according to the specified parameters.


---
### fd\_archiver\_playback\_tile\_ctx
- **Type**: `struct`
- **Members**:
    - `istream`: A buffered input stream for reading data.
    - `istream_buf`: A buffer for the input stream.
    - `stats`: Playback statistics for the archiver.
    - `tick_per_ns`: Conversion factor from ticks to nanoseconds.
    - `prev_publish_time`: The previous time a fragment was published.
    - `now`: The current time in ticks.
    - `need_notify`: Flag indicating if notification is needed before playback.
    - `notified`: Flag indicating if notification has been received.
    - `out`: Array of output contexts for playback.
    - `alloc`: Pointer to an allocator for memory management.
    - `valloc`: Virtual allocator for managing memory allocations.
    - `playback_done`: Flag indicating if playback is complete.
    - `done_time`: Time when playback was completed.
    - `playback_started`: Flag indicating if playback has started.
    - `playback_cnt`: Array counting the number of playbacks for each tile.
    - `published_wmark`: Pointer to the published watermark, shared with the replay tile.
- **Description**: The `fd_archiver_playback_tile_ctx` structure is designed to manage the playback of archived data in a networked environment. It includes fields for handling input streams, managing playback statistics, and controlling the timing and notification of data playback. The structure also manages memory allocation through allocators and tracks the state of playback, including whether it has started or completed. Additionally, it maintains an array of output contexts to handle the distribution of data to different network links.


---
### fd\_archiver\_playback\_tile\_ctx\_t
- **Type**: `struct`
- **Members**:
    - `istream`: A buffered input stream for reading data.
    - `istream_buf`: A buffer for the input stream.
    - `stats`: Statistics related to the playback process.
    - `tick_per_ns`: Conversion factor from ticks to nanoseconds.
    - `prev_publish_time`: Timestamp of the previous publication.
    - `now`: Current time in ticks.
    - `need_notify`: Flag indicating if notification is needed before playback.
    - `notified`: Flag indicating if notification has been received.
    - `out`: Array of output contexts for different network links.
    - `alloc`: Pointer to a memory allocator.
    - `valloc`: Virtual memory allocator.
    - `playback_done`: Flag indicating if playback is complete.
    - `done_time`: Timestamp when playback was completed.
    - `playback_started`: Flag indicating if playback has started.
    - `playback_cnt`: Array counting the number of playbacks for each tile type.
    - `published_wmark`: Pointer to the watermark of published data.
- **Description**: The `fd_archiver_playback_tile_ctx_t` structure is designed to manage the context for playback operations in an archiver system. It handles input streams, maintains statistics, and manages timing for playback to ensure accurate reproduction of archived data. The structure includes fields for managing memory allocation, tracking playback progress, and interfacing with network output contexts. It is integral to the playback tile's operation, ensuring data is read, processed, and forwarded correctly with appropriate timing and notifications.


# Functions

---
### scratch\_align<!-- {{#callable:scratch_align}} -->
The `scratch_align` function returns a constant alignment value of 4096 bytes.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended for use within the same translation unit and suggests the compiler to inline it for performance.
    - The function does not take any parameters.
    - It directly returns the constant value 4096UL, which is an unsigned long integer.
- **Output**: The function returns an unsigned long integer with the value 4096, representing a memory alignment size.


---
### loose\_footprint<!-- {{#callable:loose_footprint}} -->
The `loose_footprint` function calculates the memory footprint for a tile using a predefined page size.
- **Inputs**:
    - `tile`: A pointer to a `fd_topo_tile_t` structure, which is not used in the function.
- **Control Flow**:
    - The function takes a single argument, `tile`, which is marked as unused with `FD_PARAM_UNUSED`.
    - It returns the product of `1UL` and `FD_SHMEM_GIGANTIC_PAGE_SZ`, which represents a constant memory size.
- **Output**: The function returns an `ulong` representing the memory footprint size, specifically `FD_SHMEM_GIGANTIC_PAGE_SZ`.


---
### populate\_allowed\_seccomp<!-- {{#callable:populate_allowed_seccomp}} -->
The `populate_allowed_seccomp` function populates a seccomp filter policy for archiver playback and returns the instruction count of the policy.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure, representing the topology configuration; it is not used in this function.
    - `tile`: A pointer to a constant `fd_topo_tile_t` structure, representing the tile configuration, specifically used to access the `archiver.archive_fd`.
    - `out_cnt`: An unsigned long integer representing the count of output filters to be populated.
    - `out`: A pointer to a `struct sock_filter` array where the seccomp filter policy will be populated.
- **Control Flow**:
    - The function begins by explicitly ignoring the `topo` parameter, as it is not used in the function body.
    - It calls the [`populate_sock_filter_policy_archiver_playback`](generated/archiver_playback_seccomp.h.driver.md#populate_sock_filter_policy_archiver_playback) function, passing `out_cnt`, `out`, the file descriptor of the log file, and the archive file descriptor from the `tile` structure.
    - The function returns the value of `sock_filter_policy_archiver_playback_instr_cnt`, which presumably holds the count of instructions in the seccomp filter policy.
- **Output**: The function returns an unsigned long integer representing the number of instructions in the seccomp filter policy for archiver playback.
- **Functions called**:
    - [`populate_sock_filter_policy_archiver_playback`](generated/archiver_playback_seccomp.h.driver.md#populate_sock_filter_policy_archiver_playback)


---
### populate\_allowed\_fds<!-- {{#callable:populate_allowed_fds}} -->
The `populate_allowed_fds` function populates an array with file descriptors that are allowed for use, including standard error, a log file, and an archive file, and returns the count of these file descriptors.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure, which is unused in this function.
    - `tile`: A pointer to a constant `fd_topo_tile_t` structure, which contains information about the tile, including the file descriptor for the archive file.
    - `out_fds_cnt`: An unsigned long integer representing the count of output file descriptors, which is unused in this function.
    - `out_fds`: A pointer to an integer array where the allowed file descriptors will be stored.
- **Control Flow**:
    - Initialize `out_cnt` to 0, which will keep track of the number of file descriptors added to `out_fds`.
    - Add the file descriptor for standard error (2) to the `out_fds` array and increment `out_cnt`.
    - Check if the log file descriptor is valid (not -1) using `FD_LIKELY`, and if so, add it to the `out_fds` array and increment `out_cnt`.
    - Check if the archive file descriptor from the `tile` structure is valid (not -1) using `FD_LIKELY`, and if so, add it to the `out_fds` array and increment `out_cnt`.
    - Return the count of file descriptors added to `out_fds` (i.e., `out_cnt`).
- **Output**: The function returns an unsigned long integer representing the number of file descriptors added to the `out_fds` array.


---
### scratch\_footprint<!-- {{#callable:scratch_footprint}} -->
The `scratch_footprint` function calculates the memory footprint required for a scratch space layout for a given tile.
- **Inputs**:
    - `tile`: A pointer to a `fd_topo_tile_t` structure, representing the tile for which the scratch footprint is being calculated. This parameter is not used in the function.
- **Control Flow**:
    - The function begins by initializing a layout variable `l` with `FD_LAYOUT_INIT`.
    - It then appends the alignment and size of `fd_archiver_playback_tile_ctx_t` to the layout using `FD_LAYOUT_APPEND`.
    - Finally, it finalizes the layout with `FD_LAYOUT_FINI`, using the alignment value returned by `scratch_align()`, and returns the result.
- **Output**: The function returns an `ulong` representing the calculated memory footprint for the scratch space layout.
- **Functions called**:
    - [`scratch_align`](#scratch_align)


---
### privileged\_init<!-- {{#callable:privileged_init}} -->
The `privileged_init` function initializes resources and opens an archive file for a playback tile in a distributed system.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology of the system.
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing the specific tile to be initialized.
- **Control Flow**:
    - Retrieve a scratch memory address using `fd_topo_obj_laddr` with the topology and tile object ID.
    - Initialize a scratch allocator with `FD_SCRATCH_ALLOC_INIT`.
    - Allocate and zero-initialize a `fd_archiver_playback_tile_ctx_t` context structure using `FD_SCRATCH_ALLOC_APPEND` and `memset`.
    - Append additional memory allocations for alignment and footprint using `FD_SCRATCH_ALLOC_APPEND`.
    - Finalize the scratch allocation with `FD_SCRATCH_ALLOC_FINI`.
    - Attempt to open the archive file specified in `tile->archiver.archiver_path` with read-only and direct I/O flags using `open`.
    - Check if the file descriptor is valid; if not, log an error using `FD_LOG_ERR`.
- **Output**: The function does not return a value, but it initializes the tile's context and opens the archive file, storing the file descriptor in `tile->archiver.archive_fd`.
- **Functions called**:
    - [`scratch_align`](#scratch_align)


---
### unprivileged\_init<!-- {{#callable:unprivileged_init}} -->
The `unprivileged_init` function initializes the playback tile context for an archiver playback tile, setting up memory allocation, input/output buffers, and initial state for playback operations.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology configuration.
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing the specific tile configuration to be initialized.
- **Control Flow**:
    - Allocate scratch memory for the tile context using `fd_topo_obj_laddr` and `FD_SCRATCH_ALLOC_INIT`.
    - Allocate and initialize the `fd_archiver_playback_tile_ctx_t` structure within the scratch memory.
    - Allocate shared memory for the allocator using `FD_SCRATCH_ALLOC_APPEND`.
    - Finalize the scratch allocation with `FD_SCRATCH_ALLOC_FINI`.
    - Set the `tick_per_ns` field in the context using `fd_tempo_tick_per_ns`.
    - Initialize the allocator and virtual allocator, logging an error if allocation fails.
    - Allocate an input stream buffer using `fd_valloc_malloc`, logging an error if allocation fails.
    - Initialize the buffered input stream with `fd_io_buffered_istream_init`.
    - Perform an initial read from the input stream, logging a warning if it fails.
    - Set up output links by iterating over `tile->out_cnt` and configuring each link's context in `ctx->out`.
    - Initialize various playback state variables in the context, including `playback_done`, `playback_started`, `now`, `prev_publish_time`, `need_notify`, and `notified`.
    - Query and join the published watermark using `fd_pod_queryf_ulong` and `fd_fseq_join`, logging an error if joining fails.
    - Log a warning indicating the completion of playback tile initialization.
- **Output**: The function does not return a value; it initializes the playback tile context and logs errors or warnings as necessary.
- **Functions called**:
    - [`scratch_align`](#scratch_align)


---
### during\_housekeeping<!-- {{#callable:during_housekeeping}} -->
The `during_housekeeping` function updates the current time in the context structure by converting the tick count to nanoseconds.
- **Inputs**:
    - `ctx`: A pointer to a `fd_archiver_playback_tile_ctx_t` structure, which holds the context for the archiver playback tile, including timing and playback state information.
- **Control Flow**:
    - Retrieve the current tick count using `fd_tickcount()`.
    - Convert the tick count to nanoseconds by dividing it by `ctx->tick_per_ns`.
    - Store the result in `ctx->now`.
- **Output**: The function does not return a value; it updates the `now` field in the provided context structure.


---
### after\_frag<!-- {{#callable:after_frag}} -->
The `after_frag` function checks if the input index is zero and sets a notification flag in the context structure.
- **Inputs**:
    - `ctx`: A pointer to a `fd_archiver_playback_tile_ctx_t` structure, which holds the context for the archiver playback tile.
    - `in_idx`: An unsigned long integer representing the input index, which is expected to be zero.
    - `seq`: An unsigned long integer representing the sequence number, marked as unused.
    - `sig`: An unsigned long integer representing the signature, marked as unused.
    - `sz`: An unsigned long integer representing the size, marked as unused.
    - `tsorig`: An unsigned long integer representing the original timestamp, marked as unused.
    - `tspub`: An unsigned long integer representing the publish timestamp, marked as unused.
    - `stem`: A pointer to a `fd_stem_context_t` structure, marked as unused.
- **Control Flow**:
    - Check if `in_idx` is not equal to zero using `FD_UNLIKELY` macro.
    - If `in_idx` is not zero, log an error message indicating that playback seems corrupted.
    - Set the `notified` field of the `ctx` structure to 1.
- **Output**: The function does not return any value; it modifies the `ctx` structure by setting its `notified` field.


---
### after\_credit<!-- {{#callable:after_credit}} -->
The `after_credit` function manages the playback of archived fragments, ensuring they are processed and published in the correct order and timing.
- **Inputs**:
    - `ctx`: A pointer to a `fd_archiver_playback_tile_ctx_t` structure, which holds the context for the playback tile, including state and configuration information.
    - `stem`: A pointer to a `fd_stem_context_t` structure, which is used for publishing fragments.
    - `opt_poll_in`: An optional pointer to an integer, marked as unused, potentially for polling input.
    - `charge_busy`: An optional pointer to an integer, marked as unused, potentially for tracking busy state.
- **Control Flow**:
    - Check if playback is done; if so, log an error if the done time exceeds a threshold and return.
    - If playback hasn't started, check if the published watermark is updated; if so, mark playback as started and log a warning.
    - Peek at the next fragment header without consuming it to determine if waiting is necessary.
    - If the header's magic number is incorrect, log a warning, mark playback as done, and return.
    - Check if the current time is less than the scheduled publish time; if so, return to wait.
    - Ensure notification for the previous fragment is received before proceeding.
    - Consume the fragment header from the stream and determine the output link based on the tile ID.
    - Consume the fragment data from the stream and handle errors by marking playback as done.
    - Reset notification state if needed and check if the fragment size exceeds the MTU, logging an error if so.
    - Publish the fragment using `fd_stem_publish` and update the chunk for the next fragment.
- **Output**: The function does not return a value; it performs operations on the context and stem structures to manage playback and publishing of fragments.


