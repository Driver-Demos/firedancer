# Purpose
This C source code file defines the functionality for an "archiver writer tile" within a larger system, likely part of a network data processing or storage application. The primary purpose of this component is to consume data fragments from multiple input sources, timestamp them to ensure a global order, and write them to an archive. The code is structured to handle a single instance of this archiver writer tile, emphasizing its role in maintaining a consistent and ordered data archive. The file includes various system headers and custom headers, indicating its reliance on both standard system calls and specific application logic.

Key technical components include the definition of data structures for managing input contexts, statistics, and buffered output streams. The code also includes functions for initializing the tile in both privileged and unprivileged modes, handling data fragments during processing, and writing them to an output buffer. The use of seccomp filters and file descriptor management suggests a focus on security and resource management. The file defines a public API through the `fd_tile_archiver_writer` structure, which encapsulates the tile's initialization and execution logic, making it a modular component that can be integrated into a larger system.
# Imports and Dependencies

---
- `../tiles.h`
- `fd_archiver.h`
- `errno.h`
- `fcntl.h`
- `sys/mman.h`
- `sys/stat.h`
- `string.h`
- `unistd.h`
- `linux/unistd.h`
- `sys/socket.h`
- `linux/if_xdp.h`
- `generated/archiver_writer_seccomp.h`
- `../stem/fd_stem.c`


# Global Variables

---
### fd\_tile\_archiver\_writer
- **Type**: `fd_topo_run_tile_t`
- **Description**: The `fd_tile_archiver_writer` is a global variable of type `fd_topo_run_tile_t` that represents a configuration for an archiver writer tile in a distributed system. This tile is responsible for consuming data from input links, adding timestamps to ensure global ordering, and writing the data to an archive. It includes various function pointers and parameters for initialization, security policies, and runtime operations.
- **Use**: This variable is used to define and configure the behavior of the archiver writer tile, including its initialization, security settings, and execution logic.


# Data Structures

---
### fd\_archiver\_writer\_stats
- **Type**: `struct`
- **Members**:
    - `net_shred_in_cnt`: Counts the number of network shreds processed.
    - `net_repair_in_cnt`: Counts the number of network repairs processed.
- **Description**: The `fd_archiver_writer_stats` structure is used to keep track of statistics related to the archiver writer's processing of network data. It maintains counters for the number of shreds and repairs processed, which are essential for monitoring the performance and reliability of the archiver writer component in the system.


---
### fd\_archiver\_writer\_stats\_t
- **Type**: `struct`
- **Members**:
    - `net_shred_in_cnt`: Counts the number of network shreds processed.
    - `net_repair_in_cnt`: Counts the number of network repairs processed.
- **Description**: The `fd_archiver_writer_stats_t` structure is used to keep track of statistics related to the archiver writer's operations, specifically counting the number of network shreds and repairs processed. This data structure is part of a larger system that manages the archiving of data packets, ensuring that each packet is timestamped and ordered globally. The statistics collected by this structure are crucial for monitoring the performance and reliability of the archiver writer component.


---
### fd\_archiver\_writer\_in\_ctx\_t
- **Type**: `struct`
- **Members**:
    - `mem`: A pointer to a workspace memory structure, `fd_wksp_t`, used for memory management.
    - `chunk0`: An unsigned long integer representing the starting chunk index in the workspace.
    - `wmark`: An unsigned long integer representing the watermark or upper limit of chunks in the workspace.
- **Description**: The `fd_archiver_writer_in_ctx_t` structure is used to manage input context for the archiver writer tile, which processes data from input links and writes it to an archive. It contains a pointer to a memory workspace, a starting chunk index, and a watermark indicating the upper limit of chunks, facilitating efficient data handling and memory management within the archiver system.


---
### fd\_archiver\_writer\_tile\_ctx
- **Type**: `struct`
- **Members**:
    - `out_buf`: A pointer to the output buffer used for writing data.
    - `in`: An array of input context structures, each representing an input link.
    - `stats`: A structure holding statistics about the number of shreds and repairs processed.
    - `now`: The current timestamp in nanoseconds.
    - `last_packet_ns`: The timestamp of the last packet processed in nanoseconds.
    - `tick_per_ns`: The number of ticks per nanosecond for time calculations.
    - `archive_ostream`: A buffered output stream for writing to the archive.
    - `frag_buf`: A buffer for storing fragments before writing them to the archive.
    - `alloc`: A pointer to the memory allocator used for dynamic memory management.
    - `valloc`: A virtual allocator used for managing virtual memory allocations.
- **Description**: The `fd_archiver_writer_tile_ctx` structure is designed to manage the context for an archiver writer tile, which is responsible for consuming data from input links and writing it to an archive with timestamps for global ordering. It includes fields for managing input contexts, output buffering, time tracking, and memory allocation, ensuring efficient data processing and storage in a single archiver writer tile setup.


---
### fd\_archiver\_writer\_tile\_ctx\_t
- **Type**: `struct`
- **Members**:
    - `out_buf`: A pointer to the output buffer used for writing data.
    - `in`: An array of input contexts, each containing memory workspace, chunk start, and watermark.
    - `stats`: A structure holding statistics for network shred and repair input counts.
    - `now`: The current timestamp in nanoseconds.
    - `last_packet_ns`: The timestamp of the last packet processed in nanoseconds.
    - `tick_per_ns`: The number of ticks per nanosecond for timing purposes.
    - `archive_ostream`: A buffered output stream for writing to the archive.
    - `frag_buf`: A buffer for storing fragments before writing them to the output stream.
    - `alloc`: A pointer to the memory allocator used for dynamic memory management.
    - `valloc`: A virtual allocator for managing memory allocations.
- **Description**: The `fd_archiver_writer_tile_ctx_t` structure is designed to manage the context for an archiver writer tile, which is responsible for consuming data from input links, adding timestamps to ensure global ordering, and writing the data to an archive. It includes fields for managing input contexts, output buffering, timing, and statistics, as well as memory allocation utilities. This structure is central to the operation of the archiver writer tile, ensuring data is processed and stored efficiently.


# Functions

---
### scratch\_align<!-- {{#callable:scratch_align}} -->
The `scratch_align` function returns a constant alignment value of 4096 bytes.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended for use only within the file it is defined and suggests to the compiler to attempt to embed the function code directly at the call site for performance reasons.
    - The function is marked with `FD_FN_CONST`, indicating that it has no side effects and its return value is determined only by its input parameters, which in this case are none.
    - The function simply returns the constant value `4096UL`, which is an unsigned long integer.
- **Output**: The function outputs an unsigned long integer value of 4096, representing a memory alignment size.


---
### loose\_footprint<!-- {{#callable:loose_footprint}} -->
The `loose_footprint` function calculates the memory footprint of a tile using a gigantic page size.
- **Inputs**:
    - `tile`: A pointer to a `fd_topo_tile_t` structure, which is not used in the function.
- **Control Flow**:
    - The function takes a single argument, `tile`, which is marked as unused with `FD_PARAM_UNUSED`.
    - It returns the product of 1UL and `FD_SHMEM_GIGANTIC_PAGE_SZ`, which represents the size of a gigantic shared memory page.
- **Output**: The function returns an unsigned long integer representing the memory footprint size in terms of gigantic page size.


---
### populate\_allowed\_seccomp<!-- {{#callable:populate_allowed_seccomp}} -->
The `populate_allowed_seccomp` function populates a seccomp filter policy for an archiver writer tile using specified file descriptors.
- **Inputs**:
    - `topo`: A pointer to a `fd_topo_t` structure, which is unused in this function.
    - `tile`: A pointer to a `fd_topo_tile_t` structure representing the tile configuration, specifically used to access the `archive_fd`.
    - `out_cnt`: An unsigned long integer representing the count of output filters to be populated.
    - `out`: A pointer to a `struct sock_filter` array where the seccomp filter policy will be populated.
- **Control Flow**:
    - The function calls [`populate_sock_filter_policy_archiver_writer`](generated/archiver_writer_seccomp.h.driver.md#populate_sock_filter_policy_archiver_writer) with `out_cnt`, `out`, the file descriptor of the log file, and the archive file descriptor from the `tile` structure.
    - The function returns the value of `sock_filter_policy_archiver_writer_instr_cnt`, which presumably represents the number of instructions in the populated seccomp filter.
- **Output**: The function returns an unsigned long integer representing the number of instructions in the populated seccomp filter.
- **Functions called**:
    - [`populate_sock_filter_policy_archiver_writer`](generated/archiver_writer_seccomp.h.driver.md#populate_sock_filter_policy_archiver_writer)


---
### populate\_allowed\_fds<!-- {{#callable:populate_allowed_fds}} -->
The `populate_allowed_fds` function populates an array with file descriptors that are allowed for use, including standard error, a log file, and an archive file, and returns the count of these file descriptors.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure, which is not used in this function.
    - `tile`: A pointer to a constant `fd_topo_tile_t` structure, which contains the `archiver.archive_fd` used to check if the archive file descriptor is valid.
    - `out_fds_cnt`: An unsigned long integer representing the count of file descriptors to be output, which is not used in this function.
    - `out_fds`: A pointer to an integer array where the allowed file descriptors will be stored.
- **Control Flow**:
    - Initialize `out_cnt` to 0 to keep track of the number of file descriptors added.
    - Add the file descriptor for standard error (2) to the `out_fds` array and increment `out_cnt`.
    - Check if the log file descriptor is valid using `fd_log_private_logfile_fd()`, and if so, add it to the `out_fds` array and increment `out_cnt`.
    - Check if the archive file descriptor in `tile->archiver.archive_fd` is valid, and if so, add it to the `out_fds` array and increment `out_cnt`.
- **Output**: Returns the count of file descriptors added to the `out_fds` array as an unsigned long integer.


---
### scratch\_footprint<!-- {{#callable:scratch_footprint}} -->
The `scratch_footprint` function calculates the memory footprint required for a `fd_archiver_writer_tile_ctx_t` structure, aligned to a specific boundary.
- **Inputs**:
    - `tile`: A pointer to a `fd_topo_tile_t` structure, which is not used in the function.
- **Control Flow**:
    - The function begins by initializing a variable `l` with `FD_LAYOUT_INIT`.
    - It then appends the size and alignment of `fd_archiver_writer_tile_ctx_t` to `l` using `FD_LAYOUT_APPEND`.
    - Finally, it returns the finalized layout size by calling `FD_LAYOUT_FINI` with `l` and the alignment value from `scratch_align()`.
- **Output**: The function returns an `ulong` representing the memory footprint required for the `fd_archiver_writer_tile_ctx_t` structure, aligned to the boundary specified by `scratch_align()`.
- **Functions called**:
    - [`scratch_align`](#scratch_align)


---
### privileged\_init<!-- {{#callable:privileged_init}} -->
The `privileged_init` function initializes resources and opens a file descriptor for an archiver writer tile in a privileged context.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology configuration.
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing the tile configuration, including the archiver details.
- **Control Flow**:
    - Retrieve the local address of the tile object using `fd_topo_obj_laddr` and store it in `scratch`.
    - Initialize a scratch allocation context `l` with `FD_SCRATCH_ALLOC_INIT`.
    - Allocate and zero-initialize a `fd_archiver_writer_tile_ctx_t` structure using `FD_SCRATCH_ALLOC_APPEND` and `memset`.
    - Append additional scratch allocations for alignment and footprint using `FD_SCRATCH_ALLOC_APPEND`.
    - Finalize the scratch allocation with `FD_SCRATCH_ALLOC_FINI`.
    - Attempt to open or create the archive file specified in `tile->archiver.archiver_path` with `open`, setting the file descriptor in `tile->archiver.archive_fd`.
    - If opening the file fails, log an error message using `FD_LOG_ERR`.
- **Output**: The function does not return a value but initializes the tile's archiver file descriptor and allocates necessary resources.
- **Functions called**:
    - [`scratch_align`](#scratch_align)


---
### unprivileged\_init<!-- {{#callable:unprivileged_init}} -->
The `unprivileged_init` function initializes the unprivileged components of an archiver writer tile, setting up memory allocations, input links, and output streams for data archiving.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology of the system.
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing the specific tile to be initialized.
- **Control Flow**:
    - Allocate scratch memory for the tile context and shared memory using `FD_SCRATCH_ALLOC_INIT` and `FD_SCRATCH_ALLOC_APPEND`.
    - Truncate the archive file associated with the tile to zero length using `ftruncate` and check for errors.
    - Seek to the beginning of the archive file using `lseek` and check for errors.
    - Iterate over each input link of the tile, setting up memory pointers, chunk, and watermark values for each link.
    - Initialize the allocator for the tile using `fd_alloc_join` and `fd_alloc_virtual`, checking for errors.
    - Allocate an output buffer for the tile using `fd_valloc_malloc` and check for errors.
    - Initialize the output stream for the archive file using `fd_io_buffered_ostream_init` and check for errors.
    - Set the `tick_per_ns` value in the context using `fd_tempo_tick_per_ns`.
- **Output**: The function does not return a value; it initializes the tile's context and resources for archiving operations.
- **Functions called**:
    - [`scratch_align`](#scratch_align)


---
### during\_housekeeping<!-- {{#callable:during_housekeeping}} -->
The `during_housekeeping` function updates the current timestamp in the context structure by converting the tick count to nanoseconds.
- **Inputs**:
    - `ctx`: A pointer to a `fd_archiver_writer_tile_ctx_t` structure, which holds the context for the archiver writer tile, including timing and buffer information.
- **Control Flow**:
    - Retrieve the current tick count using `fd_tickcount()`.
    - Convert the tick count to nanoseconds by dividing it by `ctx->tick_per_ns`.
    - Store the result in `ctx->now` as an unsigned long integer.
- **Output**: The function does not return a value; it updates the `now` field in the provided context structure.


---
### during\_frag<!-- {{#callable:during_frag}} -->
The `during_frag` function processes an incoming data fragment, updates its timestamp for ordering, and copies it into a buffer while updating statistics.
- **Inputs**:
    - `ctx`: A pointer to the `fd_archiver_writer_tile_ctx_t` structure, which contains context information for the archiver writer tile.
    - `in_idx`: An unsigned long integer representing the index of the input context from which the fragment is being processed.
    - `seq`: An unsigned long integer representing the sequence number of the fragment, marked as unused.
    - `sig`: An unsigned long integer representing the signature of the fragment, marked as unused.
    - `chunk`: An unsigned long integer representing the chunk identifier of the fragment.
    - `sz`: An unsigned long integer representing the size of the fragment.
    - `ctl`: An unsigned long integer representing control information, marked as unused.
- **Control Flow**:
    - Check if the chunk is within the valid range and if the size is above the minimum footprint; log an error if not.
    - Convert the chunk identifier to a memory address to access the fragment data.
    - Retrieve and verify the fragment header's magic number to ensure it is valid.
    - Calculate the time since the last packet and update the fragment header with this delay.
    - Update the last packet timestamp to the current time.
    - Copy the fragment data into the context's fragment buffer.
    - Update statistics counters based on the fragment's tile ID.
- **Output**: The function does not return a value; it operates by modifying the context structure and logging errors if necessary.


---
### after\_frag<!-- {{#callable:after_frag}} -->
The `after_frag` function writes a fragment from a buffer to an output stream and logs a warning if the write operation fails.
- **Inputs**:
    - `ctx`: A pointer to a `fd_archiver_writer_tile_ctx_t` structure, which contains context information for the archiver writer tile, including the output stream and fragment buffer.
    - `in_idx`: An unused `ulong` parameter, presumably intended to represent the index of the input source.
    - `seq`: An unused `ulong` parameter, presumably intended to represent the sequence number of the fragment.
    - `sig`: An unused `ulong` parameter, presumably intended to represent the signature of the fragment.
    - `sz`: A `ulong` representing the size of the fragment to be written to the output stream.
    - `tsorig`: An unused `ulong` parameter, presumably intended to represent the original timestamp of the fragment.
    - `tspub`: An unused `ulong` parameter, presumably intended to represent the publication timestamp of the fragment.
    - `stem`: An unused pointer to a `fd_stem_context_t` structure, presumably intended to provide additional context for the operation.
- **Control Flow**:
    - The function attempts to write the fragment stored in `ctx->frag_buf` to the output stream `ctx->archive_ostream` using the `fd_io_buffered_ostream_write` function, with the size specified by `sz`.
    - If the write operation returns a non-zero error code, indicating failure, a warning is logged with the size of the fragment and the error code.
- **Output**: The function does not return a value; it performs an operation and logs a warning if an error occurs.


