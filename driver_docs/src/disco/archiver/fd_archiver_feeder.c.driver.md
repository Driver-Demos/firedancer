# Purpose
This C source code file is designed to implement a component of a data archiving system, specifically focusing on the "archiver feeder" functionality. The primary purpose of this code is to manage the forwarding of data fragments from multiple input links to a single output link, which is handled by an "archiver writer" tile. The code supports flexible data capture topologies, such as round-robin or one-to-one configurations, by allowing multiple feeder tiles to operate concurrently. The file defines a structure `fd_archiver_feeder_tile_ctx_t` to maintain the context for each feeder tile, including input and output memory management, round-robin indexing, and fragment processing.

The code includes several key technical components, such as functions for initializing the feeder tile context, managing memory alignment and footprint, and handling data fragments during and after their processing. It also defines security policies through seccomp filters and manages file descriptors for logging purposes. The file is part of a larger system, as indicated by its inclusion of other headers and its integration with a stem processing framework (`fd_stem.c`). The `fd_topo_run_tile_t` structure at the end of the file defines the public API for this feeder tile, specifying its name, initialization routines, and the main execution function (`stem_run`). This setup suggests that the code is intended to be part of a modular system where different tiles can be configured and run as part of a larger data processing pipeline.
# Imports and Dependencies

---
- `../tiles.h`
- `fd_archiver.h`
- `unistd.h`
- `linux/unistd.h`
- `sys/socket.h`
- `linux/if_xdp.h`
- `generated/archiver_feeder_seccomp.h`
- `../stem/fd_stem.c`


# Global Variables

---
### fd\_tile\_archiver\_feeder
- **Type**: `fd_topo_run_tile_t`
- **Description**: The `fd_tile_archiver_feeder` is a global variable of type `fd_topo_run_tile_t` that represents a configuration for an archiver feeder tile in a topology. It is initialized with specific function pointers and parameters that define its behavior, such as security policies, file descriptor management, memory alignment, and initialization routines. This variable is part of a system designed to forward data fragments from multiple input links to a single archiver writer tile, allowing for flexible data capture topologies.
- **Use**: This variable is used to configure and manage the behavior of an archiver feeder tile within a data processing topology.


# Data Structures

---
### fd\_archiver\_feeder\_in\_ctx\_t
- **Type**: `struct`
- **Members**:
    - `mem`: A pointer to a workspace structure, `fd_wksp_t`, used for memory management.
    - `chunk0`: An unsigned long integer representing the starting chunk index in the workspace.
    - `wmark`: An unsigned long integer representing the watermark or upper limit for chunk indices in the workspace.
- **Description**: The `fd_archiver_feeder_in_ctx_t` structure is designed to manage input context for an archiver feeder tile in a distributed system. It holds a pointer to a memory workspace, along with chunk indices that define the range of data chunks that can be processed. This structure is part of a larger system that captures and forwards data fragments to an archiver writer tile, facilitating flexible data capture topologies.


---
### fd\_archiver\_feeder\_tile\_ctx
- **Type**: `struct`
- **Members**:
    - `out_mem`: Pointer to the workspace memory for output.
    - `out_chunk0`: Initial chunk index for output.
    - `out_wmark`: Watermark for output chunks.
    - `out_chunk`: Current chunk index for output.
    - `count`: Counter for tracking operations or data.
    - `round_robin_idx`: Index for round-robin scheduling.
    - `round_robin_cnt`: Count of round-robin participants.
    - `in`: Array of input context structures for each input link.
- **Description**: The `fd_archiver_feeder_tile_ctx` structure is designed to manage the context for an archiver feeder tile, which is responsible for forwarding data fragments from multiple input links to a single archiver writer tile. It includes pointers and indices for managing output memory and chunks, as well as a round-robin mechanism for distributing load across multiple input links. The structure supports a flexible topology for data capture, allowing configurations such as round-robin or one-to-one mappings between input and output.


---
### fd\_archiver\_feeder\_tile\_ctx\_t
- **Type**: `struct`
- **Members**:
    - `out_mem`: Pointer to the workspace memory for output.
    - `out_chunk0`: Initial chunk index for output.
    - `out_wmark`: Watermark for output chunks.
    - `out_chunk`: Current chunk index for output.
    - `count`: Counter for processed fragments.
    - `round_robin_idx`: Index for round-robin processing.
    - `round_robin_cnt`: Count of round-robin participants.
    - `in`: Array of input contexts, each containing memory, initial chunk, and watermark.
- **Description**: The `fd_archiver_feeder_tile_ctx_t` structure is designed to manage the context for an archiver feeder tile, which is responsible for forwarding data fragments from multiple input links to a single output link in a network topology. It includes fields for managing output memory and chunk indices, a counter for processed fragments, and round-robin indices for distributing load among multiple feeder tiles. The structure also contains an array of input contexts, each of which holds information about the memory, initial chunk, and watermark for a specific input link, allowing for flexible and efficient data capture and forwarding.


# Functions

---
### scratch\_align<!-- {{#callable:scratch_align}} -->
The `scratch_align` function returns a constant alignment value of 4096 bytes.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended for use only within the file it is defined in and suggests to the compiler to attempt to embed the function's code at each call site for performance reasons.
    - The function does not take any parameters.
    - The function simply returns the constant value 4096UL, which is an unsigned long integer.
- **Output**: The function returns an unsigned long integer with the value 4096, representing a memory alignment size.


---
### populate\_allowed\_seccomp<!-- {{#callable:populate_allowed_seccomp}} -->
The `populate_allowed_seccomp` function configures a seccomp filter policy for an archiver feeder by populating a given array with socket filter instructions and returns the count of these instructions.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure, representing the topology configuration; it is not used in this function.
    - `tile`: A pointer to a constant `fd_topo_tile_t` structure, representing the tile configuration; it is not used in this function.
    - `out_cnt`: An unsigned long integer representing the number of socket filter instructions to populate.
    - `out`: A pointer to a `struct sock_filter` array where the socket filter instructions will be stored.
- **Control Flow**:
    - The function begins by explicitly ignoring the `topo` and `tile` parameters, indicating they are not used in the function's logic.
    - It calls the [`populate_sock_filter_policy_archiver_feeder`](generated/archiver_feeder_seccomp.h.driver.md#populate_sock_filter_policy_archiver_feeder) function, passing `out_cnt`, `out`, and the file descriptor obtained from `fd_log_private_logfile_fd()` as arguments.
    - The function returns the value of `sock_filter_policy_archiver_feeder_instr_cnt`, which presumably holds the count of instructions populated by the [`populate_sock_filter_policy_archiver_feeder`](generated/archiver_feeder_seccomp.h.driver.md#populate_sock_filter_policy_archiver_feeder) function.
- **Output**: The function returns an unsigned long integer representing the count of socket filter instructions populated in the `out` array.
- **Functions called**:
    - [`populate_sock_filter_policy_archiver_feeder`](generated/archiver_feeder_seccomp.h.driver.md#populate_sock_filter_policy_archiver_feeder)


---
### populate\_allowed\_fds<!-- {{#callable:populate_allowed_fds}} -->
The `populate_allowed_fds` function populates an array with file descriptors that are allowed for use, specifically including the standard error and optionally a log file descriptor.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure, which is not used in this function.
    - `tile`: A pointer to a constant `fd_topo_tile_t` structure, which is not used in this function.
    - `out_fds_cnt`: An unsigned long integer representing the count of file descriptors to output, which is not used in this function.
    - `out_fds`: A pointer to an integer array where the allowed file descriptors will be stored.
- **Control Flow**:
    - Initialize `out_cnt` to 0 to keep track of the number of file descriptors added.
    - Add the file descriptor for standard error (2) to the `out_fds` array and increment `out_cnt`.
    - Check if the log file descriptor is valid (not -1) using `fd_log_private_logfile_fd()`.
    - If the log file descriptor is valid, add it to the `out_fds` array and increment `out_cnt`.
    - Return the count of file descriptors added to the `out_fds` array.
- **Output**: The function returns an unsigned long integer representing the number of file descriptors added to the `out_fds` array.


---
### scratch\_footprint<!-- {{#callable:scratch_footprint}} -->
The `scratch_footprint` function calculates the memory footprint required for a `fd_archiver_feeder_tile_ctx_t` structure, aligned to a specific boundary.
- **Inputs**:
    - `tile`: A pointer to a `fd_topo_tile_t` structure, which is not used in the function.
- **Control Flow**:
    - Initialize a variable `l` with `FD_LAYOUT_INIT`.
    - Append the size and alignment of `fd_archiver_feeder_tile_ctx_t` to `l` using `FD_LAYOUT_APPEND`.
    - Finalize the layout with `FD_LAYOUT_FINI`, using the alignment value from `scratch_align()`.
    - Return the calculated memory footprint.
- **Output**: The function returns an `ulong` representing the memory footprint required for the `fd_archiver_feeder_tile_ctx_t` structure, aligned to the boundary specified by `scratch_align()`.
- **Functions called**:
    - [`scratch_align`](#scratch_align)


---
### unprivileged\_init<!-- {{#callable:unprivileged_init}} -->
The `unprivileged_init` function initializes the context for an archiver feeder tile by setting up memory allocations and configuring input and output link parameters.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology of the system.
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing the specific tile to be initialized.
- **Control Flow**:
    - Allocate scratch memory for the tile context using `FD_SCRATCH_ALLOC_INIT` and `FD_SCRATCH_ALLOC_APPEND`.
    - Initialize the allocated context memory to zero using `memset`.
    - Set the round-robin count and index in the context based on the tile's name and kind ID.
    - Iterate over each input link of the tile, setting up memory, chunk, and watermark parameters for each link in the context.
    - Configure the output memory, chunk, and watermark parameters for the tile's output link in the context.
    - Finalize the scratch memory allocation with `FD_SCRATCH_ALLOC_FINI` and check for overflow, logging an error if overflow occurs.
- **Output**: The function does not return a value; it initializes the context for the archiver feeder tile in the provided topology.
- **Functions called**:
    - [`scratch_align`](#scratch_align)
    - [`scratch_footprint`](#scratch_footprint)


---
### during\_frag<!-- {{#callable:during_frag}} -->
The `during_frag` function processes a data fragment by validating its chunk range, preparing a header, and copying the fragment data to an output location.
- **Inputs**:
    - `ctx`: A pointer to the `fd_archiver_feeder_tile_ctx_t` context structure, which contains information about input and output memory and chunk ranges.
    - `in_idx`: An unsigned long integer representing the index of the input link in the context's input array.
    - `seq`: An unsigned long integer representing the sequence number of the fragment.
    - `sig`: An unsigned long integer representing the signature of the fragment.
    - `chunk`: An unsigned long integer representing the chunk identifier of the fragment.
    - `sz`: An unsigned long integer representing the size of the fragment.
    - `ctl`: An unsigned long integer parameter that is unused in this function.
- **Control Flow**:
    - Check if the `chunk` is within the valid range defined by `chunk0` and `wmark` for the specified input index; log an error if it is not.
    - Convert the `chunk` identifier to a source memory address using `fd_chunk_to_laddr`.
    - Convert the output chunk identifier to a destination memory address using `fd_chunk_to_laddr`.
    - If the size `sz` is non-zero, prepare a header at the destination address with metadata including magic number, version, tile ID, size, signature, and sequence number.
    - Copy the fragment data from the source address to the destination address, offset by the header footprint size.
- **Output**: The function does not return a value; it performs operations on memory and logs errors if necessary.


---
### after\_frag<!-- {{#callable:after_frag}} -->
The `after_frag` function publishes a message to a queue and updates the output chunk pointer in the context.
- **Inputs**:
    - `ctx`: A pointer to the `fd_archiver_feeder_tile_ctx_t` structure, which contains context information for the archiver feeder tile, including memory and chunk management details.
    - `in_idx`: An unused parameter representing the input index.
    - `seq`: An unused parameter representing the sequence number.
    - `sig`: An unused parameter representing the signature.
    - `sz`: The size of the fragment being processed.
    - `tsorig`: The original timestamp of the fragment.
    - `tspub`: An unused parameter representing the publication timestamp.
    - `stem`: A pointer to the `fd_stem_context_t` structure, which is used for publishing the message to the queue.
- **Control Flow**:
    - Calculate the full size of the message by adding the fragment size (`sz`) to the `FD_ARCHIVER_FRAG_HEADER_FOOTPRINT`.
    - Call `fd_stem_publish` to publish the message to the queue using the `stem` context, with the calculated full size and the original timestamp (`tsorig`).
    - Update the `out_chunk` in the `ctx` by calling `fd_dcache_compact_next`, which computes the next chunk position based on the current chunk, full size, initial chunk, and watermark.
- **Output**: The function does not return a value; it modifies the `ctx` structure to update the `out_chunk`.


