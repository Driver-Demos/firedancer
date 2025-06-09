# Purpose
This C source code file defines a module for managing and processing data related to a network topology, specifically focusing on handling "shreds" and "gossip" within a distributed system. The file is part of a larger system, as indicated by the inclusion of multiple headers from different directories, such as `disco`, `choreo`, and `topo`. The primary structure defined in this file is `fd_eqvoc_tile_ctx_t`, which serves as a context for managing various data streams and operations related to network communication, including handling new cluster contact information, processing gossip messages, and managing shreds. The code includes functions for initializing this context in both privileged and unprivileged modes, handling incoming data fragments, and finalizing operations after data processing.

The file also defines several static inline functions for memory alignment and footprint calculations, which are crucial for efficient memory management in high-performance computing environments. Additionally, the file includes functions for setting up security policies and file descriptor management, which are essential for ensuring secure and efficient operation within the system. The code is structured to be integrated into a larger framework, as evidenced by the inclusion of a `fd_topo_run_tile_t` structure that defines the module's interface and operational parameters, such as its name, initialization functions, and run method. This suggests that the module is designed to be a component of a larger distributed system, likely involving multiple nodes or "tiles" that communicate and process data collaboratively.
# Imports and Dependencies

---
- `../../disco/topo/fd_topo.h`
- `generated/fd_eqvoc_tile_seccomp.h`
- `../../choreo/fd_choreo.h`
- `../../disco/fd_disco.h`
- `../../disco/keyguard/fd_keyload.h`
- `../../disco/shred/fd_stake_ci.h`
- `../../disco/stem/fd_stem.c`


# Global Variables

---
### fd\_tile\_eqvoc
- **Type**: `fd_topo_run_tile_t`
- **Description**: The `fd_tile_eqvoc` is a global variable of type `fd_topo_run_tile_t`, which is a structure used to define the configuration and behavior of a tile in a topology. This structure includes function pointers and parameters that dictate how the tile is initialized, its memory footprint, and its runtime behavior.
- **Use**: This variable is used to configure and manage the execution of a specific tile named 'eqvoc' within a larger system topology.


# Data Structures

---
### fd\_eqvoc\_tile\_ctx
- **Type**: `struct`
- **Members**:
    - `identity_key`: An array of one fd_pubkey_t representing the identity key.
    - `stake_ci`: A pointer to fd_stake_ci_t, representing the stake consensus information.
    - `new_dest_ptr`: A pointer to fd_shred_dest_weighted_t, representing new destination pointers.
    - `new_dest_cnt`: An unsigned long representing the count of new destinations.
    - `contact_in_idx`: An unsigned long representing the index for contact input.
    - `contact_in_mem`: A pointer to fd_wksp_t, representing the memory workspace for contact input.
    - `contact_in_chunk0`: An unsigned long representing the initial chunk index for contact input.
    - `contact_in_wmark`: An unsigned long representing the watermark for contact input.
    - `duplicate_shred`: An fd_gossip_duplicate_shred_t representing duplicate shred information.
    - `duplicate_shred_chunk`: An array of unsigned char for storing duplicate shred chunks.
    - `gossip_in_idx`: An unsigned long representing the index for gossip input.
    - `gossip_in_mem`: A pointer to fd_wksp_t, representing the memory workspace for gossip input.
    - `gossip_in_chunk0`: An unsigned long representing the initial chunk index for gossip input.
    - `gossip_in_wmark`: An unsigned long representing the watermark for gossip input.
    - `shred`: An fd_shred_t representing a shred.
    - `shred_net_in_idx`: An unsigned long representing the index for shred network input.
    - `shred_net_in_mem`: A pointer to fd_wksp_t, representing the memory workspace for shred network input.
    - `shred_net_in_chunk0`: An unsigned long representing the initial chunk index for shred network input.
    - `shred_net_in_wmark`: An unsigned long representing the watermark for shred network input.
    - `seed`: An unsigned long representing a seed value.
    - `eqvoc`: A pointer to fd_eqvoc_t, representing the EQVOC context.
- **Description**: The `fd_eqvoc_tile_ctx` structure is a complex data structure used in the context of EQVOC (Equivocation) processing within a distributed system. It holds various fields related to identity, stake consensus information, and network communication, including pointers to memory workspaces and indices for managing input and output data streams. The structure is designed to facilitate the handling of gossip and shred data, ensuring proper management of duplicate shreds and network communication. It also includes fields for managing new destination pointers and counts, as well as a seed for random number generation, making it integral to the EQVOC processing logic.


---
### fd\_eqvoc\_tile\_ctx\_t
- **Type**: `struct`
- **Members**:
    - `identity_key`: An array of one fd_pubkey_t representing the identity key.
    - `stake_ci`: A pointer to fd_stake_ci_t, representing the stake cluster information.
    - `new_dest_ptr`: A pointer to fd_shred_dest_weighted_t, representing new destination pointers.
    - `new_dest_cnt`: An unsigned long representing the count of new destinations.
    - `contact_in_idx`: An unsigned long representing the index for contact input.
    - `contact_in_mem`: A pointer to fd_wksp_t, representing the memory workspace for contact input.
    - `contact_in_chunk0`: An unsigned long representing the initial chunk for contact input.
    - `contact_in_wmark`: An unsigned long representing the watermark for contact input.
    - `duplicate_shred`: An fd_gossip_duplicate_shred_t representing duplicate shred information.
    - `duplicate_shred_chunk`: An array of unsigned char for storing duplicate shred chunks.
    - `gossip_in_idx`: An unsigned long representing the index for gossip input.
    - `gossip_in_mem`: A pointer to fd_wksp_t, representing the memory workspace for gossip input.
    - `gossip_in_chunk0`: An unsigned long representing the initial chunk for gossip input.
    - `gossip_in_wmark`: An unsigned long representing the watermark for gossip input.
    - `shred`: An fd_shred_t representing a shred.
    - `shred_net_in_idx`: An unsigned long representing the index for shred network input.
    - `shred_net_in_mem`: A pointer to fd_wksp_t, representing the memory workspace for shred network input.
    - `shred_net_in_chunk0`: An unsigned long representing the initial chunk for shred network input.
    - `shred_net_in_wmark`: An unsigned long representing the watermark for shred network input.
    - `seed`: An unsigned long representing a seed value.
    - `eqvoc`: A pointer to fd_eqvoc_t, representing the EQVOC context.
- **Description**: The `fd_eqvoc_tile_ctx_t` structure is a complex data structure used in the context of EQVOC (Equivocation) processing within a distributed system. It holds various fields related to identity, stake cluster information, and memory workspaces for handling contact, gossip, and shred network inputs. The structure also manages duplicate shred information and provides pointers to new destination data. It is designed to facilitate the processing and management of data within a tile in a distributed topology, ensuring efficient handling of network inputs and outputs.


# Functions

---
### scratch\_align<!-- {{#callable:scratch_align}} -->
The `scratch_align` function returns a constant alignment value of 128 bytes.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended for use within the same translation unit and suggests the compiler to inline it for performance.
    - The function does not take any parameters.
    - It directly returns the constant value 128UL, which represents 128 bytes.
- **Output**: The function returns an unsigned long integer (ulong) with a value of 128, representing the alignment size in bytes.


---
### loose\_footprint<!-- {{#callable:loose_footprint}} -->
The `loose_footprint` function returns a constant value of zero, indicating no additional memory footprint is required for a given tile.
- **Inputs**:
    - `tile`: A pointer to a `fd_topo_tile_t` structure, which is not used in the function.
- **Control Flow**:
    - The function takes a single argument, `tile`, which is marked as unused with `FD_PARAM_UNUSED`.
    - The function immediately returns the constant value `0UL`.
- **Output**: The function returns an unsigned long integer with a value of zero.


---
### scratch\_footprint<!-- {{#callable:scratch_footprint}} -->
The `scratch_footprint` function calculates the memory footprint required for a scratch space based on specific alignment and size requirements of various components.
- **Inputs**:
    - `tile`: A pointer to a `fd_topo_tile_t` structure, which is not used in the function.
- **Control Flow**:
    - Initialize a variable `l` with `FD_LAYOUT_INIT` to start the layout calculation.
    - Append the size and alignment of `fd_eqvoc_tile_ctx_t` to `l` using `FD_LAYOUT_APPEND`.
    - Append the alignment and footprint of `fd_stake_ci` to `l` using `FD_LAYOUT_APPEND`.
    - Append the alignment and footprint of `fd_eqvoc` with specific parameters to `l` using `FD_LAYOUT_APPEND`.
    - Finalize the layout calculation with `FD_LAYOUT_FINI` using `scratch_align()` and return the result.
- **Output**: Returns an `ulong` representing the total memory footprint required for the scratch space.
- **Functions called**:
    - [`scratch_align`](#scratch_align)


---
### handle\_new\_cluster\_contact\_info<!-- {{#callable:handle_new_cluster_contact_info}} -->
The `handle_new_cluster_contact_info` function processes a buffer containing new cluster contact information and updates the context with the parsed destination data.
- **Inputs**:
    - `ctx`: A pointer to an `fd_eqvoc_tile_ctx_t` structure, which holds the context for the operation and will be updated with new destination information.
    - `buf`: A constant pointer to an unsigned character array containing the buffer with new cluster contact information.
    - `buf_sz`: An unsigned long integer representing the size of the buffer in bytes.
- **Control Flow**:
    - The function casts the buffer to a constant pointer of type `ulong` to interpret the header information.
    - It calculates the number of destinations (`dest_cnt`) by dividing the buffer size by the size of `fd_shred_dest_wire_t`.
    - The function casts the header to a constant pointer of type `fd_shred_dest_wire_t` to access the input destinations.
    - It initializes the destination array in the context by calling `fd_stake_ci_dest_add_init` with the context's `stake_ci`.
    - The function updates the context's `new_dest_ptr` and `new_dest_cnt` with the initialized destination array and count, respectively.
    - A loop iterates over each destination, copying the public key, IP address, and UDP port from the input destinations to the context's destination array.
- **Output**: The function does not return a value; it updates the `ctx` structure with new destination information.


---
### finalize\_new\_cluster\_contact\_info<!-- {{#callable:finalize_new_cluster_contact_info}} -->
The `finalize_new_cluster_contact_info` function finalizes the addition of new destination contact information to a stake cluster.
- **Inputs**:
    - `ctx`: A pointer to an `fd_eqvoc_tile_ctx_t` structure, which contains context information including the stake cluster and the count of new destinations.
- **Control Flow**:
    - The function calls `fd_stake_ci_dest_add_fini` with the `stake_ci` and `new_dest_cnt` from the `ctx` structure.
    - This call finalizes the addition of new destination contact information to the stake cluster.
- **Output**: This function does not return any value; it performs an operation on the provided context.


---
### during\_frag<!-- {{#callable:during_frag}} -->
The `during_frag` function processes incoming data chunks based on their source index, handling cluster contact information, gossip duplicate shreds, or network shreds accordingly.
- **Inputs**:
    - `ctx`: A pointer to the `fd_eqvoc_tile_ctx_t` context structure containing various state and configuration information.
    - `in_idx`: An unsigned long integer representing the index of the input source.
    - `seq`: An unsigned long integer representing the sequence number, which is unused in this function.
    - `sig`: An unsigned long integer representing the signature, used for calculating header size in network shreds.
    - `chunk`: An unsigned long integer representing the chunk index to be processed.
    - `sz`: An unsigned long integer representing the size of the data chunk.
    - `ctl`: An unsigned long integer representing control information, which is unused in this function.
- **Control Flow**:
    - Check if `in_idx` matches `ctx->contact_in_idx`; if true, verify chunk range and handle new cluster contact information.
    - If `in_idx` matches `ctx->gossip_in_idx`, process the chunk as a gossip duplicate shred, copying data into the context's duplicate shred structure.
    - If `in_idx` matches `ctx->shred_net_in_idx`, verify chunk range and process the chunk as a network shred, copying data into the context's shred structure.
- **Output**: The function does not return a value; it modifies the context structure `ctx` based on the input data.
- **Functions called**:
    - [`handle_new_cluster_contact_info`](#handle_new_cluster_contact_info)


---
### after\_frag<!-- {{#callable:after_frag}} -->
The `after_frag` function processes fragments based on their input index, finalizing contact information or handling gossip data as needed.
- **Inputs**:
    - `ctx`: A pointer to a `fd_eqvoc_tile_ctx_t` structure containing context information for the operation.
    - `in_idx`: An unsigned long integer representing the input index of the fragment.
    - `seq`: An unsigned long integer representing the sequence number of the fragment (unused in this function).
    - `sig`: An unsigned long integer representing the signature of the fragment (unused in this function).
    - `sz`: An unsigned long integer representing the size of the fragment (unused in this function).
    - `tsorig`: An unsigned long integer representing the original timestamp of the fragment (unused in this function).
    - `tspub`: An unsigned long integer representing the publication timestamp of the fragment (unused in this function).
    - `stem`: A pointer to a `fd_stem_context_t` structure (unused in this function).
- **Control Flow**:
    - The function begins by casting several unused parameters to void to suppress compiler warnings.
    - It checks if `in_idx` matches `ctx->contact_in_idx`; if so, it calls [`finalize_new_cluster_contact_info`](#finalize_new_cluster_contact_info) to finalize contact information and returns.
    - If `in_idx` matches `ctx->gossip_in_idx`, it contains commented-out code for handling gossip data, which is currently not executed, and then returns.
    - The function has additional commented-out code for handling other cases, which are not currently active.
- **Output**: The function does not return any value; it performs operations based on the input index and modifies the context as needed.
- **Functions called**:
    - [`finalize_new_cluster_contact_info`](#finalize_new_cluster_contact_info)


---
### privileged\_init<!-- {{#callable:privileged_init}} -->
The `privileged_init` function initializes a privileged context for a tile in a topology by setting up scratch memory and loading an identity key.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology.
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing the tile to be initialized.
- **Control Flow**:
    - Obtain a scratch memory address using `fd_topo_obj_laddr` with the topology and tile object ID.
    - Initialize the scratch allocator with `FD_SCRATCH_ALLOC_INIT`.
    - Allocate memory for a `fd_eqvoc_tile_ctx_t` structure using `FD_SCRATCH_ALLOC_APPEND`.
    - Check if the `identity_key_path` in the tile's `eqvoc` structure is empty; if so, log an error and terminate.
    - Load the identity key from the specified path using `fd_keyload_load` and store it in the context's `identity_key`.
    - Generate a secure random seed and store it in the context's `seed` field using `fd_rng_secure`.
- **Output**: The function does not return a value; it initializes the context for the tile in the provided topology.


---
### unprivileged\_init<!-- {{#callable:unprivileged_init}} -->
The `unprivileged_init` function initializes the unprivileged context for a tile in a topology, setting up memory allocations and linking necessary components for communication.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology configuration.
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing the specific tile to initialize.
- **Control Flow**:
    - Retrieve the local address of the tile object using `fd_topo_obj_laddr` and store it in `scratch`.
    - Initialize a scratch memory allocator with `FD_SCRATCH_ALLOC_INIT`.
    - Allocate memory for `fd_eqvoc_tile_ctx_t`, `stake_ci_mem`, and `eqvoc_mem` using `FD_SCRATCH_ALLOC_APPEND`.
    - Finalize the scratch allocation and check for overflow using `FD_SCRATCH_ALLOC_FINI` and `FD_LOG_ERR` if necessary.
    - Initialize `stake_ci` and `eqvoc` by joining newly created instances using `fd_stake_ci_join` and `fd_eqvoc_join`.
    - Find and verify the index of the 'gossip_send' link using `fd_topo_find_tile_in_link` and `FD_TEST`.
    - Retrieve and set up memory and chunk information for `contact_in_mem`, `contact_in_chunk0`, and `contact_in_wmark`.
    - Repeat the process for 'gossip_eqvoc' and 'shred_net' links, setting up `gossip_in_mem`, `gossip_in_chunk0`, `gossip_in_wmark`, `shred_net_in_mem`, `shred_net_in_chunk0`, and `shred_net_in_wmark`.
- **Output**: The function does not return a value; it initializes the context and memory for the tile's unprivileged operations.
- **Functions called**:
    - [`scratch_align`](#scratch_align)
    - [`scratch_footprint`](#scratch_footprint)


---
### populate\_allowed\_seccomp<!-- {{#callable:populate_allowed_seccomp}} -->
The `populate_allowed_seccomp` function populates a seccomp filter policy for a specific tile and returns the instruction count of the policy.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure representing the topology configuration.
    - `tile`: A pointer to a constant `fd_topo_tile_t` structure representing the tile configuration.
    - `out_cnt`: An unsigned long integer representing the count of output seccomp filter instructions.
    - `out`: A pointer to a `struct sock_filter` array where the seccomp filter policy will be populated.
- **Control Flow**:
    - The function begins by explicitly ignoring the `topo` and `tile` parameters using `(void)` casts, indicating they are not used in the function body.
    - It calls the [`populate_sock_filter_policy_fd_eqvoc_tile`](generated/fd_eqvoc_tile_seccomp.h.driver.md#populate_sock_filter_policy_fd_eqvoc_tile) function with `out_cnt`, `out`, and the file descriptor obtained from `fd_log_private_logfile_fd()` to populate the seccomp filter policy.
    - Finally, it returns the value of `sock_filter_policy_fd_eqvoc_tile_instr_cnt`, which represents the number of instructions in the seccomp filter policy.
- **Output**: The function returns an unsigned long integer representing the number of instructions in the populated seccomp filter policy.
- **Functions called**:
    - [`populate_sock_filter_policy_fd_eqvoc_tile`](generated/fd_eqvoc_tile_seccomp.h.driver.md#populate_sock_filter_policy_fd_eqvoc_tile)


---
### populate\_allowed\_fds<!-- {{#callable:populate_allowed_fds}} -->
The `populate_allowed_fds` function populates an array with file descriptors that are allowed for use, specifically including standard error and optionally a log file descriptor.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure, which is not used in this function.
    - `tile`: A pointer to a constant `fd_topo_tile_t` structure, which is not used in this function.
    - `out_fds_cnt`: An unsigned long integer representing the maximum number of file descriptors that can be stored in the `out_fds` array.
    - `out_fds`: A pointer to an integer array where the allowed file descriptors will be stored.
- **Control Flow**:
    - The function begins by casting the `topo` and `tile` parameters to void to indicate they are unused.
    - It checks if `out_fds_cnt` is less than 2, and if so, logs an error and terminates the program.
    - Initializes `out_cnt` to 0 and assigns the file descriptor for standard error (2) to the first position in `out_fds`, incrementing `out_cnt`.
    - Checks if the log file descriptor is valid (not -1) using `fd_log_private_logfile_fd()`, and if valid, assigns it to the next position in `out_fds`, incrementing `out_cnt`.
- **Output**: Returns the number of file descriptors added to the `out_fds` array as an unsigned long integer.


