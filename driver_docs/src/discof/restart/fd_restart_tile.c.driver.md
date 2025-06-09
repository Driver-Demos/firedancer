# Purpose
The provided C source code file is part of a larger system, likely a distributed or networked application, that manages and coordinates the restart process of a specific component or service, referred to as a "tile." This file defines the `fd_restart_tile_ctx` structure, which encapsulates the context and state necessary for managing the restart process, including handling gossip and store input/output, managing checkpoints, and interacting with other components like the "funk" and "spad" (likely specialized data structures or services). The code is structured to handle various stages of the restart process, including initialization, processing incoming fragments, and managing state transitions.

The file is not a standalone executable but rather a component intended to be integrated into a larger system, as indicated by its inclusion of multiple headers and its definition of a `fd_topo_run_tile_t` structure, which appears to be a configuration or registration of this tile within a broader topology or framework. The code handles specific tasks such as decoding and encoding data, managing file descriptors for checkpoints, and interacting with a "funk" system for transaction management. It defines several static functions for initialization and processing, suggesting that it is part of a modular system where each tile or component has a specific role, in this case, managing the restart logic and ensuring data consistency and integrity during the process.
# Imports and Dependencies

---
- `fd_restart.h`
- `../../disco/stem/fd_stem.h`
- `../../disco/topo/fd_topo.h`
- `../../util/pod/fd_pod_format.h`
- `../../disco/keyguard/fd_keyload.h`
- `../../funk/fd_funk_filemap.h`
- `../../flamenco/runtime/fd_runtime.h`
- `../../disco/stem/fd_stem.c`


# Global Variables

---
### privileged\_init
- **Type**: `function`
- **Description**: The `privileged_init` function is a static function that initializes certain privileged operations related to the tower checkpoint in the `fd_topo_tile_t` structure. It attempts to open a file specified by `tile->restart.tower_checkpt` and assigns the file descriptor to `tile->restart.tower_checkpt_fileno`. If the file path is non-empty, it opens the file with read and write permissions, creating it if necessary.
- **Use**: This function is used to set up the file descriptor for the tower checkpoint file in the `fd_topo_tile_t` structure during the initialization phase of a tile.


---
### fd\_tile\_restart
- **Type**: `fd_topo_run_tile_t`
- **Description**: The `fd_tile_restart` is a global variable of type `fd_topo_run_tile_t`, which is a structure used to define the configuration and behavior of a tile in a topology. It includes function pointers for initialization and execution, as well as alignment and footprint specifications for memory management.
- **Use**: This variable is used to configure and manage the restart tile's operations within the system's topology, including its initialization and execution processes.


# Data Structures

---
### fd\_restart\_tile\_ctx
- **Type**: `struct`
- **Members**:
    - `restart`: Pointer to an fd_restart_t structure, managing restart operations.
    - `funk`: Array of fd_funk_t structures, managing transactional state.
    - `epoch_bank`: An fd_epoch_bank_t structure, managing epoch-related data.
    - `is_funk_active`: Integer flag indicating if the funk is active.
    - `funk_file`: Character array storing the path to the funk file.
    - `runtime_spad`: Pointer to an fd_spad_t structure, managing runtime scratchpad memory.
    - `tower_checkpt_fileno`: Integer file descriptor for the tower checkpoint file.
    - `identity`: fd_pubkey_t structure representing the identity public key.
    - `coordinator`: fd_pubkey_t structure representing the coordinator public key.
    - `genesis_hash`: fd_pubkey_t structure representing the genesis hash.
    - `new_hard_forks`: Pointer to an array of fd_slot_pair_t structures, managing new hard forks.
    - `new_hard_forks_len`: Unsigned long indicating the length of new hard forks.
    - `is_constipated`: Pointer to an unsigned long, managing constipated state.
    - `gossip_out_mcache`: Pointer to fd_frag_meta_t structure for gossip output metadata cache.
    - `gossip_out_sync`: Pointer to an unsigned long for gossip output synchronization.
    - `gossip_out_depth`: Unsigned long indicating the depth of gossip output.
    - `gossip_out_seq`: Unsigned long indicating the sequence number of gossip output.
    - `gossip_out_mem`: Pointer to fd_wksp_t structure for gossip output memory workspace.
    - `gossip_out_chunk0`: Unsigned long indicating the initial chunk of gossip output.
    - `gossip_out_wmark`: Unsigned long indicating the watermark of gossip output.
    - `gossip_out_chunk`: Unsigned long indicating the current chunk of gossip output.
    - `gossip_in_mem`: Pointer to fd_wksp_t structure for gossip input memory workspace.
    - `gossip_in_chunk0`: Unsigned long indicating the initial chunk of gossip input.
    - `gossip_in_wmark`: Unsigned long indicating the watermark of gossip input.
    - `restart_gossip_msg`: Array of unsigned characters for storing restart gossip messages.
    - `store_out_mcache`: Pointer to fd_frag_meta_t structure for store output metadata cache.
    - `store_out_sync`: Pointer to an unsigned long for store output synchronization.
    - `store_out_depth`: Unsigned long indicating the depth of store output.
    - `store_out_seq`: Unsigned long indicating the sequence number of store output.
    - `store_out_mem`: Pointer to fd_wksp_t structure for store output memory workspace.
    - `store_out_chunk0`: Unsigned long indicating the initial chunk of store output.
    - `store_out_wmark`: Unsigned long indicating the watermark of store output.
    - `store_out_chunk`: Unsigned long indicating the current chunk of store output.
    - `store_in_mem`: Pointer to fd_wksp_t structure for store input memory workspace.
    - `store_in_chunk0`: Unsigned long indicating the initial chunk of store input.
    - `store_in_wmark`: Unsigned long indicating the watermark of store input.
    - `store_xid_msg`: fd_funk_txn_xid_t structure for storing transaction ID messages.
- **Description**: The `fd_restart_tile_ctx` structure is a complex data structure used in managing the state and operations of a restart tile within a distributed system. It integrates various components such as restart management, transactional state handling, epoch data, and communication through gossip and store tiles. The structure includes pointers to memory workspaces, metadata caches, and synchronization primitives, facilitating efficient data flow and state management across different system components. It also handles file operations, public key management, and transactional messaging, making it a critical part of the system's restart and recovery processes.


---
### fd\_restart\_tile\_ctx\_t
- **Type**: `struct`
- **Members**:
    - `restart`: Pointer to an fd_restart_t structure, managing the restart process.
    - `funk`: Array of fd_funk_t structures, managing transactional data.
    - `epoch_bank`: An fd_epoch_bank_t structure, managing epoch-related data.
    - `is_funk_active`: Integer flag indicating if funk is active.
    - `funk_file`: Character array storing the path to the funk file.
    - `runtime_spad`: Pointer to an fd_spad_t structure, managing shared memory.
    - `tower_checkpt_fileno`: Integer file descriptor for the tower checkpoint file.
    - `identity`: An fd_pubkey_t structure representing the identity public key.
    - `coordinator`: An fd_pubkey_t structure representing the coordinator public key.
    - `genesis_hash`: An fd_pubkey_t structure representing the genesis hash.
    - `new_hard_forks`: Pointer to an array of fd_slot_pair_t structures, managing new hard forks.
    - `new_hard_forks_len`: Unsigned long indicating the length of new_hard_forks array.
    - `is_constipated`: Pointer to an unsigned long, indicating constipated state.
    - `gossip_out_mcache`: Pointer to an fd_frag_meta_t structure for gossip output metadata cache.
    - `gossip_out_sync`: Pointer to an unsigned long for gossip output synchronization.
    - `gossip_out_depth`: Unsigned long indicating the depth of gossip output.
    - `gossip_out_seq`: Unsigned long indicating the sequence number of gossip output.
    - `gossip_out_mem`: Pointer to an fd_wksp_t structure for gossip output memory workspace.
    - `gossip_out_chunk0`: Unsigned long indicating the initial chunk for gossip output.
    - `gossip_out_wmark`: Unsigned long indicating the watermark for gossip output.
    - `gossip_out_chunk`: Unsigned long indicating the current chunk for gossip output.
    - `gossip_in_mem`: Pointer to an fd_wksp_t structure for gossip input memory workspace.
    - `gossip_in_chunk0`: Unsigned long indicating the initial chunk for gossip input.
    - `gossip_in_wmark`: Unsigned long indicating the watermark for gossip input.
    - `restart_gossip_msg`: Array of unsigned characters for storing restart gossip messages.
    - `store_out_mcache`: Pointer to an fd_frag_meta_t structure for store output metadata cache.
    - `store_out_sync`: Pointer to an unsigned long for store output synchronization.
    - `store_out_depth`: Unsigned long indicating the depth of store output.
    - `store_out_seq`: Unsigned long indicating the sequence number of store output.
    - `store_out_mem`: Pointer to an fd_wksp_t structure for store output memory workspace.
    - `store_out_chunk0`: Unsigned long indicating the initial chunk for store output.
    - `store_out_wmark`: Unsigned long indicating the watermark for store output.
    - `store_out_chunk`: Unsigned long indicating the current chunk for store output.
    - `store_in_mem`: Pointer to an fd_wksp_t structure for store input memory workspace.
    - `store_in_chunk0`: Unsigned long indicating the initial chunk for store input.
    - `store_in_wmark`: Unsigned long indicating the watermark for store input.
    - `store_xid_msg`: An fd_funk_txn_xid_t structure for storing store transaction ID messages.
- **Description**: The `fd_restart_tile_ctx_t` structure is a complex data structure used to manage the context of a restart tile in a distributed system. It contains various fields for handling restart processes, transactional data, epoch management, and communication through gossip and store tiles. The structure includes pointers to other structures for managing shared memory, metadata caches, and synchronization, as well as arrays and flags for handling specific operational states and messages. This structure is integral to the functioning of the restart tile, coordinating various components and processes within the system.


# Functions

---
### scratch\_align<!-- {{#callable:scratch_align}} -->
The `scratch_align` function returns a constant alignment value of 128 bytes.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended for use within the same translation unit and suggests the compiler to inline it for performance.
    - The function is marked with `FD_FN_CONST`, indicating that it has no side effects and its return value depends only on its parameters (though it takes no parameters in this case).
    - The function simply returns the constant value `128UL`.
- **Output**: The function returns an unsigned long integer with the value 128, representing an alignment size.


---
### scratch\_footprint<!-- {{#callable:scratch_footprint}} -->
The `scratch_footprint` function calculates the memory footprint required for a tile's scratch space based on its alignment and size requirements.
- **Inputs**:
    - `tile`: A pointer to a `fd_topo_tile_t` structure, which contains information about the tile, including its restart context and memory limits.
- **Control Flow**:
    - Initialize a variable `l` with `FD_LAYOUT_INIT` to start the layout calculation.
    - Append the alignment and size of `fd_restart_tile_ctx_t` to `l` using `FD_LAYOUT_APPEND`.
    - Append the alignment and footprint of the restart context to `l` using `fd_restart_align()` and `fd_restart_footprint()`.
    - Append the alignment and footprint of the scratchpad memory to `l` using `fd_spad_align()` and `fd_spad_footprint(tile->restart.heap_mem_max)`.
    - Finalize the layout with `FD_LAYOUT_FINI` using `scratch_align()` to ensure proper alignment.
    - Return the calculated layout size `l`.
- **Output**: The function returns an `ulong` representing the total memory footprint required for the tile's scratch space.
- **Functions called**:
    - [`fd_restart_align`](fd_restart.h.driver.md#fd_restart_align)
    - [`fd_restart_footprint`](fd_restart.h.driver.md#fd_restart_footprint)
    - [`scratch_align`](#scratch_align)


---
### unprivileged\_init<!-- {{#callable:unprivileged_init}} -->
The `unprivileged_init` function initializes various components and resources for a tile in a distributed system, setting up memory, context, and communication links.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology of the system.
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing the specific tile to be initialized.
- **Control Flow**:
    - Allocate scratch memory for the tile context and other components using `FD_SCRATCH_ALLOC_INIT` and `FD_SCRATCH_ALLOC_APPEND`.
    - Initialize the restart context by creating and joining a new restart object.
    - Set the funk file path and mark funk as inactive.
    - Initialize the SPAD (scratchpad) memory and push it to the runtime context.
    - Check and set the tower checkpoint file descriptor, logging an error if it fails to open.
    - Decode and set the restart coordinator and genesis hash from base58 encoded strings.
    - Load the identity key and set it in the context.
    - Query the topology for a constipated object ID and join the corresponding fseq, logging an error if it fails.
    - Verify the output links for the tile, logging an error if they are unexpected.
    - Set up the gossip and store input/output links, including memory caches, synchronization, and chunk management.
- **Output**: The function does not return a value; it initializes the tile's context and resources in place.
- **Functions called**:
    - [`fd_restart_align`](fd_restart.h.driver.md#fd_restart_align)
    - [`fd_restart_footprint`](fd_restart.h.driver.md#fd_restart_footprint)
    - [`scratch_align`](#scratch_align)
    - [`fd_restart_join`](fd_restart.c.driver.md#fd_restart_join)
    - [`fd_restart_new`](fd_restart.c.driver.md#fd_restart_new)


---
### during\_frag<!-- {{#callable:during_frag}} -->
The `during_frag` function processes incoming data chunks based on their source index, either copying gossip messages or store transaction IDs after validating their integrity.
- **Inputs**:
    - `ctx`: A pointer to a `fd_restart_tile_ctx_t` structure containing context information for the restart tile.
    - `in_idx`: An unsigned long indicating the index of the input source, either GOSSIP_IN_IDX or STORE_IN_IDX.
    - `seq`: An unsigned long representing the sequence number, but it is unused in this function.
    - `sig`: An unsigned long representing the signature, but it is unused in this function.
    - `chunk`: An unsigned long representing the chunk index of the data to be processed.
    - `sz`: An unsigned long representing the size of the data chunk.
    - `ctl`: An unsigned long representing control information, but it is unused in this function.
- **Control Flow**:
    - Check if `in_idx` is `GOSSIP_IN_IDX`; if true, validate the chunk and size against the gossip input range and maximum size.
    - If the gossip input is valid, copy the data from the chunk to `ctx->restart_gossip_msg`.
    - If `in_idx` is `STORE_IN_IDX`, validate the chunk and size against the store input range and expected size for a transaction ID.
    - If the store input is valid, copy the data from the chunk to `ctx->store_xid_msg`.
- **Output**: The function does not return a value; it performs operations based on the input index and modifies the context structure accordingly.


---
### after\_frag<!-- {{#callable:after_frag}} -->
The `after_frag` function processes incoming messages to determine if a heaviest fork has been found and needs repair, and updates the slot bank with a new hard fork if necessary.
- **Inputs**:
    - `ctx`: A pointer to the `fd_restart_tile_ctx_t` structure, which contains context information for the restart tile.
    - `in_idx`: An unsigned long indicating the index of the input source, either GOSSIP_IN_IDX or STORE_IN_IDX.
    - `seq`: An unsigned long representing the sequence number, marked as unused.
    - `sig`: An unsigned long representing the signature, marked as unused.
    - `sz`: An unsigned long representing the size, marked as unused.
    - `tsorig`: An unsigned long representing the original timestamp, marked as unused.
    - `tspub`: An unsigned long representing the publish timestamp, marked as unused.
    - `stem`: A pointer to the `fd_stem_context_t` structure, marked as unused.
- **Control Flow**:
    - Check if the input index `in_idx` is `GOSSIP_IN_IDX`.
    - If `GOSSIP_IN_IDX`, call [`fd_restart_recv_gossip_msg`](fd_restart.c.driver.md#fd_restart_recv_gossip_msg) to check for the heaviest fork found.
    - If a heaviest fork is found, call [`fd_restart_find_heaviest_fork_bank_hash`](fd_restart.c.driver.md#fd_restart_find_heaviest_fork_bank_hash) to determine if repair is needed.
    - If repair is needed, prepare a buffer and publish the heaviest fork slot to the store tile for repair and replay.
    - Check if the input index `in_idx` is `STORE_IN_IDX`.
    - If `STORE_IN_IDX`, decode the slot bank for the heaviest fork slot from funk using `fd_funk_txn_query`.
    - If the transaction is not found, retry with the slot number instead of the block hash.
    - Query the record and validate its size and magic number.
    - Decode the slot bank and add a new hard fork to it.
    - Prepare and publish the updated slot bank back to funk.
    - Publish the transaction in funk and update the heaviest fork bank hash in the restart context.
- **Output**: The function does not return a value; it performs operations on the context and updates the state of the system.
- **Functions called**:
    - [`fd_restart_recv_gossip_msg`](fd_restart.c.driver.md#fd_restart_recv_gossip_msg)
    - [`fd_restart_find_heaviest_fork_bank_hash`](fd_restart.c.driver.md#fd_restart_find_heaviest_fork_bank_hash)


---
### after\_credit<!-- {{#callable:after_credit}} -->
The `after_credit` function initializes and manages the state of a 'funk' (a data structure) and related components, ensuring they are correctly set up and ready for further operations in a distributed system.
- **Inputs**:
    - `ctx`: A pointer to a `fd_restart_tile_ctx_t` structure, which holds the context and state information for the restart tile.
    - `stem`: A pointer to a `fd_stem_context_t` structure, which is unused in this function.
    - `opt_poll_in`: A pointer to an integer, which is unused in this function.
    - `charge_busy`: A pointer to an integer, which is unused in this function.
- **Control Flow**:
    - Check if the 'funk' is not active using `ctx->is_funk_active`.
    - If not active, open the 'funk' file using `fd_funk_open_file` and log success or failure.
    - Decode the slot bank from the 'funk' using `fd_funk_rec_query_try` and `fd_bincode_decode_spad`, checking for errors.
    - Decode the epoch bank similarly, updating `ctx->epoch_bank` with the decoded data.
    - Decode the slot history sysvar using `fd_txn_account_init_from_funk_readonly` and `fd_bincode_decode_spad`.
    - Initialize the restart context with [`fd_restart_init`](fd_restart.c.driver.md#fd_restart_init), using the decoded data and other context information.
    - Publish the restart information to the gossip tile using `fd_mcache_publish`.
    - Verify if the heaviest fork can be sent using [`fd_restart_verify_heaviest_fork`](fd_restart.c.driver.md#fd_restart_verify_heaviest_fork).
    - If a message needs to be sent, publish the restart_heaviest_fork message to the gossip tile.
- **Output**: The function does not return a value; it modifies the state of the `ctx` structure and potentially logs errors or notices.
- **Functions called**:
    - [`fd_restart_init`](fd_restart.c.driver.md#fd_restart_init)
    - [`fd_restart_verify_heaviest_fork`](fd_restart.c.driver.md#fd_restart_verify_heaviest_fork)


