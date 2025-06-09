# Purpose
The provided C code is part of a larger system designed to handle the replay of blockchain transactions, specifically within a distributed computing environment. This file appears to be a core component of a blockchain node, responsible for managing the execution of transactions, maintaining consensus, and interacting with other components such as storage, execution, and network communication modules. The code is structured to handle various tasks such as initializing and managing the state of the node, processing transaction slices, and ensuring the integrity and consistency of the blockchain state.

Key components of this code include the management of transaction execution contexts, handling of blockchain forks, and the integration with other system components like the blockstore and transaction cache. The code also includes mechanisms for snapshot management, which are crucial for maintaining the state of the blockchain across restarts and ensuring data consistency. Additionally, the code is designed to interact with plugins and external systems, allowing for extensibility and integration with other tools. The use of various data structures and synchronization mechanisms indicates a focus on performance and reliability, which are critical in a distributed blockchain environment.
# Imports and Dependencies

---
- `../../disco/tiles.h`
- `generated/fd_replay_tile_seccomp.h`
- `fd_replay_notif.h`
- `../restart/fd_restart.h`
- `fd_epoch_forks.h`
- `../../disco/keyguard/fd_keyload.h`
- `../../util/pod/fd_pod_format.h`
- `../../flamenco/runtime/fd_txncache.h`
- `../../flamenco/runtime/context/fd_capture_ctx.h`
- `../../flamenco/runtime/context/fd_exec_epoch_ctx.h`
- `../../flamenco/runtime/context/fd_exec_slot_ctx.h`
- `../../flamenco/runtime/program/fd_bpf_program_util.h`
- `../../flamenco/runtime/sysvar/fd_sysvar_slot_history.h`
- `../../flamenco/runtime/fd_hashes.h`
- `../../flamenco/runtime/fd_runtime_init.h`
- `../../flamenco/snapshot/fd_snapshot.h`
- `../../flamenco/stakes/fd_stakes.h`
- `../../flamenco/runtime/fd_runtime.h`
- `../../flamenco/runtime/fd_runtime_public.h`
- `../../flamenco/rewards/fd_rewards.h`
- `../../disco/metrics/fd_metrics.h`
- `../../choreo/fd_choreo.h`
- `../../funk/fd_funk_filemap.h`
- `../../flamenco/snapshot/fd_snapshot_create.h`
- `../../disco/plugin/fd_plugin.h`
- `fd_exec.h`
- `arpa/inet.h`
- `errno.h`
- `fcntl.h`
- `linux/unistd.h`
- `netdb.h`
- `netinet/in.h`
- `sys/random.h`
- `sys/socket.h`
- `sys/stat.h`
- `sys/types.h`
- `unistd.h`
- `../../util/tmpl/fd_deque.c`
- `../../disco/stem/fd_stem.c`


# Global Variables

---
### fd\_tile\_replay
- **Type**: `fd_topo_run_tile_t`
- **Description**: The `fd_tile_replay` is a global variable of type `fd_topo_run_tile_t` that represents a configuration for a replay tile in a distributed system. It is initialized with various function pointers and parameters that define the behavior and characteristics of the replay tile, such as its name, memory footprint, initialization routines, and execution function.
- **Use**: This variable is used to configure and manage the execution of a replay tile within the system, providing necessary functions and parameters for its operation.


# Data Structures

---
### fd\_replay\_out\_link
- **Type**: `struct`
- **Members**:
    - `idx`: An unsigned long integer representing the index of the link.
    - `mcache`: A pointer to a `fd_frag_meta_t` structure, representing the metadata cache.
    - `sync`: A pointer to an unsigned long integer used for synchronization.
    - `depth`: An unsigned long integer representing the depth of the link.
    - `seq`: An unsigned long integer representing the sequence number.
    - `mem`: A pointer to a `fd_wksp_t` structure, representing the memory workspace.
    - `chunk0`: An unsigned long integer representing the initial chunk.
    - `wmark`: An unsigned long integer representing the watermark.
    - `chunk`: An unsigned long integer representing the current chunk.
- **Description**: The `fd_replay_out_link` structure is used to manage output links in a replay system, providing fields for indexing, synchronization, and memory management. It includes pointers to metadata and memory workspaces, as well as fields for tracking sequence numbers and chunk management, facilitating the handling of data flow and synchronization in a distributed system.


---
### fd\_replay\_out\_link\_t
- **Type**: `typedef struct fd_replay_out_link fd_replay_out_link_t;`
- **Members**:
    - `idx`: An unsigned long integer representing the index of the link.
    - `mcache`: A pointer to fd_frag_meta_t, representing the metadata cache associated with the link.
    - `sync`: A pointer to an unsigned long integer used for synchronization purposes.
    - `depth`: An unsigned long integer representing the depth of the metadata cache.
    - `seq`: An unsigned long integer representing the sequence number for the link.
    - `mem`: A pointer to fd_wksp_t, representing the memory workspace associated with the link.
    - `chunk0`: An unsigned long integer representing the initial chunk of memory for the link.
    - `wmark`: An unsigned long integer representing the watermark for the link's memory usage.
    - `chunk`: An unsigned long integer representing the current chunk of memory being used by the link.
- **Description**: The `fd_replay_out_link_t` structure is used to manage output links in a replay system, providing fields for managing metadata, synchronization, memory allocation, and sequence tracking. It includes pointers to metadata caches and memory workspaces, as well as various unsigned long integers to track indices, sequence numbers, and memory usage. This structure is essential for handling the output of replay operations, ensuring that data is correctly synchronized and stored in the appropriate memory locations.


---
### fd\_replay\_tile\_metrics
- **Type**: `struct`
- **Members**:
    - `slot`: Represents the current slot number being processed.
    - `last_voted_slot`: Stores the last slot number that was voted on.
- **Description**: The `fd_replay_tile_metrics` structure is used to track metrics related to the replay tile's operation in a distributed system. It contains two fields: `slot`, which indicates the current slot being processed, and `last_voted_slot`, which records the last slot number that received a vote. This structure is likely used for monitoring and logging purposes to ensure the replay tile is functioning correctly and to track its progress over time.


---
### fd\_replay\_tile\_metrics\_t
- **Type**: `struct`
- **Members**:
    - `slot`: Represents the current slot number being processed.
    - `last_voted_slot`: Stores the last slot number that was voted on.
- **Description**: The `fd_replay_tile_metrics_t` structure is a simple data structure used to track metrics related to the replay tile's operation. It contains two members: `slot`, which indicates the current slot being processed, and `last_voted_slot`, which records the last slot that received a vote. This structure is likely used for monitoring and logging purposes to keep track of the replay tile's progress and voting activity.


---
### fd\_replay\_tile\_ctx
- **Type**: `struct`
- **Members**:
    - `wksp`: Pointer to a workspace used by the replay tile context.
    - `blockstore_wksp`: Pointer to a workspace for blockstore operations.
    - `funk_wksp`: Pointer to a workspace for funk operations.
    - `status_cache_wksp`: Pointer to a workspace for status cache operations.
    - `runtime_public_wksp`: Pointer to a workspace for runtime public operations.
    - `runtime_public`: Pointer to runtime public data.
    - `repair_in_mem`: Pointer to memory for storing repair tile input.
    - `repair_in_chunk0`: Initial chunk index for repair input.
    - `repair_in_wmark`: Watermark for repair input.
    - `pack_in_mem`: Pointer to memory for storing pack tile input.
    - `pack_in_chunk0`: Initial chunk index for pack input.
    - `pack_in_wmark`: Watermark for pack input.
    - `batch_in_mem`: Pointer to memory for storing batch tile input.
    - `batch_in_chunk0`: Initial chunk index for batch input.
    - `batch_in_wmark`: Watermark for batch input.
    - `notif_out`: Array of notification output link definitions.
    - `send_out`: Array of send output link definitions.
    - `stake_weights_out`: Array of stake weights output link definitions.
    - `plugin_out`: Array of plugin output link definitions.
    - `votes_plugin_out`: Array of votes plugin output link definitions.
    - `last_plugin_push_time`: Timestamp of the last plugin push.
    - `blockstore_checkpt`: Checkpoint path for blockstore.
    - `tx_metadata_storage`: Flag for transaction metadata storage.
    - `funk_checkpt`: Checkpoint path for funk.
    - `genesis`: Path to the genesis file.
    - `incremental`: Path to the incremental snapshot.
    - `snapshot`: Path to the snapshot file.
    - `snapshot_dir`: Directory path for snapshots.
    - `incremental_src_type`: Source type for incremental snapshots.
    - `snapshot_src_type`: Source type for snapshots.
    - `funk`: Array of funk transaction data.
    - `epoch_ctx`: Pointer to the execution epoch context.
    - `epoch`: Pointer to the epoch data.
    - `forks`: Pointer to the forks data.
    - `ghost`: Pointer to the ghost data.
    - `tower`: Pointer to the tower data.
    - `validator_identity`: Array containing the validator's public key.
    - `vote_authority`: Array containing the vote authority's public key.
    - `vote_acc`: Array containing the vote account's public key.
    - `epoch_voters`: Pointer to the epoch voters map chain.
    - `bank_hash_cmp`: Pointer to the bank hash comparison data.
    - `blockstore_ljoin`: Local join for blockstore operations.
    - `blockstore_fd`: File descriptor for the blockstore archival file.
    - `blockstore`: Pointer to the blockstore data.
    - `slot_ctx`: Pointer to the execution slot context.
    - `slice_exec_ctx`: Slice execution context data.
    - `exec_cnt`: Count of execution tiles.
    - `exec_out`: Array of execution output link definitions.
    - `exec_ready`: Array indicating if execution tiles are ready.
    - `prev_ids`: Array of previous transaction IDs.
    - `exec_fseq`: Array of execution sequence pointers.
    - `block_finalizing`: Flag indicating if a block is finalizing.
    - `writer_cnt`: Count of writer tiles.
    - `writer_fseq`: Array of writer sequence pointers.
    - `writer_out`: Array of writer output link definitions.
    - `curr_slot`: Current slot number.
    - `parent_slot`: Parent slot number.
    - `snapshot_slot`: Snapshot slot number.
    - `curr_turbine_slot`: Pointer to the current turbine slot.
    - `root`: Root slot number.
    - `flags`: Flags for various operations.
    - `bank_idx`: Index of the bank.
    - `funk_seed`: Seed for funk operations.
    - `status_cache_seed`: Seed for status cache operations.
    - `capture_ctx`: Pointer to the capture context.
    - `capture_file`: File pointer for capture operations.
    - `slots_replayed_file`: File pointer for slots replayed operations.
    - `bank_busy`: Array of pointers to bank busy flags.
    - `bank_cnt`: Count of banks.
    - `bank_out`: Array of bank output link definitions.
    - `published_wmark`: Pointer to the published watermark.
    - `poh`: Pointer to the proof-of-history slot.
    - `poh_init_done`: Flag indicating if PoH initialization is done.
    - `snapshot_init_done`: Flag indicating if snapshot initialization is done.
    - `tower_checkpt_fileno`: File number for tower checkpointing.
    - `vote`: Flag indicating if voting is enabled.
    - `validator_identity_pubkey`: Array containing the validator's identity public key.
    - `vote_acct_addr`: Array containing the vote account address.
    - `status_cache`: Pointer to the status cache data.
    - `bmtree`: Array of pointers to binary merkle trees.
    - `epoch_forks`: Array of epoch forks data.
    - `exec_spads`: Array of pointers to execution spad data.
    - `exec_spads_wksp`: Array of pointers to execution spad workspaces.
    - `exec_txn_ctxs`: Array of pointers to execution transaction contexts.
    - `exec_spad_cnt`: Count of execution spads.
    - `runtime_spad`: Pointer to the runtime spad data.
    - `snapshot_interval`: Interval for snapshot creation.
    - `incremental_interval`: Interval for incremental snapshot creation.
    - `last_full_snap`: Last full snapshot number.
    - `is_constipated`: Pointer to the shared sequence for funk constipation.
    - `prev_full_snapshot_dist`: Previous full snapshot distance.
    - `prev_incr_snapshot_dist`: Previous incremental snapshot distance.
    - `false_root`: Pointer to the false root transaction.
    - `is_caught_up`: Flag indicating if the node is caught up.
    - `blocked_on_mblock`: Flag indicating if blocked on microblock boundaries.
    - `metrics`: Metrics data for the replay tile.
    - `exec_slice_deque`: Pointer to the deque for buffering execution slices.
- **Description**: The `fd_replay_tile_ctx` structure is a comprehensive context for managing the replay tile operations in a distributed system. It includes pointers to various workspaces and contexts for handling different aspects of the replay process, such as blockstore, funk, status cache, and runtime public operations. The structure also manages input and output links for different tile operations, maintains execution and writer tile states, and handles metadata related to slots, banks, and snapshots. Additionally, it includes mechanisms for managing proof-of-history, voting, and metrics, making it a central component for coordinating replay activities in the system.


---
### fd\_replay\_tile\_ctx\_t
- **Type**: `struct`
- **Members**:
    - `wksp`: Pointer to a workspace for general memory allocation.
    - `blockstore_wksp`: Pointer to a workspace for blockstore memory allocation.
    - `funk_wksp`: Pointer to a workspace for funk memory allocation.
    - `status_cache_wksp`: Pointer to a workspace for status cache memory allocation.
    - `runtime_public_wksp`: Pointer to a workspace for runtime public memory allocation.
    - `runtime_public`: Pointer to a runtime public structure.
    - `repair_in_mem`: Pointer to memory for repair input.
    - `repair_in_chunk0`: Initial chunk for repair input.
    - `repair_in_wmark`: Watermark for repair input.
    - `pack_in_mem`: Pointer to memory for pack input.
    - `pack_in_chunk0`: Initial chunk for pack input.
    - `pack_in_wmark`: Watermark for pack input.
    - `batch_in_mem`: Pointer to memory for batch input.
    - `batch_in_chunk0`: Initial chunk for batch input.
    - `batch_in_wmark`: Watermark for batch input.
    - `notif_out`: Array of notification output links.
    - `send_out`: Array of send output links.
    - `stake_weights_out`: Array of stake weights output links.
    - `plugin_out`: Array of plugin output links.
    - `votes_plugin_out`: Array of votes plugin output links.
    - `last_plugin_push_time`: Timestamp of the last plugin push.
    - `blockstore_checkpt`: Checkpoint path for blockstore.
    - `tx_metadata_storage`: Flag for transaction metadata storage.
    - `funk_checkpt`: Checkpoint path for funk.
    - `genesis`: Path to the genesis file.
    - `incremental`: Path to the incremental snapshot.
    - `snapshot`: Path to the snapshot file.
    - `snapshot_dir`: Directory path for snapshots.
    - `incremental_src_type`: Source type for incremental snapshots.
    - `snapshot_src_type`: Source type for snapshots.
    - `funk`: Array of funk transaction structures.
    - `epoch_ctx`: Pointer to the execution epoch context.
    - `epoch`: Pointer to the epoch structure.
    - `forks`: Pointer to the forks structure.
    - `ghost`: Pointer to the ghost structure.
    - `tower`: Pointer to the tower structure.
    - `validator_identity`: Array of validator identity public keys.
    - `vote_authority`: Array of vote authority public keys.
    - `vote_acc`: Array of vote account public keys.
    - `epoch_voters`: Pointer to the epoch voters structure.
    - `bank_hash_cmp`: Pointer to the bank hash comparison structure.
    - `blockstore_ljoin`: Local join structure for blockstore.
    - `blockstore_fd`: File descriptor for the blockstore archival file.
    - `blockstore`: Pointer to the blockstore structure.
    - `slot_ctx`: Pointer to the execution slot context.
    - `slice_exec_ctx`: Execution context for slices.
    - `exec_cnt`: Count of execution tiles.
    - `exec_out`: Array of execution output links.
    - `exec_ready`: Array indicating readiness of execution tiles.
    - `prev_ids`: Array of previous transaction IDs for execution tiles.
    - `exec_fseq`: Array of execution sequence pointers.
    - `block_finalizing`: Flag indicating if a block is being finalized.
    - `writer_cnt`: Count of writer tiles.
    - `writer_fseq`: Array of writer sequence pointers.
    - `writer_out`: Array of writer output links.
    - `curr_slot`: Current slot being processed.
    - `parent_slot`: Parent slot of the current slot.
    - `snapshot_slot`: Slot number of the snapshot.
    - `curr_turbine_slot`: Pointer to the current turbine slot.
    - `root`: Root slot in the tower.
    - `flags`: Flags for various execution states.
    - `bank_idx`: Index of the bank being processed.
    - `funk_seed`: Seed for funk operations.
    - `status_cache_seed`: Seed for status cache operations.
    - `capture_ctx`: Pointer to the capture context.
    - `capture_file`: File pointer for capture operations.
    - `slots_replayed_file`: File pointer for slots replayed logging.
    - `bank_busy`: Array of pointers to bank busy flags.
    - `bank_cnt`: Count of banks being processed.
    - `bank_out`: Array of bank output links.
    - `published_wmark`: Pointer to the published watermark.
    - `poh`: Pointer to the proof-of-history slot.
    - `poh_init_done`: Flag indicating if PoH initialization is done.
    - `snapshot_init_done`: Flag indicating if snapshot initialization is done.
    - `tower_checkpt_fileno`: File number for tower checkpointing.
    - `vote`: Flag indicating if voting is enabled.
    - `validator_identity_pubkey`: Array of validator identity public keys for voting.
    - `vote_acct_addr`: Array of vote account addresses.
    - `status_cache`: Pointer to the status cache structure.
    - `bmtree`: Array of pointers to binary merkle trees.
    - `epoch_forks`: Array of epoch forks structures.
    - `exec_spads`: Array of pointers to execution spads.
    - `exec_spads_wksp`: Array of pointers to execution spad workspaces.
    - `exec_txn_ctxs`: Array of pointers to execution transaction contexts.
    - `exec_spad_cnt`: Count of execution spads.
    - `runtime_spad`: Pointer to the runtime spad.
    - `snapshot_interval`: Interval for full snapshots.
    - `incremental_interval`: Interval for incremental snapshots.
    - `last_full_snap`: Slot number of the last full snapshot.
    - `is_constipated`: Pointer to the constipated flag.
    - `prev_full_snapshot_dist`: Previous distance for full snapshot creation.
    - `prev_incr_snapshot_dist`: Previous distance for incremental snapshot creation.
    - `false_root`: Pointer to the false root transaction.
    - `is_caught_up`: Flag indicating if the node is caught up to the network.
    - `blocked_on_mblock`: Flag indicating if execution is blocked on a microblock boundary.
    - `metrics`: Structure containing replay tile metrics.
    - `exec_slice_deque`: Deque for buffering execution slices.
- **Description**: The `fd_replay_tile_ctx_t` structure is a comprehensive context for managing the replay tile in a distributed system. It includes pointers to various workspaces and contexts for memory management, execution, and transaction processing. The structure manages inputs and outputs for different tile operations, including repair, pack, batch, and notifications. It also handles execution and writer tiles, maintaining their states and sequences. The structure supports snapshot management, voting, and consensus operations, with fields for tracking slots, flags, and metrics. It integrates with various components like funk, blockstore, and status cache, providing a centralized context for replay operations.


# Functions

---
### scratch\_align<!-- {{#callable:scratch_align}} -->
The `scratch_align` function returns a constant alignment value of 128UL.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended for use within the same translation unit and suggests inlining for performance.
    - The function does not take any parameters.
    - The function body consists of a single return statement.
- **Output**: The function returns an unsigned long integer (ulong) with a value of 128UL, representing an alignment size.


---
### loose\_footprint<!-- {{#callable:loose_footprint}} -->
The `loose_footprint` function calculates the memory footprint for a loose configuration using a constant multiplier and a predefined page size.
- **Inputs**:
    - `tile`: A pointer to a `fd_topo_tile_t` structure, which is marked as unused in this function.
- **Control Flow**:
    - The function takes a single argument, `tile`, which is marked as unused with `FD_PARAM_UNUSED`.
    - It returns a constant value calculated as `24UL * FD_SHMEM_GIGANTIC_PAGE_SZ`.
- **Output**: The function returns an `ulong` representing the calculated memory footprint.


---
### scratch\_footprint<!-- {{#callable:scratch_footprint}} -->
The `scratch_footprint` function calculates the memory footprint required for various components in a specific order, ensuring proper alignment and size for each component.
- **Inputs**:
    - `tile`: A pointer to a `fd_topo_tile_t` structure, which is not used in the function.
- **Control Flow**:
    - Initialize a variable `l` with `FD_LAYOUT_INIT` to start the layout calculation.
    - Append the layout for `fd_replay_tile_ctx_t` using its alignment and size.
    - Append the layout for `FD_CAPTURE_CTX_ALIGN` and `FD_CAPTURE_CTX_FOOTPRINT`.
    - Append the layout for epoch-related data using `fd_epoch_align()` and `fd_epoch_footprint(FD_VOTER_MAX)`.
    - Append the layout for forks-related data using `fd_forks_align()` and `fd_forks_footprint(FD_BLOCK_MAX)`.
    - Append the layout for ghost-related data using `fd_ghost_align()` and `fd_ghost_footprint(FD_BLOCK_MAX)`.
    - Append the layout for tower-related data using `fd_tower_align()` and `fd_tower_footprint()`.
    - Iterate over `FD_PACK_MAX_BANK_TILES` to append the layout for each bank tile using `FD_BMTREE_COMMIT_ALIGN` and `FD_BMTREE_COMMIT_FOOTPRINT(0)`.
    - Append the layout for a slice with alignment `128UL` and size `FD_SLICE_MAX`.
    - Finalize the layout with `FD_LAYOUT_FINI` using `scratch_align()`.
    - Return the calculated layout size `l`.
- **Output**: The function returns an `ulong` representing the total memory footprint required for the specified components.
- **Functions called**:
    - [`scratch_align`](#scratch_align)


---
### before\_frag<!-- {{#callable:before_frag}} -->
The `before_frag` function processes incoming data slices based on their source index and either logs and queues them for execution or simply acknowledges them.
- **Inputs**:
    - `ctx`: A pointer to a `fd_replay_tile_ctx_t` structure, which contains context information for the replay tile.
    - `in_idx`: An unsigned long integer representing the index of the input source.
    - `seq`: An unsigned long integer representing the sequence number, which is unused in this function.
    - `sig`: An unsigned long integer representing the signature of the data slice.
- **Control Flow**:
    - The function first ignores the `seq` parameter as it is not used.
    - It checks if `in_idx` is equal to `REPAIR_IN_IDX`.
    - If true, it logs a debug message with details about the slice and pushes the `sig` to the execution slice deque, then returns 1.
    - If `in_idx` is equal to `SHRED_IN_IDX`, it returns 1 without further action.
    - If neither condition is met, it returns 0.
- **Output**: The function returns an integer: 1 if the slice is processed or acknowledged, and 0 if it is not.


---
### during\_frag<!-- {{#callable:during_frag}} -->
The `during_frag` function processes a fragment of data during a batch operation, specifically updating the epoch account hash if the input index matches a predefined constant.
- **Inputs**:
    - `ctx`: A pointer to an `fd_replay_tile_ctx_t` structure, which contains context information for the replay tile, including memory and state management for various operations.
    - `in_idx`: An unsigned long integer representing the index of the input source, used to determine the type of operation to perform.
    - `seq`: An unsigned long integer representing the sequence number of the fragment, marked as unused in this function.
    - `sig`: An unsigned long integer representing the signature of the fragment, marked as unused in this function.
    - `chunk`: An unsigned long integer representing the chunk of data to be processed, used to locate the source data in memory.
    - `sz`: An unsigned long integer representing the size of the fragment, marked as unused in this function.
    - `ctl`: An unsigned long integer representing control information for the fragment, marked as unused in this function.
- **Control Flow**:
    - Check if the input index `in_idx` is equal to `BATCH_IN_IDX`.
    - If true, convert the chunk to a local address using `fd_chunk_to_laddr` with `ctx->batch_in_mem` and `chunk`.
    - Copy the data from the source address to `ctx->slot_ctx->slot_bank.epoch_account_hash.uc` using `fd_memcpy`.
    - Log a notice message with the calculated epoch account hash using `FD_LOG_NOTICE`.
- **Output**: The function does not return a value; it performs operations on the provided context and logs information.


---
### publish\_stake\_weights<!-- {{#callable:publish_stake_weights}} -->
The `publish_stake_weights` function publishes the stake weights for the current and next epoch if the vote accounts root is not NULL.
- **Inputs**:
    - `ctx`: A pointer to the `fd_replay_tile_ctx_t` structure, which contains context information for the replay tile.
    - `stem`: A pointer to the `fd_stem_context_t` structure, which is used for publishing messages.
    - `slot_ctx`: A pointer to the `fd_exec_slot_ctx_t` structure, which contains context information for the current execution slot.
- **Control Flow**:
    - Retrieve the `epoch_bank` from the `slot_ctx`'s `epoch_ctx`.
    - Check if the `vote_accounts_root` of the `slot_ctx`'s `slot_bank.epoch_stakes` is not NULL.
    - If not NULL, calculate the stake weights for the current epoch, publish them, and update the chunk pointer.
    - Log the current epoch stake weights.
    - Check if the `vote_accounts_root` of the `epoch_bank.next_epoch_stakes` is not NULL.
    - If not NULL, calculate the stake weights for the next epoch, publish them, and update the chunk pointer.
    - Log the next epoch stake weights.
- **Output**: The function does not return a value; it performs actions such as publishing messages and logging information.
- **Functions called**:
    - [`generate_stake_weight_msg`](fd_exec.h.driver.md#generate_stake_weight_msg)


---
### snapshot\_hash\_tiles\_cb<!-- {{#callable:snapshot_hash_tiles_cb}} -->
The `snapshot_hash_tiles_cb` function initializes and manages the execution of hash tasks for a set of tiles, ensuring that each task is completed and results are gathered and published.
- **Inputs**:
    - `para_arg_1`: A pointer to `fd_replay_tile_ctx_t`, which contains the context for the replay tile, including execution counts and output links.
    - `para_arg_2`: A pointer to `fd_stem_context_t`, which is used for publishing messages to the stem.
    - `fn_arg_1`: A pointer to `fd_subrange_task_info_t`, which holds information about the task, including the number of lists and their associated data.
    - `fn_arg_2`: Unused parameter.
    - `fn_arg_3`: Unused parameter.
    - `fn_arg_4`: Unused parameter.
- **Control Flow**:
    - Initialize the number of lists to be processed based on the execution count from the context.
    - Allocate memory for the lists and hash values using the runtime scratchpad allocator.
    - Zero out the hash values for each list.
    - Store the number of lists, the list pointers, and the hash value pointers in the task information structure.
    - Iterate over each execution context, publishing a message to start the hash counting process and updating the chunk pointer.
    - Enter a loop to wait for all hash counting tasks to complete, checking the state of each task and allocating memory for the hash pairs when a task is done.
    - Once all tasks are acknowledged as done, iterate over each execution context again to prepare and publish a gather message with the results.
    - Reset the completion tracking array and enter another loop to wait for all gather tasks to complete, checking the state of each task.
- **Output**: The function does not return a value; it operates by modifying the state of the provided context and task information structures, and by publishing messages to the stem.


---
### bpf\_tiles\_cb<!-- {{#callable:bpf_tiles_cb}} -->
The `bpf_tiles_cb` function processes records and BPF program flags, distributing tasks across multiple execution tiles and ensuring all tasks are completed before proceeding.
- **Inputs**:
    - `para_arg_1`: A pointer to a `fd_replay_tile_ctx_t` structure, representing the context for replay tile operations.
    - `para_arg_2`: A pointer to a `fd_stem_context_t` structure, representing the context for stem operations.
    - `fn_arg_1`: A pointer to an array of `fd_funk_rec_t` pointers, representing the records to be processed.
    - `fn_arg_2`: A pointer to an array of `uchar`, indicating whether each record is a BPF program.
    - `fn_arg_3`: An `ulong` representing the count of records to be processed.
    - `fn_arg_4`: Unused parameter, marked with `FD_PARAM_UNUSED`.
- **Control Flow**:
    - Cast input pointers to their respective types for context and data handling.
    - Calculate the number of records each worker should process based on the total record count and the number of execution tiles.
    - Convert the record and BPF program pointers to global addresses using `fd_wksp_gaddr_fast` and log errors if conversion fails.
    - Initialize an array to track the previous state of execution tiles to avoid duplicate cache entries.
    - Iterate over each execution tile, generating and publishing BPF scan messages for the assigned records.
    - Wait for all execution tiles to complete their scanning tasks by polling their states and updating the `scan_done` array.
    - Break the loop once all execution tiles have completed their tasks.
- **Output**: The function does not return a value; it operates through side effects on the provided contexts and data structures.
- **Functions called**:
    - [`generate_bpf_scan_msg`](fd_exec.h.driver.md#generate_bpf_scan_msg)


---
### block\_finalize\_tiles\_cb<!-- {{#callable:block_finalize_tiles_cb}} -->
The `block_finalize_tiles_cb` function coordinates the finalization of hash computations across multiple worker tiles and ensures all tasks are completed before proceeding.
- **Inputs**:
    - `para_arg_1`: A pointer to `fd_replay_tile_ctx_t`, which contains context information for the replay tile.
    - `para_arg_2`: A pointer to `fd_stem_context_t`, which is the context for the stem operations.
    - `fn_arg_1`: A pointer to `fd_accounts_hash_task_data_t`, which contains task data for account hash operations.
    - `fn_arg_2`: Unused parameter, marked as `FD_PARAM_UNUSED`.
    - `fn_arg_3`: Unused parameter, marked as `FD_PARAM_UNUSED`.
    - `fn_arg_4`: Unused parameter, marked as `FD_PARAM_UNUSED`.
- **Control Flow**:
    - Initialize `cnt_per_worker` based on the number of execution contexts and the size of task data.
    - Calculate the global address for task information using `fd_wksp_gaddr_fast`.
    - Iterate over each worker index up to the execution count.
    - For each worker, calculate the start and end indices for the task data to be processed.
    - If the start index is beyond the task data size, mark the worker as done and continue to the next worker.
    - Generate a hash bank message for the current worker's data range and publish it using `fd_stem_publish`.
    - Compact the data cache for the current worker's output chunk.
    - Enter a loop to wait until all workers have completed their hash tasks.
    - Query each worker's execution sequence to check if the hash task is done, updating the `hash_done` array accordingly.
    - Break the loop once all workers have completed their tasks.
- **Output**: This function does not return a value; it performs operations and synchronizations on the provided context and task data.
- **Functions called**:
    - [`generate_hash_bank_msg`](fd_exec.h.driver.md#generate_hash_bank_msg)


---
### checkpt<!-- {{#callable:checkpt}} -->
The `checkpt` function manages the checkpointing process for a replay tile context by closing a file if open and creating checkpoints for blockstore and funk workspaces.
- **Inputs**:
    - `ctx`: A pointer to an `fd_replay_tile_ctx_t` structure, which contains context information for the replay tile, including file handles and workspace pointers for checkpointing.
- **Control Flow**:
    - Check if `ctx->slots_replayed_file` is open, and if so, close it using `fclose`.
    - Check if `ctx->blockstore_checkpt` is not an empty string, indicating a checkpoint is needed for the blockstore workspace.
    - If a blockstore checkpoint is needed, call `fd_wksp_checkpt` with the blockstore workspace and checkpoint path, and log an error if the checkpoint fails.
    - Always call `fd_wksp_checkpt` for the funk workspace with its checkpoint path, and log an error if this checkpoint fails.
- **Output**: The function does not return a value; it performs operations for checkpointing and logs errors if any occur during the process.


---
### funk\_cancel<!-- {{#callable:FD_FN_UNUSED::funk_cancel}} -->
The `funk_cancel` function cancels a transaction in the Funk database associated with a specific mismatch slot.
- **Inputs**:
    - `ctx`: A pointer to a `fd_replay_tile_ctx_t` structure, which contains the context for the replay tile, including the Funk database.
    - `mismatch_slot`: An unsigned long integer representing the slot number where a transaction mismatch occurred.
- **Control Flow**:
    - Begin a write transaction on the Funk database using `fd_funk_txn_start_write` with the context's Funk instance.
    - Create a transaction ID (`xid`) using the `mismatch_slot` for both elements of the `ul` array in the `fd_funk_txn_xid_t` structure.
    - Retrieve the transaction map from the Funk database using `fd_funk_txn_map`.
    - Query the transaction map for the transaction associated with the `xid` using `fd_funk_txn_query`.
    - Attempt to cancel the transaction using `fd_funk_txn_cancel`, passing the Funk instance, the transaction to cancel, and a flag set to 1.
    - End the write transaction on the Funk database using `fd_funk_txn_end_write`.
- **Output**: The function does not return a value; it performs operations to cancel a transaction in the Funk database.


---
### txncache\_publish<!-- {{#callable:txncache_publish}} -->
The `txncache_publish` function registers transaction slots in the status cache by iterating through a transaction tree from a given transaction to a rooted transaction.
- **Inputs**:
    - `ctx`: A pointer to a `fd_replay_tile_ctx_t` structure, which contains context information for the replay tile, including the status cache and funk transaction pool.
    - `to_root_txn`: A pointer to a `fd_funk_txn_t` structure representing the transaction from which to start iterating up the transaction tree.
    - `rooted_txn`: A pointer to a `fd_funk_txn_t` structure representing the transaction at which to stop iterating up the transaction tree.
- **Control Flow**:
    - Check if the status cache in the context is NULL; if so, return immediately.
    - Start reading transactions from the funk context using `fd_funk_txn_start_read`.
    - Initialize a transaction pointer `txn` to `to_root_txn` and retrieve the transaction pool from the funk context.
    - Iterate through the transaction tree from `to_root_txn` to `rooted_txn`.
    - For each transaction, retrieve the slot ID from the transaction's `xid` field.
    - Check if the status cache is constipated using `fd_txncache_get_is_constipated`.
    - If not constipated, register the slot as a root slot using `fd_txncache_register_root_slot`; otherwise, register it as a constipated slot using `fd_txncache_register_constipated_slot`.
    - Move to the parent transaction using `fd_funk_txn_parent`.
    - End the read operation on the funk context using `fd_funk_txn_end_read`.
- **Output**: This function does not return a value; it performs operations on the status cache and logs information.


---
### snapshot\_state\_update<!-- {{#callable:snapshot_state_update}} -->
The `snapshot_state_update` function checks if a snapshot is ready to be created based on certain conditions and updates the system state accordingly, but currently avoids triggering snapshot creation as it is not supported.
- **Inputs**:
    - `ctx`: A pointer to a `fd_replay_tile_ctx_t` structure, which contains the context and state information for the replay tile.
    - `wmk`: An unsigned long integer representing the current watermark or slot number being processed.
- **Control Flow**:
    - Check if the snapshot interval is set to `ULONG_MAX`, and if so, return immediately as no snapshot is needed.
    - Query the `is_constipated` flag to check if the system is currently constipated (i.e., unable to proceed with snapshot creation).
    - If the node is not caught up to the network or if the system is constipated, return immediately.
    - Calculate the current distance from the last full snapshot and determine if a full snapshot is ready based on whether this distance has decreased.
    - Calculate the current distance from the last incremental snapshot and determine if an incremental snapshot is ready based on whether this distance has decreased and a full snapshot has been taken.
    - Check if either a full or incremental snapshot is ready and if the current watermark does not fall on an epoch boundary.
    - If a snapshot is ready, log a warning that snapshot creation is not supported and return without creating a snapshot.
- **Output**: The function does not return any value; it updates the state of the context and logs messages as necessary.


---
### funk\_publish<!-- {{#callable:funk_publish}} -->
The `funk_publish` function manages the publication of transactions into the Funk system, handling both constipated and non-constipated states, and optionally computes the epoch account hash if required.
- **Inputs**:
    - `ctx`: A pointer to `fd_replay_tile_ctx_t`, which contains the context for the replay tile, including the Funk system and other related components.
    - `to_root_txn`: A pointer to `fd_funk_txn_t`, representing the transaction that should be published to the root.
    - `wmk`: An unsigned long integer representing the watermark, which is the slot number up to which transactions should be published.
    - `is_constipated`: An unsigned char indicating whether the Funk system is in a constipated state, affecting how transactions are published.
- **Control Flow**:
    - Begin a write transaction in the Funk system using `fd_funk_txn_start_write`.
    - Retrieve the transaction pool from the Funk context.
    - Check if the system is constipated using the `is_constipated` flag.
    - If constipated, log a notice and collapse the current transaction into the oldest child transaction by iterating through the transaction chain until reaching the false root.
    - If not constipated, log a notice and publish all transactions up to and including the watermark using `fd_funk_txn_publish`.
    - End the write transaction in the Funk system using `fd_funk_txn_end_write`.
    - Check if the epoch account hash feature is active and the accounts_lt_hash feature is inactive.
    - If the conditions for epoch account hash computation are met, compute the epoch account hash using `fd_accounts_hash` and log the completion.
    - Update the epoch bank's start slot to indicate the hash computation is done.
- **Output**: The function does not return a value; it performs operations on the Funk system and logs relevant information.


---
### get\_rooted\_txn<!-- {{#callable:get_rooted_txn}} -->
The `get_rooted_txn` function retrieves the rooted transaction for publishing, considering whether the system is constipated and managing the false root registration.
- **Inputs**:
    - `ctx`: A pointer to the `fd_replay_tile_ctx_t` structure, which contains the context for the replay tile, including transaction pools and status caches.
    - `to_root_txn`: A pointer to the `fd_funk_txn_t` structure representing the transaction that is intended to be rooted.
    - `is_constipated`: An `uchar` flag indicating whether the system is in a constipated state, affecting how transactions are rooted.
- **Control Flow**:
    - Initialize a transaction pool from the context's funk.
    - Check if the system is constipated.
    - If constipated and no false root is set, traverse the transaction tree to find the root transaction.
    - Set the false root in the context to the found root transaction.
    - Register the root transaction in the status cache, either as a root slot or a constipated slot, based on the status cache's constipation state.
    - Return the false root if constipated, otherwise return NULL.
- **Output**: Returns a pointer to the rooted transaction if the system is constipated, otherwise returns NULL.


---
### funk\_and\_txncache\_publish<!-- {{#callable:funk_and_txncache_publish}} -->
The `funk_and_txncache_publish` function publishes all in-prep slots up to a given watermark into the funk and transaction cache, while managing a 'constipated root' to support snapshot creation and epoch account hash generation.
- **Inputs**:
    - `ctx`: A pointer to an `fd_replay_tile_ctx_t` structure, which contains the context for the replay tile, including various workspaces, caches, and state information.
    - `wmk`: An unsigned long integer representing the watermark slot up to which transactions should be published.
    - `xid`: A pointer to a constant `fd_funk_txn_xid_t` structure, which identifies the transaction to be published.
- **Control Flow**:
    - Log the entry into the function with the given watermark.
    - Query the `is_constipated` flag to determine if the system is in a constipated state.
    - If the false root is set and the system is not constipated, unset the false root tracking.
    - Start a read transaction on the funk to get the transaction map and query the transaction to root using the provided xid.
    - If the transaction to root is not found, log an error and exit.
    - Determine the rooted transaction based on whether the system is constipated using [`get_rooted_txn`](#get_rooted_txn).
    - End the read transaction on the funk.
    - Publish the transaction to the transaction cache using [`txncache_publish`](#txncache_publish).
    - Publish the transaction to the funk using [`funk_publish`](#funk_publish).
    - Update the snapshot state using [`snapshot_state_update`](#snapshot_state_update).
    - If a capture context is present, perform a runtime checkpoint with `fd_runtime_checkpt`.
- **Output**: The function does not return a value; it performs operations to publish transactions and manage state within the context of the replay tile.
- **Functions called**:
    - [`get_rooted_txn`](#get_rooted_txn)
    - [`txncache_publish`](#txncache_publish)
    - [`funk_publish`](#funk_publish)
    - [`snapshot_state_update`](#snapshot_state_update)


---
### replay\_plugin\_publish<!-- {{#callable:replay_plugin_publish}} -->
The `replay_plugin_publish` function publishes data to a plugin output channel in a replay tile context.
- **Inputs**:
    - `ctx`: A pointer to a `fd_replay_tile_ctx_t` structure, which contains context information for the replay tile, including memory and chunk information for plugin output.
    - `stem`: A pointer to a `fd_stem_context_t` structure, which is used for publishing data.
    - `sig`: An unsigned long integer representing the signature or identifier for the data being published.
    - `data`: A pointer to a constant unsigned char array containing the data to be published.
    - `data_sz`: An unsigned long integer representing the size of the data to be published.
- **Control Flow**:
    - Convert the chunk address in the plugin output context to a local address using `fd_chunk_to_laddr`.
    - Copy the data from the input `data` to the destination address using `fd_memcpy`.
    - Compute a timestamp for publication using `fd_frag_meta_ts_comp` and `fd_tickcount`.
    - Publish the data using `fd_stem_publish`, passing the stem context, index, signature, chunk, data size, and timestamp.
    - Update the chunk in the plugin output context to the next available chunk using `fd_dcache_compact_next`.
- **Output**: The function does not return a value; it performs operations to publish data to a plugin output channel.


---
### publish\_slot\_notifications<!-- {{#callable:publish_slot_notifications}} -->
The `publish_slot_notifications` function publishes notifications about the execution of a slot, including transaction and slot details, to a memory cache and optionally to a plugin.
- **Inputs**:
    - `ctx`: A pointer to a `fd_replay_tile_ctx_t` structure, which contains context information for the replay tile, including memory caches and sequence numbers.
    - `stem`: A pointer to a `fd_stem_context_t` structure, which is used for publishing messages to the stem.
    - `fork`: A pointer to a `fd_fork_t` structure, representing the current fork being processed, which contains slot context and transaction details.
    - `block_entry_block_height`: An unsigned long integer representing the block height of the current block entry.
    - `curr_slot`: An unsigned long integer representing the current slot being processed.
- **Control Flow**:
    - Check if the notification output memory cache (`mcache`) is available; if not, return immediately.
    - Record the current time in nanoseconds for timing purposes.
    - Initialize a notification message (`msg`) and populate it with slot execution details such as slot number, parent slot, root, block height, transaction count, shred count, bank hash, validator identity, and timestamp.
    - Publish the notification message to the memory cache using `fd_mcache_publish` and update the sequence number and chunk for the next message.
    - Reset the shred count in the fork's slot context to zero.
    - Calculate the elapsed time for the notification process and log it for debugging purposes.
    - If the plugin output memory is available, prepare a message with slot completion details and publish it using [`replay_plugin_publish`](#replay_plugin_publish).
- **Output**: The function does not return a value; it performs side effects by publishing notifications to memory caches and optionally to a plugin.
- **Functions called**:
    - [`replay_plugin_publish`](#replay_plugin_publish)


---
### send\_tower\_sync<!-- {{#callable:send_tower_sync}} -->
The `send_tower_sync` function sends a synchronization message for the tower votes if voting is enabled.
- **Inputs**:
    - `ctx`: A pointer to a `fd_replay_tile_ctx_t` structure, which contains the context for the replay tile, including information about the tower, forks, blockstore, and other necessary components for synchronization.
- **Control Flow**:
    - Check if voting is enabled by evaluating `ctx->vote`; if not, return immediately.
    - Log a notice indicating that a tower sync is being sent.
    - Retrieve the slot of the last vote from the tower using `fd_tower_votes_peek_tail_const`.
    - Initialize `vote_bank_hash` and `vote_block_hash` arrays to zero.
    - Query the fork corresponding to the vote slot using `fd_forks_query_const` and copy the bank hash from the fork's slot context to `vote_bank_hash`.
    - Query the blockstore for the block hash of the vote slot using `fd_blockstore_block_hash_query`; log an error if the block hash is missing.
    - Prepare a vote transaction using `fd_tower_to_vote_txn`, which updates the vote state based on the current tower votes.
    - Publish the transaction to the mcache using `fd_mcache_publish`, increment the sequence number, and update the chunk pointer using `fd_dcache_compact_next`.
    - If the tower checkpoint file is open (file descriptor is greater than 0), update the tower checkpoint using `fd_restart_tower_checkpt`.
- **Output**: The function does not return a value; it performs actions to synchronize the tower votes by sending a transaction and updating the tower checkpoint if applicable.


---
### send\_exec\_epoch\_msg<!-- {{#callable:send_exec_epoch_msg}} -->
The `send_exec_epoch_msg` function sends execution epoch messages to all execution tiles in the context.
- **Inputs**:
    - `ctx`: A pointer to the `fd_replay_tile_ctx_t` structure, which contains the context for the replay tile, including execution count, output links, and other relevant data.
    - `stem`: A pointer to the `fd_stem_context_t` structure, which is used for publishing messages to the stem.
    - `slot_ctx`: A pointer to the `fd_exec_slot_ctx_t` structure, which contains the context for the execution slot, including runtime and bank hash comparison data.
- **Control Flow**:
    - Iterates over each execution tile in the context using a for loop with index `i` ranging from 0 to `ctx->exec_cnt`.
    - For each execution tile, it sets the `exec_ready` state to `EXEC_EPOCH_WAIT`.
    - Retrieves the output link for the current execution tile from `ctx->exec_out[i]`.
    - Converts the memory chunk to a local address and casts it to `fd_runtime_public_epoch_msg_t` to prepare the epoch message.
    - Calls [`generate_replay_exec_epoch_msg`](fd_exec.h.driver.md#generate_replay_exec_epoch_msg) to populate the epoch message with data from `slot_ctx`, `ctx->runtime_spad`, `ctx->runtime_public_wksp`, and `ctx->bank_hash_cmp`.
    - Calculates the publication timestamp `tspub` using `fd_frag_meta_ts_comp(fd_tickcount())`.
    - Publishes the epoch message using `fd_stem_publish`, specifying the stem, index, signature, chunk, size, and timestamps.
    - Updates the chunk in the output link to the next available chunk using `fd_dcache_compact_next`.
- **Output**: The function does not return a value; it performs its operations by modifying the state of the context and publishing messages.
- **Functions called**:
    - [`generate_replay_exec_epoch_msg`](fd_exec.h.driver.md#generate_replay_exec_epoch_msg)


---
### send\_exec\_slot\_msg<!-- {{#callable:send_exec_slot_msg}} -->
The `send_exec_slot_msg` function notifies execution and writer tiles that a new execution slot is ready to be published and updates their states accordingly.
- **Inputs**:
    - `ctx`: A pointer to the `fd_replay_tile_ctx_t` structure, which contains context information for the replay tile, including execution and writer tile states.
    - `stem`: A pointer to the `fd_stem_context_t` structure, which is used for publishing messages to the execution and writer tiles.
    - `slot_ctx`: A pointer to the `fd_exec_slot_ctx_t` structure, which contains context information for the current execution slot.
- **Control Flow**:
    - Iterate over each execution tile using a loop from 0 to `ctx->exec_cnt`.
    - For each execution tile, mark it as waiting for a new slot by setting `ctx->exec_ready[i]` to `EXEC_SLOT_WAIT`.
    - Retrieve the output link for the current execution tile and generate a slot message using [`generate_replay_exec_slot_msg`](fd_exec.h.driver.md#generate_replay_exec_slot_msg).
    - Publish the slot message to the execution tile using `fd_stem_publish` with the `EXEC_NEW_SLOT_SIG` signal.
    - Update the chunk for the execution tile's output link using `fd_dcache_compact_next`.
    - Iterate over each writer tile using a loop from 0 to `ctx->writer_cnt`.
    - For each writer tile, retrieve the output link and generate a writer slot message, setting the `slot_ctx_gaddr` field.
    - Publish the writer slot message to the writer tile using `fd_stem_publish` with the `FD_WRITER_SLOT_SIG` signal.
    - Update the chunk for the writer tile's output link using `fd_dcache_compact_next`.
- **Output**: The function does not return a value; it performs its operations by modifying the state of the execution and writer tiles and publishing messages to them.
- **Functions called**:
    - [`generate_replay_exec_slot_msg`](fd_exec.h.driver.md#generate_replay_exec_slot_msg)


---
### prepare\_new\_block\_execution<!-- {{#callable:prepare_new_block_execution}} -->
The `prepare_new_block_execution` function initializes and prepares a new block execution context for a given slot in a blockchain system.
- **Inputs**:
    - `ctx`: A pointer to the `fd_replay_tile_ctx_t` structure, which contains the context for the replay tile, including execution state, forks, and other necessary data for block execution.
    - `stem`: A pointer to the `fd_stem_context_t` structure, which is used for communication and coordination between different components in the system.
    - `curr_slot`: An unsigned long integer representing the current slot number for which the new block execution is being prepared.
    - `flags`: An unsigned long integer representing various flags that may affect the preparation process, such as whether the block is a packed microblock.
- **Control Flow**:
    - Initialize all execution tiles to the `EXEC_SLOT_WAIT` state.
    - Start timing the preparation process using `fd_log_wallclock`.
    - Prepare a new fork for the current slot using `fd_forks_prepare` and remove the previous slot context from the fork frontier.
    - Insert the new slot into the fork frontier and lock the fork for execution.
    - Log the start of a new block execution with the current and parent slot numbers.
    - Check if the new block is at an epoch boundary and update stake weights if necessary.
    - Prepare the block map for the current slot and update the starting PoH hash for tick verification.
    - Update the slot context with the new slot number, tick height, and other execution parameters.
    - Start a new transaction in the funk system for the current slot.
    - Process any new epoch boundary logic and send epoch messages if necessary.
    - Notify all execution tiles that a new slot is ready to be published and mark them as not ready.
    - Push a new spad frame for memory allocations during block execution.
    - Prepare the block execution context and handle any errors.
    - Read the slot history into the slot context for the current execution.
    - Publish stake weights if the new block is at an epoch boundary.
    - Log the elapsed preparation time and return the prepared fork.
- **Output**: Returns a pointer to the `fd_fork_t` structure representing the prepared fork for the new block execution.
- **Functions called**:
    - [`send_exec_epoch_msg`](#send_exec_epoch_msg)
    - [`send_exec_slot_msg`](#send_exec_slot_msg)
    - [`publish_stake_weights`](#publish_stake_weights)


---
### init\_poh<!-- {{#callable:init_poh}} -->
The `init_poh` function initializes and sends a proof-of-history (PoH) initialization message using the context provided.
- **Inputs**:
    - `ctx`: A pointer to a `fd_replay_tile_ctx_t` structure, which contains the context and state information needed for the function to operate.
- **Control Flow**:
    - Log the message 'sending init msg' to indicate the start of the initialization process.
    - Retrieve the first `fd_replay_out_link_t` from the `bank_out` array in the context.
    - Convert the memory chunk in `bank_out` to a local address and cast it to a `fd_poh_init_msg_t` pointer.
    - Retrieve the `epoch_bank` from the `epoch_ctx` in the context.
    - Set the `hashcnt_per_tick`, `ticks_per_slot`, and `tick_duration_ns` fields of the message using values from the `epoch_bank`.
    - Check if there is a `last_hash` in the `block_hash_queue` of the `slot_bank` in the context; if so, copy it to `last_entry_hash` in the message, otherwise set `last_entry_hash` to zero.
    - Calculate the `tick_height` as the product of the current slot and `ticks_per_slot`, and set it in the message.
    - Generate a signature using `fd_disco_replay_old_sig` with the current slot and `REPLAY_FLAG_INIT`.
    - Publish the message to the `mcache` of `bank_out` using `fd_mcache_publish`.
    - Update the `chunk` and `seq` fields of `bank_out` to prepare for the next message.
    - Set `poh_init_done` in the context to 1 to indicate completion.
- **Output**: The function does not return a value; it modifies the state of the `ctx` and sends a message through the `mcache`.


---
### prepare\_first\_batch\_execution<!-- {{#callable:prepare_first_batch_execution}} -->
The `prepare_first_batch_execution` function initializes the execution context for the first batch of a replayed slot in a distributed ledger system.
- **Inputs**:
    - `ctx`: A pointer to a `fd_replay_tile_ctx_t` structure, which holds the context for the replay tile, including current slot, flags, and various execution contexts.
    - `stem`: A pointer to a `fd_stem_context_t` structure, which is used for managing the execution of tasks in the system.
- **Control Flow**:
    - Retrieve the current slot and flags from the context (`ctx`).
    - Get the epoch context index for the current slot using [`fd_epoch_forks_get_epoch_ctx`](fd_epoch_forks.c.driver.md#fd_epoch_forks_get_epoch_ctx) and update the context's epoch context.
    - Query the fork frontier for the parent slot using `fd_fork_frontier_ele_query` to ensure it is not locked, logging an error if it is.
    - Query the fork frontier for the current slot; if it doesn't exist, prepare a new block execution using [`prepare_new_block_execution`](#prepare_new_block_execution).
    - Update the context's slot context to the fork's slot context.
    - If a capture context is present, set the slot for the capture context using `fd_solcap_writer_set_slot`.
- **Output**: The function does not return a value; it modifies the provided context (`ctx`) to prepare for the execution of the first batch of the current slot.
- **Functions called**:
    - [`fd_epoch_forks_get_epoch_ctx`](fd_epoch_forks.c.driver.md#fd_epoch_forks_get_epoch_ctx)
    - [`prepare_new_block_execution`](#prepare_new_block_execution)


---
### exec\_slice<!-- {{#callable:exec_slice}} -->
The `exec_slice` function manages the execution of transactions within a slice by dispatching them to execution tiles, handling synchronization at microblock boundaries, and finalizing block execution when complete.
- **Inputs**:
    - `ctx`: A pointer to the `fd_replay_tile_ctx_t` structure, which contains the context and state information for the replay tile.
    - `stem`: A pointer to the `fd_stem_context_t` structure, which is used for publishing messages and managing execution flow.
    - `slot`: An unsigned long integer representing the current slot being processed.
- **Control Flow**:
    - Initialize an array `to_exec` to track execution tiles that are ready to process transactions.
    - Count the number of free execution tiles by checking the `exec_ready` status in the context.
    - If the context is blocked on a microblock, check if all execution tiles are free; if not, return early.
    - While there are free execution tiles, check if a transaction is ready to be executed using [`fd_slice_exec_txn_ready`](fd_exec.h.driver.md#fd_slice_exec_txn_ready).
    - If a transaction is ready, parse it and dispatch it to an execution tile, updating the execution tile's status to busy.
    - If the current microblock is complete, parse the next microblock if available, and set the context to block on microblock boundaries.
    - If the entire slice is ready and not the last batch, set the context flag to indicate readiness for a new execution.
    - If the slot execution is complete, finalize the block execution by updating the block information and resetting the execution context.
- **Output**: The function does not return a value; it modifies the state of the execution context and publishes transaction execution messages.
- **Functions called**:
    - [`fd_slice_exec_txn_ready`](fd_exec.h.driver.md#fd_slice_exec_txn_ready)
    - [`fd_slice_exec_txn_parse`](fd_exec.c.driver.md#fd_slice_exec_txn_parse)
    - [`fd_slice_exec_microblock_ready`](fd_exec.h.driver.md#fd_slice_exec_microblock_ready)
    - [`fd_slice_exec_microblock_parse`](fd_exec.c.driver.md#fd_slice_exec_microblock_parse)
    - [`fd_slice_exec_slice_ready`](fd_exec.h.driver.md#fd_slice_exec_slice_ready)
    - [`fd_slice_exec_slot_complete`](fd_exec.h.driver.md#fd_slice_exec_slot_complete)
    - [`fd_slice_exec_reset`](fd_exec.c.driver.md#fd_slice_exec_reset)


---
### handle\_slice<!-- {{#callable:handle_slice}} -->
The `handle_slice` function processes a slice of executable slots from a deque, prepares it for execution, and manages the execution context for replaying slots.
- **Inputs**:
    - `ctx`: A pointer to a `fd_replay_tile_ctx_t` structure, which holds the context for the replay tile, including execution state, blockstore, and other necessary data for processing slices.
    - `stem`: A pointer to a `fd_stem_context_t` structure, which is used for managing the execution context and interactions with other components in the system.
- **Control Flow**:
    - Check if there are any slices to execute in the `exec_slice_deque` of the context `ctx`; if none, log a debug message and return.
    - Pop the head of the `exec_slice_deque` to get the signature `sig` of the slice to be executed.
    - Verify that the replay is in the expected state (`EXEC_FLAG_READY_NEW`); if not, log an error.
    - Extract the slot, parent offset, data count, and slot completion status from the signature `sig`.
    - Check if the slot or its parent slot is earlier than the published watermark; if so, log a warning and return.
    - Verify that the parent slot's block information is available in the blockstore; if not, log a warning and return.
    - If the current slot is different from the `curr_slot` in the context, update the current and parent slots, and prepare for the first batch execution.
    - Log the current slot, turbine slot, and slots behind information.
    - Set the execution flag to `EXEC_FLAG_EXECUTING_SLICE` and prepare the batch for execution by querying the blockstore for the slice data.
    - Begin execution of the slice using [`fd_slice_exec_begin`](fd_exec.c.driver.md#fd_slice_exec_begin) and update the fork's end index and shred count.
    - If there is an error querying the blockstore, log an error.
- **Output**: The function does not return a value; it modifies the state of the `ctx` and prepares the execution context for processing a slice.
- **Functions called**:
    - [`prepare_first_batch_execution`](#prepare_first_batch_execution)
    - [`fd_slice_exec_begin`](fd_exec.c.driver.md#fd_slice_exec_begin)


---
### kickoff\_repair\_orphans<!-- {{#callable:kickoff_repair_orphans}} -->
The `kickoff_repair_orphans` function initializes the blockstore and updates the published watermark and stake weights for orphaned slots.
- **Inputs**:
    - `ctx`: A pointer to an `fd_replay_tile_ctx_t` structure, which contains the context for the replay tile, including blockstore and slot context information.
    - `stem`: A pointer to an `fd_stem_context_t` structure, which is used for publishing stake weights and other operations related to the stem context.
- **Control Flow**:
    - Initialize the blockstore using `fd_blockstore_init` with parameters from the context's slot context and blockstore file descriptor.
    - Update the published watermark using `fd_fseq_update` with the current slot from the slot bank.
    - Call [`publish_stake_weights`](#publish_stake_weights) to publish the current stake weights using the provided context and stem.
- **Output**: This function does not return a value; it performs initialization and updates as side effects.
- **Functions called**:
    - [`publish_stake_weights`](#publish_stake_weights)


---
### read\_snapshot<!-- {{#callable:read_snapshot}} -->
The `read_snapshot` function loads a snapshot and an optional incremental snapshot into the system, initializing necessary contexts and kicking off repair processes.
- **Inputs**:
    - `_ctx`: A pointer to a `fd_replay_tile_ctx_t` structure, which holds the context for the replay tile.
    - `stem`: A pointer to an `fd_stem_context_t` structure, which is used for managing the execution context.
    - `snapshot`: A constant character pointer to the name or path of the full snapshot to be loaded.
    - `incremental`: A constant character pointer to the name or path of the incremental snapshot to be loaded, if any.
    - `snapshot_dir`: A constant character pointer to the directory where the snapshot is located.
- **Control Flow**:
    - Cast the `_ctx` pointer to a `fd_replay_tile_ctx_t` pointer named `ctx`.
    - Initialize an `fd_exec_para_cb_ctx_t` structure for parallel execution context with a callback function `snapshot_hash_tiles_cb`.
    - Check if the `snapshot` is already loaded by comparing it to "funk" or checking if it starts with "wksp:".
    - If the snapshot is already loaded, recover banks using `fd_runtime_recover_banks` and set `base_slot` to the current slot of the slot context.
    - If an incremental snapshot is provided, allocate memory for a temporary snapshot context and load the incremental snapshot using `fd_snapshot_load_new`.
    - Prefetch the manifest of the incremental snapshot and kick off repair processes using [`kickoff_repair_orphans`](#kickoff_repair_orphans).
    - Allocate memory for the full snapshot context and load the full snapshot using `fd_snapshot_load_new`.
    - Initialize the snapshot context with `fd_snapshot_load_init`.
    - Load the manifest and status cache for the full snapshot if no incremental snapshot is provided, otherwise load them without initialization.
    - Set `base_slot` to the slot obtained from the full snapshot context.
    - Load accounts and finalize the snapshot context with `fd_snapshot_load_accounts` and `fd_snapshot_load_fini`.
    - If an incremental snapshot is provided and the full snapshot is not "funk", load the incremental snapshot using `fd_snapshot_load_all`.
    - Update leaders in the runtime using `fd_runtime_update_leaders`.
    - Log the start and end of the BPF program cache entry creation process using `fd_bpf_scan_and_create_bpf_program_cache_entry_para`.
- **Output**: The function does not return a value; it performs operations to load snapshots and initialize contexts.
- **Functions called**:
    - [`kickoff_repair_orphans`](#kickoff_repair_orphans)


---
### init\_after\_snapshot<!-- {{#callable:init_after_snapshot}} -->
The `init_after_snapshot` function initializes the system state after loading snapshots, setting up the execution context, and preparing for block execution.
- **Inputs**:
    - `ctx`: A pointer to `fd_replay_tile_ctx_t`, which holds the context for the replay tile, including various runtime and execution state information.
    - `stem`: A pointer to `fd_stem_context_t`, which is used for managing the execution context and interactions with other components.
- **Control Flow**:
    - Recalculate partitioned rewards using `fd_rewards_recalculate_partitioned_rewards` with the current slot context and execution spads.
    - Check if the current snapshot slot is zero, indicating a genesis-specific setup is needed.
    - If genesis-specific setup is required, update leaders, initialize the slot bank, and prepare the block execution context.
    - Perform SHA-256 hashing for the proof-of-history (PoH) initialization if in genesis setup.
    - Prepare and finalize the block execution context using `fd_runtime_block_execute_prepare` and `fd_runtime_block_execute_finalize_para`.
    - Initialize BPF program cache entries using `fd_bpf_scan_and_create_bpf_program_cache_entry_para`.
    - Set the current slot, parent slot, and snapshot slot in the context, and mark the execution flags as ready for a new execution.
    - Initialize consensus structures post-snapshot, including forks, epoch, and ghost structures.
    - Set up the tower from the vote account and print the tower state.
    - Update the bank hash comparison structure with the total stake and watermark.
    - Determine the current epoch and update the epoch fork element with the parent slot and epoch information.
    - Advance the watermark if it has moved past the published watermark, updating relevant data structures and publishing changes.
- **Output**: The function does not return a value; it modifies the state of the `ctx` and `stem` structures to prepare for subsequent operations.
- **Functions called**:
    - [`fd_epoch_forks_publish`](fd_epoch_forks.c.driver.md#fd_epoch_forks_publish)


---
### init\_snapshot<!-- {{#callable:init_snapshot}} -->
The `init_snapshot` function initializes the snapshot context for a replay tile, setting up necessary structures and reading from a snapshot if available.
- **Inputs**:
    - `ctx`: A pointer to a `fd_replay_tile_ctx_t` structure, which holds the context for the replay tile, including various runtime and execution contexts.
    - `stem`: A pointer to a `fd_stem_context_t` structure, which is used for publishing messages and interacting with other components in the system.
- **Control Flow**:
    - Allocate memory for `slot_ctx` using `fd_spad_alloc_check` and initialize it with `fd_exec_slot_ctx_new` and `fd_exec_slot_ctx_join`.
    - Set various fields of `slot_ctx` from the `ctx` structure, such as `funk`, `blockstore`, `epoch_ctx`, and `status_cache`.
    - Update the number of slots per epoch using `fd_runtime_update_slots_per_epoch`.
    - Check if a snapshot is specified by examining `ctx->snapshot`, and if so, call [`read_snapshot`](#read_snapshot) to load it.
    - If `ctx->plugin_out->mem` is not null, publish a start progress message using [`replay_plugin_publish`](#replay_plugin_publish).
    - Read the genesis block using `fd_runtime_read_genesis`, which sets up the slot bank needed for blockstore initialization.
    - Initialize the blockstore with `fd_blockstore_init`, using the slot bank set up by `fd_runtime_read_genesis`.
    - Set `epoch_ctx->bank_hash_cmp` and `epoch_ctx->runtime_public` from `ctx`.
    - Call [`init_after_snapshot`](#init_after_snapshot) to perform additional initialization after loading the snapshot.
    - If `ctx->plugin_out->mem` is not null and `ctx->genesis` is specified, publish a genesis hash known message using [`replay_plugin_publish`](#replay_plugin_publish).
    - Redirect `ctx->slot_ctx` to point to the memory inside forks by querying the current fork with `fd_forks_query`.
    - Copy the current active features from `slot_ctx->epoch_ctx->features` to `ctx->runtime_public->features`.
    - Send an execution epoch message using [`send_exec_epoch_msg`](#send_exec_epoch_msg).
    - Determine the block entry height by querying the block map if a snapshot is used, otherwise set it to 1 and call [`init_poh`](#init_poh).
    - Publish slot notifications using [`publish_slot_notifications`](#publish_slot_notifications).
    - Assert that `ctx->slot_ctx` is valid with `FD_TEST`.
- **Output**: The function does not return a value; it performs initialization and setup operations on the provided context structures.
- **Functions called**:
    - [`read_snapshot`](#read_snapshot)
    - [`replay_plugin_publish`](#replay_plugin_publish)
    - [`init_after_snapshot`](#init_after_snapshot)
    - [`send_exec_epoch_msg`](#send_exec_epoch_msg)
    - [`init_poh`](#init_poh)
    - [`publish_slot_notifications`](#publish_slot_notifications)


---
### publish\_votes\_to\_plugin<!-- {{#callable:publish_votes_to_plugin}} -->
The `publish_votes_to_plugin` function publishes vote account updates to a plugin by iterating over vote accounts, decoding their state, and preparing a message for each account to be sent to the plugin.
- **Inputs**:
    - `ctx`: A pointer to a `fd_replay_tile_ctx_t` structure, which contains context information for the replay tile, including memory and state information.
    - `stem`: A pointer to a `fd_stem_context_t` structure, which is used for publishing messages to the plugin.
- **Control Flow**:
    - Convert the memory chunk address from the context to a local address for writing the output.
    - Query the current fork from the frontier using the current slot from the context.
    - If the fork is not found, return immediately.
    - Retrieve the vote accounts from the fork's slot context.
    - Initialize a counter `i` to zero for tracking the number of processed accounts.
    - Begin a scoped allocation frame for temporary memory usage.
    - Iterate over the vote accounts, starting from the minimum node in the map, and continue while there are accounts and `i` is less than the cluster node count.
    - For each account, if the stake is zero, skip to the next account.
    - Decode the vote state versioned data from the account's value using a decoding function, and handle any errors by logging an error message.
    - Depending on the discriminant of the decoded vote state, extract the node public key, commission, epoch credits, and root slot from the appropriate versioned structure.
    - Query the timestamp votes map for the current account's public key to find the last vote slot.
    - Prepare a vote update message by populating it with the account's public key, node public key, activated stake, last vote slot, root slot, epoch credits, commission, and delinquency status.
    - Increment the counter `i` for each processed account.
    - End the scoped allocation frame.
    - Store the count of processed accounts at the beginning of the output memory chunk.
    - Compute a timestamp for the publication and publish the message to the plugin using the stem context.
    - Update the chunk index in the context to the next available chunk.
- **Output**: The function does not return a value; it publishes a message to a plugin and updates the context's chunk index.


---
### join\_txn\_ctx<!-- {{#callable:join_txn_ctx}} -->
The `join_txn_ctx` function initializes and joins a transaction context for a specific execution tile by calculating its global and local addresses and updating the context's transaction context array.
- **Inputs**:
    - `ctx`: A pointer to an `fd_replay_tile_ctx_t` structure, which holds various context information for the replay tile, including execution spads and transaction contexts.
    - `exec_tile_idx`: An unsigned long integer representing the index of the execution tile for which the transaction context is being joined.
    - `txn_ctx_offset`: An unsigned integer representing the offset of the transaction context within its respective execution spad.
- **Control Flow**:
    - Calculate the global address of the execution spad using `fd_wksp_gaddr` with the workspace and spad at the given execution tile index.
    - Check if the global address is valid; if not, log an error and exit.
    - Calculate the global address of the transaction context by adding the offset to the execution spad's global address.
    - Convert the transaction context's global address to a local address using `fd_wksp_laddr`.
    - Check if the local address is valid; if not, log an error and exit.
    - Join the transaction context using `fd_exec_txn_ctx_join` with the local address, spad, and workspace, and store the result in the context's transaction context array at the given execution tile index.
    - Check if the transaction context was successfully joined; if not, log an error and exit.
- **Output**: The function does not return a value; it updates the transaction context array in the provided context structure.


---
### handle\_exec\_state\_updates<!-- {{#callable:handle_exec_state_updates}} -->
The `handle_exec_state_updates` function updates the local view of the execution states of exec tiles in a replay context.
- **Inputs**:
    - `ctx`: A pointer to a `fd_replay_tile_ctx_t` structure, which contains the context for the replay tile, including execution state information and other relevant data.
- **Control Flow**:
    - Iterates over each exec tile using a loop from 0 to `ctx->exec_cnt`.
    - For each exec tile, queries the current state using `fd_fseq_query` on `ctx->exec_fseq[i]`.
    - Checks if the exec tile is not joined using `fd_exec_fseq_is_not_joined` and logs a warning if true, then continues to the next iteration.
    - Retrieves the state of the exec tile using `fd_exec_fseq_get_state`.
    - Uses a switch statement to handle different states of the exec tile: `FD_EXEC_STATE_NOT_BOOTED`, `FD_EXEC_STATE_BOOTED`, `FD_EXEC_STATE_EPOCH_DONE`, `FD_EXEC_STATE_SLOT_DONE`, `FD_EXEC_STATE_HASH_DONE`, and `FD_EXEC_STATE_BPF_SCAN_DONE`.
    - Logs warnings or information based on the state and updates `ctx->exec_ready[i]` accordingly.
    - Handles unexpected states by logging an error.
- **Output**: The function does not return a value; it updates the state of exec tiles in the context structure and logs relevant information.
- **Functions called**:
    - [`join_txn_ctx`](#join_txn_ctx)


---
### handle\_writer\_state\_updates<!-- {{#callable:handle_writer_state_updates}} -->
The `handle_writer_state_updates` function checks and updates the state of writer tiles in a replay context, handling various states and logging warnings or errors as necessary.
- **Inputs**:
    - `ctx`: A pointer to a `fd_replay_tile_ctx_t` structure, which contains the context for the replay tile, including writer state information and other execution-related data.
- **Control Flow**:
    - Iterates over each writer tile using a loop indexed by `i`.
    - Queries the state of each writer tile using `fd_fseq_query` on `ctx->writer_fseq[i]`.
    - Checks if the writer tile is not joined using `fd_writer_fseq_is_not_joined` and logs a warning if true, then continues to the next iteration.
    - Retrieves the state of the writer tile using `fd_writer_fseq_get_state`.
    - Uses a switch statement to handle different states of the writer tile: `FD_WRITER_STATE_NOT_BOOTED`, `FD_WRITER_STATE_READY`, `FD_WRITER_STATE_TXN_DONE`, and a default case for unexpected states.
    - Logs warnings for `FD_WRITER_STATE_NOT_BOOTED` and does nothing for `FD_WRITER_STATE_READY`.
    - For `FD_WRITER_STATE_TXN_DONE`, retrieves the transaction ID and execution tile ID, checks if the execution tile is busy and the transaction ID has changed, logs a debug message, updates the execution tile state to `EXEC_TXN_READY`, updates the previous transaction ID, and sets the writer state to `FD_WRITER_STATE_READY`.
    - Logs a critical error for unexpected states in the default case.
- **Output**: The function does not return a value; it performs state updates and logging as side effects.


---
### after\_credit<!-- {{#callable:after_credit}} -->
The `after_credit` function manages the state updates and execution flow for replaying and processing blockchain slots, including handling writer and execution state updates, processing new slices, and finalizing block execution.
- **Inputs**:
    - `ctx`: A pointer to the `fd_replay_tile_ctx_t` structure, which holds the context and state information for the replay tile.
    - `stem`: A pointer to the `fd_stem_context_t` structure, which provides context for the stem operations.
    - `opt_poll_in`: An optional pointer to an integer, unused in this function, intended for polling input.
    - `charge_busy`: An optional pointer to an integer, unused in this function, intended for managing busy state charging.
- **Control Flow**:
    - Check and update the state of all writer link fseqs using [`handle_writer_state_updates`](#handle_writer_state_updates) function.
    - Check and update the state of all exec link fseqs using [`handle_exec_state_updates`](#handle_exec_state_updates) function.
    - If the context flags indicate readiness for a new slice (`EXEC_FLAG_READY_NEW`), call [`handle_slice`](#handle_slice) to poll and set up execution for a new slice.
    - If the context flags indicate a slice is currently executing (`EXEC_FLAG_EXECUTING_SLICE`), call [`exec_slice`](#exec_slice) to proceed with execution.
    - If the context flags indicate a slot has finished execution (`EXEC_FLAG_FINISHED_SLOT`), perform finalization tasks such as updating sysvars, publishing notifications, unlocking forks, updating consensus structures, and preparing for the next execution.
    - If the snapshot initialization is not done, initialize the snapshot and set the `snapshot_init_done` flag.
    - Periodically publish votes to the plugin if the time since the last plugin push exceeds a defined threshold.
- **Output**: The function does not return a value; it operates by updating the state and context of the replay tile as part of its execution flow.
- **Functions called**:
    - [`handle_writer_state_updates`](#handle_writer_state_updates)
    - [`handle_exec_state_updates`](#handle_exec_state_updates)
    - [`handle_slice`](#handle_slice)
    - [`exec_slice`](#exec_slice)
    - [`publish_slot_notifications`](#publish_slot_notifications)
    - [`replay_plugin_publish`](#replay_plugin_publish)
    - [`send_tower_sync`](#send_tower_sync)
    - [`init_snapshot`](#init_snapshot)
    - [`publish_votes_to_plugin`](#publish_votes_to_plugin)


---
### during\_housekeeping<!-- {{#callable:during_housekeeping}} -->
The `during_housekeeping` function updates the publish watermark and publishes various components if the new watermark is greater than the current published watermark.
- **Inputs**:
    - `_ctx`: A pointer to a context object of type `fd_replay_tile_ctx_t` which contains various state and configuration information for the replay tile.
- **Control Flow**:
    - Cast the input `_ctx` to a `fd_replay_tile_ctx_t` pointer named `ctx`.
    - Calculate the new watermark `wmark` as the minimum of `ctx->root` and `ctx->forks->finalized`.
    - Check if the new watermark `wmark` is less than or equal to the current published watermark; if so, return immediately.
    - Log a notice about advancing the watermark from the current published watermark to the new `wmark`.
    - Create a transaction ID `xid` with both elements set to `wmark`.
    - If `ctx->blockstore` is available, publish the new watermark to the blockstore.
    - If `ctx->forks` is available, publish the new watermark to the forks.
    - If `ctx->funk` is available, call [`funk_and_txncache_publish`](#funk_and_txncache_publish) to publish the new watermark and transaction ID.
    - If `ctx->ghost` is available, publish the new watermark to the epoch forks and ghost.
    - Update the published watermark in `ctx->published_wmark` to the new `wmark`.
- **Output**: The function does not return any value; it performs updates and publishes state changes as side effects.
- **Functions called**:
    - [`funk_and_txncache_publish`](#funk_and_txncache_publish)
    - [`fd_epoch_forks_publish`](fd_epoch_forks.c.driver.md#fd_epoch_forks_publish)


---
### privileged\_init<!-- {{#callable:privileged_init}} -->
The `privileged_init` function initializes a replay tile context by setting up memory allocations, random seeds, and opening necessary files and databases for the replay process.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology of the system, which includes information about the system's configuration and resources.
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing a specific tile in the topology, which includes configuration details specific to the replay tile.
- **Control Flow**:
    - Allocate scratch memory for the replay tile context using `fd_topo_obj_laddr` and `FD_SCRATCH_ALLOC_INIT`.
    - Initialize a `fd_replay_tile_ctx_t` structure within the allocated memory.
    - Generate random seeds for `funk_seed` and `status_cache_seed` using `getrandom`.
    - Open the blockstore archival file specified in `tile->replay.blockstore_file` with read/write and create permissions.
    - Retrieve the `runtime_pub` object ID from the topology properties and validate its existence.
    - Join the `runtime_public` workspace using the object ID and validate its success.
    - Determine the snapshot type from `tile->replay.snapshot` and open or recover the funk database accordingly.
    - Validate the successful opening or recovery of the funk database and join its workspace.
- **Output**: The function does not return a value; it initializes the replay tile context and sets up necessary resources for the replay process.
- **Functions called**:
    - [`scratch_align`](#scratch_align)


---
### unprivileged\_init<!-- {{#callable:unprivileged_init}} -->
The `unprivileged_init` function initializes various components and memory allocations for a replay tile in a distributed system, ensuring proper setup of workspaces, links, and contexts for execution.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology of the system.
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing the specific tile configuration within the topology.
- **Control Flow**:
    - Log the start of the unprivileged initialization process.
    - Retrieve the local address of the tile object using `fd_topo_obj_laddr`.
    - Check if the input links are as expected; log an error and exit if not.
    - Initialize scratch memory allocations for various contexts and components, ensuring the order of allocations is maintained.
    - Verify that the allocated scratch memory matches the expected footprint.
    - Join the workspace for the tile and other necessary components like blockstore and status cache.
    - Set up snapshot intervals and log them.
    - Initialize various contexts and join them to their respective memory allocations.
    - Set up input and output links for different components, ensuring proper memory alignment and chunk management.
    - Log the completion of the unprivileged initialization process.
- **Output**: This function does not return a value; it performs setup operations and logs errors if any issues are encountered.
- **Functions called**:
    - [`scratch_align`](#scratch_align)
    - [`scratch_footprint`](#scratch_footprint)
    - [`fd_epoch_forks_new`](fd_epoch_forks.c.driver.md#fd_epoch_forks_new)
    - [`fd_slice_exec_join`](fd_exec.c.driver.md#fd_slice_exec_join)


---
### populate\_allowed\_seccomp<!-- {{#callable:populate_allowed_seccomp}} -->
The `populate_allowed_seccomp` function initializes a scratch memory area, allocates a context structure, and populates a seccomp filter policy for a replay tile.
- **Inputs**:
    - `topo`: A pointer to a `fd_topo_t` structure representing the topology configuration.
    - `tile`: A pointer to a `fd_topo_tile_t` structure representing the tile configuration.
    - `out_cnt`: An unsigned long integer representing the count of output seccomp filters.
    - `out`: A pointer to a `struct sock_filter` array where the seccomp filter policy will be populated.
- **Control Flow**:
    - Initialize a scratch memory allocator with `FD_SCRATCH_ALLOC_INIT` using the topology and tile object ID.
    - Allocate a `fd_replay_tile_ctx_t` structure in the scratch memory using `FD_SCRATCH_ALLOC_APPEND`.
    - Finalize the scratch memory allocation with `FD_SCRATCH_ALLOC_FINI`.
    - Call [`populate_sock_filter_policy_fd_replay_tile`](generated/fd_replay_tile_seccomp.h.driver.md#populate_sock_filter_policy_fd_replay_tile) to populate the seccomp filter policy using the output count, output filter array, and file descriptors.
    - Return the instruction count from `sock_filter_policy_fd_replay_tile_instr_cnt`.
- **Output**: Returns an unsigned long integer representing the instruction count for the seccomp filter policy.
- **Functions called**:
    - [`populate_sock_filter_policy_fd_replay_tile`](generated/fd_replay_tile_seccomp.h.driver.md#populate_sock_filter_policy_fd_replay_tile)


---
### populate\_allowed\_fds<!-- {{#callable:populate_allowed_fds}} -->
The `populate_allowed_fds` function populates an array with file descriptors that are allowed for use by the program, including standard error, a log file, and a blockstore file descriptor.
- **Inputs**:
    - `topo`: A pointer to a `fd_topo_t` structure representing the topology of the system.
    - `tile`: A pointer to a `fd_topo_tile_t` structure representing the specific tile in the topology.
    - `out_fds_cnt`: An unsigned long integer representing the maximum number of file descriptors that can be stored in the `out_fds` array.
    - `out_fds`: A pointer to an integer array where the allowed file descriptors will be stored.
- **Control Flow**:
    - Allocate scratch memory and initialize a `fd_replay_tile_ctx_t` context structure using the topology and tile information.
    - Check if `out_fds_cnt` is less than 2, and if so, log an error and terminate the program.
    - Initialize `out_cnt` to 0, which will keep track of the number of file descriptors added to `out_fds`.
    - Add the standard error file descriptor (2) to the `out_fds` array and increment `out_cnt`.
    - Check if the log file descriptor is valid (not -1), and if so, add it to the `out_fds` array and increment `out_cnt`.
    - Add the blockstore file descriptor from the context to the `out_fds` array and increment `out_cnt`.
    - Return the total count of file descriptors added to `out_fds`.
- **Output**: Returns the number of file descriptors added to the `out_fds` array as an unsigned long integer.


---
### metrics\_write<!-- {{#callable:metrics_write}} -->
The `metrics_write` function updates the metrics for the last voted slot and the current slot in the replay context.
- **Inputs**:
    - `ctx`: A pointer to a `fd_replay_tile_ctx_t` structure, which contains the context for the replay tile, including metrics information.
- **Control Flow**:
    - The function uses the macro `FD_MGAUGE_SET` to set the metric `LAST_VOTED_SLOT` to the value of `ctx->metrics.last_voted_slot`.
    - It then sets the metric `SLOT` to the value of `ctx->metrics.slot` using the same macro.
- **Output**: This function does not return any value; it updates metrics in the context provided.


