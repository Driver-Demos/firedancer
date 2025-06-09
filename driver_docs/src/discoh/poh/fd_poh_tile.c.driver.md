# Purpose
The provided C code is a comprehensive implementation of a Proof of History (PoH) mechanism, which is a critical component of the Solana blockchain protocol. This code is designed to manage the PoH process, which involves generating a sequence of hashes that serve as a cryptographic timestamp, ensuring the order and integrity of transactions in the network. The code is structured to handle various tasks such as managing leader schedules, processing transactions, and interacting with other components like the bank and shred tiles.

Key components of the code include the `fd_poh_ctx_t` structure, which maintains the state of the PoH process, including the current slot, hash count, and leader information. The code also defines several functions for interacting with the PoH context, such as initializing the PoH state, handling leader transitions, and publishing ticks and microblocks. The code is designed to be integrated into a larger system, as indicated by the inclusion of various headers and the use of external functions for tasks like bank management and transaction execution. Additionally, the code includes mechanisms for handling concurrency and synchronization, ensuring that the PoH process operates correctly in a multi-threaded environment. Overall, this code provides a robust implementation of the PoH mechanism, which is essential for maintaining the security and efficiency of the Solana blockchain.
# Imports and Dependencies

---
- `../bank/fd_bank_abi.h`
- `../../disco/tiles.h`
- `../../disco/bundle/fd_bundle_crank.h`
- `../../disco/pack/fd_pack.h`
- `../../ballet/sha256/fd_sha256.h`
- `../../disco/metrics/fd_metrics.h`
- `../../util/pod/fd_pod_format.h`
- `../../disco/shred/fd_shredder.h`
- `../../disco/shred/fd_stake_ci.h`
- `../../disco/keyguard/fd_keyload.h`
- `../../disco/keyguard/fd_keyswitch.h`
- `../../disco/metrics/generated/fd_metrics_poh.h`
- `../../disco/plugin/fd_plugin.h`
- `../../flamenco/leaders/fd_leaders.h`
- `string.h`
- `../../disco/stem/fd_stem.c`


# Global Variables

---
### fd\_poh\_global\_ctx
- **Type**: ``fd_poh_ctx_t *``
- **Description**: The `fd_poh_global_ctx` is a static pointer to a `fd_poh_ctx_t` structure, which represents the global context for the Proof of History (PoH) tile in the Solana blockchain implementation. This context holds various configuration parameters, state information, and operational data necessary for managing the PoH process, including slot and hash count tracking, leader scheduling, and microblock handling.
- **Use**: This variable is used to maintain and access the global state and configuration of the PoH tile, allowing various functions to interact with and modify the PoH process.


---
### fd\_poh\_waiting\_lock
- **Type**: `volatile ulong`
- **Description**: `fd_poh_waiting_lock` is a global volatile unsigned long integer variable that is aligned to a 128-byte boundary. It is used as part of a locking mechanism to coordinate access between the PoH tile and other components, such as the Agave client, in a concurrent environment.
- **Use**: This variable is used to signal when a component wishes to acquire a lock on the PoH tile for reading or writing operations.


---
### fd\_poh\_returned\_lock
- **Type**: `volatile ulong`
- **Description**: `fd_poh_returned_lock` is a global volatile unsigned long integer variable that is aligned to 128 bytes. It is used in a locking mechanism to coordinate access between the PoH tile and other components, such as the Agave client, in a concurrent environment.
- **Use**: This variable is used to signal when the PoH tile has granted access to a waiting component, allowing it to proceed with its operations.


---
### 
- **Type**: ``static volatile ulong``
- **Description**: The variable `fd_poh_returned_lock` is a static volatile unsigned long integer, aligned to 128 bytes. It is used as part of a locking mechanism for synchronizing access to the PoH (Proof of History) tile in a concurrent environment.
- **Use**: This variable is used to signal when a waiting process can proceed with accessing the PoH tile.


---
### gossip\_dedup
- **Type**: `poh_link_t`
- **Description**: The `gossip_dedup` variable is a static instance of the `poh_link_t` structure, which is used to manage a communication link in the system. This structure contains fields for managing memory, sequence numbers, and other metadata necessary for handling data transmission and reception.
- **Use**: The `gossip_dedup` variable is used to manage and publish gossip-related data within the system, ensuring that messages are properly transmitted and deduplicated.


---
### stake\_out
- **Type**: ``poh_link_t``
- **Description**: The `stake_out` variable is a static instance of the `poh_link_t` structure, which is used to manage a communication link in the context of the Proof of History (PoH) system. This structure contains metadata and pointers necessary for managing data flow, such as memory pointers, sequence numbers, and credit availability for the link.
- **Use**: The `stake_out` variable is used to publish leader schedule data to the network, ensuring that the PoH system can communicate necessary information about leader changes and schedules.


---
### crds\_shred
- **Type**: `poh_link_t`
- **Description**: The `crds_shred` variable is a static instance of the `poh_link_t` structure, which is used to manage a communication link in the system. This structure contains metadata and pointers necessary for managing data chunks, including memory workspace pointers, chunk indices, and sequence numbers.
- **Use**: The `crds_shred` variable is used to publish cluster information to the CRDS (Cluster Replicated Data Store) shred tile, facilitating data dissemination across the network.


---
### replay\_resolv
- **Type**: ``poh_link_t``
- **Description**: The `replay_resolv` variable is a static instance of the `poh_link_t` structure. This structure is used to manage a link in the Proof of History (PoH) system, specifically for handling replay resolution tasks. It contains fields for managing memory, sequence numbers, and other metadata necessary for coordinating data flow between different components of the system.
- **Use**: The `replay_resolv` variable is used to publish data related to replay resolution, such as root banks and completed block hashes, to the appropriate channels in the PoH system.


---
### replay\_plugin
- **Type**: `poh_link_t`
- **Description**: The `replay_plugin` is a static instance of the `poh_link_t` structure, which is used to manage a communication link in the system. This structure is part of a set of similar structures that handle different types of communication or data flow within the system, such as `gossip_plugin` and `stake_out`. Each `poh_link_t` instance is responsible for managing a specific type of data or communication channel, with `replay_plugin` likely being used for handling replay-related data or messages.
- **Use**: The `replay_plugin` variable is used to manage and facilitate the communication of replay-related data within the system, ensuring that messages are properly sent and received through the designated channel.


---
### gossip\_plugin
- **Type**: `poh_link_t`
- **Description**: The `gossip_plugin` is a static instance of the `poh_link_t` structure, which is used to manage communication links in the Proof of History (PoH) tile. This structure is part of a system that handles message passing and data synchronization between different components of the Solana blockchain network.
- **Use**: The `gossip_plugin` is used to publish periodic plugin data to the gossip network, facilitating communication and data sharing across the network.


---
### start\_progress\_plugin
- **Type**: ``poh_link_t``
- **Description**: The `start_progress_plugin` is a static variable of type `poh_link_t`, which is a structure used to manage a link in the Proof of History (PoH) system. This structure contains metadata and pointers necessary for managing data flow between different components of the system, such as memory caches and data chunks.
- **Use**: This variable is used to manage the start progress plugin link, facilitating communication and data transfer within the PoH system.


---
### vote\_listener\_plugin
- **Type**: ``poh_link_t``
- **Description**: The `vote_listener_plugin` is a static global variable of type `poh_link_t`. It is part of a set of plugin links used in the Proof of History (PoH) tile to manage communication and data flow between different components of the system.
- **Use**: This variable is used to publish data related to vote listening in the PoH tile, facilitating the integration of vote-related information into the system's processing pipeline.


---
### validator\_info\_plugin
- **Type**: ``poh_link_t``
- **Description**: The `validator_info_plugin` is a static instance of the `poh_link_t` structure, which is used to manage communication links in the Proof of History (PoH) tile. This structure contains fields for managing memory, data chunks, and sequence numbers for transmitting data between different components of the system.
- **Use**: This variable is used to publish validator information through a plugin interface, facilitating communication and data exchange in the PoH system.


---
### fd\_shred\_version
- **Type**: `volatile ulong *`
- **Description**: `fd_shred_version` is a static volatile pointer to an unsigned long integer, which is used to store the shred version in a shared memory location. This variable is intended to be accessed and modified by different parts of the system, potentially across different threads or processes, hence the use of the `volatile` keyword to prevent compiler optimizations that could lead to stale data being read or written.
- **Use**: This variable is used to communicate the shred version from the PoH tile to the shred tile in a concurrent environment.


---
### fd\_tile\_poh
- **Type**: `fd_topo_run_tile_t`
- **Description**: The `fd_tile_poh` is a global variable of type `fd_topo_run_tile_t`, which is a structure used to define a tile in the Firedancer system. This particular tile is responsible for handling the Proof of History (PoH) process, which is a critical component in the Solana blockchain for ensuring the order and timing of transactions.
- **Use**: This variable is used to configure and manage the PoH tile, including its initialization, execution, and interaction with other components in the system.


# Data Structures

---
### fd\_poh\_in\_ctx\_t
- **Type**: ``struct``
- **Members**:
    - `mem`: A pointer to an `fd_wksp_t` structure, representing a memory workspace.
    - `chunk0`: An unsigned long integer representing the starting chunk index.
    - `wmark`: An unsigned long integer representing the watermark or limit for the chunks.
- **Description**: The `fd_poh_in_ctx_t` structure is a simple data structure used to manage memory workspaces in the context of Proof of History (PoH) operations. It contains a pointer to a memory workspace (`mem`), and two unsigned long integers (`chunk0` and `wmark`) that define the range of chunks available for use within that workspace. This structure is likely used to track and manage memory allocation and usage within the PoH system, ensuring that operations do not exceed predefined memory limits.


---
### fd\_poh\_out\_ctx\_t
- **Type**: `struct`
- **Members**:
    - `idx`: An unsigned long integer representing the index of the context.
    - `mem`: A pointer to an fd_wksp_t structure, representing a memory workspace.
    - `chunk0`: An unsigned long integer representing the initial chunk index in the memory workspace.
    - `wmark`: An unsigned long integer representing the watermark for the memory workspace.
    - `chunk`: An unsigned long integer representing the current chunk index in the memory workspace.
- **Description**: The `fd_poh_out_ctx_t` structure is used to manage output contexts in a Proof of History (PoH) system, specifically for handling memory workspaces and chunk management. It contains information about the memory workspace, including pointers and indices for managing data chunks within the workspace. This structure is crucial for efficiently handling data output in the PoH process, ensuring that data is correctly indexed and managed within the allocated memory space.


---
### fd\_poh\_ctx\_t
- **Type**: `struct`
- **Members**:
    - `stem`: Pointer to the stem context.
    - `tick_duration_ns`: Duration of a tick in nanoseconds.
    - `hashcnt_per_tick`: Number of hash counts per tick.
    - `ticks_per_slot`: Number of ticks per slot.
    - `slot_duration_ns`: Duration of a slot in nanoseconds, precomputed from configuration.
    - `hashcnt_duration_ns`: Duration of a hash count in nanoseconds, precomputed from configuration.
    - `hashcnt_per_slot`: Number of hash counts per slot, precomputed from configuration.
    - `max_microblocks_per_slot`: Maximum number of microblocks that can be published in each slot.
    - `limits`: Consensus-critical slot cost limits.
    - `slot`: Current slot of the proof of history.
    - `hashcnt`: Current hash count within the slot.
    - `cus_used`: Cumulative units used.
    - `last_slot`: Slot of the last published microblock.
    - `last_hashcnt`: Hash count of the last published microblock.
    - `highwater_leader_slot`: Tracks the maximum slot for which a tick or microblock has been published.
    - `lagged_consecutive_leader_start`: Indicates if the expected slot end time is not reset between consecutive leader slots.
    - `expect_sequential_leader_slot`: Expected sequential leader slot.
    - `expect_microblock_idx`: Index of the expected microblock.
    - `microblocks_lower_bound`: Tracks the lower bound of microblocks that might still be received in the slot.
    - `reset_hash`: Hash at the reset point, aligned to 32 bytes.
    - `hash`: Current hash, aligned to 32 bytes.
    - `skipped_tick_hashes`: Hashes produced when not leader, stored for replay if prior leader skips.
    - `reset_slot_start_ns`: Timestamp in nanoseconds when the reset slot was received.
    - `leader_bank_start_ns`: Timestamp in nanoseconds when the bank for the current leader slot was received.
    - `reset_slot`: Hash count corresponding to the start of the current reset slot.
    - `next_leader_slot`: Hash count at which the next leader slot begins, or ULONG max if unknown.
    - `skip_frag`: Indicates if an in-progress fragment should be skipped.
    - `max_active_descendant`: Maximum active descendant.
    - `current_leader_bank`: Pointer to the current leader bank if the node is the leader.
    - `sha256`: Pointer to the SHA-256 context.
    - `stake_ci`: Pointer to the stake context information.
    - `shred_seq`: Last sequence number of an outgoing fragment to the shred tile.
    - `halted_switching_key`: Indicates if switching key is halted.
    - `keyswitch`: Pointer to the keyswitch context.
    - `identity_key`: Public key of the identity.
    - `bundle`: Information for computing addresses for bundle crank information.
    - `signal_leader_change`: Pointer to notify the Agave client when the leader changes.
    - `_txns`: Temporary storage for transactions during fragment processing.
    - `_microblock_trailer`: Temporary storage for microblock trailer during fragment processing.
    - `in_kind`: Array indicating the kind of input for each input link.
    - `in`: Array of input contexts for processing incoming data.
    - `shred_out`: Output context for shreds.
    - `pack_out`: Output context for packs.
    - `plugin_out`: Output context for plugins.
    - `begin_leader_delay`: Histogram for measuring delay in beginning leader slot.
    - `first_microblock_delay`: Histogram for measuring delay in first microblock.
    - `slot_done_delay`: Histogram for measuring delay in slot completion.
    - `bundle_init_delay`: Histogram for measuring delay in bundle initialization.
    - `features_activation_avail`: Indicates if features activation is available.
    - `features_activation`: Tracks activation of shred features.
    - `parent_slot`: Slot of the parent block.
    - `parent_block_id`: ID of the parent block, aligned to 32 bytes.
- **Description**: The `fd_poh_ctx_t` structure is a comprehensive context for managing the Proof of History (PoH) process in a distributed ledger system, specifically designed for Solana's architecture. It encapsulates various configurations, state variables, and operational parameters necessary for maintaining the PoH chain, handling leader transitions, and managing microblocks and ticks. The structure includes fields for static configuration, derived timing information, consensus-critical limits, and current operational state, such as the current slot, hash count, and leader status. It also manages input and output contexts for data processing, tracks microblock indices, and handles potential race conditions in transaction processing. Additionally, it provides mechanisms for notifying changes in leadership and managing feature activations, ensuring the integrity and continuity of the PoH process.


---
### poh\_link
- **Type**: `struct`
- **Members**:
    - `mcache`: Pointer to a fragment metadata cache.
    - `depth`: Represents the depth of the link.
    - `tx_seq`: Transaction sequence number.
    - `mem`: Pointer to memory associated with the link.
    - `dcache`: Pointer to a data cache.
    - `chunk0`: Initial chunk index in the data cache.
    - `wmark`: Watermark for the data cache.
    - `chunk`: Current chunk index in the data cache.
    - `cr_avail`: Available credit for the link.
    - `rx_cnt`: Count of receive sequences.
    - `rx_fseqs`: Array of pointers to receive sequence numbers.
- **Description**: The `poh_link` structure is designed to manage and track the state of a link in a distributed system, particularly in the context of Solana's Proof of History (PoH) mechanism. It holds pointers to various caches and memory areas, as well as metadata about the link's current state, such as transaction sequence numbers and available credits. This structure is crucial for coordinating data flow and ensuring that transactions are processed in the correct order, maintaining the integrity and efficiency of the system.


---
### poh\_link\_t
- **Type**: `typedef struct poh_link poh_link_t;`
- **Members**:
    - `mcache`: Pointer to a metadata cache for managing fragments.
    - `depth`: Depth of the metadata cache.
    - `tx_seq`: Transaction sequence number for tracking order.
    - `mem`: Pointer to memory workspace for data storage.
    - `dcache`: Pointer to data cache for storing data chunks.
    - `chunk0`: Initial chunk index in the data cache.
    - `wmark`: Watermark indicating the end of the data cache.
    - `chunk`: Current chunk index in the data cache.
    - `cr_avail`: Available credit for publishing data.
    - `rx_cnt`: Count of receive sequences for flow control.
    - `rx_fseqs`: Array of pointers to receive sequence numbers for flow control.
- **Description**: The `poh_link_t` structure is used to manage the flow of data between different components in a distributed system, particularly in the context of Solana's Proof of History (PoH) implementation. It maintains pointers to memory and data caches, tracks transaction sequences, and manages flow control through available credits and receive sequences. This structure is crucial for ensuring that data is published and received in the correct order and that resources are efficiently utilized.


# Functions

---
### poh\_link\_wait\_credit<!-- {{#callable:poh_link_wait_credit}} -->
The `poh_link_wait_credit` function ensures that a `poh_link_t` structure has available credit by waiting until it can safely proceed with operations.
- **Inputs**:
    - `link`: A pointer to a `poh_link_t` structure representing a link that requires credit to proceed with operations.
- **Control Flow**:
    - Check if the link already has available credit (`cr_avail`), and return immediately if so.
    - Enter an infinite loop to wait for credit to become available.
    - Initialize `cr_query` to `ULONG_MAX` to find the minimum credit query value.
    - Iterate over each receive sequence (`rx_fseqs`) in the link to calculate the credit query based on the difference between the transmit sequence (`tx_seq`) and the receive sequence (`rx_seq`).
    - Update `cr_query` with the minimum value found in the iteration.
    - If `cr_query` is greater than zero, set `cr_avail` to `cr_query` and break the loop.
    - Pause the CPU briefly using `FD_SPIN_PAUSE()` to avoid busy-waiting.
- **Output**: The function does not return a value; it modifies the `cr_avail` field of the `poh_link_t` structure to reflect the available credit.


---
### poh\_link\_publish<!-- {{#callable:poh_link_publish}} -->
The `poh_link_publish` function publishes data to a specified link after ensuring the link is ready and has available credits.
- **Inputs**:
    - `link`: A pointer to a `poh_link_t` structure representing the link to which data will be published.
    - `sig`: An unsigned long integer representing the signature or identifier for the data being published.
    - `data`: A pointer to a constant unsigned char array containing the data to be published.
    - `data_sz`: An unsigned long integer representing the size of the data to be published.
- **Control Flow**:
    - The function first checks if the link's `mcache` is available using a spin-wait loop until it is ready.
    - If the link's `mem` is not available, the function returns immediately, indicating the link is not enabled for publishing.
    - The function calls [`poh_link_wait_credit`](#poh_link_wait_credit) to ensure there are available credits for publishing.
    - It calculates the destination address in the link's memory using `fd_chunk_to_laddr` and copies the data to this address using `fd_memcpy`.
    - The function calculates the publication timestamp using `fd_frag_meta_ts_comp` and `fd_tickcount`.
    - It publishes the data to the link's `mcache` using `fd_mcache_publish`, including metadata such as depth, sequence, signature, chunk, data size, and timestamp.
    - The function updates the link's `chunk` to the next available chunk using `fd_dcache_compact_next`.
    - It decrements the available credits (`cr_avail`) and increments the transaction sequence (`tx_seq`).
- **Output**: The function does not return a value; it performs its operations directly on the provided `poh_link_t` structure and its associated memory.
- **Functions called**:
    - [`poh_link_wait_credit`](#poh_link_wait_credit)


---
### poh\_link\_init<!-- {{#callable:poh_link_init}} -->
The `poh_link_init` function initializes a `poh_link_t` structure with memory and configuration details from a given topology and tile.
- **Inputs**:
    - `link`: A pointer to a `poh_link_t` structure that will be initialized.
    - `topo`: A pointer to a `fd_topo_t` structure representing the topology containing links and workspaces.
    - `tile`: A pointer to a `fd_topo_tile_t` structure representing the tile with output link information.
    - `out_idx`: An unsigned long integer representing the index of the output link in the tile's output link array.
- **Control Flow**:
    - Retrieve the `fd_topo_link_t` structure from the topology using the output link ID from the tile at the specified index.
    - Retrieve the workspace associated with the link's dcache object ID from the topology.
    - Initialize the `link` structure's `mem`, `depth`, `tx_seq`, `dcache`, `chunk0`, `wmark`, `chunk`, `cr_avail`, and `rx_cnt` fields using the retrieved link and workspace information.
    - Iterate over all tiles in the topology to find and store reliable input link sequence numbers in the `link` structure's `rx_fseqs` array.
    - Ensure memory consistency with `FD_COMPILER_MFENCE` and verify that the `mcache` is set.
- **Output**: The function does not return a value; it initializes the `poh_link_t` structure pointed to by `link`.


---
### fd\_ext\_poh\_write\_unlock<!-- {{#callable:fd_ext_poh_write_unlock}} -->
The `fd_ext_poh_write_unlock` function releases a lock by setting a volatile lock variable to zero, ensuring memory ordering with a memory fence.
- **Inputs**: None
- **Control Flow**:
    - The function begins by calling `FD_COMPILER_MFENCE()` to ensure memory ordering before modifying shared variables.
    - It then sets the volatile variable `fd_poh_returned_lock` to `0UL`, effectively releasing the lock.
- **Output**: The function does not return any value.


---
### fd\_ext\_poh\_initialize<!-- {{#callable:fd_ext_poh_initialize}} -->
The `fd_ext_poh_initialize` function initializes the Proof of History (PoH) context with configuration parameters and a starting state for hashing operations.
- **Inputs**:
    - `tick_duration_ns`: The duration of a tick in nanoseconds, typically 6.4 microseconds for mainnet-beta.
    - `hashcnt_per_tick`: The number of hashes per tick, typically 62,500 for mainnet-beta.
    - `ticks_per_slot`: The number of ticks per slot, usually 64.
    - `tick_height`: The starting tick height for hashing.
    - `last_entry_hash`: A pointer to a 32-byte memory region containing the hash at the tick height.
    - `signal_leader_change`: An opaque pointer used to signal a leader change, typically a Rust object.
- **Control Flow**:
    - The function begins by ensuring the PoH context is initialized before proceeding, using a spin-wait loop.
    - It acquires a write lock on the PoH context to ensure exclusive access.
    - The function calculates the initial slot based on the tick height and ticks per slot, and initializes various counters and state variables in the context.
    - It copies the last entry hash into the context's reset and current hash fields.
    - The function sets the static configuration parameters for tick duration, hashes per tick, and ticks per slot in the context.
    - Derived clock information such as slot duration, hash count duration, and hash count per slot are computed and stored in the context.
    - The maximum number of microblocks per slot is determined based on the hash count per tick, with special handling for low power mode.
    - Finally, the function releases the write lock on the PoH context.
- **Output**: The function does not return a value; it initializes the PoH context with the provided parameters and starting state.
- **Functions called**:
    - [`fd_ext_poh_write_unlock`](#fd_ext_poh_write_unlock)


---
### fd\_ext\_poh\_acquire\_leader\_bank<!-- {{#callable:fd_ext_poh_acquire_leader_bank}} -->
The `fd_ext_poh_acquire_leader_bank` function acquires the current leader bank if it exists, increments its reference count, and returns it.
- **Inputs**: None
- **Control Flow**:
    - Acquire a write lock on the PoH context using `fd_ext_poh_write_lock`.
    - Initialize a local variable `bank` to `NULL`.
    - Check if `ctx->current_leader_bank` is non-null using `FD_LIKELY`.
    - If true, increment the reference count of `ctx->current_leader_bank` using [`fd_ext_bank_acquire`](../../discof/bank/fd_bank_abi.c.driver.md#fd_ext_bank_acquire).
    - Assign `ctx->current_leader_bank` to `bank`.
    - Release the write lock using [`fd_ext_poh_write_unlock`](#fd_ext_poh_write_unlock).
    - Return the `bank` variable.
- **Output**: Returns a pointer to the current leader bank if it exists, otherwise returns `NULL`.
- **Functions called**:
    - [`fd_ext_bank_acquire`](../../discof/bank/fd_bank_abi.c.driver.md#fd_ext_bank_acquire)
    - [`fd_ext_poh_write_unlock`](#fd_ext_poh_write_unlock)


---
### fd\_ext\_poh\_reset\_slot<!-- {{#callable:fd_ext_poh_reset_slot}} -->
The `fd_ext_poh_reset_slot` function retrieves the slot height one above the last good (unskipped) slot that the Proof of History (PoH) is building on top of.
- **Inputs**: None
- **Control Flow**:
    - Acquire a write lock on the PoH context using `fd_ext_poh_write_lock`.
    - Retrieve the `reset_slot` value from the PoH context.
    - Release the write lock using [`fd_ext_poh_write_unlock`](#fd_ext_poh_write_unlock).
    - Return the `reset_slot` value.
- **Output**: The function returns an `ulong` representing the slot height one above the last good (unskipped) slot.
- **Functions called**:
    - [`fd_ext_poh_write_unlock`](#fd_ext_poh_write_unlock)


---
### fd\_ext\_poh\_update\_active\_descendant<!-- {{#callable:fd_ext_poh_update_active_descendant}} -->
The function `fd_ext_poh_update_active_descendant` updates the maximum active descendant value in the PoH context.
- **Inputs**:
    - `max_active_descendant`: An unsigned long integer representing the new maximum active descendant value to be set in the PoH context.
- **Control Flow**:
    - Acquire a write lock on the PoH context using `fd_ext_poh_write_lock` to ensure exclusive access.
    - Update the `max_active_descendant` field of the PoH context with the provided `max_active_descendant` value.
    - Release the write lock using [`fd_ext_poh_write_unlock`](#fd_ext_poh_write_unlock) to allow other operations to proceed.
- **Output**: This function does not return any value; it performs an update operation on the PoH context.
- **Functions called**:
    - [`fd_ext_poh_write_unlock`](#fd_ext_poh_write_unlock)


---
### fd\_ext\_poh\_reached\_leader\_slot<!-- {{#callable:fd_ext_poh_reached_leader_slot}} -->
The function `fd_ext_poh_reached_leader_slot` checks if the current slot has reached the designated leader slot and returns a status indicating whether the leader slot has been reached and is ready to start.
- **Inputs**:
    - `out_leader_slot`: A pointer to an unsigned long where the function will store the slot number of the next leader slot.
    - `out_reset_slot`: A pointer to an unsigned long where the function will store the slot number of the last good (unskipped) slot.
- **Control Flow**:
    - Acquire a write lock on the PoH context using `fd_ext_poh_write_lock`.
    - Set `*out_leader_slot` to the next leader slot and `*out_reset_slot` to the reset slot from the context.
    - Check if the next leader slot is `ULONG_MAX` or if the current slot is less than the next leader slot; if so, unlock and return 0.
    - Check if the leader pipeline is halted due to identity key switching; if so, unlock and return 0.
    - Check if the reset slot is equal to the next leader slot; if so, unlock and return 1.
    - Calculate the expected start time for the next leader slot based on the reset slot start time and slot duration.
    - Check if the current time is less than the expected start time plus a grace period; if so, check if a prior leader is still publishing and decide whether to wait or start immediately.
    - Unlock the PoH context and return 1 if the leader slot is ready to start.
- **Output**: The function returns an integer: 1 if the leader slot has been reached and is ready to start, or 0 if it has not been reached or is not ready due to other conditions.
- **Functions called**:
    - [`fd_ext_poh_write_unlock`](#fd_ext_poh_write_unlock)


---
### publish\_plugin\_slot\_start<!-- {{#callable:publish_plugin_slot_start}} -->
The `publish_plugin_slot_start` function initializes and publishes a plugin message indicating the start of a slot in a Proof of History (PoH) context.
- **Inputs**:
    - `ctx`: A pointer to an `fd_poh_ctx_t` structure representing the PoH context.
    - `slot`: An unsigned long integer representing the current slot number.
    - `parent_slot`: An unsigned long integer representing the parent slot number.
- **Control Flow**:
    - Check if the `plugin_out->mem` in the context is NULL; if so, return immediately.
    - Convert the current chunk in `plugin_out` to a local address and cast it to a `fd_plugin_msg_slot_start_t` pointer.
    - Initialize the `slot_start` structure with the provided `slot` and `parent_slot` values.
    - Publish the `slot_start` message using `fd_stem_publish` with the appropriate parameters.
    - Update the `plugin_out->chunk` to the next compacted chunk using `fd_dcache_compact_next`.
- **Output**: The function does not return a value; it performs operations to publish a plugin message indicating the start of a slot.


---
### publish\_plugin\_slot\_end<!-- {{#callable:publish_plugin_slot_end}} -->
The `publish_plugin_slot_end` function publishes a message indicating the end of a plugin slot with the specified slot number and consumed units (cus_used) to a designated output context.
- **Inputs**:
    - `ctx`: A pointer to an `fd_poh_ctx_t` structure, which contains context information for the Proof of History (PoH) process, including output memory and chunk information.
    - `slot`: An unsigned long integer representing the slot number that is ending.
    - `cus_used`: An unsigned long integer representing the number of consumed units used in the slot.
- **Control Flow**:
    - Check if the `plugin_out->mem` in the context is NULL; if so, return immediately without doing anything.
    - Convert the current chunk in `plugin_out` to a local address and cast it to a `fd_plugin_msg_slot_end_t` pointer.
    - Assign the slot number and consumed units to the `slot_end` structure.
    - Publish the `slot_end` message using `fd_stem_publish` with the appropriate parameters, including the message type `FD_PLUGIN_MSG_SLOT_END`.
    - Update the `plugin_out->chunk` to the next compacted chunk using `fd_dcache_compact_next`.
- **Output**: The function does not return a value; it performs an action by publishing a message to indicate the end of a plugin slot.


---
### publish\_became\_leader<!-- {{#callable:publish_became_leader}} -->
The `publish_became_leader` function initializes and publishes the state of a node when it becomes the leader in a distributed system, handling timing, configuration, and account loading.
- **Inputs**:
    - `ctx`: A pointer to the `fd_poh_ctx_t` structure, which contains the context and state information for the Proof of History (PoH) tile.
    - `slot`: An unsigned long integer representing the current slot number for which the node has become the leader.
    - `epoch`: An unsigned long integer representing the current epoch number.
- **Control Flow**:
    - Calculate the time delay since the last reset slot start and sample it into the `begin_leader_delay` histogram.
    - If the node is starting a consecutive leader slot, adjust the reset slot start time to exclude waiting time.
    - Initialize configuration and owner address structures for tip payment if the bundle is enabled.
    - If the bundle is enabled, calculate the time taken to load account addresses and sample it into the `bundle_init_delay` histogram.
    - Calculate the start time for the current slot based on the reset slot start time and slot duration.
    - Prepare a `fd_became_leader_t` structure with the current leader's slot information, including start and end times, bank, microblock limits, ticks, and epoch.
    - Copy the reset hash and tip receiver owner into the leader's bundle configuration.
    - Check if the total skipped ticks exceed the maximum allowed and log an error if so.
    - Generate a signature for the PoH packet and publish the leader information using `fd_stem_publish`.
    - Update the chunk pointer for the next data to be published.
- **Output**: The function does not return a value; it performs operations to publish the leader's state and configuration.
- **Functions called**:
    - [`fd_ext_bank_load_account`](../../discof/bank/fd_bank_abi.c.driver.md#fd_ext_bank_load_account)


---
### fd\_ext\_poh\_begin\_leader<!-- {{#callable:fd_ext_poh_begin_leader}} -->
The `fd_ext_poh_begin_leader` function initializes the context for a new leader slot in the Proof of History (PoH) system, setting up parameters and ensuring consistency with the current state.
- **Inputs**:
    - `bank`: A pointer to the bank object associated with the current leader slot.
    - `slot`: The slot number for which the leader is beginning.
    - `epoch`: The epoch number associated with the current slot.
    - `hashcnt_per_tick`: The number of hashes to be computed per tick.
    - `cus_block_limit`: The maximum compute units allowed for the block.
    - `cus_vote_cost_limit`: The maximum compute units allowed for vote transactions.
    - `cus_account_cost_limit`: The maximum compute units allowed for account write transactions.
- **Control Flow**:
    - Acquire a write lock on the PoH context using `fd_ext_poh_write_lock`.
    - Check that there is no current leader bank set in the context.
    - Verify that the provided slot matches the current and next leader slot in the context, logging an error if not.
    - If `hashcnt_per_tick` has changed, log a warning and recompute clock-related parameters, resetting the slot and hash count if necessary.
    - Set the current leader bank and initialize microblock and compute unit usage tracking variables.
    - Set the compute unit limits for the slot, clamping them to predefined upper bounds if necessary and logging warnings if limits are exceeded.
    - Update the highwater mark for the leader slot to prevent republishing in the same slot.
    - Call [`publish_became_leader`](#publish_became_leader) to notify the system of the new leader status.
    - Log the beginning of the leader slot with relevant slot and hash count information.
    - Release the write lock on the PoH context using [`fd_ext_poh_write_unlock`](#fd_ext_poh_write_unlock).
- **Output**: The function does not return a value; it operates by modifying the state of the PoH context.
- **Functions called**:
    - [`publish_became_leader`](#publish_became_leader)
    - [`fd_ext_poh_write_unlock`](#fd_ext_poh_write_unlock)


---
### next\_leader\_slot<!-- {{#callable:next_leader_slot}} -->
The `next_leader_slot` function determines the next slot in which the current node will act as the leader, based on the current slot and the leader schedule.
- **Inputs**:
    - `ctx`: A pointer to an `fd_poh_ctx_t` structure, which contains the context for the Proof of History (PoH) process, including the current slot, highwater leader slot, identity key, and stake information.
- **Control Flow**:
    - Initialize `min_leader_slot` to the maximum of the current slot and the highwater leader slot, ensuring the node does not become leader for a slot it has already published to.
    - Enter an infinite loop to find the next leader slot.
    - Retrieve the leader schedule for `min_leader_slot` using `fd_stake_ci_get_lsched_for_slot`.
    - If no leader schedule is found, break the loop and return `ULONG_MAX`.
    - Iterate over the slots in the leader schedule, checking if the current node's identity key matches the leader's key for each slot.
    - If a match is found, return the current `min_leader_slot` as the next leader slot.
    - Increment `min_leader_slot` and continue the search if no match is found.
- **Output**: Returns the next slot number where the current node is scheduled to be the leader, or `ULONG_MAX` if no such slot is found in the current and next epoch.


---
### maybe\_change\_identity<!-- {{#callable:FD_FN_SENSITIVE::maybe_change_identity}} -->
The `maybe_change_identity` function attempts to change the identity key of a context if certain conditions are met, ensuring the integrity of the PoH state machine.
- **Inputs**:
    - `ctx`: A pointer to a `fd_poh_ctx_t` structure representing the context in which the function operates, containing state information for the PoH tile.
    - `definitely_not_leader`: An integer flag indicating whether the current context is definitely not the leader (non-zero) or potentially the leader (zero).
- **Control Flow**:
    - Check if the context is in a halted switching state and the keyswitch state is pending unhalt; if so, reset the halted state and update the keyswitch state to completed, returning 1.
    - Determine if the context is currently a leader by checking the `definitely_not_leader` flag and comparing the current slot with the next leader slot; if it is a leader, return 0.
    - Check if the keyswitch state is pending switch; if so, attempt to set a new identity using [`fd_ext_admin_rpc_set_identity`](../../discof/bank/fd_bank_abi.c.driver.md#fd_ext_admin_rpc_set_identity).
    - If setting the new identity fails, update the keyswitch state to failed and return 0.
    - If successful, update the identity key in the context, reset the PoH state to the reset slot, and update the keyswitch state to completed.
- **Output**: Returns 1 if the identity change was completed successfully, otherwise returns 0.
- **Functions called**:
    - [`fd_ext_admin_rpc_set_identity`](../../discof/bank/fd_bank_abi.c.driver.md#fd_ext_admin_rpc_set_identity)


---
### no\_longer\_leader<!-- {{#callable:no_longer_leader}} -->
The `no_longer_leader` function handles the transition of a node from a leader state to a non-leader state in a distributed system, updating relevant context and signaling changes.
- **Inputs**:
    - `ctx`: A pointer to an `fd_poh_ctx_t` structure representing the context of the Proof of History (PoH) tile, containing state information about the current leader, slots, and other operational parameters.
- **Control Flow**:
    - Check if the current leader bank is non-null and release it if so.
    - Update the `highwater_leader_slot` to ensure the node cannot become leader in the current slot again.
    - Set `current_leader_bank` to NULL to indicate no active leader bank.
    - Call [`maybe_change_identity`](#FD_FN_SENSITIVEmaybe_change_identity) to handle any pending identity changes, passing 1 to indicate the node is definitely not a leader.
    - Determine the next leader slot by calling [`next_leader_slot`](#next_leader_slot).
    - Log an informational message if the identity has changed.
    - Signal a leader change using [`fd_ext_poh_signal_leader_change`](../../discof/bank/fd_bank_abi.c.driver.md#fd_ext_poh_signal_leader_change).
    - Log an informational message indicating the node is no longer a leader and the next leader slot.
- **Output**: The function does not return a value; it performs operations to update the state and signal changes.
- **Functions called**:
    - [`fd_ext_bank_release`](../../discof/bank/fd_bank_abi.c.driver.md#fd_ext_bank_release)
    - [`FD_FN_SENSITIVE::maybe_change_identity`](#FD_FN_SENSITIVEmaybe_change_identity)
    - [`next_leader_slot`](#next_leader_slot)
    - [`fd_ext_poh_signal_leader_change`](../../discof/bank/fd_bank_abi.c.driver.md#fd_ext_poh_signal_leader_change)


---
### fd\_ext\_poh\_reset<!-- {{#callable:fd_ext_poh_reset}} -->
The `fd_ext_poh_reset` function resets the Proof of History (PoH) context to a new slot after a block is completed, updating various state parameters and handling leader transitions.
- **Inputs**:
    - `completed_bank_slot`: The slot number of the bank that successfully produced a block.
    - `reset_blockhash`: A pointer to the hash of the last tick in the produced block, which is 32 bytes long.
    - `hashcnt_per_tick`: The number of hashes per tick for the bank that completed.
    - `parent_block_id`: A pointer to the block ID of the parent block, which is 32 bytes long.
    - `features_activation`: A pointer to the activation slot of shred-tile features.
- **Control Flow**:
    - Acquire a write lock on the PoH context to ensure exclusive access.
    - Check if the current slot is a leader slot and handle any in-flight microblocks if necessary.
    - Update the leader bank start time to the current wall clock time.
    - Determine the reset slot start time based on whether the completed bank slot is sequentially expected.
    - Copy the reset block hash to the context's reset hash and current hash fields.
    - If a parent block ID is provided, update the context's parent slot and parent block ID.
    - Update the slot, hash count, last slot, last hash count, and reset slot in the context.
    - If the hash count per tick has changed, log a warning and recompute derived clock information.
    - Set the microblocks lower bound to allow PoH to tick freely after reset.
    - If the slot was a leader slot before reset, handle the transition out of leadership.
    - Determine the next leader slot and log the reset operation.
    - If the current slot is a leader slot, handle the transition into leadership if necessary.
    - Copy the features activation data to the context and mark it as available.
    - Release the write lock on the PoH context.
- **Output**: The function does not return a value; it modifies the PoH context state in place.
- **Functions called**:
    - [`no_longer_leader`](#no_longer_leader)
    - [`next_leader_slot`](#next_leader_slot)
    - [`publish_plugin_slot_end`](#publish_plugin_slot_end)
    - [`publish_plugin_slot_start`](#publish_plugin_slot_start)
    - [`fd_ext_poh_write_unlock`](#fd_ext_poh_write_unlock)


---
### fd\_ext\_poh\_get\_leader\_after\_n\_slots<!-- {{#callable:fd_ext_poh_get_leader_after_n_slots}} -->
The function `fd_ext_poh_get_leader_after_n_slots` retrieves the public key of the leader scheduled for a specific slot in the future, relative to the current slot.
- **Inputs**:
    - `n`: An unsigned long integer representing the number of slots after the current slot for which the leader's public key is to be retrieved.
    - `out_pubkey`: A pointer to an array of 32 unsigned characters where the leader's public key will be copied if found.
- **Control Flow**:
    - Acquire a write lock on the PoH context using `fd_ext_poh_write_lock` to ensure thread safety.
    - Calculate the target slot by adding `n` to the current slot stored in the PoH context.
    - Retrieve the leader schedule for the target slot using `fd_stake_ci_get_lsched_for_slot`.
    - Check if the leader schedule is available; if not, skip copying the public key.
    - If the leader schedule is available, retrieve the leader's public key for the target slot using `fd_epoch_leaders_get`.
    - If the leader's public key is found, copy it to `out_pubkey` and set `copied` to 1.
    - Release the write lock using [`fd_ext_poh_write_unlock`](#fd_ext_poh_write_unlock).
    - Return the value of `copied`, indicating whether the leader's public key was successfully copied.
- **Output**: Returns an integer value, 1 if the leader's public key was successfully copied to `out_pubkey`, otherwise 0.
- **Functions called**:
    - [`fd_ext_poh_write_unlock`](#fd_ext_poh_write_unlock)


---
### scratch\_align<!-- {{#callable:scratch_align}} -->
The `scratch_align` function returns a constant alignment value of 128 bytes.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended for use within the same translation unit and suggests the compiler to inline it for performance.
    - The function does not take any parameters.
    - It simply returns the constant value 128UL, which is an unsigned long integer.
- **Output**: The function outputs a constant unsigned long integer value of 128, representing an alignment size.


---
### scratch\_footprint<!-- {{#callable:scratch_footprint}} -->
The `scratch_footprint` function calculates the memory footprint required for a specific tile's context and related components in a layout.
- **Inputs**:
    - `tile`: A pointer to a `fd_topo_tile_t` structure, representing the tile for which the memory footprint is being calculated.
- **Control Flow**:
    - Initialize a variable `l` with `FD_LAYOUT_INIT` to start the layout calculation.
    - Append the size and alignment of `fd_poh_ctx_t` to the layout using `FD_LAYOUT_APPEND`.
    - Append the size and alignment of `fd_stake_ci` to the layout using `FD_LAYOUT_APPEND`.
    - Append the size and alignment of `FD_SHA256` to the layout using `FD_LAYOUT_APPEND`.
    - Finalize the layout calculation with `FD_LAYOUT_FINI`, using `scratch_align()` for alignment.
- **Output**: Returns an `ulong` representing the total memory footprint required for the tile's context and related components.
- **Functions called**:
    - [`scratch_align`](#scratch_align)


---
### publish\_tick<!-- {{#callable:publish_tick}} -->
The `publish_tick` function publishes a tick to the shred tile, updating metadata and handling skipped slots.
- **Inputs**:
    - `ctx`: A pointer to the `fd_poh_ctx_t` structure, which contains the context for the Proof of History (PoH) process.
    - `stem`: A pointer to the `fd_stem_context_t` structure, which is used for publishing data to the shred tile.
    - `hash`: An array of 32 unsigned characters representing the hash to be published with the tick.
    - `is_skipped`: An integer flag indicating whether the tick is for a skipped slot (non-zero) or not (zero).
- **Control Flow**:
    - Calculate `hashcnt` as the next tick boundary based on the last hash count and ticks per slot.
    - Convert the memory chunk to a local address and set up a pointer `dst` for writing metadata.
    - Check if the current slot is greater than or equal to the reset slot using `FD_TEST`.
    - If `is_skipped` is true, set `reference_tick` and `block_complete` to zero in the metadata; otherwise, calculate them based on `hashcnt`.
    - Determine the `slot` and `parent_offset` based on whether the block is complete.
    - Validate the `parent_block_id` and copy it if valid.
    - Calculate `hash_delta` as the difference between the current and last hash count.
    - Advance the `dst` pointer and set up the tick header with `hashcnt_delta`, `hash`, and `txn_cnt`.
    - Publish the tick using `fd_stem_publish` with the calculated signature and size.
    - Update the context's `shred_seq` and `shred_out->chunk` for the next operation.
    - Update `last_slot` and `last_hashcnt` based on whether the slot is complete.
- **Output**: The function does not return a value; it performs operations to publish a tick and update the context state.


---
### publish\_features\_activation<!-- {{#callable:publish_features_activation}} -->
The `publish_features_activation` function publishes the features activation data to the shred tile for a given context and stem.
- **Inputs**:
    - `ctx`: A pointer to an `fd_poh_ctx_t` structure, which contains the context for the Proof of History (PoH) operations, including the features activation data to be published.
    - `stem`: A pointer to an `fd_stem_context_t` structure, which represents the stem context used for publishing data to the shred tile.
- **Control Flow**:
    - Convert the memory address of the output chunk in `ctx->shred_out` to a local address and cast it to a `uchar` pointer `dst`.
    - Cast `dst` to a `fd_shred_features_activation_t` pointer `act_data`.
    - Copy the features activation data from `ctx->features_activation` to `act_data`.
    - Compute the publication timestamp `tspub` using `fd_frag_meta_ts_comp` and `fd_tickcount`.
    - Determine the size `sz` of the features activation data using `sizeof(fd_shred_features_activation_t)`.
    - Compute the signature `sig` for the publication using `fd_disco_poh_sig` with the current slot and packet type `POH_PKT_TYPE_FEAT_ACT_SLOT`.
    - Publish the features activation data to the shred tile using `fd_stem_publish` with the computed parameters.
    - Update the chunk index in `ctx->shred_out` using `fd_dcache_compact_next` to prepare for the next publication.
- **Output**: The function does not return a value; it performs an inline operation to publish features activation data to the shred tile.


---
### after\_credit<!-- {{#callable:after_credit}} -->
The `after_credit` function manages the state of the Proof of History (PoH) tile, handling leader transitions, tick publishing, and hash counting, while ensuring synchronization with external components.
- **Inputs**:
    - `ctx`: A pointer to the `fd_poh_ctx_t` structure, which holds the context and state information for the PoH tile.
    - `stem`: A pointer to the `fd_stem_context_t` structure, which is used for publishing messages to the shred tile.
    - `opt_poll_in`: A pointer to an integer that indicates whether the PoH tile should poll for incoming microblocks.
    - `charge_busy`: A pointer to an integer that indicates whether the PoH tile is busy processing.
- **Control Flow**:
    - Set the `stem` field of the `ctx` to the provided `stem` pointer.
    - Check if the `fd_poh_waiting_lock` is set, indicating an external component is waiting for access; if so, handle the lock and return.
    - If `features_activation_avail` is set, publish the features activation to the shred tile and reset the flag.
    - Determine if the current slot is a leader slot and if the leader bank is available; if not, return without processing.
    - If there are skipped ticks due to slot skipping, register and publish them, then return without processing further.
    - Calculate the maximum remaining microblocks and ticks, adjusting for low power mode if necessary.
    - Determine the restricted and minimum hash counts based on the current state and constraints.
    - Calculate the target hash count based on the current time and slot duration, clamping it within allowed bounds.
    - If the current hash count equals the target hash count, return without further processing.
    - Set `charge_busy` to 1, indicating the tile is busy, and increment the hash count up to the target hash count.
    - If a tick boundary is reached, handle tick registration and publishing, and manage leader transitions if necessary.
- **Output**: The function does not return a value but modifies the state of the PoH context and potentially publishes ticks or transitions the leader state.
- **Functions called**:
    - [`publish_features_activation`](#publish_features_activation)
    - [`fd_ext_poh_register_tick`](../../discof/bank/fd_bank_abi.c.driver.md#fd_ext_poh_register_tick)
    - [`publish_tick`](#publish_tick)
    - [`publish_plugin_slot_start`](#publish_plugin_slot_start)
    - [`publish_plugin_slot_end`](#publish_plugin_slot_end)
    - [`no_longer_leader`](#no_longer_leader)
    - [`next_leader_slot`](#next_leader_slot)


---
### during\_housekeeping<!-- {{#callable:during_housekeeping}} -->
The `during_housekeeping` function checks if the identity of the node has changed and updates the next leader slot accordingly, signaling a leader change if necessary.
- **Inputs**:
    - `ctx`: A pointer to the `fd_poh_ctx_t` context structure, which holds the state and configuration for the Proof of History (PoH) process.
- **Control Flow**:
    - The function checks if the identity change is likely by calling [`maybe_change_identity`](#FD_FN_SENSITIVEmaybe_change_identity) with the context and a flag set to 0.
    - If the identity has changed, it updates the [`next_leader_slot`](#next_leader_slot) by calling [`next_leader_slot`](#next_leader_slot) with the context.
    - Logs the identity change with the new [`next_leader_slot`](#next_leader_slot).
    - Performs a memory fence to ensure memory operations are completed before signaling.
    - Signals a leader change by calling [`fd_ext_poh_signal_leader_change`](../../discof/bank/fd_bank_abi.c.driver.md#fd_ext_poh_signal_leader_change) with the `signal_leader_change` from the context.
- **Output**: This function does not return any value; it performs operations on the context and may trigger a signal for leader change.
- **Functions called**:
    - [`FD_FN_SENSITIVE::maybe_change_identity`](#FD_FN_SENSITIVEmaybe_change_identity)
    - [`next_leader_slot`](#next_leader_slot)
    - [`fd_ext_poh_signal_leader_change`](../../discof/bank/fd_bank_abi.c.driver.md#fd_ext_poh_signal_leader_change)


---
### metrics\_write<!-- {{#callable:metrics_write}} -->
The `metrics_write` function copies specific delay metrics from a context structure to a metrics histogram for tracking performance.
- **Inputs**:
    - `ctx`: A pointer to an `fd_poh_ctx_t` structure containing delay metrics to be copied.
- **Control Flow**:
    - The function uses the `FD_MHIST_COPY` macro to copy the `begin_leader_delay` from the context to the `BEGIN_LEADER_DELAY_SECONDS` histogram.
    - It copies the `first_microblock_delay` to the `FIRST_MICROBLOCK_DELAY_SECONDS` histogram.
    - It copies the `slot_done_delay` to the `SLOT_DONE_DELAY_SECONDS` histogram.
    - It copies the `bundle_init_delay` to the `BUNDLE_INITIALIZE_DELAY_SECONDS` histogram.
- **Output**: The function does not return any value; it performs operations to update metrics histograms.


---
### before\_frag<!-- {{#callable:before_frag}} -->
The `before_frag` function checks if a microblock fragment is in sequence for processing and updates the expected microblock index accordingly.
- **Inputs**:
    - `ctx`: A pointer to the `fd_poh_ctx_t` context structure, which holds the state and configuration for the Proof of History (PoH) process.
    - `in_idx`: An unsigned long integer representing the index of the input source in the context's input array.
    - `seq`: An unsigned long integer representing the sequence number of the fragment, which is not used in this function.
    - `sig`: An unsigned long integer representing the signature of the fragment, used to determine the microblock index.
- **Control Flow**:
    - The function begins by casting the `seq` parameter to void, indicating it is unused.
    - It checks if the input kind at `in_idx` in the context is `IN_KIND_BANK`.
    - If true, it retrieves the microblock index from the signature using `fd_disco_bank_sig_microblock_idx`.
    - It asserts that the retrieved microblock index is greater than or equal to the expected microblock index in the context.
    - If the microblock index is greater than the expected index, it returns -1, indicating the fragment is out of sequence.
    - If the microblock index is in sequence, it increments the expected microblock index in the context.
    - The function returns 0, indicating successful processing of the fragment.
- **Output**: The function returns an integer: 0 if the fragment is in sequence and -1 if it is not.


---
### during\_frag<!-- {{#callable:during_frag}} -->
The `during_frag` function processes incoming fragments based on their type and updates the context accordingly, handling errors and specific conditions for different fragment types.
- **Inputs**:
    - `ctx`: A pointer to the `fd_poh_ctx_t` structure, which holds the context for the Proof of History (PoH) process.
    - `in_idx`: An unsigned long integer representing the index of the input source in the context's input array.
    - `seq`: An unsigned long integer representing the sequence number of the fragment, marked as unused with `FD_PARAM_UNUSED`.
    - `sig`: An unsigned long integer representing the signature of the fragment.
    - `chunk`: An unsigned long integer representing the chunk index of the fragment in the data cache.
    - `sz`: An unsigned long integer representing the size of the fragment.
    - `ctl`: An unsigned long integer representing control information, marked as unused with `FD_PARAM_UNUSED`.
- **Control Flow**:
    - Initialize `ctx->skip_frag` to 0, indicating no fragments should be skipped initially.
    - Check if the input kind at `in_idx` is `IN_KIND_STAKE`; if so, verify the chunk is within valid range and initialize a stake message, then return.
    - Determine the packet type and slot based on the input kind (`IN_KIND_BANK` or `IN_KIND_PACK`) using the signature.
    - Check if the fragment is for a prior leader slot by comparing the slot with `ctx->highwater_leader_slot`.
    - If the input kind is `IN_KIND_PACK`, set `ctx->skip_frag` to 1 and handle `POH_PKT_TYPE_DONE_PACKING` by updating `ctx->microblocks_lower_bound` if the fragment is not for a prior leader slot.
    - For other input kinds, verify the chunk is within valid range and size is not greater than `USHORT_MAX`, then copy the transaction data and trailer to the context.
    - Set `ctx->skip_frag` based on whether the fragment is for a prior leader slot.
- **Output**: The function does not return a value; it modifies the context (`ctx`) based on the fragment's type and conditions.


---
### publish\_microblock<!-- {{#callable:publish_microblock}} -->
The `publish_microblock` function publishes a microblock by preparing metadata, copying transaction data, and sending it to the shred tile for further processing.
- **Inputs**:
    - `ctx`: A pointer to the `fd_poh_ctx_t` structure, which contains the context and state information for the Proof of History (PoH) process.
    - `stem`: A pointer to the `fd_stem_context_t` structure, which is used for publishing data to the shred tile.
    - `slot`: An unsigned long integer representing the current slot number for which the microblock is being published.
    - `hashcnt_delta`: An unsigned long integer representing the change in hash count since the last microblock or tick was published.
    - `txn_cnt`: An unsigned long integer representing the number of transactions to be included in the microblock.
- **Control Flow**:
    - Convert the memory chunk to a local address using `fd_chunk_to_laddr` to get the destination pointer `dst` for writing the microblock data.
    - Verify that the `slot` is greater than or equal to `ctx->reset_slot`.
    - Initialize the `fd_entry_batch_meta_t` structure at `dst` with metadata such as `parent_offset`, `reference_tick`, and `block_complete`.
    - Determine if the `parent_block_id` is valid and copy it if valid.
    - Advance `dst` to point to the location for the `fd_entry_batch_header_t` structure and set `hashcnt_delta` and `hash` fields.
    - Iterate over the transactions, copying successful ones to `dst` and updating `payload_sz` and `included_txn_cnt`.
    - Set the `txn_cnt` in the header to the number of included transactions.
    - Calculate the total size of the microblock and publish it using `fd_stem_publish`.
    - Update the `shred_seq` and `shred_out->chunk` to reflect the new state after publishing.
- **Output**: The function does not return a value; it performs its operations by modifying the state of the provided context and publishing the microblock data.


---
### after\_frag<!-- {{#callable:after_frag}} -->
The `after_frag` function processes a fragment after it has been received, updating the leader state, handling microblock transactions, and publishing microblocks if necessary.
- **Inputs**:
    - `ctx`: A pointer to the `fd_poh_ctx_t` context structure, which holds the state and configuration for the Proof of History (PoH) tile.
    - `in_idx`: An unsigned long integer representing the index of the input source for the fragment.
    - `seq`: An unsigned long integer representing the sequence number of the fragment.
    - `sig`: An unsigned long integer representing the signature of the fragment, used to identify the slot and type of the fragment.
    - `sz`: An unsigned long integer representing the size of the fragment data.
    - `tsorig`: An unsigned long integer representing the original timestamp of the fragment.
    - `tspub`: An unsigned long integer representing the publication timestamp of the fragment.
    - `stem`: A pointer to the `fd_stem_context_t` structure, which is used for publishing microblocks and ticks.
- **Control Flow**:
    - Check if the fragment should be skipped based on the `skip_frag` flag in the context; if so, return immediately.
    - If the fragment is of type `IN_KIND_STAKE`, finalize the stake message and update the leader schedule, potentially transitioning into a leader state.
    - If the fragment is not of type `IN_KIND_STAKE`, check if the microblocks lower bound is zero and record the delay for the first microblock if necessary.
    - Determine the target slot from the fragment's signature and verify it matches the current or next leader slot; log an error if it does not.
    - Increment the microblocks lower bound and process each transaction in the fragment, counting executed transactions and accumulating consumed compute units (CUs).
    - If no transactions were executed, return without publishing.
    - Hash the current state and the microblock trailer to update the PoH hash and increment the hash count.
    - Check if the hash count crosses a tick boundary and register a tick with the leader bank if necessary.
    - Publish the microblock using the [`publish_microblock`](#publish_microblock) function.
- **Output**: The function does not return a value; it updates the PoH context and potentially publishes microblocks or transitions the leader state.
- **Functions called**:
    - [`next_leader_slot`](#next_leader_slot)
    - [`publish_plugin_slot_start`](#publish_plugin_slot_start)
    - [`fd_ext_poh_register_tick`](../../discof/bank/fd_bank_abi.c.driver.md#fd_ext_poh_register_tick)
    - [`publish_plugin_slot_end`](#publish_plugin_slot_end)
    - [`no_longer_leader`](#no_longer_leader)
    - [`publish_microblock`](#publish_microblock)


---
### privileged\_init<!-- {{#callable:privileged_init}} -->
The `privileged_init` function initializes a Proof of History (PoH) context by setting up memory allocations and loading identity and vote account keys.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology configuration.
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing the tile configuration, including paths for identity and vote account keys.
- **Control Flow**:
    - Allocate scratch memory for the PoH context using `fd_topo_obj_laddr` to get the local address of the tile object ID.
    - Initialize the scratch allocator with `FD_SCRATCH_ALLOC_INIT`.
    - Allocate memory for the `fd_poh_ctx_t` context structure using `FD_SCRATCH_ALLOC_APPEND`.
    - Check if the `identity_key_path` is set; if not, log an error and exit.
    - Load the identity key from the specified path using `fd_keyload_load` and copy it into the context's `identity_key` field.
    - Check if the `vote_account_path` is set; if not, disable the bundle feature.
    - If the bundle feature is enabled, attempt to decode the vote account path using `fd_base58_decode_32`; if decoding fails, load the vote key from the path and copy it into the context's `bundle.vote_account` field.
- **Output**: This function does not return a value; it initializes the PoH context and logs errors if key paths are not set.


---
### fd\_ext\_shred\_set\_shred\_version<!-- {{#callable:fd_ext_shred_set_shred_version}} -->
The function `fd_ext_shred_set_shred_version` sets the shred version in a shared memory location once it is available.
- **Inputs**:
    - `shred_version`: An unsigned long integer representing the shred version to be set.
- **Control Flow**:
    - The function enters a while loop that continues as long as `fd_shred_version` is not available (i.e., it is NULL).
    - Inside the loop, it calls `FD_SPIN_PAUSE()` to yield the processor, allowing other threads to run while waiting for `fd_shred_version` to become available.
    - Once `fd_shred_version` is available, it exits the loop and sets the value of `fd_shred_version` to the provided `shred_version`.
- **Output**: This function does not return any value; it performs an action by setting a shared memory variable.


---
### fd\_ext\_poh\_publish\_gossip\_vote<!-- {{#callable:fd_ext_poh_publish_gossip_vote}} -->
The function `fd_ext_poh_publish_gossip_vote` publishes a gossip vote using the [`poh_link_publish`](#poh_link_publish) function with a specific signature and data.
- **Inputs**:
    - `data`: A pointer to the data to be published, represented as an array of unsigned characters.
    - `data_len`: The length of the data to be published, represented as an unsigned long integer.
- **Control Flow**:
    - The function calls [`poh_link_publish`](#poh_link_publish) with the `gossip_dedup` link, a signature of `1UL`, and the provided `data` and `data_len` as arguments.
    - The [`poh_link_publish`](#poh_link_publish) function handles the actual publishing process, which involves waiting for credit, copying the data to a destination, and publishing it to a memory cache.
- **Output**: The function does not return any value; it performs its operation by side effects, specifically publishing the data to a gossip link.
- **Functions called**:
    - [`poh_link_publish`](#poh_link_publish)


---
### fd\_ext\_poh\_publish\_leader\_schedule<!-- {{#callable:fd_ext_poh_publish_leader_schedule}} -->
The `fd_ext_poh_publish_leader_schedule` function publishes the leader schedule data to the `stake_out` link using the [`poh_link_publish`](#poh_link_publish) function.
- **Inputs**:
    - `data`: A pointer to the data buffer containing the leader schedule information to be published.
    - `data_len`: The length of the data buffer in bytes.
- **Control Flow**:
    - The function calls [`poh_link_publish`](#poh_link_publish) with the `stake_out` link, a signature value of `2UL`, and the provided data and data length.
    - The [`poh_link_publish`](#poh_link_publish) function handles the actual publishing of the data to the specified link.
- **Output**: This function does not return any value.
- **Functions called**:
    - [`poh_link_publish`](#poh_link_publish)


---
### fd\_ext\_poh\_publish\_cluster\_info<!-- {{#callable:fd_ext_poh_publish_cluster_info}} -->
The `fd_ext_poh_publish_cluster_info` function publishes cluster information data to a specific Poh link.
- **Inputs**:
    - `data`: A pointer to the data to be published.
    - `data_len`: The length of the data to be published.
- **Control Flow**:
    - The function calls [`poh_link_publish`](#poh_link_publish) with the `crds_shred` link, a signature value of `2UL`, and the provided data and data length.
    - The [`poh_link_publish`](#poh_link_publish) function handles the actual publishing of the data to the specified link.
- **Output**: This function does not return any value.
- **Functions called**:
    - [`poh_link_publish`](#poh_link_publish)


---
### fd\_ext\_plugin\_publish\_replay\_stage<!-- {{#callable:fd_ext_plugin_publish_replay_stage}} -->
The function `fd_ext_plugin_publish_replay_stage` publishes data to the replay plugin using a specified signature and data length.
- **Inputs**:
    - `sig`: An unsigned long integer representing the signature associated with the data to be published.
    - `data`: A pointer to an unsigned char array containing the data to be published.
    - `data_len`: An unsigned long integer representing the length of the data to be published.
- **Control Flow**:
    - The function calls [`poh_link_publish`](#poh_link_publish) with the `replay_plugin`, `sig`, `data`, and `data_len` as arguments.
    - [`poh_link_publish`](#poh_link_publish) handles the actual publishing of the data to the replay plugin.
- **Output**: The function does not return any value; it performs an action by publishing data to the replay plugin.
- **Functions called**:
    - [`poh_link_publish`](#poh_link_publish)


---
### fd\_ext\_plugin\_publish\_genesis\_hash<!-- {{#callable:fd_ext_plugin_publish_genesis_hash}} -->
The function `fd_ext_plugin_publish_genesis_hash` publishes a genesis hash to the replay plugin using a specified signature and data.
- **Inputs**:
    - `sig`: An unsigned long integer representing the signature associated with the data to be published.
    - `data`: A pointer to an unsigned char array containing the data to be published.
    - `data_len`: An unsigned long integer representing the length of the data to be published.
- **Control Flow**:
    - The function calls [`poh_link_publish`](#poh_link_publish) with the `replay_plugin`, `sig`, `data`, and `data_len` as arguments.
    - The [`poh_link_publish`](#poh_link_publish) function handles the actual publishing of the data to the specified plugin.
- **Output**: The function does not return any value; it performs an action by publishing data to a plugin.
- **Functions called**:
    - [`poh_link_publish`](#poh_link_publish)


---
### fd\_ext\_plugin\_publish\_start\_progress<!-- {{#callable:fd_ext_plugin_publish_start_progress}} -->
The `fd_ext_plugin_publish_start_progress` function publishes data to the `start_progress_plugin` using a signature, data, and data length.
- **Inputs**:
    - `sig`: An unsigned long integer representing the signature for the data to be published.
    - `data`: A pointer to an unsigned char array containing the data to be published.
    - `data_len`: An unsigned long integer representing the length of the data to be published.
- **Control Flow**:
    - The function calls [`poh_link_publish`](#poh_link_publish) with the `start_progress_plugin`, `sig`, `data`, and `data_len` as arguments.
    - The [`poh_link_publish`](#poh_link_publish) function handles the actual publishing of the data to the specified plugin.
- **Output**: The function does not return any value; it performs an action by publishing data to a plugin.
- **Functions called**:
    - [`poh_link_publish`](#poh_link_publish)


---
### fd\_ext\_plugin\_publish\_vote\_listener<!-- {{#callable:fd_ext_plugin_publish_vote_listener}} -->
The `fd_ext_plugin_publish_vote_listener` function publishes data to the `vote_listener_plugin` using the [`poh_link_publish`](#poh_link_publish) function.
- **Inputs**:
    - `sig`: An unsigned long integer representing the signature or identifier for the data being published.
    - `data`: A pointer to an unsigned char array containing the data to be published.
    - `data_len`: An unsigned long integer representing the length of the data to be published.
- **Control Flow**:
    - The function calls [`poh_link_publish`](#poh_link_publish) with the `vote_listener_plugin`, `sig`, `data`, and `data_len` as arguments.
    - The [`poh_link_publish`](#poh_link_publish) function handles the actual publishing of the data to the specified plugin.
- **Output**: The function does not return any value; it performs an action by publishing data to a plugin.
- **Functions called**:
    - [`poh_link_publish`](#poh_link_publish)


---
### fd\_ext\_plugin\_publish\_validator\_info<!-- {{#callable:fd_ext_plugin_publish_validator_info}} -->
The `fd_ext_plugin_publish_validator_info` function publishes validator information using the [`poh_link_publish`](#poh_link_publish) function.
- **Inputs**:
    - `sig`: An unsigned long integer representing the signature or identifier for the data being published.
    - `data`: A pointer to an unsigned character array containing the data to be published.
    - `data_len`: An unsigned long integer representing the length of the data to be published.
- **Control Flow**:
    - The function calls [`poh_link_publish`](#poh_link_publish) with the `validator_info_plugin` link, passing the `sig`, `data`, and `data_len` as arguments.
- **Output**: The function does not return any value; it performs an action by publishing the data.
- **Functions called**:
    - [`poh_link_publish`](#poh_link_publish)


---
### fd\_ext\_plugin\_publish\_periodic<!-- {{#callable:fd_ext_plugin_publish_periodic}} -->
The `fd_ext_plugin_publish_periodic` function publishes data to the gossip plugin using a specified signature and data length.
- **Inputs**:
    - `sig`: An unsigned long integer representing the signature associated with the data to be published.
    - `data`: A pointer to an unsigned char array containing the data to be published.
    - `data_len`: An unsigned long integer representing the length of the data to be published.
- **Control Flow**:
    - The function calls [`poh_link_publish`](#poh_link_publish) with the `gossip_plugin`, `sig`, `data`, and `data_len` as arguments.
    - The [`poh_link_publish`](#poh_link_publish) function handles the actual publishing of the data to the specified plugin.
- **Output**: The function does not return any value; it performs an action by publishing data to the gossip plugin.
- **Functions called**:
    - [`poh_link_publish`](#poh_link_publish)


---
### fd\_ext\_resolv\_publish\_root\_bank<!-- {{#callable:fd_ext_resolv_publish_root_bank}} -->
The function `fd_ext_resolv_publish_root_bank` publishes data related to the root bank to the replay resolution link.
- **Inputs**:
    - `data`: A pointer to the data to be published, represented as an array of unsigned characters (uchar).
    - `data_len`: The length of the data to be published, represented as an unsigned long integer (ulong).
- **Control Flow**:
    - The function calls [`poh_link_publish`](#poh_link_publish) with the `replay_resolv` link, a signature of 0UL, the provided data, and the data length.
    - The [`poh_link_publish`](#poh_link_publish) function handles the actual publishing of the data to the specified link.
- **Output**: The function does not return any value; it performs its operation by side effect, publishing data to a specified link.
- **Functions called**:
    - [`poh_link_publish`](#poh_link_publish)


---
### fd\_ext\_resolv\_publish\_completed\_blockhash<!-- {{#callable:fd_ext_resolv_publish_completed_blockhash}} -->
The function `fd_ext_resolv_publish_completed_blockhash` publishes a completed blockhash to the `replay_resolv` link using the [`poh_link_publish`](#poh_link_publish) function.
- **Inputs**:
    - `data`: A pointer to the data (blockhash) to be published.
    - `data_len`: The length of the data to be published.
- **Control Flow**:
    - The function calls [`poh_link_publish`](#poh_link_publish) with the `replay_resolv` link, a signature value of `1UL`, the `data`, and `data_len` as arguments.
    - The [`poh_link_publish`](#poh_link_publish) function handles the actual publishing of the data to the specified link.
- **Output**: The function does not return any value; it performs an action by publishing the data.
- **Functions called**:
    - [`poh_link_publish`](#poh_link_publish)


---
### out1<!-- {{#callable:out1}} -->
The `out1` function retrieves the output context for a specified link name from a given topology and tile configuration.
- **Inputs**:
    - `topo`: A pointer to a `fd_topo_t` structure representing the topology configuration.
    - `tile`: A pointer to a `fd_topo_tile_t` structure representing the tile configuration.
    - `name`: A constant character pointer representing the name of the output link to be retrieved.
- **Control Flow**:
    - Initialize `idx` to `ULONG_MAX` to track the index of the desired output link.
    - Iterate over the output links of the tile using a loop from 0 to `tile->out_cnt`.
    - For each link, check if the link's name matches the provided `name` using `strcmp`.
    - If a match is found and `idx` is not `ULONG_MAX`, log an error indicating multiple links with the same name.
    - If a match is found and `idx` is `ULONG_MAX`, set `idx` to the current index.
    - After the loop, if `idx` is still `ULONG_MAX`, log an error indicating no link with the specified name was found.
    - Retrieve the memory workspace, chunk0, and watermark for the link at the found index.
    - Return a `fd_poh_out_ctx_t` structure initialized with the retrieved values.
- **Output**: Returns a `fd_poh_out_ctx_t` structure containing the index, memory workspace, chunk0, watermark, and initial chunk for the specified output link.


---
### unprivileged\_init<!-- {{#callable:unprivileged_init}} -->
The `unprivileged_init` function initializes the unprivileged components of a Proof of History (PoH) tile in a distributed system, setting up various contexts and links for communication and processing.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology of the system, which includes information about the network of tiles and their connections.
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing the specific tile being initialized, which contains configuration and state information for the tile.
- **Control Flow**:
    - Allocate scratch memory for the PoH context and other necessary components using `FD_SCRATCH_ALLOC_INIT` and `FD_SCRATCH_ALLOC_APPEND` macros.
    - Initialize the `fd_poh_ctx_t` context structure, including joining the stake and SHA256 contexts using `fd_stake_ci_join` and `fd_sha256_join`.
    - Set initial values for various fields in the context, such as `shred_seq`, `halted_switching_key`, `slot`, `hashcnt`, and others to their default states.
    - Check if the bundle feature is enabled and initialize the bundle context if necessary using `fd_bundle_crank_gen_init`.
    - Query the topology properties to find the PoH shred object ID and join the shred version using `fd_fseq_join`.
    - Initialize communication links for various plugins and outputs using [`poh_link_init`](#poh_link_init) for each required link.
    - Log a message indicating that the PoH is waiting to be initialized by the Agave client and set up a synchronization mechanism using volatile locks to wait for initialization to complete.
    - Join histogram contexts for various delay metrics using `fd_histf_join`.
    - Iterate over input links to set up memory and chunk information for each input, determining the kind of input based on the link name.
    - Set up output contexts for shred, pack, and plugin outputs using the [`out1`](#out1) function to determine the appropriate memory and chunk settings.
    - Finalize the scratch allocation and check for overflow, logging an error if the allocated memory exceeds the expected footprint.
- **Output**: The function does not return a value; it initializes the PoH tile's context and communication links, preparing it for operation within the distributed system.
- **Functions called**:
    - [`poh_link_init`](#poh_link_init)
    - [`out1`](#out1)
    - [`scratch_footprint`](#scratch_footprint)


# Function Declarations (Public API)

---
### fd\_ext\_bank\_acquire<!-- {{#callable_declaration:fd_ext_bank_acquire}} -->
Logs an error message indicating the function is not implemented.
- **Description**: This function is a placeholder and does not perform any operations other than logging an error message. It is intended to be called when acquiring a bank, but currently, it only logs an error indicating that the functionality is not implemented. This function should not be used in production as it does not fulfill its intended purpose.
- **Inputs**:
    - `bank`: A pointer to a bank object. The parameter is marked as unused, and the function does not perform any operations with it. The caller retains ownership, and the value can be null or any other value without affecting the function's behavior.
- **Output**: None
- **See also**: [`fd_ext_bank_acquire`](../../discof/bank/fd_bank_abi.c.driver.md#fd_ext_bank_acquire)  (Implementation)


---
### fd\_ext\_bank\_release<!-- {{#callable_declaration:fd_ext_bank_release}} -->
Logs an error message indicating the function is not implemented.
- **Description**: This function is a placeholder for releasing a bank resource, but it currently does nothing except log an error message. It is not intended for use in its current form and should be replaced or implemented properly in the future. Calling this function will not release any resources and will only result in an error log entry.
- **Inputs**:
    - `bank`: A pointer to a bank resource that is intended to be released. The parameter is marked as unused, indicating it is not currently utilized by the function.
- **Output**: None
- **See also**: [`fd_ext_bank_release`](../../discof/bank/fd_bank_abi.c.driver.md#fd_ext_bank_release)  (Implementation)


---
### fd\_ext\_poh\_signal\_leader\_change<!-- {{#callable_declaration:fd_ext_poh_signal_leader_change}} -->
Signals a leader change in the Proof of History (PoH) system.
- **Description**: This function is used to notify the system that a change in leadership has occurred within the Proof of History (PoH) system. It is typically called when the leader of the PoH process changes, which is a critical event in maintaining the integrity and continuity of the PoH chain. This function should be used in contexts where the PoH system is integrated with other components that need to be aware of leadership changes, such as during the transition of leader roles in a distributed network. The function does not perform any operations on the input parameter and will log an error if invoked.
- **Inputs**:
    - `sender`: An opaque pointer to a sender object, which is not used by the function. The parameter is marked as unused and can be null or any value, as it does not affect the function's behavior.
- **Output**: None
- **See also**: [`fd_ext_poh_signal_leader_change`](../../discof/bank/fd_bank_abi.c.driver.md#fd_ext_poh_signal_leader_change)  (Implementation)


---
### fd\_ext\_poh\_register\_tick<!-- {{#callable_declaration:fd_ext_poh_register_tick}} -->
Logs an error message indicating an unsupported operation.
- **Description**: This function is intended to register a tick in the Proof of History (PoH) system, but it currently only logs an error message indicating that the operation is not supported. It is a placeholder function and does not perform any meaningful action. This function should not be used in production as it does not fulfill its intended purpose.
- **Inputs**:
    - `bank`: A pointer to a bank object, which is currently unused. The parameter is marked as unused and can be null.
    - `hash`: A pointer to a hash value, which is currently unused. The parameter is marked as unused and can be null.
- **Output**: None
- **See also**: [`fd_ext_poh_register_tick`](../../discof/bank/fd_bank_abi.c.driver.md#fd_ext_poh_register_tick)  (Implementation)


---
### fd\_ext\_bank\_load\_account<!-- {{#callable_declaration:fd_ext_bank_load_account}} -->
Loads account information from a bank.
- **Description**: This function is used to retrieve account information from a specified bank. It requires the bank to be specified, along with the account address. The function will populate the owner and data fields with the account's owner and data, respectively, and update the data size. It is important to ensure that the bank and address are valid and that the owner, data, and data_sz pointers are not null before calling this function.
- **Inputs**:
    - `bank`: A pointer to the bank from which the account information is to be loaded. This parameter is expected to be valid and non-null.
    - `fixed_root`: An integer parameter that is currently unused. It can be set to any value.
    - `addr`: A pointer to a constant unsigned character array representing the account address. This must be a valid address and not null.
    - `owner`: A pointer to an unsigned character array where the account owner information will be stored. This must not be null.
    - `data`: A pointer to an unsigned character array where the account data will be stored. This must not be null.
    - `data_sz`: A pointer to an unsigned long where the size of the account data will be stored. This must not be null.
- **Output**: Returns an integer status code. The function logs an error and returns 0, indicating that the operation is not implemented.
- **See also**: [`fd_ext_bank_load_account`](../../discof/bank/fd_bank_abi.c.driver.md#fd_ext_bank_load_account)  (Implementation)


---
### fd\_ext\_admin\_rpc\_set\_identity<!-- {{#callable_declaration:fd_ext_admin_rpc_set_identity}} -->
Sets the identity keypair for the admin RPC.
- **Description**: This function is used to set the identity keypair for the admin RPC interface. It is typically called when there is a need to update or initialize the identity keypair used for administrative operations. The function does not perform any operations if the parameters are marked as unused, and it always returns a fixed value. It is important to ensure that the identity keypair provided is valid and correctly formatted.
- **Inputs**:
    - `identity_keypair`: A pointer to an unsigned char array representing the identity keypair. The caller retains ownership of the memory, and it must not be null.
    - `require_tower`: An integer flag indicating whether a tower is required. This parameter is marked as unused in the current implementation.
- **Output**: Returns an integer value, which is always 0 in the current implementation.
- **See also**: [`fd_ext_admin_rpc_set_identity`](../../discof/bank/fd_bank_abi.c.driver.md#fd_ext_admin_rpc_set_identity)  (Implementation)


