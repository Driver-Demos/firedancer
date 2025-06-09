# Purpose
The provided C code is a comprehensive implementation of a Proof of History (PoH) mechanism, which is a critical component of the Solana blockchain protocol. This file is part of a larger system and is designed to be integrated with other components, such as the bank, shredder, and pack modules, to facilitate the efficient and secure operation of the blockchain. The code is structured to handle the complex task of maintaining a verifiable sequence of events (or history) by continuously hashing data, even when the node is not the leader, to ensure that the network can trust the sequence of events and detect any attempts to manipulate the order of transactions.

The code defines a PoH context structure (`fd_poh_ctx_t`) that maintains the state of the PoH process, including the current slot, hash count, and leader information. It also includes functions for initializing the PoH context, handling leader transitions, and publishing ticks and microblocks to the network. The PoH mechanism is designed to solve specific problems in distributed systems, such as leader schedule transitions and transaction verification, by providing a cryptographic proof that a certain amount of time has passed between events. This is achieved through continuous hashing, which acts as a "proof of work" to demonstrate that the node has been actively participating in the network. The code also includes mechanisms for handling external interactions, such as receiving leader bank information and publishing data to other components, ensuring that the PoH process is tightly integrated with the rest of the system.
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
- **Description**: The `fd_poh_global_ctx` is a static pointer to a `fd_poh_ctx_t` structure, which represents the global context for the Proof of History (PoH) tile in the Solana blockchain implementation. This context contains various configuration parameters, state information, and operational data necessary for managing the PoH process, including slot and hash count tracking, leader scheduling, and microblock handling.
- **Use**: This variable is used to maintain and access the global state and configuration of the PoH tile, allowing various functions to interact with and modify the PoH process.


---
### fd\_poh\_waiting\_lock
- **Type**: `volatile ulong`
- **Description**: `fd_poh_waiting_lock` is a static volatile unsigned long integer variable that is aligned to 128 bytes. It is used as a lock indicator in a concurrency control mechanism between the PoH tile and other components, such as Agave, to manage access to shared resources.
- **Use**: This variable is used to signal when a component wishes to acquire a lock on the PoH tile for reading or writing operations.


---
### fd\_poh\_returned\_lock
- **Type**: `volatile ulong`
- **Description**: `fd_poh_returned_lock` is a global volatile unsigned long integer variable that is aligned to 128 bytes. It is used in a locking mechanism to coordinate access between the PoH tile and other components, such as the Agave client, in the system.
- **Use**: This variable is used to signal when the PoH tile has granted access to a waiting component, allowing it to proceed with its operations.


---
### 
- **Type**: ``ulong``
- **Description**: The `fd_poh_returned_lock` is a global variable of type `ulong` that is declared as `static volatile` and is aligned to 128 bytes. It is used in a locking mechanism to coordinate access between the PoH tile and the Agave client.
- **Use**: This variable is used to signal to a waiting process that it can proceed with accessing the PoH tile.


---
### gossip\_dedup
- **Type**: `poh_link_t`
- **Description**: The `gossip_dedup` variable is a static instance of the `poh_link_t` structure, which is used to manage a communication link in the system. This structure contains fields for managing memory, data chunks, and sequence numbers, among other things.
- **Use**: The `gossip_dedup` variable is used to handle the deduplication of gossip messages by managing the flow of data through a specific communication link.


---
### stake\_out
- **Type**: ``poh_link_t``
- **Description**: The `stake_out` variable is a static instance of the `poh_link_t` structure, which is used to manage a communication link in the context of the Proof of History (PoH) system. This structure contains fields for managing metadata cache, memory allocation, and sequence tracking for data transmission.
- **Use**: The `stake_out` variable is used to publish leader schedule data to the network, ensuring that the PoH system can communicate necessary information about leader changes and scheduling.


---
### crds\_shred
- **Type**: `poh_link_t`
- **Description**: The `crds_shred` variable is a static instance of the `poh_link_t` structure, which is used to manage a communication link in the system. This structure contains metadata and pointers necessary for managing data chunks, including memory workspace pointers, chunk indices, and sequence numbers.
- **Use**: The `crds_shred` variable is used to facilitate the publishing of cluster information to the CRDS (Cluster Replicated Data Store) shred tile, managing the flow of data and ensuring proper synchronization and credit availability.


---
### replay\_resolv
- **Type**: ``poh_link_t``
- **Description**: The `replay_resolv` variable is a static instance of the `poh_link_t` structure. This structure is used to manage a communication link in the context of the Proof of History (PoH) system, specifically for handling replay resolution tasks.
- **Use**: This variable is used to publish data related to root bank and completed blockhashes in the PoH system.


---
### replay\_plugin
- **Type**: `poh_link_t`
- **Description**: The `replay_plugin` is a static global variable of type `poh_link_t`, which is a structure used to manage a link in the Proof of History (PoH) system. This structure contains metadata and pointers necessary for managing data flow and synchronization between different components of the system.
- **Use**: The `replay_plugin` is used to facilitate communication and data transfer between the PoH system and the replay stage, allowing for the publication of replay-related data.


---
### gossip\_plugin
- **Type**: ``poh_link_t``
- **Description**: The `gossip_plugin` is a static variable of type `poh_link_t`, which is a structure used to manage a link in a distributed system. This structure contains fields for managing memory caches, data chunks, and sequence numbers, among other things. It is used to facilitate communication between different components of the system, specifically for the gossip protocol in this context.
- **Use**: The `gossip_plugin` is used to publish periodic data related to the gossip protocol in the system, ensuring that the data is correctly managed and transmitted across the network.


---
### start\_progress\_plugin
- **Type**: `poh_link_t`
- **Description**: The `start_progress_plugin` is a static instance of the `poh_link_t` structure, which is used to manage a communication link in the system. This structure contains various fields for managing memory, data chunks, and sequence numbers for transmitting data.
- **Use**: This variable is used to initialize and manage a specific plugin link for starting progress in the system, facilitating data transmission and synchronization.


---
### vote\_listener\_plugin
- **Type**: ``poh_link_t``
- **Description**: The `vote_listener_plugin` is a static global variable of type `poh_link_t`. This data structure is used to manage a link in a distributed system, specifically for handling vote listener plugin operations.
- **Use**: This variable is used to initialize and manage the state and operations of the vote listener plugin link within the system.


---
### validator\_info\_plugin
- **Type**: `poh_link_t`
- **Description**: The `validator_info_plugin` is a static instance of the `poh_link_t` structure, which is used to manage communication links in the Proof of History (PoH) tile. This structure is part of a set of plugins that facilitate various functionalities within the PoH system.
- **Use**: This variable is used to publish validator information through the PoH plugin system, enabling communication and data exchange between different components of the network.


---
### fd\_shred\_version
- **Type**: `volatile ulong *`
- **Description**: `fd_shred_version` is a pointer to a volatile unsigned long integer, indicating that it is used to store a shred version number that can be modified by different parts of the program or by different threads. The use of `volatile` suggests that the value of this variable can change at any time, and the compiler should not optimize accesses to it.
- **Use**: This variable is used to communicate the shred version from the PoH tile to the shred tile in a shared memory space.


---
### fd\_tile\_poh
- **Type**: `fd_topo_run_tile_t`
- **Description**: The `fd_tile_poh` is a global variable of type `fd_topo_run_tile_t` that represents a configuration for a Proof of History (PoH) tile in the Firedancer system. It is initialized with specific function pointers and parameters that define its behavior, such as initialization routines and a run function. This structure is crucial for setting up and managing the PoH tile's operations within the system.
- **Use**: This variable is used to configure and manage the execution of a PoH tile, which is part of the Firedancer system's infrastructure for handling Proof of History operations.


# Data Structures

---
### fd\_poh\_in\_ctx\_t
- **Type**: `struct`
- **Members**:
    - `mem`: A pointer to an fd_wksp_t structure, representing a memory workspace.
    - `chunk0`: An unsigned long integer representing the starting chunk index in the workspace.
    - `wmark`: An unsigned long integer representing the watermark or limit for the workspace.
- **Description**: The `fd_poh_in_ctx_t` structure is a simple data structure used to manage memory workspaces in the context of Proof of History (PoH) operations. It contains a pointer to a memory workspace (`mem`), and two unsigned long integers (`chunk0` and `wmark`) that define the starting chunk and the watermark or limit for the workspace, respectively. This structure is likely used to track and manage memory allocation and usage within the PoH system.


---
### fd\_poh\_out\_ctx\_t
- **Type**: `struct`
- **Members**:
    - `idx`: An unsigned long integer representing the index of the context.
    - `mem`: A pointer to an fd_wksp_t structure, representing a memory workspace.
    - `chunk0`: An unsigned long integer representing the initial chunk in the memory workspace.
    - `wmark`: An unsigned long integer representing the watermark in the memory workspace.
    - `chunk`: An unsigned long integer representing the current chunk in the memory workspace.
- **Description**: The `fd_poh_out_ctx_t` structure is used to manage output contexts in a memory workspace, specifically for handling chunks of data. It includes an index to identify the context, a pointer to the memory workspace, and several unsigned long integers to track the initial chunk, the watermark, and the current chunk within the workspace. This structure is likely used in the context of managing data output in a system that processes and organizes data in chunks, such as a blockchain or distributed ledger system.


---
### fd\_poh\_ctx\_t
- **Type**: `struct`
- **Members**:
    - `stem`: Pointer to a stem context.
    - `tick_duration_ns`: Duration of a tick in nanoseconds.
    - `hashcnt_per_tick`: Number of hash counts per tick.
    - `ticks_per_slot`: Number of ticks per slot.
    - `slot_duration_ns`: Duration of a slot in nanoseconds.
    - `hashcnt_duration_ns`: Duration of a hash count in nanoseconds.
    - `hashcnt_per_slot`: Number of hash counts per slot.
    - `max_microblocks_per_slot`: Maximum number of microblocks per slot.
    - `limits`: Consensus-critical slot cost limits.
    - `slot`: Current slot number in the proof of history.
    - `hashcnt`: Current hash count within the slot.
    - `cus_used`: Cumulative units used.
    - `last_slot`: Slot number of the last published microblock.
    - `last_hashcnt`: Hash count of the last published microblock.
    - `highwater_leader_slot`: Tracks the maximum slot for which a tick or microblock has been published.
    - `lagged_consecutive_leader_start`: Indicates if the expected slot end time is not reset between consecutive leader slots.
    - `expect_sequential_leader_slot`: Expected sequential leader slot number.
    - `expect_microblock_idx`: Expected index of the next microblock.
    - `microblocks_lower_bound`: Tracks the lower bound of microblocks that might still be received in the slot.
    - `reset_hash`: Hash value at the reset point, aligned to 32 bytes.
    - `hash`: Current hash value, aligned to 32 bytes.
    - `skipped_tick_hashes`: Hashes produced when not leader, stored for replay if prior leader skips.
    - `reset_slot_start_ns`: Timestamp of when the reset slot was received.
    - `leader_bank_start_ns`: Timestamp of when the bank for the current leader slot was received.
    - `reset_slot`: Hash count at the start of the current reset slot.
    - `next_leader_slot`: Hash count at which the next leader slot begins.
    - `skip_frag`: Indicates if an in-progress fragment should be skipped.
    - `max_active_descendant`: Maximum active descendant slot number.
    - `current_leader_bank`: Pointer to the current leader bank, if applicable.
    - `sha256`: Pointer to a SHA-256 context.
    - `stake_ci`: Pointer to a stake context interface.
    - `shred_seq`: Last sequence number of an outgoing fragment to the shred tile.
    - `halted_switching_key`: Indicates if switching key is halted.
    - `keyswitch`: Pointer to a keyswitch context.
    - `identity_key`: Public key for identity.
    - `bundle`: Information for computing addresses for bundle crank information.
    - `signal_leader_change`: Pointer to a signal for leader change notification.
    - `_txns`: Temporary storage for transactions during fragment processing.
    - `_microblock_trailer`: Temporary storage for microblock trailer during fragment processing.
    - `in_kind`: Array indicating the kind of input for each input context.
    - `in`: Array of input contexts.
    - `shred_out`: Output context for shreds.
    - `pack_out`: Output context for packs.
    - `plugin_out`: Output context for plugins.
    - `begin_leader_delay`: Histogram for leader delay metrics.
    - `first_microblock_delay`: Histogram for first microblock delay metrics.
    - `slot_done_delay`: Histogram for slot done delay metrics.
    - `bundle_init_delay`: Histogram for bundle initialization delay metrics.
    - `features_activation_avail`: Indicates if feature activation is available.
    - `features_activation`: Feature activation slots.
    - `parent_slot`: Parent slot number.
    - `parent_block_id`: ID of the parent block, aligned to 32 bytes.
- **Description**: The `fd_poh_ctx_t` structure is a comprehensive context for managing the Proof of History (PoH) process in a distributed ledger system, such as Solana. It encapsulates various configuration parameters, state variables, and operational contexts necessary for maintaining the PoH chain, handling leader transitions, and managing microblocks and ticks. The structure includes fields for static configuration, derived timing information, consensus-critical limits, and current operational state, such as the current slot, hash count, and leader bank. It also manages input and output contexts for processing transactions and publishing results, as well as tracking metrics and handling feature activations.


---
### poh\_link
- **Type**: `struct`
- **Members**:
    - `mcache`: A pointer to a fragment metadata cache.
    - `depth`: An unsigned long representing the depth of the link.
    - `tx_seq`: An unsigned long representing the transaction sequence number.
    - `mem`: A pointer to memory associated with the link.
    - `dcache`: A pointer to a data cache associated with the link.
    - `chunk0`: An unsigned long representing the initial chunk index.
    - `wmark`: An unsigned long representing the watermark for the data cache.
    - `chunk`: An unsigned long representing the current chunk index.
    - `cr_avail`: An unsigned long representing the available credit for the link.
    - `rx_cnt`: An unsigned long representing the count of receive sequences.
    - `rx_fseqs`: An array of pointers to unsigned long representing receive sequence numbers.
- **Description**: The `poh_link` structure is designed to manage and track the state of a link in a Proof of History (PoH) system. It includes pointers to metadata and data caches, as well as various unsigned long fields to track the depth, transaction sequence, and chunk indices. Additionally, it manages credit availability and receive sequences, which are crucial for coordinating data flow and ensuring the integrity of the PoH process.


---
### poh\_link\_t
- **Type**: `typedef struct poh_link poh_link_t;`
- **Members**:
    - `mcache`: Pointer to a metadata cache for managing fragments.
    - `depth`: Depth of the metadata cache.
    - `tx_seq`: Transaction sequence number for the link.
    - `mem`: Pointer to memory associated with the link.
    - `dcache`: Pointer to a data cache for storing data.
    - `chunk0`: Initial chunk index in the data cache.
    - `wmark`: Watermark for the data cache, indicating the end of valid data.
    - `chunk`: Current chunk index in the data cache.
    - `cr_avail`: Available credit for publishing data.
    - `rx_cnt`: Count of receive sequences.
    - `rx_fseqs`: Array of pointers to receive sequence numbers.
- **Description**: The `poh_link_t` structure is used to manage data flow between different components in a distributed system, specifically in the context of Solana's Proof of History (PoH) implementation. It holds pointers to memory and data caches, manages transaction sequences, and tracks available credits for data publishing. The structure also maintains receive sequences to coordinate data reception and ensure data integrity across different nodes or components.


# Functions

---
### poh\_link\_wait\_credit<!-- {{#callable:poh_link_wait_credit}} -->
The `poh_link_wait_credit` function ensures that a `poh_link_t` structure has available credit by waiting until it can determine a positive credit availability from its receivers.
- **Inputs**:
    - `link`: A pointer to a `poh_link_t` structure representing a link that requires credit availability to proceed.
- **Control Flow**:
    - Check if the link already has available credit (`cr_avail`), and return immediately if so.
    - Enter an infinite loop to wait for credit availability.
    - Initialize `cr_query` to `ULONG_MAX` to find the minimum credit query value.
    - Iterate over each receiver (`rx_fseqs`) in the link to calculate the credit query based on the difference between the link's transmission sequence (`tx_seq`) and the receiver's sequence (`rx_seq`).
    - Update `cr_query` to the minimum of the current `cr_query` and the calculated credit query for each receiver.
    - If a positive `cr_query` is found, set the link's `cr_avail` to this value and break the loop.
    - Pause the CPU briefly if no credit is available, then repeat the loop.
- **Output**: The function does not return a value but updates the `cr_avail` field of the `poh_link_t` structure to reflect the available credit.


---
### poh\_link\_publish<!-- {{#callable:poh_link_publish}} -->
The `poh_link_publish` function publishes data to a specified link after ensuring the link is ready and has sufficient credit.
- **Inputs**:
    - `link`: A pointer to a `poh_link_t` structure representing the link to which data will be published.
    - `sig`: An unsigned long integer representing the signature or identifier for the data being published.
    - `data`: A pointer to a constant unsigned char array containing the data to be published.
    - `data_sz`: An unsigned long integer representing the size of the data to be published.
- **Control Flow**:
    - The function enters a loop that pauses execution until the `mcache` field of the `link` is non-zero, indicating the link is ready.
    - It checks if the `mem` field of the `link` is non-zero; if it is zero, the function returns immediately, indicating the link is not enabled for publishing.
    - The function calls [`poh_link_wait_credit`](#poh_link_wait_credit) to ensure there is enough credit available for publishing.
    - It calculates the destination address in memory using `fd_chunk_to_laddr` and copies the data to this address using `fd_memcpy`.
    - The function calculates a timestamp using `fd_frag_meta_ts_comp` and `fd_tickcount`.
    - It calls `fd_mcache_publish` to publish the data to the link's mcache with the provided signature, chunk, data size, and timestamp.
    - The function updates the `chunk` field of the link using `fd_dcache_compact_next` to point to the next available chunk.
    - It decrements the `cr_avail` field of the link to reflect the consumption of credit.
    - Finally, it increments the `tx_seq` field of the link to indicate the next sequence number for transactions.
- **Output**: The function does not return a value; it performs operations to publish data to a link and updates the link's state accordingly.
- **Functions called**:
    - [`poh_link_wait_credit`](#poh_link_wait_credit)


---
### poh\_link\_init<!-- {{#callable:poh_link_init}} -->
The `poh_link_init` function initializes a `poh_link_t` structure with memory and configuration details from a given topology and tile, setting up the link for data transmission.
- **Inputs**:
    - `link`: A pointer to a `poh_link_t` structure that will be initialized.
    - `topo`: A pointer to a `fd_topo_t` structure representing the topology containing links and workspaces.
    - `tile`: A pointer to a `fd_topo_tile_t` structure representing the tile with output link information.
    - `out_idx`: An unsigned long integer representing the index of the output link in the tile's output link array.
- **Control Flow**:
    - Retrieve the `fd_topo_link_t` structure for the specified output link index from the tile's `out_link_id` array.
    - Retrieve the workspace associated with the link's `dcache_obj_id` from the topology's workspaces.
    - Initialize the `link` structure's `mem`, `depth`, `tx_seq`, `dcache`, `chunk0`, `wmark`, `chunk`, `cr_avail`, and `rx_cnt` fields using the retrieved link and workspace information.
    - Iterate over all tiles in the topology to find and store reliable input link sequence numbers in `link->rx_fseqs` if they match the current link's ID.
    - Ensure memory consistency with `FD_COMPILER_MFENCE()` and set the `link->mcache` to the link's `mcache`.
    - Verify that the `link->mcache` is not null using `FD_TEST`.
- **Output**: The function does not return a value; it initializes the `poh_link_t` structure in place.


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
    - `signal_leader_change`: A pointer to an opaque Rust object used to signal leader changes.
- **Control Flow**:
    - The function begins by ensuring the PoH context is initialized before proceeding.
    - It acquires a write lock on the PoH context to ensure exclusive access.
    - The function calculates the initial slot based on the tick height and ticks per slot.
    - It initializes various fields in the PoH context, such as slot, hash count, and reset slot start time.
    - The function copies the last entry hash into the context's reset and current hash fields.
    - It sets the signal_leader_change pointer in the context for leader change notifications.
    - The function configures static clock parameters in the context, including tick duration, hashes per tick, and ticks per slot.
    - Derived clock information is computed, such as slot duration, hash count duration, and hash count per slot.
    - The function determines the maximum number of microblocks per slot based on the hash count per tick.
    - Finally, it releases the write lock on the PoH context.
- **Output**: The function does not return a value; it initializes the PoH context with the provided parameters.
- **Functions called**:
    - [`fd_ext_poh_write_unlock`](#fd_ext_poh_write_unlock)


---
### fd\_ext\_poh\_acquire\_leader\_bank<!-- {{#callable:fd_ext_poh_acquire_leader_bank}} -->
The function `fd_ext_poh_acquire_leader_bank` acquires and returns the current leader bank if it exists, incrementing its reference count before releasing the lock.
- **Inputs**: None
- **Control Flow**:
    - Acquire a write lock on the PoH context using `fd_ext_poh_write_lock`.
    - Initialize a local variable `bank` to `NULL`.
    - Check if `ctx->current_leader_bank` is non-null using `FD_LIKELY`.
    - If true, increment the reference count of `ctx->current_leader_bank` using [`fd_ext_bank_acquire`](../bank/fd_bank_abi.c.driver.md#fd_ext_bank_acquire) and assign it to `bank`.
    - Release the write lock using [`fd_ext_poh_write_unlock`](#fd_ext_poh_write_unlock).
    - Return the `bank` variable, which is either the current leader bank or `NULL`.
- **Output**: Returns a pointer to the current leader bank if it exists, otherwise returns `NULL`.
- **Functions called**:
    - [`fd_ext_bank_acquire`](../bank/fd_bank_abi.c.driver.md#fd_ext_bank_acquire)
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
    - Acquire a write lock on the PoH context using `fd_ext_poh_write_lock`.
    - Set the `max_active_descendant` field of the PoH context to the provided `max_active_descendant` value.
    - Release the write lock using [`fd_ext_poh_write_unlock`](#fd_ext_poh_write_unlock).
- **Output**: This function does not return any value; it updates the PoH context in place.
- **Functions called**:
    - [`fd_ext_poh_write_unlock`](#fd_ext_poh_write_unlock)


---
### fd\_ext\_poh\_reached\_leader\_slot<!-- {{#callable:fd_ext_poh_reached_leader_slot}} -->
The function `fd_ext_poh_reached_leader_slot` checks if the current slot has reached the designated leader slot and determines if the leader should start processing.
- **Inputs**:
    - `out_leader_slot`: A pointer to an unsigned long where the function will store the slot number of the next leader slot.
    - `out_reset_slot`: A pointer to an unsigned long where the function will store the slot number of the last good (unskipped) slot.
- **Control Flow**:
    - Acquire a write lock on the PoH context using `fd_ext_poh_write_lock`.
    - Set `out_leader_slot` to the next leader slot and `out_reset_slot` to the reset slot from the context.
    - Check if the next leader slot is `ULONG_MAX` or if the current slot is less than the next leader slot; if so, release the lock and return 0.
    - Check if the leader pipeline is halted due to identity key switching; if so, release the lock and return 0.
    - Check if the reset slot is equal to the next leader slot; if so, release the lock and return 1.
    - Calculate the expected start time for the next leader slot based on the reset slot start time and slot duration.
    - If the current time is less than the expected start time plus a grace period, check if a prior leader is still publishing; if so, release the lock and return 0.
    - Release the lock and return 1, indicating the leader slot has been reached and processing can start.
- **Output**: Returns 1 if the leader slot has been reached and processing can start, otherwise returns 0.
- **Functions called**:
    - [`fd_ext_poh_write_unlock`](#fd_ext_poh_write_unlock)


---
### publish\_plugin\_slot\_start<!-- {{#callable:publish_plugin_slot_start}} -->
The `publish_plugin_slot_start` function initializes and publishes a plugin message indicating the start of a slot in the Proof of History (PoH) context.
- **Inputs**:
    - `ctx`: A pointer to the `fd_poh_ctx_t` structure, which contains the context for the Proof of History (PoH) operations.
    - `slot`: An unsigned long integer representing the current slot number that is starting.
    - `parent_slot`: An unsigned long integer representing the parent slot number of the current slot.
- **Control Flow**:
    - Check if the `plugin_out->mem` in the context is not initialized; if not, return immediately.
    - Convert the current chunk in `plugin_out->mem` to a local address and cast it to a `fd_plugin_msg_slot_start_t` pointer.
    - Initialize the `slot_start` structure with the provided `slot` and `parent_slot` values.
    - Publish the `slot_start` message using `fd_stem_publish` with the appropriate parameters.
    - Update the `plugin_out->chunk` to the next compacted chunk using `fd_dcache_compact_next`.
- **Output**: The function does not return a value; it performs operations to publish a slot start message in the PoH context.


---
### publish\_plugin\_slot\_end<!-- {{#callable:publish_plugin_slot_end}} -->
The `publish_plugin_slot_end` function publishes a message indicating the end of a plugin slot with the specified slot number and consumed units.
- **Inputs**:
    - `ctx`: A pointer to an `fd_poh_ctx_t` structure, which contains context information for the Proof of History (PoH) process.
    - `slot`: An unsigned long integer representing the slot number that is ending.
    - `cus_used`: An unsigned long integer representing the number of consumed units used in the slot.
- **Control Flow**:
    - Check if the `plugin_out->mem` in the context is NULL; if so, return immediately without doing anything.
    - Convert the current chunk in `plugin_out->mem` to a local address and cast it to a `fd_plugin_msg_slot_end_t` pointer.
    - Assign the slot number and consumed units to the `fd_plugin_msg_slot_end_t` structure.
    - Publish the slot end message using `fd_stem_publish` with the appropriate parameters.
    - Update the `plugin_out->chunk` to the next compacted chunk using `fd_dcache_compact_next`.
- **Output**: The function does not return a value; it performs an action by publishing a message to indicate the end of a plugin slot.


---
### publish\_became\_leader<!-- {{#callable:publish_became_leader}} -->
The `publish_became_leader` function initializes and publishes the state of a node when it becomes the leader in a distributed system, handling timing, configuration, and account data retrieval.
- **Inputs**:
    - `ctx`: A pointer to the `fd_poh_ctx_t` structure, which contains the context and state information for the Proof of History (PoH) tile.
    - `slot`: An unsigned long integer representing the current slot number for which the node has become the leader.
    - `epoch`: An unsigned long integer representing the current epoch number.
- **Control Flow**:
    - Calculate the time delay since the last reset slot start and sample it into the `begin_leader_delay` histogram.
    - If the node is starting a consecutive leader slot, adjust the reset slot start time to exclude waiting time.
    - Initialize configuration and account address structures for bundle crank tip payment if the bundle is enabled.
    - Retrieve account data for tip payment configuration and tip receiver from the current leader bank, handling potential deadlock issues with Rust calls.
    - Calculate the start time for the current slot based on the reset slot start time and slot duration.
    - Prepare a `fd_became_leader_t` structure with the current slot's start and end times, bank information, microblock limits, and epoch data.
    - Copy the reset hash and tip receiver owner data into the leader structure.
    - Check if the total skipped ticks exceed the maximum allowed and log an error if so.
    - Generate a signature for the PoH packet and publish the leader information to the stem.
    - Update the chunk pointer for the next data publication.
- **Output**: The function does not return a value; it performs operations to publish the leader state and update the context.
- **Functions called**:
    - [`fd_ext_bank_load_account`](../bank/fd_bank_abi.c.driver.md#fd_ext_bank_load_account)


---
### fd\_ext\_poh\_begin\_leader<!-- {{#callable:fd_ext_poh_begin_leader}} -->
The `fd_ext_poh_begin_leader` function initializes the context for a new leader slot in a Proof of History (PoH) system, setting up various parameters and ensuring consistency with the current state.
- **Inputs**:
    - `bank`: A pointer to the bank object representing the current leader bank.
    - `slot`: The slot number for which the leader is beginning.
    - `epoch`: The epoch number associated with the slot.
    - `hashcnt_per_tick`: The number of hashes per tick for the current slot.
    - `cus_block_limit`: The maximum compute units allowed for the block.
    - `cus_vote_cost_limit`: The maximum compute units allowed for vote transactions.
    - `cus_account_cost_limit`: The maximum compute units allowed for account write transactions.
- **Control Flow**:
    - Acquire a write lock on the PoH context using `fd_ext_poh_write_lock`.
    - Check that there is no current leader bank set in the context.
    - Verify that the provided slot matches the current and next leader slot in the context, logging an error if not.
    - If `hashcnt_per_tick` has changed, log a warning and recompute clock-related parameters, resetting the slot and hash count if necessary.
    - Set the current leader bank and initialize microblock and compute unit usage counters.
    - Set the compute unit limits for the slot, clamping them to predefined upper bounds if necessary and logging warnings if limits are underutilized.
    - Update the highwater mark for the leader slot to prevent republishing in the same slot.
    - Call [`publish_became_leader`](#publish_became_leader) to notify the system of the new leader status.
    - Log the beginning of the leader slot with relevant slot and hash count information.
    - Release the write lock on the PoH context using [`fd_ext_poh_write_unlock`](#fd_ext_poh_write_unlock).
- **Output**: The function does not return a value; it modifies the PoH context to reflect the beginning of a new leader slot.
- **Functions called**:
    - [`publish_became_leader`](#publish_became_leader)
    - [`fd_ext_poh_write_unlock`](#fd_ext_poh_write_unlock)


---
### next\_leader\_slot<!-- {{#callable:next_leader_slot}} -->
The `next_leader_slot` function determines the next slot in which the current node is scheduled to be the leader, based on the current slot and the leader schedule.
- **Inputs**:
    - `ctx`: A pointer to an `fd_poh_ctx_t` structure, which contains the context for the Proof of History (PoH) process, including the current slot, highwater leader slot, and identity key.
- **Control Flow**:
    - Calculate `min_leader_slot` as the maximum of the current slot and the highwater leader slot, ensuring the node does not become leader for a slot it has already published.
    - Enter an infinite loop to find the next leader slot.
    - Retrieve the leader schedule for `min_leader_slot` using `fd_stake_ci_get_lsched_for_slot`.
    - If no leader schedule is found, break the loop and return `ULONG_MAX`.
    - Iterate over the slots in the leader schedule, checking if the current node's identity key matches the leader's key for each slot.
    - If a match is found, return the current `min_leader_slot` as the next leader slot.
    - If no match is found, increment `min_leader_slot` and continue the loop.
- **Output**: Returns the next slot number where the current node is scheduled to be the leader, or `ULONG_MAX` if no such slot is found in the current and next epoch.


---
### maybe\_change\_identity<!-- {{#callable:FD_FN_SENSITIVE::maybe_change_identity}} -->
The `maybe_change_identity` function attempts to change the identity of a node in a distributed system, ensuring it is not in the middle of a leader slot to prevent state corruption.
- **Inputs**:
    - `ctx`: A pointer to an `fd_poh_ctx_t` structure, which contains the context and state information for the Proof of History (PoH) tile.
    - `definitely_not_leader`: An integer flag indicating whether the current node is definitely not the leader (non-zero) or potentially the leader (zero).
- **Control Flow**:
    - Check if the node is in a halted switching state and if the keyswitch state is pending unhalt; if so, reset the halted state and update the keyswitch state to completed, returning 1.
    - Determine if the node is currently a leader by checking the `definitely_not_leader` flag and comparing the current slot with the next leader slot; if it is a leader, return 0.
    - Check if the keyswitch state is pending a switch; if so, attempt to set a new identity using [`fd_ext_admin_rpc_set_identity`](../bank/fd_bank_abi.c.driver.md#fd_ext_admin_rpc_set_identity).
    - If setting the new identity fails, update the keyswitch state to failed and return 0.
    - If successful, update the identity key in the context, reset the PoH state to the reset slot, and update the keyswitch state to completed.
- **Output**: Returns 1 if the identity change was initiated successfully, otherwise returns 0.
- **Functions called**:
    - [`fd_ext_admin_rpc_set_identity`](../bank/fd_bank_abi.c.driver.md#fd_ext_admin_rpc_set_identity)


---
### no\_longer\_leader<!-- {{#callable:no_longer_leader}} -->
The `no_longer_leader` function handles the transition of a node from a leader state to a non-leader state in a distributed system, updating relevant context and signaling changes.
- **Inputs**:
    - `ctx`: A pointer to an `fd_poh_ctx_t` structure, which holds the context and state information for the Proof of History (PoH) process.
- **Control Flow**:
    - Check if `ctx->current_leader_bank` is non-null; if so, release the current leader bank using [`fd_ext_bank_release`](../bank/fd_bank_abi.c.driver.md#fd_ext_bank_release).
    - Update `ctx->highwater_leader_slot` to ensure the node cannot become leader again in the current slot, using `fd_ulong_max` and `fd_ulong_if`.
    - Set `ctx->current_leader_bank` to NULL to indicate the node is no longer a leader.
    - Call [`maybe_change_identity`](#FD_FN_SENSITIVEmaybe_change_identity) with `definitely_not_leader` set to 1 to handle any potential identity changes.
    - Determine the next leader slot by calling [`next_leader_slot`](#next_leader_slot) and update `ctx->next_leader_slot`.
    - Log an informational message if the identity has changed, indicating the new [`next_leader_slot`](#next_leader_slot).
    - Use `FD_COMPILER_MFENCE` to ensure memory ordering before signaling a leader change.
    - Signal the leader change using [`fd_ext_poh_signal_leader_change`](../bank/fd_bank_abi.c.driver.md#fd_ext_poh_signal_leader_change).
    - Log an informational message indicating the transition out of the leader state and the next leader slot.
- **Output**: The function does not return a value; it performs state updates and side effects on the provided context.
- **Functions called**:
    - [`fd_ext_bank_release`](../bank/fd_bank_abi.c.driver.md#fd_ext_bank_release)
    - [`FD_FN_SENSITIVE::maybe_change_identity`](#FD_FN_SENSITIVEmaybe_change_identity)
    - [`next_leader_slot`](#next_leader_slot)
    - [`fd_ext_poh_signal_leader_change`](../bank/fd_bank_abi.c.driver.md#fd_ext_poh_signal_leader_change)


---
### fd\_ext\_poh\_reset<!-- {{#callable:fd_ext_poh_reset}} -->
The `fd_ext_poh_reset` function resets the Proof of History (PoH) context to a new slot after a block is successfully produced, updating various state parameters and handling leader transitions.
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
    - If the hash count per tick has changed, log a warning and update related timing parameters.
    - Set the microblocks lower bound to allow PoH to tick freely again.
    - If the context was in a leader slot before the reset, call [`no_longer_leader`](#no_longer_leader) to handle leader transition.
    - Determine the next leader slot and log the reset operation.
    - Handle cases where the context is reset onto the same or a different slot, publishing slot start or end as needed.
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
    - Check if the leader schedule is available; if so, retrieve the leader's public key for the target slot using `fd_epoch_leaders_get`.
    - If the leader's public key is found, copy it to `out_pubkey` and set `copied` to 1.
    - Release the write lock using [`fd_ext_poh_write_unlock`](#fd_ext_poh_write_unlock).
    - Return the value of `copied`, indicating whether the leader's public key was successfully retrieved and copied.
- **Output**: Returns an integer value, 1 if the leader's public key was successfully retrieved and copied to `out_pubkey`, otherwise 0.
- **Functions called**:
    - [`fd_ext_poh_write_unlock`](#fd_ext_poh_write_unlock)


---
### scratch\_align<!-- {{#callable:scratch_align}} -->
The `scratch_align` function returns a constant alignment value of 128 bytes.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended for use only within the file it is defined in and suggests the compiler to inline it for performance.
    - The function body contains a single return statement that returns the constant value 128UL.
- **Output**: The function outputs an unsigned long integer value of 128, representing the alignment size.


---
### scratch\_footprint<!-- {{#callable:scratch_footprint}} -->
The `scratch_footprint` function calculates the memory footprint required for a specific tile's context and related components in a layout.
- **Inputs**:
    - `tile`: A pointer to a `fd_topo_tile_t` structure, representing the tile for which the memory footprint is being calculated.
- **Control Flow**:
    - The function begins by initializing a layout with `FD_LAYOUT_INIT`.
    - It appends the size and alignment of `fd_poh_ctx_t` to the layout using `FD_LAYOUT_APPEND`.
    - It appends the size and alignment of `fd_stake_ci` using `fd_stake_ci_align()` and `fd_stake_ci_footprint()`.
    - It appends the size and alignment of SHA-256 using `FD_SHA256_ALIGN` and `FD_SHA256_FOOTPRINT`.
    - Finally, it finalizes the layout with `FD_LAYOUT_FINI` using the alignment from `scratch_align()`.
- **Output**: The function returns an `ulong` representing the total memory footprint required for the specified tile's context and related components.
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
    - Calculate `hashcnt` as the next tick boundary based on the last hash count and the hash count per tick.
    - Convert the chunk memory address to a local address for the destination buffer.
    - Check if the last slot is greater than or equal to the reset slot, ensuring valid state.
    - If `is_skipped` is true, set `reference_tick` and `block_complete` to zero in the metadata; otherwise, calculate them based on `hashcnt`.
    - Determine the current slot and calculate the `parent_offset` for the metadata.
    - Check if the `parent_block_id` is valid by comparing the current slot and parent slot, and copy the `parent_block_id` if valid.
    - Calculate the `hash_delta` as the difference between the current and last hash count.
    - Prepare the tick header with `hashcnt_delta`, copy the hash, and set `txn_cnt` to zero.
    - Publish the tick to the shred tile using `fd_stem_publish`, updating the sequence and chunk information.
    - Update the context's last slot and hash count based on whether the slot is complete.
- **Output**: The function does not return a value; it updates the PoH context and publishes a tick to the shred tile.


---
### publish\_features\_activation<!-- {{#callable:publish_features_activation}} -->
The `publish_features_activation` function publishes the features activation data to the shred tile for a given context and stem.
- **Inputs**:
    - `ctx`: A pointer to an `fd_poh_ctx_t` structure, which contains the context for the Proof of History (PoH) tile, including the features activation data to be published.
    - `stem`: A pointer to an `fd_stem_context_t` structure, which represents the stem context used for publishing data to the shred tile.
- **Control Flow**:
    - Convert the memory address of the shred output chunk to a local address using `fd_chunk_to_laddr` and store it in `dst`.
    - Cast `dst` to a pointer of type `fd_shred_features_activation_t` and store it in `act_data`.
    - Copy the features activation data from `ctx->features_activation` to `act_data` using `fd_memcpy`.
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
    - `opt_poll_in`: A pointer to an integer that indicates whether to poll for incoming microblocks.
    - `charge_busy`: A pointer to an integer that indicates whether the function has performed significant work, affecting the busy state.
- **Control Flow**:
    - Set the `stem` field of the `ctx` to the provided `stem` pointer.
    - Check if the `fd_poh_waiting_lock` is set, indicating a request for exclusive access, and handle the lock synchronization if needed.
    - If `features_activation_avail` is set, publish the features activation to the shred tile and reset the flag.
    - Determine if the current slot is a leader slot and if the leader bank is available; if not, return early.
    - If there are skipped ticks due to slot skipping, register and publish them one at a time, and set `opt_poll_in` to 0 and `charge_busy` to 1.
    - Calculate the maximum remaining microblocks and ticks, and determine the restricted hash count based on the current slot state.
    - Calculate the target hash count based on the current system clock and clamp it to the allowed range.
    - If the current hash count equals the target hash count, return early to avoid duplicate tick publishing.
    - Set `charge_busy` to 1 to indicate work has been done.
    - Increment the hash count by hashing until the target hash count is reached.
    - Handle slot and tick transitions, including saving hashes for skipped ticks and publishing ticks to the shred tile.
    - Manage leader transitions, including starting and ending leader slots, and updating the state machine.
- **Output**: The function does not return a value but modifies the state of the PoH context and potentially updates the `opt_poll_in` and `charge_busy` flags.
- **Functions called**:
    - [`publish_features_activation`](#publish_features_activation)
    - [`fd_ext_poh_register_tick`](../bank/fd_bank_abi.c.driver.md#fd_ext_poh_register_tick)
    - [`publish_tick`](#publish_tick)
    - [`publish_plugin_slot_start`](#publish_plugin_slot_start)
    - [`publish_plugin_slot_end`](#publish_plugin_slot_end)
    - [`no_longer_leader`](#no_longer_leader)
    - [`next_leader_slot`](#next_leader_slot)


---
### during\_housekeeping<!-- {{#callable:during_housekeeping}} -->
The `during_housekeeping` function checks if the identity of the node has changed and updates the next leader slot accordingly, signaling a leader change if necessary.
- **Inputs**:
    - `ctx`: A pointer to the `fd_poh_ctx_t` structure, which holds the context and state information for the Proof of History (PoH) process.
- **Control Flow**:
    - The function checks if the identity change is likely using `FD_UNLIKELY` and [`maybe_change_identity`](#FD_FN_SENSITIVEmaybe_change_identity) function.
    - If the identity has changed, it updates `ctx->next_leader_slot` with the result of `next_leader_slot(ctx)`.
    - Logs the identity change with the new leader slot using `FD_LOG_INFO`.
    - Performs a memory fence with `FD_COMPILER_MFENCE` to ensure memory operations are completed.
    - Signals a leader change using `fd_ext_poh_signal_leader_change(ctx->signal_leader_change)`.
- **Output**: This function does not return any value; it performs operations on the `ctx` structure and logs information.
- **Functions called**:
    - [`FD_FN_SENSITIVE::maybe_change_identity`](#FD_FN_SENSITIVEmaybe_change_identity)
    - [`next_leader_slot`](#next_leader_slot)
    - [`fd_ext_poh_signal_leader_change`](../bank/fd_bank_abi.c.driver.md#fd_ext_poh_signal_leader_change)


---
### metrics\_write<!-- {{#callable:metrics_write}} -->
The `metrics_write` function copies specific delay metrics from a context structure to a metrics histogram for tracking performance.
- **Inputs**:
    - `ctx`: A pointer to an `fd_poh_ctx_t` structure containing delay metrics to be copied.
- **Control Flow**:
    - The function uses the `FD_MHIST_COPY` macro to copy four specific delay metrics from the `ctx` structure to the corresponding metrics histograms.
    - Each call to `FD_MHIST_COPY` specifies a different delay metric to be copied, such as `BEGIN_LEADER_DELAY_SECONDS`, `FIRST_MICROBLOCK_DELAY_SECONDS`, `SLOT_DONE_DELAY_SECONDS`, and `BUNDLE_INITIALIZE_DELAY_SECONDS`.
- **Output**: The function does not return any value; it performs its operations directly on the provided context and metrics histograms.


---
### before\_frag<!-- {{#callable:before_frag}} -->
The `before_frag` function checks if a microblock fragment is in sequence for processing and updates the expected microblock index accordingly.
- **Inputs**:
    - `ctx`: A pointer to the `fd_poh_ctx_t` context structure, which holds the state and configuration for the Proof of History (PoH) process.
    - `in_idx`: An unsigned long integer representing the index of the input source in the context's input array.
    - `seq`: An unsigned long integer representing the sequence number of the fragment, which is not used in this function.
    - `sig`: An unsigned long integer representing the signature of the fragment, used to determine the microblock index.
- **Control Flow**:
    - The function first checks if the input kind at the given index is `IN_KIND_BANK` using `FD_LIKELY` for branch prediction optimization.
    - If the input kind is `IN_KIND_BANK`, it calculates the microblock index from the signature using `fd_disco_bank_sig_microblock_idx`.
    - It asserts that the calculated microblock index is greater than or equal to the expected microblock index using `FD_TEST`.
    - If the calculated microblock index is greater than the expected microblock index, it returns -1 to indicate the fragment is out of sequence.
    - If the fragment is in sequence, it increments the expected microblock index.
- **Output**: Returns 0 if the fragment is in sequence and -1 if it is not.


---
### during\_frag<!-- {{#callable:during_frag}} -->
The `during_frag` function processes incoming fragments based on their type and updates the context accordingly, handling errors and specific conditions for different fragment types.
- **Inputs**:
    - `ctx`: A pointer to the `fd_poh_ctx_t` context structure, which holds the state and configuration for the Proof of History (PoH) process.
    - `in_idx`: An unsigned long integer representing the index of the input source in the context's input array.
    - `seq`: An unsigned long integer representing the sequence number of the fragment, marked as unused with `FD_PARAM_UNUSED`.
    - `sig`: An unsigned long integer representing the signature of the fragment, used to determine packet type and slot.
    - `chunk`: An unsigned long integer representing the chunk identifier of the fragment, used to locate data in memory.
    - `sz`: An unsigned long integer representing the size of the fragment.
    - `ctl`: An unsigned long integer representing control information, marked as unused with `FD_PARAM_UNUSED`.
- **Control Flow**:
    - Initialize `ctx->skip_frag` to 0, indicating that the fragment should not be skipped by default.
    - Check if the input kind at `in_idx` is `IN_KIND_STAKE`; if so, verify the chunk range and initialize a stake message, then return.
    - Determine the packet type and slot based on the input kind and signature; log an error if the input kind is unexpected.
    - Check if the fragment is for a prior leader slot by comparing the slot with `ctx->highwater_leader_slot`.
    - If the input kind is `IN_KIND_PACK`, set `ctx->skip_frag` to 1 and handle `POH_PKT_TYPE_DONE_PACKING` by updating `ctx->microblocks_lower_bound` and logging information.
    - For other input kinds, verify the chunk range and size, copy transaction data and trailer to the context, and set `ctx->skip_frag` based on whether the fragment is for a prior leader slot.
- **Output**: The function does not return a value; it modifies the context `ctx` based on the fragment's type and content.


---
### publish\_microblock<!-- {{#callable:publish_microblock}} -->
The `publish_microblock` function prepares and publishes a microblock containing transaction data to the shred tile in a Solana-like blockchain system.
- **Inputs**:
    - `ctx`: A pointer to the `fd_poh_ctx_t` structure, which holds the context for the Proof of History (PoH) tile, including state and configuration data.
    - `stem`: A pointer to the `fd_stem_context_t` structure, which is used for publishing data to the shred tile.
    - `slot`: An unsigned long integer representing the current slot number for which the microblock is being published.
    - `hashcnt_delta`: An unsigned long integer representing the change in hash count since the last published microblock or tick.
    - `txn_cnt`: An unsigned long integer representing the number of transactions included in the microblock.
- **Control Flow**:
    - Convert the memory chunk to a local address using `fd_chunk_to_laddr` to get the destination pointer `dst` for writing the microblock data.
    - Verify that the current slot is greater than or equal to the reset slot in the context.
    - Initialize the `fd_entry_batch_meta_t` structure at `dst` with metadata about the microblock, including parent offset, reference tick, and block completion status.
    - Check if the parent block ID is valid by comparing the parent slot with the calculated parent offset, and copy the parent block ID if valid.
    - Advance the `dst` pointer past the metadata structure and initialize the `fd_entry_batch_header_t` structure with the hash count delta and current hash.
    - Iterate over the transactions, copying successful transaction payloads to `dst`, updating the payload size and transaction count.
    - Calculate the total size of the microblock, including metadata, header, and payload, and publish it using `fd_stem_publish`.
    - Update the shred sequence and advance the chunk pointer for the next publication.
- **Output**: The function does not return a value; it publishes a microblock to the shred tile and updates the context state.


---
### after\_frag<!-- {{#callable:after_frag}} -->
The `after_frag` function processes a fragment after it has been received, updating the leader state and handling microblock transactions.
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
    - The function begins by checking if the fragment should be skipped using `ctx->skip_frag`; if true, it returns immediately.
    - If the fragment is of type `IN_KIND_STAKE`, it finalizes the stake message and updates the leader schedule, potentially transitioning the leader state.
    - If the fragment is not a stake message, it checks if the microblocks lower bound is zero and records the delay for the first microblock if necessary.
    - It calculates the target slot from the signature and verifies that it matches the current and next leader slots, logging an error if not.
    - The function processes transactions within the fragment, counting executed transactions and accumulating consumed compute units (CUs).
    - If no transactions were executed, it returns without publishing.
    - Otherwise, it updates the hash with the microblock trailer hash, increments the hash count, and checks for tick boundaries.
    - If a tick boundary is crossed, it registers the tick with the leader bank and checks for leader transitions, publishing slot start or end messages as needed.
    - Finally, it publishes the microblock using the [`publish_microblock`](#publish_microblock) function.
- **Output**: The function does not return a value; it updates the PoH context state and publishes microblocks or transitions the leader state as necessary.
- **Functions called**:
    - [`next_leader_slot`](#next_leader_slot)
    - [`publish_plugin_slot_start`](#publish_plugin_slot_start)
    - [`fd_ext_poh_register_tick`](../bank/fd_bank_abi.c.driver.md#fd_ext_poh_register_tick)
    - [`publish_plugin_slot_end`](#publish_plugin_slot_end)
    - [`no_longer_leader`](#no_longer_leader)
    - [`publish_microblock`](#publish_microblock)


---
### privileged\_init<!-- {{#callable:privileged_init}} -->
The `privileged_init` function initializes a Proof of History (PoH) context by setting up memory allocations and loading identity and vote account keys from specified paths.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology configuration.
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing the tile configuration, including paths for identity and vote account keys.
- **Control Flow**:
    - Allocate memory for the PoH context using `FD_SCRATCH_ALLOC_INIT` and `FD_SCRATCH_ALLOC_APPEND`.
    - Check if the `identity_key_path` is set; if not, log an error and exit.
    - Load the identity key from the specified path using `fd_keyload_load` and copy it into the PoH context.
    - Check if the `vote_account_path` is set; if not, disable the bundle feature.
    - If the bundle feature is enabled, attempt to decode the vote account path using `fd_base58_decode_32`; if decoding fails, load the vote key from the path and copy it into the PoH context.
- **Output**: The function does not return a value; it initializes the PoH context with identity and vote account keys.


---
### fd\_ext\_shred\_set\_shred\_version<!-- {{#callable:fd_ext_shred_set_shred_version}} -->
The function `fd_ext_shred_set_shred_version` sets the shred version in a shared memory location once it becomes available.
- **Inputs**:
    - `shred_version`: An unsigned long integer representing the shred version to be set.
- **Control Flow**:
    - The function enters a loop that continues as long as `fd_shred_version` is not available (i.e., it is NULL).
    - Within the loop, it calls `FD_SPIN_PAUSE()` to yield the processor, allowing other threads to run while waiting for `fd_shred_version` to become available.
    - Once `fd_shred_version` is available, it exits the loop and sets the value of `fd_shred_version` to the provided `shred_version`.
- **Output**: This function does not return any value; it performs an action by setting a shared memory variable.


---
### fd\_ext\_poh\_publish\_gossip\_vote<!-- {{#callable:fd_ext_poh_publish_gossip_vote}} -->
The function `fd_ext_poh_publish_gossip_vote` publishes a gossip vote using the [`poh_link_publish`](#poh_link_publish) function with the `gossip_dedup` link.
- **Inputs**:
    - `data`: A pointer to the data to be published as a gossip vote.
    - `data_len`: The length of the data to be published.
- **Control Flow**:
    - The function calls [`poh_link_publish`](#poh_link_publish) with the `gossip_dedup` link, a signature value of `1UL`, the provided `data`, and `data_len`.
- **Output**: The function does not return any value; it performs an action by publishing the data.
- **Functions called**:
    - [`poh_link_publish`](#poh_link_publish)


---
### fd\_ext\_poh\_publish\_leader\_schedule<!-- {{#callable:fd_ext_poh_publish_leader_schedule}} -->
The `fd_ext_poh_publish_leader_schedule` function publishes the leader schedule data to the `stake_out` link using the [`poh_link_publish`](#poh_link_publish) function.
- **Inputs**:
    - `data`: A pointer to the data buffer containing the leader schedule information to be published.
    - `data_len`: The length of the data buffer in bytes.
- **Control Flow**:
    - The function calls [`poh_link_publish`](#poh_link_publish) with the `stake_out` link, a signature value of `2UL`, and the provided `data` and `data_len` arguments.
    - The [`poh_link_publish`](#poh_link_publish) function handles the actual publishing of the data to the specified link.
- **Output**: This function does not return any value; it performs an action by publishing data.
- **Functions called**:
    - [`poh_link_publish`](#poh_link_publish)


---
### fd\_ext\_poh\_publish\_cluster\_info<!-- {{#callable:fd_ext_poh_publish_cluster_info}} -->
The `fd_ext_poh_publish_cluster_info` function publishes cluster information data to the CRDS shred link using the [`poh_link_publish`](#poh_link_publish) function.
- **Inputs**:
    - `data`: A pointer to the data buffer containing the cluster information to be published.
    - `data_len`: The length of the data buffer in bytes.
- **Control Flow**:
    - The function calls [`poh_link_publish`](#poh_link_publish) with the `crds_shred` link, a signature value of `2UL`, and the provided `data` and `data_len` arguments.
    - The [`poh_link_publish`](#poh_link_publish) function handles the actual publishing of the data to the specified link.
- **Output**: The function does not return any value; it performs an action by publishing data.
- **Functions called**:
    - [`poh_link_publish`](#poh_link_publish)


---
### fd\_ext\_plugin\_publish\_replay\_stage<!-- {{#callable:fd_ext_plugin_publish_replay_stage}} -->
The `fd_ext_plugin_publish_replay_stage` function publishes data to the replay plugin using a specified signature and data buffer.
- **Inputs**:
    - `sig`: An unsigned long integer representing the signature associated with the data to be published.
    - `data`: A pointer to an unsigned char array containing the data to be published.
    - `data_len`: An unsigned long integer representing the length of the data to be published.
- **Control Flow**:
    - The function calls [`poh_link_publish`](#poh_link_publish) with the `replay_plugin`, `sig`, `data`, and `data_len` as arguments.
    - The [`poh_link_publish`](#poh_link_publish) function handles the actual publishing of the data to the specified plugin.
- **Output**: This function does not return any value; it performs an action by publishing data to a plugin.
- **Functions called**:
    - [`poh_link_publish`](#poh_link_publish)


---
### fd\_ext\_plugin\_publish\_genesis\_hash<!-- {{#callable:fd_ext_plugin_publish_genesis_hash}} -->
The `fd_ext_plugin_publish_genesis_hash` function publishes a genesis hash to the replay plugin using the [`poh_link_publish`](#poh_link_publish) function.
- **Inputs**:
    - `sig`: An unsigned long integer representing the signature or identifier for the data being published.
    - `data`: A pointer to an unsigned char array containing the data to be published.
    - `data_len`: An unsigned long integer representing the length of the data to be published.
- **Control Flow**:
    - The function calls [`poh_link_publish`](#poh_link_publish) with the `replay_plugin` link, passing the `sig`, `data`, and `data_len` as arguments.
    - The [`poh_link_publish`](#poh_link_publish) function handles the actual publishing of the data to the specified link.
- **Output**: The function does not return any value; it performs an action by publishing data to a plugin.
- **Functions called**:
    - [`poh_link_publish`](#poh_link_publish)


---
### fd\_ext\_plugin\_publish\_start\_progress<!-- {{#callable:fd_ext_plugin_publish_start_progress}} -->
The `fd_ext_plugin_publish_start_progress` function publishes data to the `start_progress_plugin` link using a given signature, data, and data length.
- **Inputs**:
    - `sig`: An unsigned long integer representing the signature for the data to be published.
    - `data`: A pointer to an unsigned char array containing the data to be published.
    - `data_len`: An unsigned long integer representing the length of the data to be published.
- **Control Flow**:
    - The function calls [`poh_link_publish`](#poh_link_publish) with the `start_progress_plugin` link, the provided signature, data, and data length.
    - The [`poh_link_publish`](#poh_link_publish) function handles the actual publishing process, including waiting for credit, copying data to the destination, and updating metadata.
- **Output**: This function does not return any value; it performs an action by publishing data to a specified link.
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
    - The [`poh_link_publish`](#poh_link_publish) function handles the actual publishing of the data to the specified link.
- **Output**: The function does not return any value; it performs its operation by side effect, publishing the data to the specified link.
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
    - The [`poh_link_publish`](#poh_link_publish) function handles the actual publishing of the data to the gossip plugin.
- **Output**: The function does not return any value; it performs an action by publishing data to the gossip plugin.
- **Functions called**:
    - [`poh_link_publish`](#poh_link_publish)


---
### fd\_ext\_resolv\_publish\_root\_bank<!-- {{#callable:fd_ext_resolv_publish_root_bank}} -->
The `fd_ext_resolv_publish_root_bank` function publishes data related to the root bank to the `replay_resolv` link using the [`poh_link_publish`](#poh_link_publish) function.
- **Inputs**:
    - `data`: A pointer to the data buffer containing the information to be published.
    - `data_len`: The length of the data buffer in bytes.
- **Control Flow**:
    - The function calls [`poh_link_publish`](#poh_link_publish) with the `replay_resolv` link, a signature of `0UL`, the provided data, and the data length.
    - The [`poh_link_publish`](#poh_link_publish) function handles the actual publishing of the data to the specified link.
- **Output**: The function does not return any value; it performs an action by publishing data.
- **Functions called**:
    - [`poh_link_publish`](#poh_link_publish)


---
### fd\_ext\_resolv\_publish\_completed\_blockhash<!-- {{#callable:fd_ext_resolv_publish_completed_blockhash}} -->
The function `fd_ext_resolv_publish_completed_blockhash` publishes a completed blockhash to the replay resolution link.
- **Inputs**:
    - `data`: A pointer to the data (blockhash) to be published.
    - `data_len`: The length of the data to be published.
- **Control Flow**:
    - The function calls [`poh_link_publish`](#poh_link_publish) with the `replay_resolv` link, a signature of `1UL`, the provided `data`, and `data_len`.
- **Output**: The function does not return any value.
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
    - For each link, retrieve the link from `topo->links` using the index from `tile->out_link_id`.
    - Compare the link's name with the provided `name` using `strcmp`.
    - If a match is found and `idx` is not `ULONG_MAX`, log an error indicating multiple links with the same name.
    - If a match is found and `idx` is `ULONG_MAX`, set `idx` to the current index.
    - After the loop, if `idx` is still `ULONG_MAX`, log an error indicating no link was found with the specified name.
    - Retrieve the memory workspace, chunk0, and watermark for the link at the found index.
    - Return a `fd_poh_out_ctx_t` structure initialized with the retrieved values.
- **Output**: A `fd_poh_out_ctx_t` structure containing the index, memory workspace, chunk0, watermark, and initial chunk for the specified output link.


---
### unprivileged\_init<!-- {{#callable:unprivileged_init}} -->
The `unprivileged_init` function initializes various components and configurations for a Proof of History (PoH) tile in a distributed system, setting up memory allocations, context structures, and communication links.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology of the system, which includes properties and links between different components.
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing a specific tile in the topology, which includes configuration details and identifiers for various objects.
- **Control Flow**:
    - Allocate scratch memory for the PoH context and other components using `FD_SCRATCH_ALLOC_INIT` and `FD_SCRATCH_ALLOC_APPEND`.
    - Initialize the `fd_poh_ctx_t` context structure, setting default values for various fields such as `slot`, `hashcnt`, and `highwater_leader_slot`.
    - Join the stake and SHA256 components to the context using `fd_stake_ci_join` and `fd_sha256_join`, ensuring they are not NULL.
    - Check if the bundle feature is enabled and initialize the bundle crank generator if so.
    - Query the topology properties for the `poh_shred` object ID and join the shred version using `fd_fseq_join`.
    - Initialize communication links for various plugins if they are enabled, or mark them as available if not.
    - Log a message indicating the PoH is waiting for initialization by the Agave client and set up a synchronization mechanism using volatile locks.
    - Initialize histograms for various delays using `fd_histf_join`.
    - Set up input links by iterating over the tile's input links and configuring the context's input structures based on the link names.
    - Configure output links for `shred_out`, `pack_out`, and optionally `plugin_out` based on the tile's configuration.
    - Finalize the scratch memory allocation and check for overflow, logging an error if it occurs.
- **Output**: The function does not return a value; it initializes the PoH context and related components in place.
- **Functions called**:
    - [`poh_link_init`](#poh_link_init)
    - [`out1`](#out1)
    - [`scratch_footprint`](#scratch_footprint)


# Function Declarations (Public API)

---
### fd\_ext\_bank\_acquire<!-- {{#callable_declaration:fd_ext_bank_acquire}} -->
Logs an error message indicating the function is not implemented.
- **Description**: This function is a placeholder and does not perform any operations other than logging an error message. It is intended to be called when acquiring a bank resource, but currently, it only logs an error indicating that the functionality is not implemented. This function should not be used in production as it does not fulfill its intended purpose.
- **Inputs**:
    - `bank`: A pointer to a bank resource. This parameter is currently unused and can be null or any value, as the function does not perform any operations with it.
- **Output**: None
- **See also**: [`fd_ext_bank_acquire`](../bank/fd_bank_abi.c.driver.md#fd_ext_bank_acquire)  (Implementation)


---
### fd\_ext\_bank\_release<!-- {{#callable_declaration:fd_ext_bank_release}} -->
Logs an error message indicating the function is not implemented.
- **Description**: This function is a placeholder that logs an error message indicating that the functionality to release a bank is not implemented. It is intended to be called when there is an attempt to release a bank resource, but currently, it does not perform any operation other than logging an error. This function should be used with the understanding that it does not actually release any resources and will always result in an error log.
- **Inputs**:
    - `bank`: A pointer to a bank resource that is intended to be released. The parameter is marked as unused, indicating that it is not utilized within the function. The caller retains ownership, and the function does not perform any operations on this parameter.
- **Output**: None
- **See also**: [`fd_ext_bank_release`](../bank/fd_bank_abi.c.driver.md#fd_ext_bank_release)  (Implementation)


---
### fd\_ext\_poh\_signal\_leader\_change<!-- {{#callable_declaration:fd_ext_poh_signal_leader_change}} -->
Signals a leader change event.
- **Description**: This function is used to notify the system of a change in the leader, which is a critical event in distributed systems like Solana. It should be called whenever a leader change is detected to ensure that all components are aware of the new leader. This function does not perform any operations other than logging an error, indicating that it is not yet implemented or should not be used in its current form.
- **Inputs**:
    - `sender`: An opaque pointer to the sender object, which is not used in the current implementation. The caller retains ownership and it can be null or any value since it is marked as unused.
- **Output**: None
- **See also**: [`fd_ext_poh_signal_leader_change`](../bank/fd_bank_abi.c.driver.md#fd_ext_poh_signal_leader_change)  (Implementation)


---
### fd\_ext\_poh\_register\_tick<!-- {{#callable_declaration:fd_ext_poh_register_tick}} -->
Logs an error message indicating an unsupported operation.
- **Description**: This function is intended to register a tick in the Proof of History (PoH) system, but it currently only logs an error message indicating that the operation is not supported. It is a placeholder function and does not perform any meaningful action. This function should not be used in production as it does not fulfill its intended purpose.
- **Inputs**:
    - `bank`: A pointer to a constant void type, which is currently unused. The parameter is expected to represent a bank context but is not utilized in the function.
    - `hash`: A pointer to a constant unsigned char type, which is currently unused. The parameter is expected to represent a hash value but is not utilized in the function.
- **Output**: None
- **See also**: [`fd_ext_poh_register_tick`](../bank/fd_bank_abi.c.driver.md#fd_ext_poh_register_tick)  (Implementation)


---
### fd\_ext\_bank\_load\_account<!-- {{#callable_declaration:fd_ext_bank_load_account}} -->
Loads account information from a bank.
- **Description**: This function is used to load account information from a specified bank using the provided address. It is typically called when account details such as the owner and data need to be retrieved. The function requires valid pointers for the address, owner, data, and data size parameters. It is important to ensure that these pointers are not null before calling the function to avoid undefined behavior.
- **Inputs**:
    - `bank`: A pointer to the bank from which the account information is to be loaded. The caller retains ownership and it must not be null.
    - `fixed_root`: An integer parameter that is currently unused. It can be any integer value.
    - `addr`: A pointer to a constant unsigned character array representing the address of the account. It must not be null.
    - `owner`: A pointer to an unsigned character array where the account owner information will be stored. It must not be null.
    - `data`: A pointer to an unsigned character array where the account data will be stored. It must not be null.
    - `data_sz`: A pointer to an unsigned long where the size of the account data will be stored. It must not be null.
- **Output**: Returns an integer status code. The function always returns 0 in its current implementation.
- **See also**: [`fd_ext_bank_load_account`](../bank/fd_bank_abi.c.driver.md#fd_ext_bank_load_account)  (Implementation)


---
### fd\_ext\_admin\_rpc\_set\_identity<!-- {{#callable_declaration:fd_ext_admin_rpc_set_identity}} -->
Sets the identity keypair for the admin RPC.
- **Description**: This function is used to set the identity keypair for the admin RPC interface. It is typically called when there is a need to update or initialize the identity keypair used for administrative operations. The function does not perform any operations if the parameters are marked as unused, and it logs an error message before returning. This function should be used with caution, as improper use may lead to unexpected behavior or security issues.
- **Inputs**:
    - `identity_keypair`: A pointer to an unsigned char array representing the identity keypair. The parameter is marked as unused, indicating it is not utilized in the function's current implementation.
    - `require_tower`: An integer indicating whether a tower is required. The parameter is marked as unused, indicating it is not utilized in the function's current implementation.
- **Output**: Returns an integer value of 0, indicating the function's completion without performing any operations.
- **See also**: [`fd_ext_admin_rpc_set_identity`](../bank/fd_bank_abi.c.driver.md#fd_ext_admin_rpc_set_identity)  (Implementation)


