# Purpose
This C source code file is designed to facilitate the playback and verification of data stored in a RocksDB database, specifically in the context of a distributed system or blockchain environment. The code is structured around a context (`ctx_t`) that manages the state and operations necessary for interacting with RocksDB, including iterating over stored data (shreds) and verifying their integrity against expected values. The file includes functions for initializing the context, retrieving data from RocksDB, and notifying other components of the system about the progress and results of the playback process. The code is part of a larger system, as indicated by the inclusion of multiple headers from different directories, suggesting a modular architecture.

The primary functionality of this file revolves around the [`rocksdb_get_shred`](#rocksdb_get_shred) function, which retrieves data from RocksDB, and the [`notify_one_slot`](#notify_one_slot) function, which processes and verifies this data. The code also includes initialization routines ([`unprivileged_init`](#unprivileged_init)) to set up the necessary resources and state for playback, and callback functions ([`after_credit`](#after_credit), [`during_frag`](#during_frag), [`after_frag`](#after_frag)) that handle different stages of the data processing lifecycle. The file defines a `fd_topo_run_tile_t` structure, `fd_tile_backtest`, which encapsulates the functionality provided by this code, indicating that it is intended to be used as a tile or component within a larger system, likely for testing or backtesting purposes. The code is tightly integrated with the system's architecture, as evidenced by its reliance on specific data structures and functions from the included headers.
# Imports and Dependencies

---
- `../../disco/tiles.h`
- `../../disco/fd_disco.h`
- `../../disco/stem/fd_stem.h`
- `../../util/pod/fd_pod_format.h`
- `../../flamenco/runtime/fd_rocksdb.h`
- `../../discof/replay/fd_replay_notif.h`
- `../../disco/stem/fd_stem.c`


# Global Variables

---
### fd\_tile\_backtest
- **Type**: `fd_topo_run_tile_t`
- **Description**: The `fd_tile_backtest` is a global variable of type `fd_topo_run_tile_t`, which is a structure used to define a tile in the system's topology. It is initialized with specific function pointers and a name, indicating its role in the system.
- **Use**: This variable is used to configure and run a specific tile in the system's topology, particularly for backtesting purposes.


# Data Structures

---
### ctx\_t
- **Type**: `struct`
- **Members**:
    - `use_rocksdb`: Indicates whether RocksDB is used (non-zero) or not (zero).
    - `rocksdb`: Holds the RocksDB database instance.
    - `rocksdb_iter`: Pointer to a RocksDB iterator for traversing database entries.
    - `rocksdb_root_iter`: Iterator for traversing the root entries in RocksDB.
    - `rocksdb_slot_meta`: Metadata for the current slot in RocksDB.
    - `rocksdb_curr_idx`: Current index within the RocksDB slot.
    - `rocksdb_end_idx`: End index for the current RocksDB slot.
    - `rocksdb_end_slot`: The last slot available in RocksDB.
    - `rocksdb_bank_hash`: Pointer to the bank hash data in RocksDB.
    - `replay_end_slot`: Slot at which replay should end.
    - `blockstore_wksp`: Pointer to the workspace for blockstore operations.
    - `blockstore_ljoin`: Local join structure for blockstore operations.
    - `blockstore`: Pointer to the blockstore instance.
    - `replay_in_mem`: Pointer to the memory workspace for replay operations.
    - `replay_in_chunk0`: Initial chunk index for replay input.
    - `replay_in_wmark`: Watermark for replay input.
    - `replay_notification`: Notification message structure for replay events.
    - `playback_started`: Indicates if playback has started (non-zero) or not (zero).
    - `end_slot`: The slot at which operations should end.
    - `start_slot`: The slot at which operations should start.
    - `published_wmark`: Pointer to the published watermark, shared with the replay tile.
    - `alloc`: Pointer to the memory allocator instance.
    - `valloc`: Virtual allocator for memory management.
- **Description**: The `ctx_t` structure is a complex data structure designed to manage and coordinate operations involving RocksDB and blockstore in a distributed system. It contains various fields to handle database instances, iterators, metadata, and memory management, facilitating efficient data retrieval and processing. The structure supports replay and notification mechanisms, ensuring that data operations are synchronized and managed correctly across different components of the system.


# Functions

---
### loose\_footprint<!-- {{#callable:loose_footprint}} -->
The `loose_footprint` function calculates and returns the memory footprint for a tile in terms of gigantic page size.
- **Inputs**:
    - `tile`: A pointer to a `fd_topo_tile_t` structure, which is not used in the function.
- **Control Flow**:
    - The function takes a single argument, `tile`, which is marked as unused with `FD_PARAM_UNUSED`.
    - It returns a constant value calculated as `2UL * FD_SHMEM_GIGANTIC_PAGE_SZ`.
- **Output**: The function returns an `ulong` representing twice the size of a gigantic shared memory page.


---
### rocksdb\_get\_shred<!-- {{#callable:rocksdb_get_shred}} -->
The `rocksdb_get_shred` function retrieves a shred from a RocksDB database, ensuring the correct slot and index, and returns the parsed shred data.
- **Inputs**:
    - `ctx`: A pointer to a `ctx_t` structure containing the context for RocksDB operations, including iterators and metadata.
    - `out_sz`: A pointer to an `ulong` where the size of the retrieved shred data will be stored.
- **Control Flow**:
    - Check if the current index has reached the end index; if so, advance the root iterator and update metadata.
    - Construct a key using the current slot and index, and seek the RocksDB iterator to this key.
    - Check if the iterator is valid and if the key matches the expected slot and index; log errors if not.
    - Retrieve the shred data from the iterator and parse it into a `fd_shred_t` structure.
    - Increment the current index and store the size of the data in `out_sz`.
- **Output**: Returns a pointer to a `fd_shred_t` structure containing the parsed shred data, or `NULL` if an error occurs.


---
### notify\_one\_slot<!-- {{#callable:notify_one_slot}} -->
The `notify_one_slot` function processes shreds from a RocksDB database, inserts them into a blockstore, and notifies a replay tile when a complete slot is detected.
- **Inputs**:
    - `ctx`: A pointer to a `ctx_t` structure containing context information, including RocksDB and blockstore details.
    - `stem`: A pointer to a `fd_stem_context_t` structure used for publishing notifications.
- **Control Flow**:
    - Initialize `entry_batch_start_idx` to 0 and `slot_complete` to 0.
    - Enter a loop that continues until `slot_complete` is set to a non-zero value.
    - Within the loop, call [`rocksdb_get_shred`](#rocksdb_get_shred) to retrieve the next shred from the RocksDB database.
    - If the shred is `NULL`, break out of the loop.
    - Insert the retrieved shred into the blockstore using `fd_blockstore_shred_insert`.
    - Check if the shred's data flags indicate that the data is complete.
    - If the data is complete, check if the slot is complete and update `slot_complete` accordingly.
    - Log a debug message indicating the notification of the replay tile.
    - Calculate the count of shreds processed since the last notification and update `entry_batch_start_idx`.
    - Generate a signature using `fd_disco_repair_replay_sig` and publish it using `fd_stem_publish`.
- **Output**: The function does not return a value; it performs operations on the provided context and stem structures.
- **Functions called**:
    - [`rocksdb_get_shred`](#rocksdb_get_shred)


---
### unprivileged\_init<!-- {{#callable:unprivileged_init}} -->
The `unprivileged_init` function initializes the context and resources required for a tile to interact with RocksDB and other components in a distributed system.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology of the system.
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing the specific tile to be initialized.
- **Control Flow**:
    - Allocate scratch memory and initialize a context (`ctx_t`) structure.
    - Allocate shared memory for the allocator and initialize it using `fd_alloc_join`.
    - Initialize RocksDB-related structures and set up the RocksDB instance using `fd_rocksdb_init`.
    - Allocate memory for the RocksDB bank hash using `fd_valloc_malloc`.
    - Set up replay input memory and watermark using `fd_dcache_compact_chunk0` and `fd_dcache_compact_wmark`.
    - Check if the `end_slot` is valid and log an error if it is not set.
    - Retrieve the last slot from RocksDB and verify it against the `end_slot`, logging an error if it is insufficient.
    - Set up the blockstore workspace and join it using `fd_blockstore_join`.
    - Reset the shred pool in the blockstore and verify its magic number.
    - Set up the watermark sequence shared with the replay tile using `fd_fseq_join`.
    - Log a warning indicating the completion of the RocksDB tile initialization.
- **Output**: The function does not return a value; it initializes the context and resources for the tile.


---
### after\_credit<!-- {{#callable:after_credit}} -->
The `after_credit` function initializes playback from a RocksDB database if it hasn't started yet, by setting up iterators and notifying the system of the current slot.
- **Inputs**:
    - `ctx`: A pointer to a `ctx_t` structure containing context information for the playback process, including RocksDB iterators and metadata.
    - `stem`: A pointer to a `fd_stem_context_t` structure used for publishing notifications.
    - `opt_poll_in`: An unused integer pointer parameter, marked with `FD_PARAM_UNUSED`.
    - `charge_busy`: An unused integer pointer parameter, marked with `FD_PARAM_UNUSED`.
- **Control Flow**:
    - Check if playback has not started by evaluating `ctx->playback_started`.
    - Query the watermark using `fd_fseq_query` and store it in `wmark`.
    - If `wmark` is `ULONG_MAX`, return immediately.
    - If `ctx->start_slot` is `ULONG_MAX`, set it to `wmark`.
    - Check if `wmark` matches `ctx->replay_notification.slot_exec.slot`; if not, return.
    - Set `ctx->playback_started` to 1 to indicate playback has started.
    - Initialize a new RocksDB root iterator using `fd_rocksdb_root_iter_new`.
    - Seek the RocksDB root iterator to the watermark position using `fd_rocksdb_root_iter_seek`; log an error if it fails.
    - Create a new RocksDB iterator for the data shred column family using `rocksdb_create_iterator_cf`.
    - Call [`notify_one_slot`](#notify_one_slot) to notify the system of the current slot.
- **Output**: The function does not return a value; it modifies the state of the `ctx` structure and may log errors or notify the system of the current slot.
- **Functions called**:
    - [`notify_one_slot`](#notify_one_slot)


---
### during\_frag<!-- {{#callable:during_frag}} -->
The `during_frag` function copies a replay notification message from a specified memory chunk into a context structure, ensuring certain conditions are met.
- **Inputs**:
    - `ctx`: A pointer to a `ctx_t` structure that holds various context information, including where the replay notification will be stored.
    - `in_idx`: An unsigned long integer representing the input index, which is expected to be 0.
    - `seq`: An unsigned long integer representing the sequence number, which is unused in this function.
    - `sig`: An unsigned long integer representing the signal, which is unused in this function.
    - `chunk`: An unsigned long integer representing the memory chunk from which the replay notification message will be copied.
    - `sz`: An unsigned long integer representing the size of the data to be copied, expected to be the size of `fd_replay_notif_msg_t`.
    - `ctl`: An unsigned long integer representing control information, which is unused in this function.
- **Control Flow**:
    - Check that `in_idx` is equal to 0 using `FD_TEST` macro.
    - Check that `sz` is equal to the size of `fd_replay_notif_msg_t` using `FD_TEST` macro.
    - Copy the replay notification message from the memory location calculated by `fd_chunk_to_laddr` using `fd_memcpy` into `ctx->replay_notification`.
- **Output**: The function does not return any value; it modifies the `ctx` structure by updating its `replay_notification` field.


---
### after\_frag<!-- {{#callable:after_frag}} -->
The `after_frag` function processes a replay notification by verifying a bank hash against a stored value in RocksDB and notifies the system if the hash matches or mismatches.
- **Inputs**:
    - `ctx`: A pointer to a `ctx_t` structure containing context information for the operation, including RocksDB and replay notification details.
    - `in_idx`: An unused parameter of type `ulong`.
    - `seq`: An unused parameter of type `ulong`.
    - `sig`: An unused parameter of type `ulong`.
    - `sz`: An unused parameter of type `ulong`.
    - `tsorig`: An unused parameter of type `ulong`.
    - `tspub`: An unused parameter of type `ulong`.
    - `stem`: A pointer to a `fd_stem_context_t` structure used for publishing notifications.
- **Control Flow**:
    - Check if the replay notification type is `FD_REPLAY_SLOT_TYPE` using `FD_LIKELY` macro.
    - Retrieve the slot and bank hash from the replay notification.
    - Convert the slot to big-endian format and attempt to retrieve the corresponding bank hash from RocksDB using `rocksdb_get_cf`.
    - If an error occurs or no value is found, log an error and exit.
    - Decode the retrieved bank hash using `fd_frozen_hash_versioned_decode_footprint` and `fd_frozen_hash_versioned_decode`.
    - Check for decoding errors or mismatches in the discriminant and log an error if any issues are found.
    - If the slot is not the start slot and the start slot is not `ULONG_MAX`, compare the bank hash with the decoded hash.
    - Log a warning if the hashes match, otherwise log an error for a mismatch.
    - Call [`notify_one_slot`](#notify_one_slot) to notify the system of the slot processing.
    - If the slot is greater than or equal to the end slot, log an error indicating that RocksDB playback is done.
- **Output**: The function does not return a value; it performs operations based on the replay notification and logs errors or warnings as necessary.
- **Functions called**:
    - [`notify_one_slot`](#notify_one_slot)


