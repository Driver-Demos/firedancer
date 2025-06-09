# Purpose
The provided C header file, `fd_gui.h`, is part of a larger software system and serves as a comprehensive interface for managing and monitoring a graphical user interface (GUI) component within a distributed system. This file defines a variety of data structures, constants, and function prototypes that facilitate the tracking and visualization of transaction processing, network communication, and system state in a distributed ledger or blockchain environment. The file includes definitions for handling transaction history, slot management, validator information, and network peer interactions, indicating its role in providing detailed insights into the system's operational metrics and state transitions.

Key components of this header file include structures such as `fd_gui_slot`, `fd_gui_txn`, and `fd_gui`, which encapsulate information about transaction slots, individual transactions, and the overall GUI state, respectively. The file also defines numerous constants for transaction flags, slot levels, and progress types, which are used to categorize and manage different states and events within the system. Additionally, the file provides function prototypes for initializing and managing the GUI, handling WebSocket connections, processing plugin messages, and tracking leadership changes in the network. This header file is intended to be included in other C source files, providing a public API for interacting with the GUI component of the system, and is crucial for developers looking to extend or maintain the GUI functionality within this distributed system.
# Imports and Dependencies

---
- `../fd_disco_base.h`
- `../pack/fd_microblock.h`
- `../../waltz/http/fd_http_server.h`
- `../../flamenco/leaders/fd_leaders.h`
- `../topo/fd_topo.h`


# Global Variables

---
### fd\_gui\_new
- **Type**: `function pointer`
- **Description**: `fd_gui_new` is a function pointer that initializes a new GUI instance for a distributed system. It takes several parameters including shared memory, an HTTP server instance, version and cluster information, an identity key, a voting flag, and a topology structure.
- **Use**: This function is used to create and configure a new GUI instance, setting up necessary components and linking it to the provided HTTP server and topology.


---
### fd\_gui\_join
- **Type**: `fd_gui_t *`
- **Description**: The `fd_gui_join` is a function that returns a pointer to an `fd_gui_t` structure. This function is used to join or attach to a shared memory segment that represents the GUI state in the application.
- **Use**: This function is used to obtain a pointer to the GUI state from a shared memory segment, allowing the application to interact with or modify the GUI state.


# Data Structures

---
### fd\_gui\_gossip\_peer
- **Type**: `struct`
- **Members**:
    - `pubkey`: An array of one public key used to identify the peer.
    - `wallclock`: A timestamp representing the current time for the peer.
    - `shred_version`: A version number indicating the shred version used by the peer.
    - `has_version`: A flag indicating whether the version information is available.
    - `version`: A nested structure containing version details including major, minor, patch numbers, commit information, and feature set.
    - `sockets`: An array of socket structures, each containing an IPv4 address and port number, representing the peer's network endpoints.
- **Description**: The `fd_gui_gossip_peer` structure represents a peer in a gossip network, containing identification, versioning, and network connectivity information. It includes a public key for peer identification, a wallclock timestamp for time synchronization, and a shred version for protocol compatibility. The structure also holds version details, including major, minor, and patch numbers, as well as commit and feature set information. Additionally, it maintains an array of socket structures to manage up to 12 network connections, each defined by an IPv4 address and port number.


---
### fd\_gui\_vote\_account
- **Type**: `struct`
- **Members**:
    - `pubkey`: An array containing the public key of the vote account.
    - `vote_account`: An array containing the public key of the associated vote account.
    - `activated_stake`: The amount of stake that has been activated for this vote account.
    - `last_vote`: The slot number of the last vote cast by this account.
    - `root_slot`: The slot number of the last rooted vote.
    - `epoch_credits`: The number of credits earned by this account in the current epoch.
    - `commission`: The commission percentage taken by the vote account.
    - `delinquent`: An integer indicating if the account is delinquent.
- **Description**: The `fd_gui_vote_account` structure is used to represent a vote account in the system, containing information about the account's public key, associated vote account, and various metrics related to its voting activity, such as activated stake, last vote, root slot, and epoch credits. It also includes a commission rate and a delinquency status, which are important for managing and monitoring the account's performance and compliance within the voting framework.


---
### fd\_gui\_validator\_info
- **Type**: `struct`
- **Members**:
    - `pubkey`: An array of public keys, with a single element, representing the validator's public key.
    - `name`: A character array of length 64 to store the name of the validator.
    - `website`: A character array of length 128 to store the website URL of the validator.
    - `details`: A character array of length 256 to store additional details about the validator.
    - `icon_uri`: A character array of length 128 to store the URI of the validator's icon.
- **Description**: The `fd_gui_validator_info` structure is designed to encapsulate information about a validator in a GUI context. It includes a public key for identification, along with metadata such as the validator's name, website, additional details, and an icon URI. This structure is likely used to display validator information in a user interface, providing a comprehensive overview of each validator's identity and associated resources.


---
### fd\_gui\_txn\_waterfall
- **Type**: `struct`
- **Members**:
    - `in`: A nested structure containing counters for incoming transaction sources such as quic, udp, gossip, block_engine, and pack_cranked.
    - `out`: A nested structure containing counters for various transaction processing outcomes and errors, including overrun, invalid transactions, and block success or failure.
- **Description**: The `fd_gui_txn_waterfall` structure is designed to track and categorize the flow of transactions through a system, capturing both incoming transaction sources and various outcomes or errors during processing. The `in` sub-structure records the number of transactions received from different sources, while the `out` sub-structure provides detailed counters for different types of processing results, such as overruns, invalid transactions, and block processing success or failure. This structure is useful for monitoring and debugging transaction processing pipelines by providing a comprehensive view of transaction flow and issues.


---
### fd\_gui\_txn\_waterfall\_t
- **Type**: `struct`
- **Members**:
    - `in`: A nested structure containing counters for different input sources like quic, udp, gossip, block_engine, and pack_cranked.
    - `out`: A nested structure containing counters for various output and error conditions such as net_overrun, quic_overrun, verify_failed, block_success, and block_fail.
- **Description**: The `fd_gui_txn_waterfall_t` structure is designed to track and categorize transaction flow metrics within a system, specifically focusing on the input and output stages of transaction processing. It contains two nested structures: `in` and `out`. The `in` structure records the number of transactions received from different sources, while the `out` structure tracks various outcomes and errors encountered during transaction processing. This data structure is crucial for monitoring and diagnosing the performance and reliability of transaction handling in the system.


---
### fd\_gui\_tile\_timers
- **Type**: `struct`
- **Members**:
    - `caughtup_housekeeping_ticks`: Stores the number of ticks for caught-up housekeeping operations.
    - `processing_housekeeping_ticks`: Stores the number of ticks for processing housekeeping operations.
    - `backpressure_housekeeping_ticks`: Stores the number of ticks for backpressure housekeeping operations.
    - `caughtup_prefrag_ticks`: Stores the number of ticks for caught-up pre-fragmentation operations.
    - `processing_prefrag_ticks`: Stores the number of ticks for processing pre-fragmentation operations.
    - `backpressure_prefrag_ticks`: Stores the number of ticks for backpressure pre-fragmentation operations.
    - `caughtup_postfrag_ticks`: Stores the number of ticks for caught-up post-fragmentation operations.
    - `processing_postfrag_ticks`: Stores the number of ticks for processing post-fragmentation operations.
- **Description**: The `fd_gui_tile_timers` structure is designed to track various timing metrics related to different stages of tile processing in a GUI system. It includes fields for recording the number of ticks spent in housekeeping, pre-fragmentation, and post-fragmentation phases, both for caught-up and processing states. This structure is likely used to monitor and optimize the performance of tile operations by providing detailed timing information.


---
### fd\_gui\_tile\_timers\_t
- **Type**: `struct`
- **Members**:
    - `caughtup_housekeeping_ticks`: Tracks the number of housekeeping ticks when caught up.
    - `processing_housekeeping_ticks`: Tracks the number of housekeeping ticks during processing.
    - `backpressure_housekeeping_ticks`: Tracks the number of housekeeping ticks under backpressure.
    - `caughtup_prefrag_ticks`: Tracks the number of pre-fragmentation ticks when caught up.
    - `processing_prefrag_ticks`: Tracks the number of pre-fragmentation ticks during processing.
    - `backpressure_prefrag_ticks`: Tracks the number of pre-fragmentation ticks under backpressure.
    - `caughtup_postfrag_ticks`: Tracks the number of post-fragmentation ticks when caught up.
    - `processing_postfrag_ticks`: Tracks the number of post-fragmentation ticks during processing.
- **Description**: The `fd_gui_tile_timers_t` structure is designed to track various timing metrics related to the processing of tiles in a GUI system. It includes fields for counting ticks during different stages of processing, such as housekeeping, pre-fragmentation, and post-fragmentation, under different conditions like being caught up, processing, or experiencing backpressure. This structure is likely used to monitor and optimize the performance of tile processing in the GUI.


---
### fd\_gui\_tile\_stats
- **Type**: `struct`
- **Members**:
    - `sample_time_nanos`: Represents the time of the sample in nanoseconds.
    - `net_in_rx_bytes`: Number of bytes received by the net or sock tile.
    - `quic_conn_cnt`: Number of active QUIC connections.
    - `verify_drop_cnt`: Number of transactions dropped by verify tiles.
    - `verify_total_cnt`: Number of transactions received by verify tiles.
    - `dedup_drop_cnt`: Number of transactions dropped by dedup tile.
    - `dedup_total_cnt`: Number of transactions received by dedup tile.
    - `pack_buffer_cnt`: Number of buffered transactions in the pack tile.
    - `pack_buffer_capacity`: Total size of the pack transaction buffer.
    - `bank_txn_exec_cnt`: Number of transactions processed by the bank tile.
    - `net_out_tx_bytes`: Number of bytes sent by the net or sock tile.
- **Description**: The `fd_gui_tile_stats` structure is designed to capture various statistics related to the performance and activity of different tiles in a networked system. It includes metrics such as the number of bytes received and sent by network tiles, the count of active QUIC connections, and the number of transactions processed or dropped by verification and deduplication tiles. Additionally, it tracks the number of transactions buffered and the capacity of the buffer in the pack tile, as well as the number of transactions executed by the bank tile. This structure is useful for monitoring and analyzing the efficiency and throughput of the system's components.


---
### fd\_gui\_tile\_stats\_t
- **Type**: `struct`
- **Members**:
    - `sample_time_nanos`: Represents the time of the sample in nanoseconds.
    - `net_in_rx_bytes`: Number of bytes received by the net or sock tile.
    - `quic_conn_cnt`: Number of active QUIC connections.
    - `verify_drop_cnt`: Number of transactions dropped by verify tiles.
    - `verify_total_cnt`: Number of transactions received by verify tiles.
    - `dedup_drop_cnt`: Number of transactions dropped by dedup tile.
    - `dedup_total_cnt`: Number of transactions received by dedup tile.
    - `pack_buffer_cnt`: Number of buffered transactions in the pack tile.
    - `pack_buffer_capacity`: Total size of the pack transaction buffer.
    - `bank_txn_exec_cnt`: Number of transactions processed by the bank tile.
    - `net_out_tx_bytes`: Number of bytes sent by the net or sock tile.
- **Description**: The `fd_gui_tile_stats_t` structure is designed to capture various statistics related to the performance and activity of different tiles in a GUI system. It includes metrics such as the number of bytes received and sent, the number of active connections, and the count of transactions processed or dropped by various tiles. This data structure is essential for monitoring and analyzing the efficiency and throughput of the system's network and transaction processing components.


---
### fd\_gui\_slot
- **Type**: `struct`
- **Members**:
    - `slot`: The unique identifier for the current slot.
    - `parent_slot`: The identifier for the parent slot of the current slot.
    - `max_compute_units`: The maximum number of compute units available for this slot.
    - `completed_time`: The timestamp indicating when the slot was completed.
    - `mine`: A flag indicating if the slot is owned by the current node.
    - `skipped`: A flag indicating if the slot was skipped.
    - `must_republish`: A flag indicating if the slot must be republished.
    - `level`: The level of confirmation for the slot.
    - `total_txn_cnt`: The total number of transactions in the slot.
    - `vote_txn_cnt`: The number of vote transactions in the slot.
    - `failed_txn_cnt`: The number of failed transactions in the slot.
    - `nonvote_failed_txn_cnt`: The number of non-vote failed transactions in the slot.
    - `compute_units`: The number of compute units used in the slot.
    - `transaction_fee`: The total transaction fee for the slot.
    - `priority_fee`: The priority fee for the slot.
    - `tips`: The total tips for the slot.
    - `leader_state`: The state of the leader for the slot.
    - `txs`: A nested structure containing transaction timing and microblock information for the slot.
    - `waterfall_begin`: An array of transaction waterfall statistics at the beginning of the slot.
    - `waterfall_end`: An array of transaction waterfall statistics at the end of the slot.
    - `tile_stats_begin`: An array of tile statistics at the beginning of the slot.
    - `tile_stats_end`: An array of tile statistics at the end of the slot.
    - `tile_timers_history_idx`: The index for the tile timers history.
- **Description**: The `fd_gui_slot` structure is a comprehensive data structure used to represent a slot in a distributed ledger system. It contains various fields that track the slot's unique identifier, its parent slot, and the maximum compute units available. The structure also records the completion time, ownership, and status flags such as whether the slot was skipped or needs republishing. It maintains counts of total, vote, and failed transactions, as well as compute units used, transaction fees, and tips. The leader state is tracked, and a nested structure provides detailed timing and microblock information. Additionally, the structure includes arrays for transaction waterfall statistics and tile statistics at both the beginning and end of the slot, along with an index for tile timers history.


---
### fd\_gui\_slot\_t
- **Type**: `struct`
- **Members**:
    - `slot`: The unique identifier for the slot.
    - `parent_slot`: The identifier of the parent slot.
    - `max_compute_units`: The maximum compute units allowed for the slot.
    - `completed_time`: The time when the slot was completed.
    - `mine`: Indicates if the slot is owned by the current node.
    - `skipped`: Indicates if the slot was skipped.
    - `must_republish`: Indicates if the slot must be republished.
    - `level`: The level of confirmation for the slot.
    - `total_txn_cnt`: The total number of transactions in the slot.
    - `vote_txn_cnt`: The number of vote transactions in the slot.
    - `failed_txn_cnt`: The number of failed transactions in the slot.
    - `nonvote_failed_txn_cnt`: The number of non-vote failed transactions in the slot.
    - `compute_units`: The compute units used in the slot.
    - `transaction_fee`: The total transaction fee for the slot.
    - `priority_fee`: The total priority fee for the slot.
    - `tips`: The total tips for the slot.
    - `leader_state`: The state of the leader for the slot.
    - `txs`: A nested structure containing transaction timing and microblock information.
    - `waterfall_begin`: The transaction waterfall statistics at the beginning of the slot.
    - `waterfall_end`: The transaction waterfall statistics at the end of the slot.
    - `tile_stats_begin`: The tile statistics at the beginning of the slot.
    - `tile_stats_end`: The tile statistics at the end of the slot.
    - `tile_timers_history_idx`: The index for the tile timers history.
- **Description**: The `fd_gui_slot_t` structure represents a slot in a distributed ledger system, encapsulating various attributes related to the slot's execution and status. It includes identifiers for the slot and its parent, compute unit limits, transaction counts, and fees. The structure also tracks the slot's confirmation level, leader state, and timing information for transactions and microblocks. Additionally, it holds statistical data on transaction processing and tile performance, providing a comprehensive overview of the slot's activity and performance metrics.


---
### fd\_gui\_txn
- **Type**: `struct`
- **Members**:
    - `priority_fee`: Represents the priority fee of the transaction, stored as a 64-bit unsigned long.
    - `tips`: Represents the tips associated with the transaction, stored as a 64-bit unsigned long.
    - `compute_units_requested`: Indicates the number of compute units requested for the transaction, stored as a 21-bit unsigned integer.
    - `compute_units_estimated`: Indicates the estimated number of compute units for the transaction, stored as a 21-bit unsigned integer.
    - `actual_consumed_cus`: Represents the actual number of compute units consumed by the transaction, stored as a 21-bit unsigned integer.
    - `bank_idx`: Stores the bank index as a 6-bit unsigned integer, with a range of [0, 64).
    - `error_code`: Stores the error code as a 6-bit unsigned integer, with a range of [0, 64).
    - `timestamp_delta_start_nanos`: Represents the start timestamp delta in nanoseconds as a signed integer.
    - `timestamp_delta_end_nanos`: Represents the end timestamp delta in nanoseconds as a signed integer.
    - `txn_start_pct`: Indicates the start percentage of the transaction execution within the microblock duration as an unsigned char.
    - `txn_load_end_pct`: Indicates the load end percentage of the transaction execution within the microblock duration as an unsigned char.
    - `txn_end_pct`: Indicates the end percentage of the transaction execution within the microblock duration as an unsigned char.
    - `flags`: Stores flags related to the transaction, assigned using FD_GUI_TXN_FLAGS_* macros, as an unsigned char.
    - `microblock_idx`: Represents the index of the microblock associated with the transaction as an unsigned integer.
- **Description**: The `fd_gui_txn` structure is a packed data structure designed to encapsulate various attributes of a transaction within a graphical user interface context. It includes fields for priority fees, tips, and compute units, both requested and estimated, as well as the actual compute units consumed. The structure also contains fields for bank index, error codes, and timestamp deltas to track the start and end of transaction execution in nanoseconds. Additionally, it includes percentage fields to represent the transaction's execution progress within a microblock, flags for transaction status, and an index for the associated microblock. This structure is optimized for memory efficiency and is used to manage transaction data in a high-performance computing environment.


---
### fd\_gui\_txn\_t
- **Type**: `struct`
- **Members**:
    - `priority_fee`: The priority fee associated with the transaction, stored as a 64-bit unsigned long.
    - `tips`: The tips associated with the transaction, stored as a 64-bit unsigned long.
    - `compute_units_requested`: The number of compute units requested for the transaction, stored as a 21-bit unsigned integer.
    - `compute_units_estimated`: The estimated number of compute units for the transaction, stored as a 21-bit unsigned integer.
    - `actual_consumed_cus`: The actual number of compute units consumed by the transaction, stored as a 21-bit unsigned integer.
    - `bank_idx`: The index of the bank processing the transaction, stored as a 6-bit unsigned integer.
    - `error_code`: The error code associated with the transaction, stored as a 6-bit unsigned integer.
    - `timestamp_delta_start_nanos`: The start timestamp delta in nanoseconds for the transaction, stored as an integer.
    - `timestamp_delta_end_nanos`: The end timestamp delta in nanoseconds for the transaction, stored as an integer.
    - `txn_start_pct`: The percentage of the transaction start time relative to the microblock duration, stored as an unsigned char.
    - `txn_load_end_pct`: The percentage of the transaction load end time relative to the microblock duration, stored as an unsigned char.
    - `txn_end_pct`: The percentage of the transaction end time relative to the microblock duration, stored as an unsigned char.
    - `flags`: Flags associated with the transaction, stored as an unsigned char, using FD_GUI_TXN_FLAGS_* macros.
    - `microblock_idx`: The index of the microblock containing the transaction, stored as an unsigned integer.
- **Description**: The `fd_gui_txn_t` structure represents a transaction within the GUI system, encapsulating various attributes such as fees, compute units, timestamps, and flags. It is designed to efficiently store transaction data with bit fields for certain attributes to minimize memory usage. The structure includes fields for priority and tips fees, requested and estimated compute units, actual consumed compute units, bank index, error code, and timestamp deltas. Additionally, it contains percentage fields to represent transaction timing within a microblock and a set of flags to indicate transaction states or properties. This structure is crucial for tracking and managing transactions in a high-performance, memory-efficient manner within the GUI system.


---
### fd\_gui
- **Type**: `struct`
- **Members**:
    - `http`: Pointer to an HTTP server structure.
    - `topo`: Pointer to a topology structure.
    - `next_sample_400millis`: Time for the next 400ms sample.
    - `next_sample_100millis`: Time for the next 100ms sample.
    - `next_sample_10millis`: Time for the next 10ms sample.
    - `debug_in_leader_slot`: Debug information for the leader slot.
    - `summary`: Contains various metrics and state information about the GUI.
    - `slots`: Array of slot structures representing different slots in the GUI.
    - `pack_txn_idx`: Index of the most recently received transaction.
    - `txs`: Array of transaction structures for transaction history.
    - `block_engine`: Information about the block engine, including status and connection details.
    - `epoch`: Information about the current and previous epochs.
    - `gossip`: Information about gossip peers in the network.
    - `vote_account`: Information about vote accounts in the network.
    - `validator_info`: Information about validators in the network.
- **Description**: The `fd_gui` structure is a comprehensive data structure used to manage and track the state and metrics of a GUI in a distributed system. It includes pointers to HTTP server and topology structures, timing information for sampling, and a detailed summary of various metrics such as identity keys, version, cluster, and startup progress. The structure also maintains arrays for slots, transactions, gossip peers, vote accounts, and validator information, providing a complete overview of the system's state and performance. Additionally, it contains information about the block engine and epoch details, making it a central component for monitoring and managing the GUI's operation in the network.


---
### fd\_gui\_t
- **Type**: `struct`
- **Members**:
    - `http`: Pointer to an HTTP server instance.
    - `topo`: Pointer to a topology structure.
    - `next_sample_400millis`: Timestamp for the next 400ms sample.
    - `next_sample_100millis`: Timestamp for the next 100ms sample.
    - `next_sample_10millis`: Timestamp for the next 10ms sample.
    - `debug_in_leader_slot`: Debugging information for the leader slot.
    - `summary`: Contains various summary statistics and state information.
    - `slots`: Array of slot structures, each representing a slot in the GUI.
    - `pack_txn_idx`: Index of the most recently received transaction.
    - `txs`: Array of transactions with historical data.
    - `block_engine`: Information about the block engine, including status and connection details.
    - `epoch`: Contains epoch-related information and scheduling.
    - `gossip`: Information about gossip peers in the network.
    - `vote_account`: Details about vote accounts in the network.
    - `validator_info`: Information about validators, including their public keys and metadata.
- **Description**: The `fd_gui_t` structure is a comprehensive data structure used to manage and represent the state of a graphical user interface (GUI) in a distributed system. It includes pointers to essential components like the HTTP server and topology, and maintains timestamps for sampling intervals. The structure holds detailed information about the current state of the system, including slots, transactions, and network peers. It also tracks the status of the block engine and contains epoch scheduling data. The `fd_gui_t` structure is designed to facilitate the monitoring and management of a distributed system's GUI, providing a centralized repository for various metrics and state information.


# Function Declarations (Public API)

---
### fd\_gui\_align<!-- {{#callable_declaration:fd_gui_align}} -->
Returns the alignment requirement for GUI structures.
- **Description**: This function provides the alignment requirement in bytes for structures used in the GUI module. It is useful when allocating memory for these structures to ensure proper alignment, which can be critical for performance and correctness on some architectures. This function can be called at any time and does not depend on any prior initialization.
- **Inputs**: None
- **Output**: The function returns an unsigned long integer representing the alignment requirement in bytes, which is 128.
- **See also**: [`fd_gui_align`](fd_gui.c.driver.md#fd_gui_align)  (Implementation)


---
### fd\_gui\_footprint<!-- {{#callable_declaration:fd_gui_footprint}} -->
Return the memory footprint of the GUI structure.
- **Description**: Use this function to determine the size, in bytes, of the `fd_gui_t` structure. This can be useful for memory allocation or estimation purposes when working with the GUI system. The function does not require any initialization or prior setup and can be called at any time.
- **Inputs**: None
- **Output**: The function returns an `ulong` representing the size of the `fd_gui_t` structure in bytes.
- **See also**: [`fd_gui_footprint`](fd_gui.c.driver.md#fd_gui_footprint)  (Implementation)


---
### fd\_gui\_new<!-- {{#callable_declaration:fd_gui_new}} -->
Creates and initializes a new GUI instance in shared memory.
- **Description**: This function sets up a new GUI instance using the provided shared memory region, HTTP server, version, cluster, identity key, voting status, and topology. It must be called with a valid, aligned shared memory pointer and a topology with a tile count not exceeding the defined limit. The function initializes various GUI components and returns a pointer to the newly created GUI instance. If any preconditions are not met, such as a null or misaligned shared memory pointer, or an excessive tile count, the function returns null.
- **Inputs**:
    - `shmem`: A pointer to a shared memory region where the GUI instance will be created. Must not be null and must be aligned according to fd_gui_align(). If invalid, the function returns null.
    - `http`: A pointer to an fd_http_server_t structure representing the HTTP server to be used by the GUI. The caller retains ownership.
    - `version`: A constant character pointer to a string representing the version of the GUI. The caller retains ownership.
    - `cluster`: A constant character pointer to a string representing the cluster name. The caller retains ownership.
    - `identity_key`: A constant pointer to an array of unsigned characters representing the identity key. Must be 32 bytes long. The caller retains ownership.
    - `is_voting`: An integer indicating whether the GUI is in voting mode (non-zero) or non-voting mode (zero).
    - `topo`: A pointer to an fd_topo_t structure representing the topology. Must not have a tile count exceeding FD_GUI_TILE_TIMER_TILE_CNT. The caller retains ownership.
- **Output**: Returns a pointer to the initialized fd_gui_t structure on success, or null on failure due to invalid input parameters.
- **See also**: [`fd_gui_new`](fd_gui.c.driver.md#fd_gui_new)  (Implementation)


---
### fd\_gui\_join<!-- {{#callable_declaration:fd_gui_join}} -->
Casts a shared memory pointer to a GUI structure pointer.
- **Description**: Use this function to obtain a pointer to a `fd_gui_t` structure from a shared memory region. This is typically called after the shared memory has been initialized and is ready to be used as a GUI structure. Ensure that the shared memory is correctly aligned and sized for a `fd_gui_t` structure before calling this function. This function does not perform any validation on the input pointer.
- **Inputs**:
    - `shmem`: A pointer to a shared memory region that is expected to be properly aligned and sized for a `fd_gui_t` structure. The caller must ensure that the memory is valid and correctly initialized. No validation is performed on this pointer.
- **Output**: Returns a pointer to a `fd_gui_t` structure cast from the provided shared memory pointer.
- **See also**: [`fd_gui_join`](fd_gui.c.driver.md#fd_gui_join)  (Implementation)


---
### fd\_gui\_set\_identity<!-- {{#callable_declaration:fd_gui_set_identity}} -->
Sets the identity public key for the GUI and broadcasts the update.
- **Description**: This function updates the identity public key of the GUI and encodes it in Base58 format for display purposes. It should be called whenever the identity of the GUI needs to be updated. After setting the new identity, the function broadcasts this change to all connected WebSocket clients. This function assumes that the `gui` parameter is a valid, non-null pointer to an initialized `fd_gui_t` structure.
- **Inputs**:
    - `gui`: A pointer to an `fd_gui_t` structure representing the GUI. Must not be null and should be properly initialized before calling this function.
    - `identity_pubkey`: A pointer to a 32-byte array containing the new identity public key. The caller retains ownership of this data, and it must not be null.
- **Output**: None
- **See also**: [`fd_gui_set_identity`](fd_gui.c.driver.md#fd_gui_set_identity)  (Implementation)


---
### fd\_gui\_ws\_open<!-- {{#callable_declaration:fd_gui_ws_open}} -->
Sends GUI data over a WebSocket connection.
- **Description**: This function is used to send various pieces of GUI-related data over a specified WebSocket connection. It should be called when there is a need to update the client with the current state of the GUI. The function iterates over a set of predefined data printers, sending each piece of data over the WebSocket. It also conditionally sends additional data if certain features, like block engine or epoch information, are available. This function must be called with a valid GUI context and a valid WebSocket connection ID.
- **Inputs**:
    - `gui`: A pointer to an fd_gui_t structure representing the GUI context. Must not be null, and should be properly initialized before calling this function.
    - `ws_conn_id`: An unsigned long representing the WebSocket connection ID. It should correspond to an active WebSocket connection managed by the HTTP server.
- **Output**: None
- **See also**: [`fd_gui_ws_open`](fd_gui.c.driver.md#fd_gui_ws_open)  (Implementation)


---
### fd\_gui\_ws\_message<!-- {{#callable_declaration:fd_gui_ws_message}} -->
Processes a WebSocket message for the GUI.
- **Description**: This function is used to handle incoming WebSocket messages for the GUI, parsing the message data as JSON and executing specific actions based on the message content. It expects the message to contain certain fields such as 'id', 'topic', and 'key', and performs different operations depending on the values of 'topic' and 'key'. The function should be called whenever a new WebSocket message is received. It returns specific error codes if the message is malformed or if an unknown method is requested. The function assumes that the GUI has been properly initialized and that the WebSocket connection is valid.
- **Inputs**:
    - `gui`: A pointer to an fd_gui_t structure representing the GUI context. Must not be null, and the GUI should be properly initialized before calling this function.
    - `ws_conn_id`: An unsigned long representing the WebSocket connection ID. It should correspond to a valid, open WebSocket connection.
    - `data`: A pointer to an array of unsigned characters containing the message data. The data should be in JSON format and must not be null.
    - `data_len`: An unsigned long indicating the length of the data array. It should accurately reflect the size of the data to be parsed.
- **Output**: Returns an integer status code indicating the result of processing the message. Possible return values include success, bad request, or unknown method errors.
- **See also**: [`fd_gui_ws_message`](fd_gui.c.driver.md#fd_gui_ws_message)  (Implementation)


---
### fd\_gui\_plugin\_message<!-- {{#callable_declaration:fd_gui_plugin_message}} -->
Processes a plugin message for the GUI.
- **Description**: This function is used to handle various types of plugin messages that are sent to the GUI. It should be called whenever a plugin message is received that needs to be processed by the GUI. The function expects a valid GUI context and a message type identifier, along with the message data. It handles different message types by dispatching them to appropriate handlers based on the message type. If an unrecognized message type is provided, an error is logged. This function assumes that the GUI has been properly initialized before it is called.
- **Inputs**:
    - `gui`: A pointer to an fd_gui_t structure representing the GUI context. Must not be null, and the GUI should be properly initialized before calling this function. The caller retains ownership.
    - `plugin_msg`: An unsigned long integer representing the type of plugin message. It must be one of the predefined message types that the function can handle. If an invalid message type is provided, an error is logged.
    - `msg`: A pointer to a constant unsigned char array containing the message data. The format and content of this data depend on the message type. The caller retains ownership, and the pointer must not be null.
- **Output**: None
- **See also**: [`fd_gui_plugin_message`](fd_gui.c.driver.md#fd_gui_plugin_message)  (Implementation)


---
### fd\_gui\_became\_leader<!-- {{#callable_declaration:fd_gui_became_leader}} -->
Updates the GUI state to reflect leadership in a slot.
- **Description**: This function should be called when the GUI becomes the leader for a specific slot. It initializes the slot transactions and updates the slot's maximum compute units and leader time range. The function must be called with a valid GUI context and a slot index within the valid range. It is important to ensure that the slot index is correctly calculated to avoid overwriting other slots' data. The function does not handle invalid input values, so care must be taken to provide valid parameters.
- **Inputs**:
    - `gui`: A pointer to an fd_gui_t structure representing the GUI context. Must not be null, and the caller retains ownership.
    - `tickcount`: A long integer representing the current tick count. It should be a valid tick count value.
    - `_slot`: An unsigned long integer representing the slot index. It should be within the range of available slots.
    - `start_time_nanos`: A long integer representing the start time in nanoseconds when leadership begins. It should be a valid timestamp.
    - `end_time_nanos`: A long integer representing the end time in nanoseconds when leadership ends. It should be a valid timestamp.
    - `max_compute_units`: An unsigned long integer representing the maximum compute units available for the slot. It should be a valid non-negative value.
    - `max_microblocks`: An unsigned long integer representing the maximum number of microblocks for the slot. It should be a valid non-negative value.
- **Output**: None
- **See also**: [`fd_gui_became_leader`](fd_gui.c.driver.md#fd_gui_became_leader)  (Implementation)


---
### fd\_gui\_unbecame\_leader<!-- {{#callable_declaration:fd_gui_unbecame_leader}} -->
Updates the GUI state when a node stops being the leader of a slot.
- **Description**: This function should be called when a node transitions from being the leader of a slot to a non-leader state. It updates the transaction slot information in the GUI, specifically setting the upper bound of microblocks for the given slot. This function must be called with a valid GUI context and a slot index that is within the valid range. It is important to ensure that the slot index corresponds to a slot that the node was previously leading.
- **Inputs**:
    - `gui`: A pointer to an fd_gui_t structure representing the GUI context. Must not be null, and the caller retains ownership.
    - `tickcount`: A long integer representing the current tick count. It is used for internal timing and must be a valid tick count value.
    - `_slot`: An unsigned long integer representing the slot index. It must be within the range of available slots, specifically less than FD_GUI_SLOTS_CNT.
    - `microblocks_in_slot`: An unsigned long integer representing the number of microblocks in the slot. It is used to set the upper bound of microblocks for the slot.
- **Output**: None
- **See also**: [`fd_gui_unbecame_leader`](fd_gui.c.driver.md#fd_gui_unbecame_leader)  (Implementation)


---
### fd\_gui\_microblock\_execution\_begin<!-- {{#callable_declaration:fd_gui_microblock_execution_begin}} -->
Begin execution of a microblock in the GUI system.
- **Description**: This function is used to initiate the execution of a microblock within the GUI system, updating the transaction history and slot information accordingly. It should be called when a new microblock execution begins, providing necessary transaction details and indices. The function updates the transaction start offsets and calculates cost estimates for each transaction, marking them as started. It is important to ensure that the `gui` structure is properly initialized and that the `_slot` index is valid before calling this function.
- **Inputs**:
    - `gui`: A pointer to an `fd_gui_t` structure representing the GUI system. Must not be null and should be properly initialized before use.
    - `tickcount`: A long integer representing the current tick count, used for timestamp calculations.
    - `_slot`: An unsigned long integer representing the slot index. It should be a valid index within the range of available slots.
    - `txns`: A pointer to an array of `fd_txn_p_t` structures representing the transactions to be processed. Must not be null and should point to a valid array of transactions.
    - `txn_cnt`: An unsigned long integer indicating the number of transactions in the `txns` array. Should be greater than zero.
    - `microblock_idx`: An unsigned integer representing the index of the microblock being executed.
    - `pack_txn_idx`: An unsigned long integer representing the starting index for packing transactions. It is used to update transaction history and should be a valid index.
- **Output**: None
- **See also**: [`fd_gui_microblock_execution_begin`](fd_gui.c.driver.md#fd_gui_microblock_execution_begin)  (Implementation)


---
### fd\_gui\_microblock\_execution\_end<!-- {{#callable_declaration:fd_gui_microblock_execution_end}} -->
Finalize the execution of a microblock and update transaction records.
- **Description**: This function is used to mark the end of a microblock's execution within a GUI context, updating the transaction records accordingly. It should be called after a microblock has been processed to ensure that the transaction data is correctly recorded and any necessary flags are set. The function expects exactly one transaction per microblock, and it will log an error if this condition is not met. It updates the transaction history and slot information based on the provided parameters, ensuring that the transaction indices and execution percentages are recorded. This function must be called with valid transaction data and indices to maintain the integrity of the transaction history.
- **Inputs**:
    - `gui`: A pointer to an fd_gui_t structure representing the GUI context. Must not be null.
    - `tickcount`: A long integer representing the current tick count. Used for timestamp calculations.
    - `bank_idx`: An unsigned long representing the bank index. Must be within the range [0, 64).
    - `_slot`: An unsigned long representing the slot index. Used to identify the current slot in the GUI context.
    - `txn_cnt`: An unsigned long representing the number of transactions. Must be exactly 1; otherwise, an error is logged.
    - `txns`: A pointer to an array of fd_txn_p_t structures representing the transactions. Must not be null and must contain exactly one transaction.
    - `pack_txn_idx`: An unsigned long representing the packed transaction index. Used to update transaction history.
    - `txn_start_pct`: An unsigned char representing the percentage of the transaction start time relative to the microblock duration.
    - `txn_load_end_pct`: An unsigned char representing the percentage of the transaction load end time relative to the microblock duration.
    - `txn_end_pct`: An unsigned char representing the percentage of the transaction end time relative to the microblock duration.
    - `tips`: An unsigned long representing the tips associated with the transaction.
- **Output**: None
- **See also**: [`fd_gui_microblock_execution_end`](fd_gui.c.driver.md#fd_gui_microblock_execution_end)  (Implementation)


---
### fd\_gui\_poll<!-- {{#callable_declaration:fd_gui_poll}} -->
Polls the GUI for updates and broadcasts data if necessary.
- **Description**: This function checks the current time against predefined intervals to determine if certain GUI updates and data broadcasts should occur. It should be called regularly to ensure that the GUI remains up-to-date with the latest transaction and tile statistics. The function will perform updates and broadcasts at intervals of 400 milliseconds, 100 milliseconds, and 10 milliseconds, depending on the current time. It returns an indication of whether any work was done during the call.
- **Inputs**:
    - `gui`: A pointer to an fd_gui_t structure representing the GUI context. Must not be null, and should be properly initialized before calling this function.
- **Output**: Returns an integer indicating whether any updates or broadcasts were performed (1 if work was done, 0 otherwise).
- **See also**: [`fd_gui_poll`](fd_gui.c.driver.md#fd_gui_poll)  (Implementation)


