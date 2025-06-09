# Purpose
This C header file defines several data structures and types that are integral to a system managing transaction processing and consensus in a distributed ledger or blockchain environment. The file includes multiple structures, each serving a specific role in the transaction lifecycle, from batching and processing transactions to managing consensus-critical operations. The `fd_shred34` structure, for instance, is designed to handle a collection of up to 34 transaction shreds, optimized for cache usage and Rust interoperability. This structure is crucial for efficiently managing transaction data within the system's memory constraints.

Other structures, such as `fd_became_leader`, `fd_rooted_bank`, and `fd_completed_bank`, are focused on managing the state and operations of the blockchain's leader node, including slot timing, bank references, and consensus cost limits. These structures ensure that the system can accurately track and manage the execution of transactions, maintain the order of operations, and handle the complexities of leader election and slot management. The file also includes structures like `fd_microblock_trailer` and `fd_microblock_bank_trailer`, which provide metadata and state information necessary for processing microblocks, ensuring that transactions are executed and committed in the correct order. Overall, this header file is a critical component of a larger system, providing the necessary data structures and definitions to support efficient transaction processing and consensus management in a blockchain environment.
# Imports and Dependencies

---
- `stem/fd_stem.h`
- `shred/fd_shredder.h`
- `../ballet/shred/fd_shred.h`
- `pack/fd_pack.h`
- `topo/fd_topo.h`
- `bundle/fd_bundle_crank.h`
- `fd_txn_m_t.h`
- `linux/filter.h`


# Data Structures

---
### fd\_shred34
- **Type**: `struct`
- **Members**:
    - `shred_cnt`: The number of shreds contained in this structure.
    - `est_txn_cnt`: An estimate of the number of transactions contained in this shred34_t for diagnostic purposes.
    - `stride`: The byte stride between consecutive shreds.
    - `offset`: The byte offset for the start of the first shred.
    - `shred_sz`: The size of each shred in bytes.
    - `pkts`: An array of 34 unions, each containing either a fd_shred_t or a buffer of maximum size FD_SHRED_MAX_SZ.
- **Description**: The `fd_shred34` structure is designed to hold a collection of up to 34 shreds, optimized for use in a data cache and accessible from Rust. It includes metadata such as the count of shreds (`shred_cnt`), an estimated transaction count (`est_txn_cnt`), and parameters for calculating the byte range of each shred (`stride`, `offset`, `shred_sz`). The `pkts` array holds the actual shreds, each of which can be represented as either a `fd_shred_t` or a buffer of bytes, ensuring flexibility in handling shred data. The structure is aligned to `FD_CHUNK_ALIGN` and is constrained to be smaller than `USHORT_MAX` in size.


---
### fd\_shred34\_t
- **Type**: `struct`
- **Members**:
    - `shred_cnt`: The number of shreds contained in this fd_shred34 structure.
    - `est_txn_cnt`: An estimate of the number of transactions contained in this fd_shred34 structure.
    - `stride`: The byte stride between the start of each shred's payload.
    - `offset`: The byte offset from the start of the structure to the start of the first shred's payload.
    - `shred_sz`: The size in bytes of each individual shred.
    - `pkts`: An array of up to 34 shreds, each containing a payload that can be accessed as either a fd_shred_t or a byte buffer.
- **Description**: The `fd_shred34_t` structure is designed to hold a collection of up to 34 shreds, optimized for use in a data cache and accessible from Rust. It includes metadata such as the number of shreds (`shred_cnt`), an estimated transaction count (`est_txn_cnt`), and parameters for calculating the byte range of each shred's payload (`stride`, `offset`, `shred_sz`). The shreds themselves are stored in the `pkts` array, which can hold either `fd_shred_t` structures or raw byte buffers, ensuring flexibility in how the data is accessed and manipulated.


---
### fd\_became\_leader
- **Type**: `struct`
- **Members**:
    - `slot_start_ns`: Start time of the slot in nanoseconds.
    - `slot_end_ns`: End time of the slot in nanoseconds.
    - `bank`: Opaque pointer to a Rust Arc<Bank> object for transaction execution or bank dropping.
    - `max_microblocks_in_slot`: Maximum number of microblocks allowed in the block.
    - `ticks_per_slot`: Number of ticks the PoH tile will put in the block.
    - `total_skipped_ticks`: Number of ticks skipped by the PoH tile that need to be published.
    - `epoch`: Epoch of the slot for which the leader is becoming leader.
    - `limits`: Consensus-critical cost limits for the slot.
    - `bundle`: Information from the accounts database necessary for bundle tip programs.
- **Description**: The `fd_became_leader` structure is designed to manage and track the state and parameters of a slot when a node becomes the leader in a distributed ledger system. It includes timing information, a reference to a bank object for transaction management, and various limits and configurations related to microblocks and ticks. Additionally, it holds consensus-critical cost limits and bundle information necessary for executing bundle tip programs. This structure is crucial for ensuring the correct execution and management of transactions during the leader's slot.


---
### fd\_became\_leader\_t
- **Type**: `struct`
- **Members**:
    - `slot_start_ns`: Start time of the slot in nanoseconds.
    - `slot_end_ns`: End time of the slot in nanoseconds.
    - `bank`: Opaque pointer to a Rust Arc<Bank> object for transaction execution.
    - `max_microblocks_in_slot`: Maximum number of microblocks allowed in the block.
    - `ticks_per_slot`: Number of ticks the PoH tile will put in the block.
    - `total_skipped_ticks`: Number of ticks skipped by the PoH tile that need to be published.
    - `epoch`: Epoch of the slot for which leadership is assumed.
    - `limits`: Consensus-critical cost limits for the slot.
    - `bundle`: Information from the accounts database necessary for bundle tip programs.
- **Description**: The `fd_became_leader_t` structure is used to represent the state and configuration of a leader node in a distributed system during a specific slot. It includes timing information, a reference to a bank object for transaction execution, and various limits and configurations related to microblocks and ticks. Additionally, it contains consensus-critical cost limits and bundle information necessary for processing transactions and maintaining the integrity of the system during the leadership period.


---
### fd\_rooted\_bank
- **Type**: `struct`
- **Members**:
    - `bank`: A pointer to a bank object, which is likely used for managing or accessing financial data or transactions.
    - `slot`: An unsigned long integer representing a specific slot, possibly indicating a time or sequence position in a series of operations.
- **Description**: The `fd_rooted_bank` structure is a simple data structure that contains a pointer to a bank object and an unsigned long integer representing a slot. This structure is likely used in a financial or transactional context, where the bank pointer provides access to a bank's data or operations, and the slot indicates a specific position or time frame within a sequence of events or transactions. The structure's simplicity suggests it serves as a basic reference or identifier within a larger system.


---
### fd\_rooted\_bank\_t
- **Type**: `struct`
- **Members**:
    - `bank`: A pointer to a bank object, likely used for transaction execution or management.
    - `slot`: An unsigned long integer representing the slot number associated with the bank.
- **Description**: The `fd_rooted_bank_t` structure is a simple data structure that contains a pointer to a bank object and an associated slot number. This structure is likely used to manage or reference a specific bank instance within a particular slot, facilitating operations such as transaction execution or state management in a banking or ledger system.


---
### fd\_completed\_bank
- **Type**: `struct`
- **Members**:
    - `slot`: An unsigned long integer representing the slot number associated with the completed bank.
    - `hash`: An array of 32 unsigned characters representing the hash of the completed bank.
- **Description**: The `fd_completed_bank` structure is used to represent a completed bank in a system, identified by a specific slot number and a corresponding hash. The `slot` member indicates the particular slot associated with the bank, while the `hash` member provides a 32-byte hash value that uniquely identifies the state or contents of the bank at the time of completion. This structure is likely used in contexts where tracking the completion and verification of banks is necessary, such as in financial or blockchain systems.


---
### fd\_completed\_bank\_t
- **Type**: `struct`
- **Members**:
    - `slot`: Represents the slot number associated with the completed bank.
    - `hash`: A 32-byte array representing the hash of the completed bank.
- **Description**: The `fd_completed_bank_t` structure is a simple data structure used to represent a completed bank in a blockchain or distributed ledger system. It contains two members: `slot`, which indicates the specific slot number for which the bank has been completed, and `hash`, a 32-byte array that stores the cryptographic hash of the bank. This structure is likely used to track and verify the completion of banks within the system, ensuring data integrity and consistency.


---
### fd\_microblock\_trailer
- **Type**: `struct`
- **Members**:
    - `hash`: An array of 32 unsigned characters representing the hash of the transactions in the microblock.
    - `pack_txn_idx`: An unsigned long representing a sequentially increasing index of the first transaction in the microblock.
    - `tips`: An unsigned long representing the tips included in the transaction, in lamports.
    - `txn_start_pct`: An unsigned character representing the percentage of elapsed time at which the transaction started.
    - `txn_load_end_pct`: An unsigned character representing the percentage of elapsed time at which the transaction finished loading.
    - `txn_end_pct`: An unsigned character representing the percentage of elapsed time at which the transaction execution ended.
- **Description**: The `fd_microblock_trailer` structure is designed to encapsulate metadata about a microblock in a blockchain system. It includes a hash of the transactions, an index for tracking the first transaction across all slots, and tips in lamports for bundle transactions. Additionally, it records the percentage of elapsed time for key state transitions of the first transaction, providing insights into the microblock's execution timeline.


---
### fd\_microblock\_trailer\_t
- **Type**: `struct`
- **Members**:
    - `hash`: The hash of the transactions in the microblock, ready to be mixed into PoH.
    - `pack_txn_idx`: A sequentially increasing index of the first transaction in the microblock, used for maintaining an ordered history of transactions.
    - `tips`: The tips included in the transaction, in lamports, with 0 for non-bundle transactions.
    - `txn_start_pct`: Represents the elapsed time percentage for the start of the first transaction in the microblock.
    - `txn_load_end_pct`: Represents the elapsed time percentage for the end of loading the first transaction in the microblock.
    - `txn_end_pct`: Represents the elapsed time percentage for the end of execution of the first transaction in the microblock.
- **Description**: The `fd_microblock_trailer_t` structure is designed to encapsulate metadata about a microblock, including a hash of its transactions, an index for tracking transaction order, and tips associated with the transactions. It also includes timing information that represents the percentage of elapsed time for various state transitions of the first transaction in the microblock, which is useful for performance monitoring and diagnostics.


---
### fd\_done\_packing
- **Type**: `struct`
- **Members**:
    - `microblocks_in_slot`: Represents the number of microblocks contained within a slot.
- **Description**: The `fd_done_packing` structure is a simple data structure that encapsulates a single field, `microblocks_in_slot`, which is used to store the count of microblocks present in a slot. This structure is likely used in contexts where tracking the number of microblocks processed or packed into a slot is necessary, providing a straightforward way to manage and access this specific piece of information.


---
### fd\_done\_packing\_t
- **Type**: `struct`
- **Members**:
    - `microblocks_in_slot`: Represents the number of microblocks contained within a slot.
- **Description**: The `fd_done_packing_t` structure is a simple data structure that encapsulates a single field, `microblocks_in_slot`, which indicates the number of microblocks that have been packed into a slot. This structure is likely used to track or report the completion of a packing process within a slot, providing a count of the microblocks involved.


---
### fd\_microblock\_bank\_trailer
- **Type**: `struct`
- **Members**:
    - `bank`: An opaque pointer to the bank used for executing and committing transactions, with its lifetime managed by the PoH tile.
    - `microblock_idx`: A sequentially increasing index of the microblock across all banks, ensuring order of execution and commitment.
    - `pack_txn_idx`: A sequentially increasing index of the first transaction in the microblock across all slots processed by pack, used for maintaining an ordered transaction history.
    - `is_bundle`: Indicates if the microblock is a bundle of transactions that should be executed in order and either commit or fail atomically.
- **Description**: The `fd_microblock_bank_trailer` structure is designed to manage metadata associated with microblocks in a banking system. It includes a pointer to the bank for transaction execution, indices for tracking the order of microblocks and transactions, and a flag to indicate if the microblock is a bundle of transactions that must be executed atomically. This structure ensures that microblocks are processed in the correct sequence and provides necessary information for transaction history monitoring.


---
### fd\_microblock\_bank\_trailer\_t
- **Type**: `struct`
- **Members**:
    - `bank`: An opaque pointer to the bank used for executing and committing transactions.
    - `microblock_idx`: A sequentially increasing index of the microblock across all banks.
    - `pack_txn_idx`: A sequentially increasing index of the first transaction in the microblock across all slots.
    - `is_bundle`: Indicates if the microblock is a bundle with potentially conflicting transactions that should be executed in order.
- **Description**: The `fd_microblock_bank_trailer_t` structure is used to manage metadata associated with microblocks in a banking system. It includes a pointer to the bank for transaction execution, indices for tracking the order of microblocks and transactions, and a flag to indicate if the microblock is a bundle of transactions that must be executed atomically. This structure ensures that microblocks are committed in the correct order and provides necessary information for monitoring and execution purposes.


---
### fd\_poh\_init\_msg\_t
- **Type**: `struct`
- **Members**:
    - `tick_duration_ns`: Specifies the duration of a tick in nanoseconds.
    - `hashcnt_per_tick`: Indicates the number of hash counts per tick.
    - `ticks_per_slot`: Represents the number of ticks per slot.
    - `tick_height`: Denotes the height of the tick.
    - `last_entry_hash`: Stores the hash of the last entry as a 32-byte array.
- **Description**: The `fd_poh_init_msg_t` structure is a packed data structure used to initialize the Proof of History (PoH) mechanism. It contains fields that define the timing and hashing parameters for PoH, such as the duration of each tick, the number of hash counts per tick, and the number of ticks per slot. Additionally, it includes a tick height and a 32-byte array to store the hash of the last entry, which is crucial for maintaining the integrity and continuity of the PoH sequence.


