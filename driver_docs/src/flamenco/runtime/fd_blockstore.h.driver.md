# Purpose
The provided C header file defines the interface and data structures for a high-performance in-memory database called `fd_blockstore`, which is designed for indexing and durably storing blocks. This blockstore is part of a larger system, likely related to blockchain or distributed ledger technology, as indicated by the terminology used (e.g., "shreds," "slots," "blocks," and "transactions"). The file includes definitions for various data structures such as `fd_block_t`, `fd_block_shred`, and `fd_block_txn`, which are used to manage and organize data within the blockstore. It also defines constants, macros, and inline functions to facilitate memory alignment, error handling, and data manipulation.

The blockstore provides a comprehensive API for managing blocks and shreds, including functions for creating, joining, and deleting blockstores, as well as querying and updating block metadata. It supports concurrent operations through the use of locks and provides mechanisms for archiving finalized blocks to disk. The file also includes detailed comments and documentation, explaining the purpose and usage of each component, making it a well-documented and organized piece of software. The blockstore is designed to be efficient and scalable, with support for large numbers of blocks, shreds, and transactions, and it includes mechanisms for handling errors and ensuring data integrity.
# Imports and Dependencies

---
- `../../ballet/block/fd_microblock.h`
- `../../ballet/shred/fd_deshredder.h`
- `../../ballet/shred/fd_shred.h`
- `../fd_flamenco_base.h`
- `../types/fd_types.h`
- `fd_rwseq_lock.h`
- `stdbool.h`
- `fcntl.h`
- `../../util/tmpl/fd_pool_para.c`
- `../../util/tmpl/fd_map_chain_para.c`
- `../../util/tmpl/fd_deque_dynamic.c`
- `../../util/tmpl/fd_set.c`
- `../../util/tmpl/fd_map_slot_para.c`
- `../../util/tmpl/fd_map_dynamic.c`
- `../../util/tmpl/fd_map_giant.c`


# Global Variables

---
### fd\_shred\_key\_null
- **Type**: ``fd_shred_key_t``
- **Description**: The `fd_shred_key_null` is a constant of type `fd_shred_key_t`, which is a structure containing two fields: `slot` and `idx`, both initialized to zero. This structure is used to represent a null or invalid shred key in the context of the blockstore system.
- **Use**: This variable is used as a sentinel value to represent an uninitialized or invalid shred key in the blockstore system.


---
### fd\_blockstore\_new
- **Type**: `function pointer`
- **Description**: `fd_blockstore_new` is a function that initializes a memory region to be used as a blockstore, which is a high-performance database for in-memory indexing and storing blocks. It takes several parameters including a pointer to shared memory, workspace tag, seed, and maximum limits for shreds, blocks, indices, and transactions.
- **Use**: This function is used to format a memory region into a blockstore, preparing it for use in storing and managing block data.


---
### fd\_blockstore\_join
- **Type**: `fd_blockstore_t *`
- **Description**: The `fd_blockstore_join` is a function that returns a pointer to a `fd_blockstore_t` structure. This function is used to join a blockstore, which is a high-performance database for in-memory indexing and durably storing blocks. The function takes two parameters: `ljoin`, a pointer to a memory region in the caller's address space used to hold information about the local join, and `shblockstore`, a pointer to the memory region containing the blockstore.
- **Use**: This function is used to establish a local join to a blockstore, allowing the caller to interact with the blockstore's data structures and operations.


---
### fd\_blockstore\_leave
- **Type**: `function pointer`
- **Description**: `fd_blockstore_leave` is a function that takes a pointer to an `fd_blockstore_t` structure and returns a void pointer. This function is likely used to handle the process of leaving or disconnecting from a blockstore, which is a high-performance database for in-memory indexing and storing blocks durably.
- **Use**: This function is used to properly disconnect from a blockstore, ensuring any necessary cleanup or state management is performed.


---
### fd\_blockstore\_delete
- **Type**: `function pointer`
- **Description**: `fd_blockstore_delete` is a function pointer that takes a single argument, a pointer to a shared blockstore (`void * shblockstore`), and returns a `void *`. This function is likely used to delete or deallocate resources associated with a blockstore in a shared memory context.
- **Use**: This function is used to delete or clean up a blockstore instance from shared memory.


---
### fd\_blockstore\_init
- **Type**: `fd_blockstore_t *`
- **Description**: The `fd_blockstore_init` function initializes a blockstore structure, which is a high-performance database for in-memory indexing and durably storing blocks. It sets up the blockstore with a given slot bank, file descriptor, and maximum file size, and rebuilds an in-memory index of the archival file.
- **Use**: This function is used to initialize a blockstore with necessary parameters and prepare it for operations such as live replay and archival indexing.


---
### fd\_blockstore\_block\_map\_query
- **Type**: `fd_block_info_t *`
- **Description**: The `fd_blockstore_block_map_query` function returns a pointer to an `fd_block_info_t` structure, which contains metadata about a block in the blockstore, such as its slot, parent slot, child slots, block height, and various indices related to shreds and block data. This structure is used to manage and query information about blocks stored in the blockstore.
- **Use**: This function is used to query the blockstore for metadata about a specific block identified by its slot number.


---
### fd\_blockstore\_txn\_query
- **Type**: `fd_txn_map_t *`
- **Description**: The `fd_blockstore_txn_query` is a function that returns a pointer to an `fd_txn_map_t` structure. This function is used to query transaction data within a blockstore using a given signature.
- **Use**: This function is used to retrieve transaction data from the blockstore based on a specific transaction signature.


# Data Structures

---
### fd\_shred\_key
- **Type**: `struct`
- **Members**:
    - `slot`: An unsigned long integer representing the slot number.
    - `idx`: An unsigned integer representing the index within the slot.
- **Description**: The `fd_shred_key` structure is a simple data structure used to uniquely identify a shred within a blockstore system. It consists of two members: `slot`, which indicates the slot number, and `idx`, which specifies the index of the shred within that slot. This structure is essential for managing and accessing shreds in a high-performance blockstore, allowing for efficient indexing and retrieval of data shreds.


---
### fd\_shred\_key\_t
- **Type**: `struct`
- **Members**:
    - `slot`: Represents the slot number associated with the shred key.
    - `idx`: Represents the index of the shred within the slot.
- **Description**: The `fd_shred_key_t` structure is a simple data structure used to uniquely identify a shred within a blockstore system. It consists of two members: `slot`, which indicates the slot number, and `idx`, which specifies the index of the shred within that slot. This structure is essential for managing and accessing shreds in a blockstore, allowing for efficient indexing and retrieval of shreds based on their unique slot and index combination.


---
### fd\_buf\_shred
- **Type**: `struct`
- **Members**:
    - `key`: A key of type `fd_shred_key_t` used to identify the shred.
    - `prev`: An unsigned long integer representing the previous shred in a sequence.
    - `next`: An unsigned long integer representing the next shred in a sequence.
    - `memo`: An unsigned long integer used for memoization or additional metadata.
    - `eqvoc`: An integer flag indicating if an equivocating version of this shred has been seen.
    - `hdr`: A union member representing the shred header.
    - `buf`: A union member representing the entire shred buffer, including both header and payload.
- **Description**: The `fd_buf_shred` structure is a data structure designed to facilitate the buffering of data shreds before all shreds for a slot have been received. It includes a key for identifying the shred, pointers to previous and next shreds in a sequence, and a memoization field. The structure also contains a flag to indicate if an equivocating version of the shred has been encountered. The union within the structure allows access to either the shred header or the entire shred buffer, which includes both the header and payload. This structure is aligned to 128 bytes to optimize memory access and reduce false sharing.


---
### fd\_buf\_shred\_t
- **Type**: `struct`
- **Members**:
    - `key`: A unique identifier for the shred, consisting of a slot and index.
    - `prev`: The index of the previous shred in the buffer.
    - `next`: The index of the next shred in the buffer.
    - `memo`: A field for storing additional information or metadata about the shred.
    - `eqvoc`: Indicates if an equivocating version of this shred has been seen.
    - `hdr`: The header of the shred, used when accessing the shred's metadata.
    - `buf`: A buffer containing the entire shred, including both header and payload.
- **Description**: The `fd_buf_shred_t` structure is a wrapper around `fd_shred_t` designed to facilitate the buffering of data shreds before all shreds for a slot have been received. It includes fields for managing the shred's position in a buffer, tracking if an equivocating version has been seen, and storing the shred's header and payload. This structure is aligned to 128 bytes to optimize memory access and reduce false sharing.


---
### fd\_block\_shred
- **Type**: `struct`
- **Members**:
    - `hdr`: Pointer to the data shred header.
    - `off`: Offset to the payload relative to the start of the block's data region.
- **Description**: The `fd_block_shred` structure represents a shred that has been assembled into a block within a blockstore system. It contains a pointer to the shred's header and an offset indicating where the shred's payload begins relative to the start of the block's data region. This structure is used to manage and access the data shreds that are part of a block, facilitating efficient storage and retrieval of block data in a high-performance database environment.


---
### fd\_block\_shred\_t
- **Type**: `struct`
- **Members**:
    - `hdr`: Pointer to the data shred header.
    - `off`: Offset to the payload relative to the start of the block's data region.
- **Description**: The `fd_block_shred_t` structure represents a shred that has been assembled into a block within a blockstore system. It contains a pointer to the shred's header and an offset indicating where the shred's payload begins relative to the start of the block's data region. This structure is used to manage and access shreds that are part of a block, facilitating the organization and retrieval of block data in a high-performance database designed for in-memory indexing and durable storage of blocks.


---
### fd\_block\_entry\_batch
- **Type**: `struct`
- **Members**:
    - `end_off`: An unsigned long integer representing the exclusive end offset of the entry batch within a block.
- **Description**: The `fd_block_entry_batch` structure represents a microblock or entry batch within a block in the blockstore system. It contains a single member, `end_off`, which indicates the exclusive end offset of the batch relative to the start of the block's data region. This offset helps in determining the boundaries of the batch, as the end offset of one batch is the start offset of the next. This structure is crucial for managing and processing batches of entries, especially for deserialization purposes, as each batch is expected to contain a single array of microblocks or entries.


---
### fd\_block\_entry\_batch\_t
- **Type**: `struct`
- **Members**:
    - `end_off`: Represents the exclusive end offset of the entry batch relative to the start of the block's data region.
- **Description**: The `fd_block_entry_batch_t` structure represents a microblock or entry batch within a block in the blockstore system. It is used to define the boundaries of a batch within the block's data region, where the `end_off` member indicates the exclusive end offset of the batch. This structure is crucial for managing the serialization and deserialization of data, as each batch is expected to contain a single array of microblocks or entries. The alignment of batch ends with shred ends and batch starts with shred starts is significant for the blockstore's data processing and storage operations.


---
### fd\_block\_micro
- **Type**: `struct`
- **Members**:
    - `off`: Offset into block data.
- **Description**: The `fd_block_micro` structure represents a microblock within a block, specifically in the context of a blockstore system. It contains a single member, `off`, which indicates the offset of the microblock relative to the start of the block's data region. This structure is used to manage and reference microblocks efficiently within the larger block data structure.


---
### fd\_block\_micro\_t
- **Type**: `struct`
- **Members**:
    - `off`: Offset into block data.
- **Description**: The `fd_block_micro_t` structure represents a microblock within a block, specifically in the context of Solana's blockchain architecture. It contains a single member, `off`, which indicates the offset of the microblock relative to the start of the block's data region. This structure is used to manage and reference microblocks, which are smaller units of data within a larger block, facilitating efficient data handling and processing in the blockstore system.


---
### fd\_block\_txn
- **Type**: `struct`
- **Members**:
    - `txn_off`: Offset into block data of the transaction.
    - `id_off`: Offset into block data of transaction identifiers.
    - `sz`: Size of the transaction data.
- **Description**: The `fd_block_txn` structure represents a transaction that has been parsed and is part of a block in a blockstore system. It contains offsets that indicate where the transaction and its identifiers are located within the block's data, as well as the size of the transaction data. This structure is used to manage and access transaction data efficiently within the blockstore's memory layout.


---
### fd\_block\_txn\_t
- **Type**: `struct`
- **Members**:
    - `txn_off`: Offset into block data of the transaction.
    - `id_off`: Offset into block data of transaction identifiers.
    - `sz`: Size of the transaction.
- **Description**: The `fd_block_txn_t` structure represents a transaction that has been parsed and is part of a block in the blockstore system. It contains offsets that point to the location of the transaction and its identifiers within the block's data region, as well as the size of the transaction. This structure is used to manage and access transaction data efficiently within the blockstore's memory layout.


---
### fd\_block\_rewards
- **Type**: `struct`
- **Members**:
    - `collected_fees`: The total amount of fees collected in the block.
    - `leader`: The hash identifier of the leader responsible for the block.
    - `post_balance`: The balance after the block execution.
- **Description**: The `fd_block_rewards` structure is used to represent the rewards associated with a block after its execution. It includes the total fees collected during the block, the leader's identifier who is responsible for the block, and the balance after the block's execution. This structure is essential for tracking the financial outcomes and leader accountability in a blockchain system.


---
### fd\_block\_rewards\_t
- **Type**: `struct`
- **Members**:
    - `collected_fees`: Stores the total fees collected after block execution.
    - `leader`: Holds the hash of the leader responsible for the block.
    - `post_balance`: Represents the balance after block execution.
- **Description**: The `fd_block_rewards_t` structure is used to encapsulate the rewards information associated with a block after its execution. It includes the total fees collected, the leader's hash, and the post-execution balance, providing a comprehensive summary of the financial outcomes of processing a block.


---
### fd\_block\_info
- **Type**: `struct`
- **Members**:
    - `slot`: A unique identifier for the block, used as a map key.
    - `next`: Reserved for use by fd_map_giant.c.
    - `parent_slot`: The slot of the parent block in the block's ancestry.
    - `child_slots`: An array holding the slots of child blocks, with a maximum size defined by FD_BLOCKSTORE_CHILD_SLOT_MAX.
    - `child_slot_cnt`: The count of child slots currently stored in child_slots.
    - `block_height`: The height of the block in the blockchain.
    - `block_hash`: The hash of the block, used for verification and integrity checks.
    - `bank_hash`: The hash of the bank state after executing the block.
    - `merkle_hash`: The Merkle hash of the last FEC set in the block.
    - `fec_cnt`: The number of FEC (Forward Error Correction) sets in the slot.
    - `flags`: A set of flags indicating the status and properties of the block.
    - `ts`: The timestamp indicating when the block was fully received.
    - `consumed_idx`: The highest shred index that has been consumed in order.
    - `buffered_idx`: The highest shred index that has been buffered in order.
    - `received_idx`: The highest shred index received, which may be out-of-order.
    - `data_complete_idx`: The highest shred index with complete data in contiguous entry batches.
    - `slot_complete_idx`: The highest shred index for the entire slot, indicating completion.
    - `data_complete_idxs`: A bit vector tracking shred indices marked as data complete.
    - `ticks_consumed`: The number of ticks consumed for batching tick verification.
    - `tick_hash_count_accum`: An accumulated count of tick hashes for verification purposes.
    - `in_poh_hash`: A hash used in the Proof of History (PoH) process.
    - `block_gaddr`: The global address pointing to the start of the allocated fd_block_t.
- **Description**: The `fd_block_info` structure is a comprehensive data structure used to manage and track the state of a block within a high-performance blockstore system. It includes fields for ancestry information, such as parent and child slots, as well as metadata like block height, hashes, and flags indicating the block's status. The structure also manages windowing information for shreds, which are buffered and consumed as they are received, and includes indices for tracking the progress of data completeness and slot completion. Additionally, it contains fields for tick verification and a global address for the block's memory allocation, making it a critical component for block management and processing in the blockstore.


---
### fd\_block\_info\_t
- **Type**: `struct`
- **Members**:
    - `slot`: The map key representing the block's slot.
    - `next`: Reserved for use by fd_map_giant.c.
    - `parent_slot`: The slot of the parent block.
    - `child_slots`: Array of slots for child blocks.
    - `child_slot_cnt`: Count of child slots.
    - `block_height`: The height of the block in the blockchain.
    - `block_hash`: Hash of the block.
    - `bank_hash`: Hash of the bank state after executing the block.
    - `merkle_hash`: Merkle hash of the last FEC set.
    - `fec_cnt`: Number of FEC sets in the slot.
    - `flags`: Flags indicating the block's state.
    - `ts`: Timestamp when the block was fully received.
    - `consumed_idx`: Highest shred index that has been consumed.
    - `buffered_idx`: Highest shred index that has been buffered.
    - `received_idx`: Highest shred index that has been received.
    - `data_complete_idx`: Highest shred index for contiguous entry batches.
    - `slot_complete_idx`: Highest shred index for the entire slot.
    - `data_complete_idxs`: Bit vector tracking shreds marked with FD_SHRED_DATA_FLAG_DATA_COMPLETE.
    - `ticks_consumed`: Number of ticks consumed.
    - `tick_hash_count_accum`: Accumulated count of tick hashes.
    - `in_poh_hash`: Hash used in Proof of History (PoH).
    - `block_gaddr`: Global address to the start of the allocated fd_block_t.
- **Description**: The `fd_block_info_t` structure is a comprehensive data structure used to store metadata and state information about a block in a high-performance blockstore system. It includes fields for managing the block's position in the blockchain (such as slot, parent slot, and child slots), metadata about the block (such as block height, hashes, and flags), and state information for processing shreds (such as indices for consumed, buffered, and received shreds). Additionally, it contains fields for managing the block's execution state and memory allocation, making it a critical component for tracking and managing blocks within the blockstore.


---
### fd\_block\_idx
- **Type**: `struct`
- **Members**:
    - `slot`: Represents the slot number associated with the block index.
    - `next`: Holds the offset to the next block index in a linked list or similar structure.
    - `hash`: Stores a hash value for quick lookup or verification purposes.
    - `off`: Indicates the byte offset of the block data relative to the start of the file.
    - `block_hash`: Contains the hash of the block for integrity and verification.
    - `bank_hash`: Holds the hash of the bank state after executing the block.
- **Description**: The `fd_block_idx` structure is used to maintain an in-memory index of finalized blocks that have been archived to disk. It records essential metadata such as the slot number, byte offset, and hash values for both the block and the bank state. This structure facilitates efficient retrieval and verification of archived block data, ensuring data integrity and quick access in a high-performance blockstore system.


---
### fd\_block\_idx\_t
- **Type**: `struct`
- **Members**:
    - `slot`: The slot number associated with the block index.
    - `next`: A pointer to the next block index in the list.
    - `hash`: A hash value for the block index.
    - `off`: The byte offset of the block relative to the start of the file.
    - `block_hash`: The hash of the block.
    - `bank_hash`: The hash of the bank associated with the block.
- **Description**: The `fd_block_idx_t` structure is used to represent an in-memory index of finalized blocks that have been archived to disk. It contains information about the slot number, the byte offset of the block in the archival file, and hashes for both the block and the bank. This structure is part of a larger system for managing and indexing blocks in a high-performance blockstore database.


---
### fd\_txn\_key
- **Type**: `struct`
- **Members**:
    - `v`: An array of unsigned long integers with a size determined by the constant FD_ED25519_SIG_SZ divided by the size of an unsigned long.
- **Description**: The `fd_txn_key` structure is designed to hold a transaction key, which is represented as an array of unsigned long integers. The size of this array is determined by the constant `FD_ED25519_SIG_SZ`, which is divided by the size of an unsigned long integer. This structure is likely used to store or manipulate cryptographic keys or signatures in a format that is compatible with the Ed25519 signature scheme, which is commonly used in secure communications and blockchain technologies.


---
### fd\_txn\_key\_t
- **Type**: `struct`
- **Members**:
    - `v`: An array of unsigned long integers, with a size determined by the macro FD_ED25519_SIG_SZ divided by the size of an unsigned long.
- **Description**: The `fd_txn_key_t` structure is a simple data structure used to represent a transaction key in the system. It consists of a single member, `v`, which is an array of unsigned long integers. The size of this array is determined by the macro `FD_ED25519_SIG_SZ` divided by the size of an unsigned long, indicating that it is used to store a fixed-size signature or key data. This structure is likely used as a key in transaction maps or for identifying transactions uniquely within the blockstore system.


---
### fd\_txn\_map
- **Type**: `struct`
- **Members**:
    - `sig`: A unique transaction key of type `fd_txn_key_t`.
    - `next`: An unsigned long integer indicating the next transaction in a sequence.
    - `slot`: An unsigned long integer representing the slot number associated with the transaction.
    - `offset`: An unsigned long integer indicating the offset of the transaction data.
    - `sz`: An unsigned long integer representing the size of the transaction data.
    - `meta_gaddr`: An unsigned long integer pointing to the transaction metadata.
    - `meta_sz`: An unsigned long integer representing the size of the transaction metadata.
- **Description**: The `fd_txn_map` structure is designed to map transaction keys to their respective metadata and data within a blockstore system. It includes fields for a unique transaction signature (`sig`), pointers to the next transaction (`next`), and details about the transaction's location and size (`slot`, `offset`, `sz`). Additionally, it holds pointers and sizes for associated metadata (`meta_gaddr`, `meta_sz`), facilitating efficient transaction management and retrieval in a high-performance blockstore environment.


---
### fd\_txn\_map\_t
- **Type**: `struct`
- **Members**:
    - `sig`: A unique transaction signature represented as an array of unsigned long integers.
    - `next`: An index or pointer to the next transaction in a linked list or chain.
    - `slot`: The slot number indicating the block or position in the blockchain where the transaction is stored.
    - `offset`: The offset within the block data where the transaction begins.
    - `sz`: The size of the transaction data.
    - `meta_gaddr`: A pointer or global address to the transaction metadata.
    - `meta_sz`: The size of the transaction metadata.
- **Description**: The `fd_txn_map_t` structure is designed to represent a transaction within a block in a blockchain system. It includes a unique signature for identifying the transaction, along with various fields for managing its position and metadata within the block. The structure supports linking transactions through a 'next' field, and provides offsets for locating transaction data and metadata within the block's data region. This structure is crucial for efficiently managing and accessing transaction information in a high-performance blockstore environment.


---
### fd\_blockstore\_archiver
- **Type**: `struct`
- **Members**:
    - `fd_size_max`: Maximum size of the archival file.
    - `num_blocks`: Number of blocks in the archival file, needed for reading back.
    - `head`: Location of the least recently written block.
    - `tail`: Location after the most recently written block.
- **Description**: The `fd_blockstore_archiver` structure is used to define metadata at the start of an archive file, which is essential for reading back archive files during initialization. It includes information about the maximum size of the archival file, the number of blocks it contains, and pointers to the head and tail of the block sequence, indicating the least and most recently written blocks, respectively.


---
### fd\_blockstore\_archiver\_t
- **Type**: `struct`
- **Members**:
    - `fd_size_max`: Maximum size of the archival file.
    - `num_blocks`: Number of blocks in the archival file, needed for reading back.
    - `head`: Location of the least recently written block.
    - `tail`: Location after the most recently written block.
- **Description**: The `fd_blockstore_archiver_t` structure is used to define the metadata format at the start of an archive file in the blockstore system. This metadata is crucial for managing the archival process, allowing the system to track the maximum size of the archive, the number of blocks it contains, and the positions of the head and tail blocks. This information is essential for efficiently reading back archived data during initialization or recovery processes.


---
### fd\_blockstore\_shmem
- **Type**: `struct`
- **Members**:
    - `magic`: A magic number used to verify the integrity of the blockstore memory.
    - `blockstore_gaddr`: Global address of the blockstore in memory.
    - `wksp_tag`: Tag used for workspace allocation.
    - `seed`: Hash seed used for various hash functions.
    - `archiver`: Metadata for managing archival files.
    - `mrw_slot`: Most recently written slot.
    - `lps`: Latest processed slot.
    - `hcs`: Highest confirmed slot.
    - `wmk`: Watermark indicating the highest slot that should not be modified directly.
    - `shred_max`: Maximum number of shreds that can be held in memory.
    - `block_max`: Maximum number of blocks that can be held in memory.
    - `idx_max`: Maximum number of blocks that can be indexed from the archival file.
    - `txn_max`: Maximum number of transactions that can be indexed from blocks.
    - `alloc_max`: Maximum bytes that can be allocated.
    - `block_idx_gaddr`: Global address of the block index map.
    - `slot_deque_gaddr`: Global address of the slot deque.
    - `txn_map_gaddr`: Global address of the transaction map, not safe for multi-threaded writes.
    - `alloc_gaddr`: Global address of the allocator.
- **Description**: The `fd_blockstore_shmem` structure is a shared memory data structure used in a high-performance blockstore database for in-memory indexing and durable storage of blocks. It contains metadata for managing the blockstore, including a magic number for integrity verification, global addresses for various maps and deques, and configuration limits for shreds, blocks, and transactions. The structure also includes fields for persistence, such as the most recently written slot and an archiver for managing archival files. It is designed to be aligned to mitigate false sharing and is not safe for multi-threaded writes to certain fields.


---
### fd\_blockstore\_shmem\_t
- **Type**: `struct`
- **Members**:
    - `magic`: A magic number used to verify the integrity of the blockstore memory.
    - `blockstore_gaddr`: Global address of the blockstore in memory.
    - `wksp_tag`: Tag used for workspace allocations.
    - `seed`: Hash seed used for various hash functions.
    - `archiver`: Metadata for the archival file format.
    - `mrw_slot`: Most recently written slot.
    - `lps`: Latest processed slot.
    - `hcs`: Highest confirmed slot.
    - `wmk`: Watermark, not to be modified directly.
    - `shred_max`: Maximum number of shreds that can be held in memory.
    - `block_max`: Maximum number of blocks that can be held in memory.
    - `idx_max`: Maximum number of blocks that can be indexed from the archival file.
    - `txn_max`: Maximum number of transactions that can be indexed from blocks.
    - `alloc_max`: Maximum bytes that can be allocated.
    - `block_idx_gaddr`: Global address of the block index map.
    - `slot_deque_gaddr`: Global address of the slot deque.
    - `txn_map_gaddr`: Global address of the transaction map.
    - `alloc_gaddr`: Global address of the allocator.
- **Description**: The `fd_blockstore_shmem_t` structure is a shared memory data structure used in the Firedancer blockstore system to manage metadata and configuration for in-memory indexing and durable storage of blocks. It includes fields for managing the memory layout, persistence, slot metadata, and configuration limits, as well as pointers to various maps and deques used for efficient data access and manipulation. This structure is aligned to mitigate false sharing and is critical for ensuring the integrity and performance of the blockstore operations.


---
### fd\_blockstore
- **Type**: `struct`
- **Members**:
    - `shmem`: A pointer to a shared memory region of type `fd_blockstore_shmem_t`.
    - `shred_pool`: An array of one `fd_buf_shred_pool_t` used for managing shred buffers.
    - `shred_map`: An array of one `fd_buf_shred_map_t` used for mapping shreds.
    - `block_map`: An array of one `fd_block_map_t` used for mapping blocks.
- **Description**: The `fd_blockstore` structure is a local join to a high-performance in-memory database designed for indexing and storing blocks. It contains a pointer to a shared memory region (`shmem`) that must be accessed with specific read/write functions to ensure data integrity. Additionally, it includes local join handles for managing shred buffers (`shred_pool`), mapping shreds (`shred_map`), and mapping blocks (`block_map`). This structure is crucial for managing the data flow and storage within the blockstore system, ensuring efficient access and manipulation of block data.


---
### fd\_blockstore\_t
- **Type**: `struct`
- **Members**:
    - `shmem`: Pointer to shared memory region for blockstore metadata and configuration.
    - `shred_pool`: Array of shred pools for managing memory allocation of shreds.
    - `shred_map`: Array of shred maps for indexing and accessing shreds.
    - `block_map`: Array of block maps for indexing and accessing block metadata.
- **Description**: The `fd_blockstore_t` structure represents a local join to a blockstore, which is a high-performance database designed for in-memory indexing and durable storage of blocks. It includes a pointer to a shared memory region (`shmem`) that holds metadata and configuration details, as well as local join handles for managing shreds and blocks through arrays of shred pools (`shred_pool`), shred maps (`shred_map`), and block maps (`block_map`). This structure is specific to the local address space and should not be shared across different processing units or tiles.


# Functions

---
### fd\_blockstore\_strerror<!-- {{#callable:fd_blockstore_strerror}} -->
The `fd_blockstore_strerror` function returns a human-readable string describing the error code passed to it.
- **Inputs**:
    - `err`: An integer representing an error code related to blockstore operations.
- **Control Flow**:
    - The function uses a switch statement to match the input error code against predefined constants.
    - For each matched case, it returns a corresponding string that describes the error.
    - If the error code does not match any predefined case, it defaults to returning "unknown".
- **Output**: A constant character pointer to a string describing the error code.


---
### fd\_blockstore\_align<!-- {{#callable:fd_blockstore_align}} -->
The `fd_blockstore_align` function returns the alignment requirement for the blockstore, which is defined as a constant value `FD_BLOCKSTORE_ALIGN`.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended to be used within the same translation unit and suggests inlining for performance.
    - It returns a constant value, `FD_BLOCKSTORE_ALIGN`, which is predefined as 128UL, representing the alignment requirement for the blockstore.
- **Output**: The function returns an unsigned long integer representing the alignment requirement for the blockstore, specifically 128UL.


---
### fd\_blockstore\_footprint<!-- {{#callable:fd_blockstore_footprint}} -->
The `fd_blockstore_footprint` function calculates the memory footprint required for a blockstore shared memory region based on various input parameters.
- **Inputs**:
    - `shred_max`: The maximum number of shreds that can be held in memory.
    - `block_max`: The maximum number of blocks that can be held in memory.
    - `idx_max`: The maximum number of blocks that can be indexed from the archival file.
    - `txn_max`: The maximum number of transactions that can be indexed from blocks.
- **Control Flow**:
    - The function first adjusts `block_max` to the nearest power of two using `fd_ulong_pow2_up`.
    - It calculates `lock_cnt` as the minimum of `block_max` and `BLOCK_INFO_LOCK_CNT`.
    - It determines `lg_idx_max` as the most significant bit of the nearest power of two of `idx_max`.
    - The function then calculates the total footprint by sequentially appending the sizes and alignments of various components using `FD_LAYOUT_APPEND` and finalizes the layout with `FD_LAYOUT_FINI`.
- **Output**: The function returns an `ulong` representing the total memory footprint required for the blockstore shared memory region.
- **Functions called**:
    - [`fd_blockstore_align`](#fd_blockstore_align)


---
### fd\_blockstore\_wksp<!-- {{#callable:fd_blockstore_wksp}} -->
The `fd_blockstore_wksp` function returns a pointer to the workspace backing the blockstore from a given blockstore structure.
- **Inputs**:
    - `blockstore`: A pointer to an `fd_blockstore_t` structure, which represents a local join to the blockstore.
- **Control Flow**:
    - The function takes a single argument, `blockstore`, which is a pointer to an `fd_blockstore_t` structure.
    - It calculates the address of the workspace by subtracting the `blockstore_gaddr` from the `shmem` pointer within the `blockstore` structure.
    - The result is cast to a `fd_wksp_t` pointer and returned.
- **Output**: A pointer to the `fd_wksp_t` structure representing the workspace backing the blockstore.


---
### fd\_blockstore\_wksp\_tag<!-- {{#callable:fd_blockstore_wksp_tag}} -->
The `fd_blockstore_wksp_tag` function retrieves the workspace allocation tag from a given blockstore.
- **Inputs**:
    - `blockstore`: A pointer to a constant `fd_blockstore_t` structure, representing the blockstore from which the workspace tag is to be retrieved.
- **Control Flow**:
    - Access the `shmem` member of the `blockstore` structure.
    - Return the `wksp_tag` member from the `shmem` structure.
- **Output**: The function returns an `ulong` representing the workspace allocation tag used by the blockstore.


---
### fd\_blockstore\_seed<!-- {{#callable:fd_blockstore_seed}} -->
The `fd_blockstore_seed` function retrieves the hash seed used by the blockstore for various hash functions from the blockstore's shared memory.
- **Inputs**:
    - `blockstore`: A pointer to a constant `fd_blockstore_t` structure, which represents the blockstore from which the seed is to be retrieved.
- **Control Flow**:
    - Access the `shmem` member of the `blockstore` structure, which points to the shared memory region of the blockstore.
    - Retrieve the `seed` value from the `shmem` structure.
- **Output**: The function returns an `ulong` representing the hash seed used by the blockstore.


---
### fd\_blockstore\_slot\_deque<!-- {{#callable:fd_blockstore_slot_deque}} -->
The `fd_blockstore_slot_deque` function retrieves a pointer to the slot deque within the blockstore's workspace.
- **Inputs**:
    - `blockstore`: A pointer to an `fd_blockstore_t` structure, representing the blockstore from which the slot deque is to be retrieved.
- **Control Flow**:
    - The function calls [`fd_blockstore_wksp`](#fd_blockstore_wksp) with the `blockstore` argument to get the workspace associated with the blockstore.
    - It then calls `fd_wksp_laddr_fast` with the workspace and the global address of the slot deque (`slot_deque_gaddr`) to get the local address of the slot deque.
    - Finally, it returns the local address of the slot deque.
- **Output**: A pointer to an `ulong` representing the local address of the slot deque in the blockstore's workspace.
- **Functions called**:
    - [`fd_blockstore_wksp`](#fd_blockstore_wksp)


---
### fd\_blockstore\_alloc<!-- {{#callable:fd_blockstore_alloc}} -->
The `fd_blockstore_alloc` function returns a pointer to the allocator associated with a given blockstore, which is used for managing workspace resources.
- **Inputs**:
    - `blockstore`: A pointer to an `fd_blockstore_t` structure, representing the blockstore from which the allocator is to be retrieved.
- **Control Flow**:
    - The function calls [`fd_blockstore_wksp`](#fd_blockstore_wksp) with the `blockstore` argument to get the workspace associated with the blockstore.
    - It then calls `fd_wksp_laddr_fast` with the workspace and the `alloc_gaddr` from the blockstore's shared memory to get the local address of the allocator.
    - Finally, it returns the pointer to the allocator.
- **Output**: A pointer to an `fd_alloc_t` structure, representing the allocator for the blockstore's workspace.
- **Functions called**:
    - [`fd_blockstore_wksp`](#fd_blockstore_wksp)


# Function Declarations (Public API)

---
### fd\_txn\_key\_equal<!-- {{#callable_declaration:fd_txn_key_equal}} -->
Compares two transaction keys for equality.
- **Description**: Use this function to determine if two transaction keys are identical. It is useful in scenarios where you need to verify if two transactions are the same based on their keys. This function should be called with valid pointers to transaction keys, and it assumes that both keys are fully initialized and non-null.
- **Inputs**:
    - `k0`: A pointer to the first transaction key to compare. Must not be null and should point to a valid, initialized fd_txn_key_t structure.
    - `k1`: A pointer to the second transaction key to compare. Must not be null and should point to a valid, initialized fd_txn_key_t structure.
- **Output**: Returns 1 if the keys are equal, 0 otherwise.
- **See also**: [`fd_txn_key_equal`](fd_blockstore.c.driver.md#fd_txn_key_equal)  (Implementation)


---
### fd\_txn\_key\_hash<!-- {{#callable_declaration:fd_txn_key_hash}} -->
Computes a hash for a transaction key with a given seed.
- **Description**: Use this function to generate a hash value for a transaction key, which can be useful for indexing or storing transaction data. The function takes a transaction key and a seed value, combines them, and returns a hash. This function is pure, meaning it has no side effects and its output depends only on its inputs. It is important to ensure that the transaction key is valid and properly initialized before calling this function.
- **Inputs**:
    - `k`: A pointer to a constant fd_txn_key_t structure representing the transaction key. The pointer must not be null, and the structure should be properly initialized before use.
    - `seed`: An unsigned long integer used as the initial value for the hash computation. It can be any valid ulong value.
- **Output**: Returns an unsigned long integer representing the computed hash value of the transaction key combined with the seed.
- **See also**: [`fd_txn_key_hash`](fd_blockstore.c.driver.md#fd_txn_key_hash)  (Implementation)


---
### fd\_blockstore\_new<!-- {{#callable_declaration:fd_blockstore_new}} -->
Formats a memory region into a blockstore.
- **Description**: This function initializes a memory region as a blockstore, which is a high-performance database for in-memory indexing and storing blocks. It should be called with a properly aligned and sized memory region, as determined by `fd_blockstore_align` and `fd_blockstore_footprint`. The function returns a pointer to the formatted blockstore on success, or NULL if the initialization fails. The caller is responsible for ensuring that the memory region is part of a workspace and that the parameters meet the required constraints.
- **Inputs**:
    - `shmem`: Pointer to the memory region to be formatted as a blockstore. Must not be null and must be aligned according to `fd_blockstore_align`.
    - `wksp_tag`: A non-zero tag used for workspace allocations. It identifies the blockstore's allocations within the workspace.
    - `seed`: An arbitrary value used as a hash seed for various hash functions within the blockstore.
    - `shred_max`: Maximum number of shreds that can be held in memory. Must be a power of two; if not, it will be rounded up to the nearest power of two.
    - `block_max`: Maximum number of blocks that can be held in memory. Will be rounded up to the nearest power of two if not already.
    - `idx_max`: Maximum number of blocks that can be indexed from the archival file. Should be a positive value.
    - `txn_max`: Maximum number of transactions that can be indexed from blocks. Should be a positive value.
- **Output**: Returns a pointer to the initialized blockstore on success, or NULL on failure.
- **See also**: [`fd_blockstore_new`](fd_blockstore.c.driver.md#fd_blockstore_new)  (Implementation)


---
### fd\_blockstore\_join<!-- {{#callable_declaration:fd_blockstore_join}} -->
Joins a blockstore to a local memory region.
- **Description**: This function is used to join a blockstore, which is a high-performance in-memory database for indexing and storing blocks, to a local memory region. It should be called when you need to access or manipulate the blockstore from a specific local address space. The function requires valid, aligned pointers to both the local join memory region and the shared blockstore memory region. It returns a handle to the local join on success, or NULL if any of the preconditions are not met, such as misalignment or invalid magic number in the blockstore.
- **Inputs**:
    - `ljoin`: A pointer to a memory region in the caller's address space that will hold information about the local join. Must not be null and must be aligned to the alignment requirements of fd_blockstore_t. Caller retains ownership.
    - `shblockstore`: A pointer to the memory region containing the blockstore. Must not be null and must be aligned to the alignment requirements of fd_blockstore_shmem_t. The blockstore must have a valid magic number. Caller retains ownership.
- **Output**: Returns a pointer to fd_blockstore_t on success, or NULL on failure if any preconditions are violated.
- **See also**: [`fd_blockstore_join`](fd_blockstore.c.driver.md#fd_blockstore_join)  (Implementation)


---
### fd\_blockstore\_leave<!-- {{#callable_declaration:fd_blockstore_leave}} -->
Leaves a blockstore, releasing associated resources.
- **Description**: This function is used to leave a blockstore, which involves releasing resources associated with the blockstore's various components. It should be called when the blockstore is no longer needed, ensuring that all resources are properly released. The function must be called with a valid blockstore that is part of a workspace. If the blockstore is null or not part of a workspace, the function will log a warning and return null. This function is typically used in cleanup routines to ensure that all resources are properly released before the application exits or the blockstore is re-initialized.
- **Inputs**:
    - `blockstore`: A pointer to an fd_blockstore_t structure representing the blockstore to leave. Must not be null and must be part of a workspace. If invalid, the function logs a warning and returns null.
- **Output**: Returns a pointer to the blockstore on success, or null if the blockstore is null or not part of a workspace.
- **See also**: [`fd_blockstore_leave`](fd_blockstore.c.driver.md#fd_blockstore_leave)  (Implementation)


---
### fd\_blockstore\_delete<!-- {{#callable_declaration:fd_blockstore_delete}} -->
Deletes a blockstore and returns a pointer to it.
- **Description**: Use this function to delete a blockstore that was previously created and is no longer needed. It performs necessary cleanup operations and ensures that the blockstore is properly removed from memory. This function should be called when the blockstore is no longer in use to free up resources. It is important to ensure that the blockstore is correctly aligned and has a valid magic number before calling this function. If the blockstore is null, misaligned, or has an invalid magic number, the function will log a warning and return null.
- **Inputs**:
    - `shblockstore`: A pointer to the shared blockstore to be deleted. It must not be null, must be properly aligned according to FD_BLOCKSTORE_ALIGN, and must have a valid magic number (FD_BLOCKSTORE_MAGIC). The caller retains ownership of the pointer.
- **Output**: Returns a pointer to the deleted blockstore if successful, or null if the input was invalid or the blockstore could not be deleted.
- **See also**: [`fd_blockstore_delete`](fd_blockstore.c.driver.md#fd_blockstore_delete)  (Implementation)


---
### fd\_blockstore\_init<!-- {{#callable_declaration:fd_blockstore_init}} -->
Initializes a blockstore with a given slot bank and archival file descriptor.
- **Description**: This function sets up a blockstore for use by initializing it with the provided slot bank and file descriptor for the archival file. It should be called when setting up a blockstore, typically after loading a snapshot or at genesis. The function ensures that the blockstore is ready for operations like live replay by populating necessary metadata. The archival file size must be at least 64MB, otherwise the function will log an error and return NULL. The caller must ensure that the blockstore is properly allocated and that the slot bank is valid before calling this function.
- **Inputs**:
    - `blockstore`: A pointer to an fd_blockstore_t structure that will be initialized. Must not be null and should point to a valid, allocated blockstore structure.
    - `fd`: A file descriptor for the blockstore archival file. It should be valid and open for reading and writing.
    - `fd_size_max`: The maximum size of the archival file in bytes. Must be at least 64MB; otherwise, the function will log an error and return NULL.
    - `slot_bank`: A pointer to a constant fd_slot_bank_t structure used to initialize fields in the blockstore. Must not be null and should contain valid slot bank data.
- **Output**: Returns a pointer to the initialized fd_blockstore_t on success, or NULL if the initialization fails due to invalid input or other errors.
- **See also**: [`fd_blockstore_init`](fd_blockstore.c.driver.md#fd_blockstore_init)  (Implementation)


---
### fd\_blockstore\_fini<!-- {{#callable_declaration:fd_blockstore_fini}} -->
Finalizes a blockstore by freeing all allocations.
- **Description**: Use this function to finalize a blockstore when it is no longer needed, ensuring that all resources are properly released. It must be called while holding the read lock to ensure thread safety. This function will remove all slots from the blockstore, regardless of their completion status, effectively freeing all associated memory allocations.
- **Inputs**:
    - `blockstore`: A pointer to an fd_blockstore_t structure representing the blockstore to be finalized. The caller must ensure this pointer is valid and that the read lock is held before calling this function.
- **Output**: None
- **See also**: [`fd_blockstore_fini`](fd_blockstore.c.driver.md#fd_blockstore_fini)  (Implementation)


---
### fd\_blockstore\_shred\_test<!-- {{#callable_declaration:fd_blockstore_shred_test}} -->
Checks if a shred is present in the blockstore.
- **Description**: Use this function to determine if a specific shred, identified by its slot and index, is already stored in the blockstore. This function is useful for verifying the presence of shreds before attempting operations that require their existence. It is a non-blocking call and can be used in concurrent environments. The function will return an error code if the shred map is corrupt, which should be handled appropriately by the caller.
- **Inputs**:
    - `blockstore`: A pointer to an fd_blockstore_t structure representing the blockstore to query. Must not be null.
    - `slot`: An unsigned long representing the slot number of the shred. Must be a valid slot number.
    - `idx`: An unsigned integer representing the index of the shred within the slot. Must be a valid index.
- **Output**: Returns 1 if the shred is present, 0 if it is not, and an error code if the shred map is corrupt.
- **See also**: [`fd_blockstore_shred_test`](fd_blockstore.c.driver.md#fd_blockstore_shred_test)  (Implementation)


---
### fd\_buf\_shred\_query\_copy\_data<!-- {{#callable_declaration:fd_buf_shred_query_copy_data}} -->
Copies shred data from the blockstore to a buffer.
- **Description**: This function queries the blockstore for a shred identified by a specific slot and index, and copies the shred data into a provided buffer. It should be used when you need to retrieve shred data from the blockstore for further processing or analysis. The function requires that the buffer size is at least as large as the maximum shred size, and it must be called while holding the read lock on the blockstore. If the buffer size is insufficient or if the shred cannot be found, the function returns -1.
- **Inputs**:
    - `blockstore`: A pointer to an fd_blockstore_t structure representing the blockstore to query. The caller must ensure this is a valid and initialized blockstore.
    - `slot`: An unsigned long representing the slot number of the shred to query. Must be a valid slot present in the blockstore.
    - `idx`: An unsigned integer representing the index of the shred within the slot. Must be a valid index for the specified slot.
    - `buf`: A pointer to a buffer where the shred data will be copied. Must not be null and must point to a memory region large enough to hold the maximum shred size.
    - `buf_sz`: An unsigned long representing the size of the buffer. Must be at least FD_SHRED_MAX_SZ to ensure the buffer can hold the shred data.
- **Output**: Returns the size of the copied shred data on success, or -1 on failure.
- **See also**: [`fd_buf_shred_query_copy_data`](fd_blockstore.c.driver.md#fd_buf_shred_query_copy_data)  (Implementation)


---
### fd\_blockstore\_block\_hash\_query<!-- {{#callable_declaration:fd_blockstore_block_hash_query}} -->
Queries the block hash for a specified slot in the blockstore.
- **Description**: Use this function to retrieve the block hash associated with a specific slot in the blockstore. It performs a blocking query, meaning it will repeatedly attempt to access the block hash until successful, without blocking concurrent writers. This function should be called when you need to verify or utilize the block hash for a given slot. Ensure that the blockstore is properly initialized and joined before calling this function. The function will return an error code if the slot is not found in the blockstore.
- **Inputs**:
    - `blockstore`: A pointer to an fd_blockstore_t structure representing the blockstore. Must not be null and should be a valid, initialized blockstore.
    - `slot`: An unsigned long integer representing the slot number for which the block hash is queried. Must be a valid slot number present in the blockstore.
    - `hash_out`: A pointer to an fd_hash_t structure where the block hash will be stored upon successful query. Must not be null.
- **Output**: Returns FD_BLOCKSTORE_SUCCESS on success, with the block hash written to hash_out. Returns FD_BLOCKSTORE_ERR_KEY if the slot is not found in the blockstore.
- **See also**: [`fd_blockstore_block_hash_query`](fd_blockstore.c.driver.md#fd_blockstore_block_hash_query)  (Implementation)


---
### fd\_blockstore\_bank\_hash\_query<!-- {{#callable_declaration:fd_blockstore_bank_hash_query}} -->
Performs a blocking query for the bank hash of a specified slot.
- **Description**: This function is used to retrieve the bank hash associated with a specific slot in the blockstore. It performs a blocking query, meaning it will wait until the query can be completed without interference from concurrent writers. The function should be called when you need to obtain the bank hash for a slot, which represents the execution state after the block for that slot has been executed. It returns a success code if the slot is found and the bank hash is successfully retrieved, or an error code if the slot is not present in the blockstore.
- **Inputs**:
    - `blockstore`: A pointer to an fd_blockstore_t structure representing the blockstore. Must not be null, and the blockstore should be properly initialized and joined.
    - `slot`: An unsigned long integer representing the slot number for which the bank hash is being queried. Must be a valid slot number within the blockstore.
    - `hash_out`: A pointer to an fd_hash_t structure where the bank hash will be stored. Must not be null, and the caller is responsible for ensuring it points to a valid memory location.
- **Output**: Returns FD_BLOCKSTORE_SUCCESS on success, with the bank hash written to the location pointed to by hash_out. Returns FD_BLOCKSTORE_ERR_KEY if the slot is not found in the blockstore.
- **See also**: [`fd_blockstore_bank_hash_query`](fd_blockstore.c.driver.md#fd_blockstore_bank_hash_query)  (Implementation)


---
### fd\_blockstore\_block\_map\_query<!-- {{#callable_declaration:fd_blockstore_block_map_query}} -->
Queries the blockstore for block metadata at a specified slot.
- **Description**: Use this function to retrieve metadata for a block at a given slot in the blockstore. It is intended for single-threaded or offline use cases, as it does not handle concurrent access. If the block metadata is not found, the function returns NULL. This function should not be used in live systems where concurrent access to the blockstore is expected.
- **Inputs**:
    - `blockstore`: A pointer to an fd_blockstore_t structure representing the blockstore to query. Must not be null.
    - `slot`: An unsigned long representing the slot number to query. Must be a valid slot number within the blockstore.
- **Output**: Returns a pointer to an fd_block_info_t structure containing the block metadata if the slot is found, or NULL if the slot is not in the blockstore.
- **See also**: [`fd_blockstore_block_map_query`](fd_blockstore.c.driver.md#fd_blockstore_block_map_query)  (Implementation)


---
### fd\_blockstore\_parent\_slot\_query<!-- {{#callable_declaration:fd_blockstore_parent_slot_query}} -->
Queries the parent slot of a given slot in the blockstore.
- **Description**: Use this function to retrieve the parent slot of a specified slot within a blockstore. It is a non-blocking operation that repeatedly attempts to query the block map until a valid result is obtained or the slot is determined to be missing. This function is useful for understanding the ancestry of slots in a blockstore, particularly in scenarios where the block map might be concurrently accessed or modified. It returns a special value if the slot is not found, indicating that the queried slot does not exist in the blockstore.
- **Inputs**:
    - `blockstore`: A pointer to an fd_blockstore_t structure representing the blockstore to query. Must not be null.
    - `slot`: The slot number for which the parent slot is being queried. Must be a valid slot number within the blockstore.
- **Output**: Returns the parent slot number if found, or FD_SLOT_NULL if the slot is not present in the blockstore.
- **See also**: [`fd_blockstore_parent_slot_query`](fd_blockstore.c.driver.md#fd_blockstore_parent_slot_query)  (Implementation)


---
### fd\_blockstore\_block\_map\_query\_volatile<!-- {{#callable_declaration:fd_blockstore_block_map_query_volatile}} -->
Queries the blockstore for volatile block map entry metadata.
- **Description**: Use this function to retrieve metadata for a block map entry at a specified slot in a blockstore. It is suitable for scenarios where only the metadata is needed and not the full block data. The function requires a valid file descriptor for seeking and reading operations. It returns an error if the slot is missing or if there are issues with file operations. Ensure that the blockstore is properly initialized before calling this function.
- **Inputs**:
    - `blockstore`: A pointer to an initialized fd_blockstore_t structure. Must not be null.
    - `fd`: A valid file descriptor for the blockstore's archival file. Used for seeking and reading operations.
    - `slot`: The slot number to query. Must be a valid slot within the blockstore.
    - `block_info_out`: A pointer to an fd_block_info_t structure where the queried metadata will be stored. Must not be null.
- **Output**: Returns FD_BLOCKSTORE_SUCCESS on success, or FD_BLOCKSTORE_ERR_SLOT_MISSING if the slot is not found or if there are file operation errors.
- **See also**: [`fd_blockstore_block_map_query_volatile`](fd_blockstore.c.driver.md#fd_blockstore_block_map_query_volatile)  (Implementation)


---
### fd\_blockstore\_txn\_query<!-- {{#callable_declaration:fd_blockstore_txn_query}} -->
Query transaction data for a given signature.
- **Description**: Use this function to retrieve transaction data associated with a specific signature from the blockstore. It is essential to hold the read lock on the blockstore before calling this function to ensure thread safety. This function is useful when you need to access transaction metadata or verify transaction existence within the blockstore.
- **Inputs**:
    - `blockstore`: A pointer to an fd_blockstore_t structure representing the blockstore to query. Must be a valid, non-null pointer, and the caller must hold the read lock.
    - `sig`: A constant pointer to an array of unsigned characters representing the transaction signature. The array must have a size of FD_ED25519_SIG_SZ and must not be null.
- **Output**: Returns a pointer to an fd_txn_map_t structure containing the transaction data if found, or NULL if the transaction is not present in the blockstore.
- **See also**: [`fd_blockstore_txn_query`](fd_blockstore.c.driver.md#fd_blockstore_txn_query)  (Implementation)


---
### fd\_blockstore\_txn\_query\_volatile<!-- {{#callable_declaration:fd_blockstore_txn_query_volatile}} -->
Query transaction data for a given signature in a thread-safe manner.
- **Description**: This function retrieves transaction data associated with a given signature from the blockstore in a thread-safe manner. It is useful when you need to access transaction metadata and optionally the transaction data itself. The function can be called when you have a valid blockstore and a file descriptor for the archival file. It handles cases where the transaction or slot might be missing, returning specific error codes in such scenarios. The function does not modify the blockstore or the archival file.
- **Inputs**:
    - `blockstore`: A pointer to an fd_blockstore_t structure representing the blockstore. Must not be null.
    - `fd`: An integer file descriptor for the archival file. Must be valid and open.
    - `sig`: A constant pointer to an array of unsigned characters representing the transaction signature. The array must have a size of FD_ED25519_SIG_SZ.
    - `txn_out`: A pointer to an fd_txn_map_t structure where the transaction metadata will be copied. Must not be null.
    - `blk_ts`: A pointer to a long where the block timestamp will be stored. Can be null if the timestamp is not needed.
    - `blk_flags`: A pointer to an unsigned char where the block flags will be stored. Can be null if the flags are not needed.
    - `txn_data_out`: An array of unsigned characters where the transaction data will be copied. The array must have a size of FD_TXN_MTU. Can be null if only metadata is needed.
- **Output**: Returns an integer status code: FD_BLOCKSTORE_SUCCESS on success, FD_BLOCKSTORE_ERR_SLOT_MISSING if the slot is missing, or FD_BLOCKSTORE_ERR_TXN_MISSING if the transaction is missing.
- **See also**: [`fd_blockstore_txn_query_volatile`](fd_blockstore.c.driver.md#fd_blockstore_txn_query_volatile)  (Implementation)


---
### fd\_blockstore\_block\_info\_test<!-- {{#callable_declaration:fd_blockstore_block_info_test}} -->
Checks if a block meta entry exists for a given slot.
- **Description**: Use this function to determine if a block meta entry is present for a specific slot in the blockstore. It returns a boolean-like integer indicating the presence of the entry. This function should not be called while in a block_map_t prepare state, as it is intended for use outside of any ongoing block map preparations.
- **Inputs**:
    - `blockstore`: A pointer to an fd_blockstore_t structure representing the blockstore to query. Must not be null.
    - `slot`: An unsigned long integer representing the slot number to check for a block meta entry. Must be a valid slot number within the blockstore.
- **Output**: Returns 1 if the block meta entry exists for the given slot, and 0 if it does not.
- **See also**: [`fd_blockstore_block_info_test`](fd_blockstore.c.driver.md#fd_blockstore_block_info_test)  (Implementation)


---
### fd\_blockstore\_block\_info\_remove<!-- {{#callable_declaration:fd_blockstore_block_info_remove}} -->
Removes a block meta entry for a specified slot from the blockstore.
- **Description**: Use this function to remove a block meta entry associated with a given slot from the blockstore. This operation is necessary when you want to delete metadata for a slot that is no longer needed. It is important to ensure that the caller is not in a block_map_t prepare state when invoking this function, as it may interfere with ongoing operations. The function will return a success code if the entry exists and is successfully removed, or an error code if the entry does not exist.
- **Inputs**:
    - `blockstore`: A pointer to an fd_blockstore_t structure representing the blockstore from which the block meta entry should be removed. The caller must ensure this pointer is valid and properly initialized.
    - `slot`: An unsigned long integer representing the slot for which the block meta entry should be removed. The slot must be a valid identifier within the blockstore.
- **Output**: Returns FD_BLOCKSTORE_SUCCESS if the block meta entry is successfully removed, or FD_BLOCKSTORE_ERR_SLOT_MISSING if the entry does not exist.
- **See also**: [`fd_blockstore_block_info_remove`](fd_blockstore.c.driver.md#fd_blockstore_block_info_remove)  (Implementation)


---
### fd\_blockstore\_slot\_remove<!-- {{#callable_declaration:fd_blockstore_slot_remove}} -->
Removes a slot from the blockstore.
- **Description**: This function removes a specified slot from the blockstore, including all associated internal structures. It should be used when a slot is no longer needed and can be safely removed. The function ensures that a slot with a replay in progress is not removed, and it handles the unlinking of the slot from its parent if it is not published. It is important to ensure that the caller is not in a block_map_t prepare state when calling this function.
- **Inputs**:
    - `blockstore`: A pointer to the fd_blockstore_t structure representing the blockstore from which the slot will be removed. Must not be null.
    - `slot`: The slot number to be removed from the blockstore. It should be a valid slot number that exists in the blockstore.
- **Output**: None
- **See also**: [`fd_blockstore_slot_remove`](fd_blockstore.c.driver.md#fd_blockstore_slot_remove)  (Implementation)


---
### fd\_blockstore\_shred\_insert<!-- {{#callable_declaration:fd_blockstore_shred_insert}} -->
Inserts a data shred into the blockstore.
- **Description**: Use this function to insert a data shred into the blockstore, ensuring that the shred is not already present and that it is valid for insertion. The function checks if the shred is a data shred and whether its slot is above the watermark. If a shred with the same key already exists, it will not be inserted again. This function manages its own locking, so the caller should not acquire any locks before calling it. It is important to ensure that the blockstore is properly initialized and that the shred is correctly formatted before calling this function.
- **Inputs**:
    - `blockstore`: A pointer to an fd_blockstore_t structure representing the blockstore where the shred will be inserted. Must not be null.
    - `shred`: A pointer to a constant fd_shred_t structure representing the shred to be inserted. Must not be null and must be a data shred. The function will not insert shreds with slots below the watermark or duplicate shreds with the same key.
- **Output**: None
- **See also**: [`fd_blockstore_shred_insert`](fd_blockstore.c.driver.md#fd_blockstore_shred_insert)  (Implementation)


---
### fd\_blockstore\_shred\_remove<!-- {{#callable_declaration:fd_blockstore_shred_remove}} -->
Removes a shred from the blockstore.
- **Description**: Use this function to remove a specific shred identified by its slot and index from the blockstore. This operation is typically performed when a shred is no longer needed or to free up resources. The function assumes that the blockstore is properly initialized and joined. It handles errors related to map corruption and pool inconsistencies internally, logging errors if such conditions are detected. This function should be used in contexts where the removal of shreds is necessary, such as cleanup operations or when managing memory constraints.
- **Inputs**:
    - `blockstore`: A pointer to an fd_blockstore_t structure representing the blockstore from which the shred will be removed. Must not be null and should be a valid, joined blockstore.
    - `slot`: An unsigned long representing the slot number of the shred to be removed. Must correspond to a valid slot in the blockstore.
    - `idx`: An unsigned integer representing the index of the shred within the specified slot. Must correspond to a valid shred index in the blockstore.
- **Output**: None
- **See also**: [`fd_blockstore_shred_remove`](fd_blockstore.c.driver.md#fd_blockstore_shred_remove)  (Implementation)


---
### fd\_blockstore\_slice\_query<!-- {{#callable_declaration:fd_blockstore_slice_query}} -->
Queries a block slice and copies shred payloads into a buffer.
- **Description**: Use this function to retrieve a slice of shreds from a blockstore, starting from a specified index and ending at another, inclusive. It is important to ensure that the indices provided are valid batch boundaries. The function will copy up to a specified maximum number of bytes of shred payloads into a provided buffer. If the buffer is too small to hold the data, the function will return an error. This function is lock-free and can be safely used with concurrent operations on the blockstore.
- **Inputs**:
    - `blockstore`: A pointer to an fd_blockstore_t structure representing the blockstore to query. Must not be null.
    - `slot`: The slot number to query within the blockstore. Must be a valid slot present in the blockstore.
    - `start_idx`: The starting index of the shred slice to query. Must be a valid batch boundary.
    - `end_idx`: The ending index of the shred slice to query, inclusive. Must be a valid batch boundary.
    - `max`: The maximum number of bytes to copy into the buffer. Must be large enough to hold the data, or an error will be returned.
    - `buf`: A pointer to a buffer where the shred payloads will be copied. Must not be null and should have enough space to hold up to 'max' bytes.
    - `buf_sz`: A pointer to an ulong where the function will store the number of bytes copied into the buffer. Must not be null.
- **Output**: Returns FD_BLOCKSTORE_SUCCESS on success, with 'buf' populated and 'buf_sz' set to the number of bytes copied. Returns a negative FD_MAP_ERR code on failure, and 'buf' and 'buf_sz' should be ignored.
- **See also**: [`fd_blockstore_slice_query`](fd_blockstore.c.driver.md#fd_blockstore_slice_query)  (Implementation)


---
### fd\_blockstore\_shreds\_complete<!-- {{#callable_declaration:fd_blockstore_shreds_complete}} -->
Check if all shreds for a given slot are complete.
- **Description**: Use this function to determine if all shreds for a specified slot in the blockstore are complete and ready for processing. It is useful in scenarios where you need to verify the completeness of shreds without accessing the actual block data. The function is non-blocking and safe to use concurrently with other operations on the blockstore. It returns a boolean-like integer indicating the completeness status of the shreds for the given slot.
- **Inputs**:
    - `blockstore`: A pointer to an fd_blockstore_t structure representing the blockstore. Must not be null, and the caller retains ownership.
    - `slot`: An unsigned long integer representing the slot number to check for shred completeness. Must be a valid slot number within the blockstore.
- **Output**: Returns 1 if all shreds for the specified slot are complete, and 0 if they are not complete or if the slot is not found.
- **See also**: [`fd_blockstore_shreds_complete`](fd_blockstore.c.driver.md#fd_blockstore_shreds_complete)  (Implementation)


---
### fd\_blockstore\_block\_height\_update<!-- {{#callable_declaration:fd_blockstore_block_height_update}} -->
Updates the block height for a specified slot in the blockstore.
- **Description**: Use this function to set the block height for a specific slot within the blockstore. It is important to ensure that the caller is not in a block_map_t prepare state when invoking this function. The function will attempt to update the block height if the slot exists in the blockstore. If the slot does not exist or an error occurs during the preparation phase, the function will return without making any changes.
- **Inputs**:
    - `blockstore`: A pointer to an fd_blockstore_t structure representing the blockstore. The caller must ensure this is a valid, non-null pointer.
    - `slot`: An unsigned long integer representing the slot for which the block height is to be updated. The slot must exist in the blockstore for the update to occur.
    - `height`: An unsigned long integer representing the new block height to be set for the specified slot.
- **Output**: None
- **See also**: [`fd_blockstore_block_height_update`](fd_blockstore.c.driver.md#fd_blockstore_block_height_update)  (Implementation)


---
### fd\_blockstore\_block\_height\_query<!-- {{#callable_declaration:fd_blockstore_block_height_query}} -->
Queries the block height for a given slot in the blockstore.
- **Description**: Use this function to retrieve the block height associated with a specific slot in the blockstore. This function is useful when you need to determine the height of a block for a given slot, which can be important for understanding the block's position in the blockchain. The function performs a blocking query, meaning it will wait until the block height is successfully retrieved. It is important to ensure that the blockstore is properly initialized and joined before calling this function.
- **Inputs**:
    - `blockstore`: A pointer to an fd_blockstore_t structure representing the blockstore. Must not be null and should be a valid, joined blockstore instance.
    - `slot`: An unsigned long integer representing the slot for which the block height is queried. Must be a valid slot number present in the blockstore.
- **Output**: Returns the block height as an unsigned long integer for the specified slot.
- **See also**: [`fd_blockstore_block_height_query`](fd_blockstore.c.driver.md#fd_blockstore_block_height_query)  (Implementation)


---
### fd\_blockstore\_publish<!-- {{#callable_declaration:fd_blockstore_publish}} -->
Publish blocks up to a specified watermark in the blockstore.
- **Description**: Use this function to publish blocks in the blockstore up to a specified watermark, which involves pruning non-finalized blocks and archiving finalized blocks to disk. This function should be called when you need to update the blockstore's state to reflect a new stable state of the blockchain. It is important to hold the write lock on the blockstore before calling this function to ensure thread safety and data integrity.
- **Inputs**:
    - `blockstore`: A pointer to an fd_blockstore_t structure representing the blockstore to be published. Must not be null, and the caller must hold the write lock on the blockstore.
    - `fd`: An integer file descriptor for the archival file where finalized blocks will be written. This parameter is currently unused in the function.
    - `wmk`: An unsigned long representing the new watermark up to which blocks should be published. It must be greater than the current watermark in the blockstore to have any effect.
- **Output**: None
- **See also**: [`fd_blockstore_publish`](fd_blockstore.c.driver.md#fd_blockstore_publish)  (Implementation)


---
### fd\_blockstore\_log\_block\_status<!-- {{#callable_declaration:fd_blockstore_log_block_status}} -->
Logs the status of blocks around a specified slot.
- **Description**: Use this function to log the status of blocks in the blockstore around a specified slot. It examines a range of slots from 5 slots before to 20 slots after the specified slot, logging the received, buffered, and completed indices for each slot. This function is useful for monitoring and debugging the state of blocks in the blockstore. It should be called when you need to inspect the block status for a range of slots, particularly around a specific point of interest. Ensure that the blockstore is properly initialized and joined before calling this function.
- **Inputs**:
    - `blockstore`: A pointer to an fd_blockstore_t structure representing the blockstore. Must not be null and should be a valid, initialized blockstore.
    - `around_slot`: An unsigned long integer specifying the slot around which to log block statuses. It determines the center of the range of slots to be logged.
- **Output**: None
- **See also**: [`fd_blockstore_log_block_status`](fd_blockstore.c.driver.md#fd_blockstore_log_block_status)  (Implementation)


---
### fd\_blockstore\_log\_mem\_usage<!-- {{#callable_declaration:fd_blockstore_log_mem_usage}} -->
Logs the memory usage of a blockstore in a human-readable format.
- **Description**: Use this function to log the current memory usage statistics of a blockstore, providing insights into the memory footprint of various components such as the shred pool, shred map, and transaction map. This function is useful for monitoring and debugging purposes to ensure that the blockstore is operating within expected memory constraints. It must be called while holding the read lock to ensure consistent and accurate logging of memory usage.
- **Inputs**:
    - `blockstore`: A pointer to an fd_blockstore_t structure representing the blockstore whose memory usage is to be logged. Must not be null, and the caller must hold the read lock when calling this function.
- **Output**: None
- **See also**: [`fd_blockstore_log_mem_usage`](fd_blockstore.c.driver.md#fd_blockstore_log_mem_usage)  (Implementation)


