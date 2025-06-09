# Purpose
The provided C source code implements a transaction cache system, which is designed to manage and store transaction data efficiently in a concurrent environment. This code is part of a larger system, likely a blockchain or distributed ledger technology, where transactions are processed and stored in a cache for quick access and manipulation. The primary components of this code include data structures for managing transactions, block hashes, and slots, as well as functions for inserting, querying, and managing these transactions within the cache.

The code defines several key data structures, such as `fd_txncache_private_txn`, `fd_txncache_private_txnpage`, `fd_txncache_private_blockcache`, and `fd_txncache_private_slotcache`, which are used to organize transactions by blockhash and slot. The cache is designed to handle concurrent access, using read-write locks (`fd_rwlock_t`) to ensure thread safety. The code includes functions for initializing and managing the cache ([`fd_txncache_new`](#fd_txncache_new), [`fd_txncache_join`](#fd_txncache_join), [`fd_txncache_delete`](#fd_txncache_delete)), inserting transactions ([`fd_txncache_insert_batch`](#fd_txncache_insert_batch)), querying transactions ([`fd_txncache_query_batch`](#fd_txncache_query_batch)), and handling special states like "constipated" slots, which are slots that cannot be flushed due to ongoing operations. The code also provides mechanisms for snapshotting the cache state and managing transaction hash offsets, which are crucial for maintaining consistency and efficiency in transaction processing.
# Imports and Dependencies

---
- `fd_txncache.h`
- `../fd_rwlock.h`
- `../../util/tmpl/fd_sort.c`


# Data Structures

---
### fd\_txncache\_private\_txn
- **Type**: `struct`
- **Members**:
    - `blockcache_next`: Pointer to the next element in the blockcache hash chain containing this entry from the pool.
    - `slotblockcache_next`: Pointer to the next element in the slotcache hash chain containing this entry from the pool.
    - `slot`: Slot that the transaction was executed, allowing multiple entries if executed in different slots on different forks.
    - `txnhash`: The transaction hash, truncated to 20 bytes, starting at an arbitrary offset.
    - `result`: The result of executing the transaction, with 0 indicating success.
- **Description**: The `fd_txncache_private_txn` structure is designed to store information about a transaction within a transaction cache system. It includes pointers to manage hash chains for block and slot caches, a slot identifier to track where the transaction was executed, a truncated transaction hash for efficient storage, and a result field to indicate the outcome of the transaction execution. This structure is part of a larger system that manages transaction data across different slots and forks, ensuring efficient access and storage.


---
### fd\_txncache\_private\_txn\_t
- **Type**: `struct`
- **Members**:
    - `blockcache_next`: Pointer to the next element in the blockcache hash chain containing this entry from the pool.
    - `slotblockcache_next`: Pointer to the next element in the slotcache hash chain containing this entry from the pool.
    - `slot`: Slot that the transaction was executed, allowing for multiple entries if executed in different slots on different forks.
    - `txnhash`: The transaction hash, truncated to 20 bytes, starting at an arbitrary offset.
    - `result`: The result of executing the transaction, with 0 indicating success.
- **Description**: The `fd_txncache_private_txn_t` structure represents a transaction entry within a transaction cache system. It includes pointers to manage linked lists for blockcache and slotcache, a slot identifier to track where the transaction was executed, a truncated transaction hash for identification, and a result field to indicate the outcome of the transaction execution. This structure is part of a larger system designed to efficiently manage and query transactions across different slots and blockhashes, supporting concurrent access and operations.


---
### fd\_txncache\_private\_txnpage
- **Type**: `struct`
- **Members**:
    - `free`: The number of free transaction entries in this page.
    - `txns`: An array of transactions in the page, with a fixed size defined by FD_TXNCACHE_TXNS_PER_PAGE.
- **Description**: The `fd_txncache_private_txnpage` structure is designed to manage a page of transaction entries within a transaction cache system. It contains a count of free transaction slots (`free`) and an array of transactions (`txns`) that can hold a predefined number of transactions per page. This structure is part of a larger system that handles transaction caching, likely for performance optimization in a concurrent environment.


---
### fd\_txncache\_private\_txnpage\_t
- **Type**: `struct`
- **Members**:
    - `free`: The number of free transaction entries in this page.
    - `txns`: An array of transactions contained within this page, with a fixed size defined by FD_TXNCACHE_TXNS_PER_PAGE.
- **Description**: The `fd_txncache_private_txnpage_t` structure is designed to manage a page of transactions within a transaction cache system. It contains a count of free transaction slots and an array of transactions, allowing for efficient allocation and management of transaction entries. This structure is part of a larger system that handles transaction caching, ensuring that transactions are stored and retrieved efficiently within a defined memory space.


---
### fd\_txncache\_private\_blockcache
- **Type**: `struct`
- **Members**:
    - `blockhash`: An array of 32 unsigned characters representing the actual blockhash of the transactions.
    - `max_slot`: An unsigned long representing the maximum slot seen that contains a transaction referencing this blockhash.
    - `txnhash_offset`: An unsigned long indicating the offset used to truncate the transaction hash to 20 bytes.
    - `heads`: An array of unsigned integers serving as a hash table for the blockhash, each entry pointing to the head of a linked list of transactions.
    - `pages_cnt`: An unsigned short representing the number of transaction pages currently in use to store transactions in this blockcache.
    - `pages`: A pointer to an array of unsigned integers listing the transaction pages containing the transactions for this blockcache.
- **Description**: The `fd_txncache_private_blockcache` structure is designed to manage and store transactions associated with a specific blockhash in a transaction cache system. It maintains a hash table to efficiently reference transactions by their truncated hashes, which are stored in linked lists. The structure also tracks the maximum slot number for transactions referencing the blockhash to determine when entries can be purged. Additionally, it manages memory usage by keeping a count of transaction pages in use and a list of these pages, allowing for efficient storage and retrieval of transaction data.


---
### fd\_txncache\_private\_blockcache\_t
- **Type**: `struct`
- **Members**:
    - `blockhash`: The actual blockhash of these transactions, stored as a 32-byte array.
    - `max_slot`: The maximum slot observed that contains a transaction referencing this blockhash.
    - `txnhash_offset`: Offset used to truncate transaction hashes to 20 bytes for memory efficiency.
    - `heads`: Hash table for the blockhash, each entry points to the head of a linked list of transactions.
    - `pages_cnt`: The number of transaction pages currently in use for this blockcache.
    - `pages`: List of transaction pages containing transactions for this blockcache.
- **Description**: The `fd_txncache_private_blockcache_t` structure is designed to manage a cache of transactions associated with a specific blockhash. It includes a 32-byte blockhash, a maximum slot number to track the latest slot with transactions referencing the blockhash, and an offset for truncating transaction hashes to save memory. The structure also contains a hash table (`heads`) for quick access to transactions, a count of transaction pages (`pages_cnt`), and a list of these pages (`pages`) to efficiently store and retrieve transactions. This structure is part of a larger transaction caching system that supports concurrent access and is optimized for performance in environments with high transaction volumes.


---
### fd\_txncache\_private\_slotblockcache
- **Type**: `struct`
- **Members**:
    - `blockhash`: The actual blockhash of these transactions.
    - `txnhash_offset`: As described above.
    - `heads`: A map of the head of a linked list of transactions in this slot and blockhash.
- **Description**: The `fd_txncache_private_slotblockcache` structure is designed to manage a cache of transactions associated with a specific blockhash and slot. It contains a 32-byte array `blockhash` to store the blockhash of the transactions, a `txnhash_offset` to indicate the offset for transaction hash truncation, and an array `heads` that serves as a map for the head of linked lists of transactions within the slot and blockhash. This structure is part of a larger transaction caching system that supports efficient transaction lookup and management in a concurrent environment.


---
### fd\_txncache\_private\_slotblockcache\_t
- **Type**: `struct`
- **Members**:
    - `blockhash`: The actual blockhash of these transactions.
    - `txnhash_offset`: Offset for the truncated transaction hash.
    - `heads`: A map of the head of a linked list of transactions in this slot and blockhash.
- **Description**: The `fd_txncache_private_slotblockcache_t` structure is designed to manage a cache of transactions associated with a specific blockhash and slot. It contains a blockhash, an offset for the transaction hash, and a map of linked list heads for transactions, facilitating efficient transaction lookup and management within a slot and blockhash context.


---
### fd\_txncache\_private\_slotcache
- **Type**: `struct`
- **Members**:
    - `slot`: The slot that this slotcache is for.
    - `blockcache`: An array of 300 slotblockcache structures associated with the slot.
- **Description**: The `fd_txncache_private_slotcache` structure is designed to manage transaction caches associated with specific slots in a blockchain or distributed ledger system. It contains a `slot` field to identify the specific slot it is associated with, and a `blockcache` array of 300 `fd_txncache_private_slotblockcache_t` structures, which are used to store and manage transaction data related to different blockhashes within that slot. This structure is part of a larger transaction caching system that supports concurrent access and efficient querying of transaction data.


---
### fd\_txncache\_private\_slotcache\_t
- **Type**: `struct`
- **Members**:
    - `slot`: The slot that this slotcache is for.
    - `blockcache`: An array of 300 slotblockcache structures, each representing a blockhash and its associated transactions for this slot.
- **Description**: The `fd_txncache_private_slotcache_t` structure is designed to manage transaction data associated with a specific slot in a transaction cache system. It contains a `slot` field indicating the slot number and an array of `fd_txncache_private_slotblockcache_t` structures, each representing a blockhash and its associated transactions for that slot. This structure is part of a larger system that handles transaction caching, allowing for efficient querying and management of transactions by slot and blockhash.


---
### fd\_txncache\_private
- **Type**: `struct`
- **Members**:
    - `lock`: A read-write lock for managing concurrent access to the transaction cache.
    - `root_slots_max`: The maximum number of root slots that can be tracked.
    - `live_slots_max`: The maximum number of live slots that can be tracked.
    - `constipated_slots_max`: The maximum number of constipated slots that can be supported.
    - `txnpages_per_blockhash_max`: The maximum number of transaction pages per blockhash.
    - `txnpages_max`: The maximum number of transaction pages.
    - `root_slots_cnt`: The current count of root slots being tracked.
    - `root_slots_off`: Offset to the array of root slots.
    - `blockcache_off`: Offset to the blockcache, which maps blockhashes to transactions.
    - `slotcache_off`: Offset to the slotcache, which maps slots to transactions.
    - `txnpages_free_cnt`: The count of free transaction pages.
    - `txnpages_free_off`: Offset to the array of free transaction pages.
    - `txnpages_off`: Offset to the actual storage for transactions.
    - `blockcache_pages_off`: Offset to the pages for blockcache entries.
    - `probed_entries_off`: Offset to the map of probed entries.
    - `constipated_slots_cnt`: The count of constipated root slots being tracked.
    - `constipated_slots_off`: Offset to the array of constipated slots.
    - `is_constipated`: Flag indicating if the cache is in a constipated state.
    - `is_constipated_off`: Offset related to the constipated state.
    - `magic`: A magic number for validation, expected to be FD_TXNCACHE_MAGIC.
- **Description**: The `fd_txncache_private` structure is a complex data structure designed to manage a transaction cache in a concurrent environment. It supports operations such as insertion, querying, and management of transactions across multiple threads, using a read-write lock for synchronization. The structure maintains various caches and offsets for efficient transaction storage and retrieval, including root slots, blockhash-based caches, and slot-based caches. It also handles special states like 'constipated' mode, where transaction eviction is temporarily halted to ensure consistency during snapshot operations. The structure is aligned according to `FD_TXNCACHE_ALIGN` and includes a magic number for integrity checks.


# Functions

---
### fd\_txncache\_get\_root\_slots<!-- {{#callable:fd_txncache_get_root_slots}} -->
The `fd_txncache_get_root_slots` function retrieves the pointer to the array of root slots from a transaction cache structure.
- **Inputs**:
    - `tc`: A pointer to an `fd_txncache_t` structure, which represents the transaction cache from which the root slots are to be retrieved.
- **Control Flow**:
    - The function takes a pointer to an `fd_txncache_t` structure as input.
    - It calculates the address of the root slots by adding the `root_slots_off` offset to the base address of the transaction cache structure.
    - The function returns the calculated address cast to a pointer to `ulong`.
- **Output**: A pointer to an array of `ulong` representing the root slots in the transaction cache.


---
### fd\_txncache\_get\_constipated\_slots<!-- {{#callable:fd_txncache_get_constipated_slots}} -->
The function `fd_txncache_get_constipated_slots` retrieves a pointer to the array of constipated slots within a transaction cache structure.
- **Inputs**:
    - `tc`: A pointer to an `fd_txncache_t` structure, which represents the transaction cache from which the constipated slots are to be retrieved.
- **Control Flow**:
    - The function calculates the address of the constipated slots array by adding the offset `constipated_slots_off` to the base address of the transaction cache structure `tc`.
    - It casts the resulting address to a pointer of type `ulong *` and returns it.
- **Output**: A pointer to an array of `ulong` representing the constipated slots in the transaction cache.


---
### fd\_txncache\_get\_txnpages\_free<!-- {{#callable:fd_txncache_get_txnpages_free}} -->
The function `fd_txncache_get_txnpages_free` retrieves a pointer to the array of free transaction pages within a transaction cache structure.
- **Inputs**:
    - `tc`: A pointer to an `fd_txncache_t` structure, which represents the transaction cache from which the free transaction pages are to be retrieved.
- **Control Flow**:
    - The function takes a single argument, `tc`, which is a pointer to a transaction cache structure.
    - It calculates the address of the free transaction pages by adding the offset `txnpages_free_off` to the base address of the transaction cache structure, `tc`.
    - The calculated address is cast to a `uint *` type and returned.
- **Output**: A pointer to a `uint` array representing the free transaction pages in the transaction cache.


---
### fd\_txncache\_get\_probed\_entries<!-- {{#callable:fd_txncache_get_probed_entries}} -->
The function `fd_txncache_get_probed_entries` retrieves a pointer to the probed entries array within a transaction cache structure.
- **Inputs**:
    - `tc`: A pointer to an `fd_txncache_t` structure, representing the transaction cache from which the probed entries are to be retrieved.
- **Control Flow**:
    - The function takes a single argument, a pointer to an `fd_txncache_t` structure.
    - It calculates the address of the probed entries by adding the offset `probed_entries_off` to the base address of the transaction cache structure `tc`.
    - The calculated address is cast to a pointer to `ulong` and returned.
- **Output**: A pointer to an array of `ulong` representing the probed entries in the transaction cache.


---
### fd\_txncache\_get\_probed\_entries\_const<!-- {{#callable:fd_txncache_get_probed_entries_const}} -->
The function `fd_txncache_get_probed_entries_const` retrieves a pointer to the probed entries array from a constant transaction cache structure.
- **Inputs**:
    - `tc`: A pointer to a constant `fd_txncache_t` structure, representing the transaction cache from which the probed entries are to be retrieved.
- **Control Flow**:
    - The function calculates the address of the probed entries by adding the offset `probed_entries_off` to the base address of the transaction cache `tc`.
    - It casts the resulting address to a pointer of type `ulong *` and returns it.
- **Output**: A pointer to an array of `ulong` representing the probed entries in the transaction cache.


---
### fd\_txncache\_max\_txnpages\_per\_blockhash<!-- {{#callable:fd_txncache_max_txnpages_per_blockhash}} -->
The function `fd_txncache_max_txnpages_per_blockhash` calculates the maximum number of transaction pages needed to store all transactions referencing a single blockhash, given a maximum number of transactions per slot.
- **Inputs**:
    - `max_txn_per_slot`: The maximum number of transactions that can occur in a single slot.
- **Control Flow**:
    - Calculate the maximum number of transactions that could reference a single blockhash over 150 slots, which is `max_txn_per_slot * 150`.
    - Divide this number by the number of transactions per page (`FD_TXNCACHE_TXNS_PER_PAGE`) to determine the number of pages needed, adding 1 to account for any remainder.
    - Check if the calculated number of pages exceeds `USHORT_MAX`; if so, return 0.
    - Otherwise, cast the result to `ushort` and return it.
- **Output**: The function returns a `ushort` representing the maximum number of transaction pages needed, or 0 if the calculated number exceeds `USHORT_MAX`.


---
### fd\_txncache\_max\_txnpages<!-- {{#callable:fd_txncache_max_txnpages}} -->
The `fd_txncache_max_txnpages` function calculates the maximum number of transaction pages needed to store all transactions in live slots, considering potential page wastage.
- **Inputs**:
    - `max_live_slots`: The maximum number of slots that can be live at any given time.
    - `max_txn_per_slot`: The maximum number of transactions that can be stored in a single slot.
- **Control Flow**:
    - Calculate the number of pages needed for a fully populated blockhash using the formula `(max_live_slots*max_txn_per_slot)/FD_TXNCACHE_TXNS_PER_PAGE`.
    - Add one page for each of the remaining blockhashes, resulting in `max_live_slots-1UL+max_live_slots*(1UL+(max_txn_per_slot-1UL)/FD_TXNCACHE_TXNS_PER_PAGE)` pages.
    - Check if the calculated result exceeds `UINT_MAX`, and if so, return 0.
    - Otherwise, cast the result to `uint` and return it.
- **Output**: Returns the maximum number of transaction pages as a `uint`, or 0 if the result exceeds `UINT_MAX`.


---
### fd\_txncache\_align<!-- {{#callable:fd_txncache_align}} -->
The `fd_txncache_align` function returns the alignment requirement for the transaction cache structure.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a constant function, indicating it does not modify any state and always returns the same value.
    - It directly returns the value of the macro `FD_TXNCACHE_ALIGN`.
- **Output**: The function returns an unsigned long integer representing the alignment requirement for the transaction cache.


---
### fd\_txncache\_footprint<!-- {{#callable:fd_txncache_footprint}} -->
The `fd_txncache_footprint` function calculates the memory footprint required for a transaction cache based on specified parameters.
- **Inputs**:
    - `max_rooted_slots`: The maximum number of rooted slots that the transaction cache can support.
    - `max_live_slots`: The maximum number of live slots that the transaction cache can support.
    - `max_txn_per_slot`: The maximum number of transactions per slot that the transaction cache can support.
    - `max_constipated_slots`: The maximum number of constipated slots that the transaction cache can support.
- **Control Flow**:
    - Check if `max_rooted_slots` or `max_live_slots` is less than 1, returning 0 if true.
    - Check if `max_live_slots` is less than `max_rooted_slots`, returning 0 if true.
    - Check if `max_txn_per_slot` is less than 1, returning 0 if true.
    - Check if `max_live_slots` or `max_txn_per_slot` is not a power of 2, returning 0 if true.
    - Calculate `max_txnpages` using [`fd_txncache_max_txnpages`](#fd_txncache_max_txnpages) and return 0 if it is 0.
    - Calculate `max_txnpages_per_blockhash` using [`fd_txncache_max_txnpages_per_blockhash`](#fd_txncache_max_txnpages_per_blockhash) and return 0 if it is 0.
    - Initialize a layout variable `l` with `FD_LAYOUT_INIT`.
    - Append various memory allocations to `l` using `FD_LAYOUT_APPEND` for different components of the transaction cache.
    - Return the final calculated footprint using `FD_LAYOUT_FINI`.
- **Output**: The function returns the calculated memory footprint as an unsigned long integer, or 0 if any validation checks fail.
- **Functions called**:
    - [`fd_txncache_max_txnpages`](#fd_txncache_max_txnpages)
    - [`fd_txncache_max_txnpages_per_blockhash`](#fd_txncache_max_txnpages_per_blockhash)


---
### fd\_txncache\_new<!-- {{#callable:fd_txncache_new}} -->
The `fd_txncache_new` function initializes a new transaction cache in shared memory with specified parameters for rooted slots, live slots, transactions per slot, and constipated slots.
- **Inputs**:
    - `shmem`: A pointer to the shared memory region where the transaction cache will be initialized.
    - `max_rooted_slots`: The maximum number of rooted slots that the transaction cache can handle.
    - `max_live_slots`: The maximum number of live slots that the transaction cache can handle, which must be a power of two and greater than or equal to `max_rooted_slots`.
    - `max_txn_per_slot`: The maximum number of transactions per slot, which must be a power of two.
    - `max_constipated_slots`: The maximum number of constipated slots that the transaction cache can handle.
- **Control Flow**:
    - Check if `shmem` is NULL or misaligned and return NULL if so.
    - Validate input parameters: `max_rooted_slots`, `max_live_slots`, `max_txn_per_slot`, and ensure they are powers of two where required.
    - Calculate `max_txnpages` and `max_txnpages_per_blockhash` using helper functions and return NULL if they are zero.
    - Initialize scratch memory allocations for various components of the transaction cache, such as root slots, blockcache, slotcache, and transaction pages.
    - Set offsets for these allocations in the transaction cache structure.
    - Initialize various counters and maximum values in the transaction cache structure.
    - Set initial values for root slots and constipated slots to indicate they are empty.
    - Initialize blockcache and slotcache entries to indicate they are empty.
    - Initialize free transaction pages and set their indices.
    - Set the transaction cache's magic number to indicate successful initialization.
    - Return a pointer to the initialized transaction cache.
- **Output**: A pointer to the initialized transaction cache structure, or NULL if initialization fails due to invalid inputs or memory alignment issues.
- **Functions called**:
    - [`fd_txncache_align`](#fd_txncache_align)
    - [`fd_txncache_max_txnpages`](#fd_txncache_max_txnpages)
    - [`fd_txncache_max_txnpages_per_blockhash`](#fd_txncache_max_txnpages_per_blockhash)


---
### fd\_txncache\_join<!-- {{#callable:fd_txncache_join}} -->
The `fd_txncache_join` function validates and initializes a transaction cache structure from a shared memory pointer.
- **Inputs**:
    - `shtc`: A pointer to the shared memory region that is expected to contain a transaction cache structure.
- **Control Flow**:
    - Check if the input pointer `shtc` is NULL and log a warning if it is, returning NULL.
    - Verify that `shtc` is properly aligned according to `fd_txncache_align()` and log a warning if it is not, returning NULL.
    - Cast `shtc` to a `fd_txncache_t` pointer and check if its `magic` field matches `FD_TXNCACHE_MAGIC`, logging a warning and returning NULL if it does not.
    - Calculate the base address of the transaction cache and obtain a pointer to the block cache using the offset stored in the transaction cache structure.
    - Iterate over the live slots, initializing the `pages` field of each block cache entry to point to the appropriate location in memory.
    - Return the initialized transaction cache pointer.
- **Output**: A pointer to the initialized `fd_txncache_t` structure, or NULL if any validation checks fail.
- **Functions called**:
    - [`fd_txncache_align`](#fd_txncache_align)


---
### fd\_txncache\_leave<!-- {{#callable:fd_txncache_leave}} -->
The `fd_txncache_leave` function checks if a given transaction cache pointer is valid and returns it as a void pointer, logging a warning if the pointer is NULL.
- **Inputs**:
    - `tc`: A pointer to a `fd_txncache_t` structure, representing the transaction cache to be left.
- **Control Flow**:
    - Check if the input pointer `tc` is NULL using `FD_UNLIKELY` macro.
    - If `tc` is NULL, log a warning message 'NULL tc' and return NULL.
    - If `tc` is not NULL, cast it to a void pointer and return it.
- **Output**: Returns the input transaction cache pointer `tc` cast to a void pointer, or NULL if `tc` is NULL.


---
### fd\_txncache\_delete<!-- {{#callable:fd_txncache_delete}} -->
The `fd_txncache_delete` function invalidates a transaction cache by checking its alignment and magic number, then setting its magic number to zero.
- **Inputs**:
    - `shtc`: A pointer to the shared transaction cache object to be deleted.
- **Control Flow**:
    - Check if the input pointer `shtc` is NULL; if so, log a warning and return NULL.
    - Check if `shtc` is aligned according to [`fd_txncache_align`](#fd_txncache_align); if not, log a warning and return NULL.
    - Cast `shtc` to a `fd_txncache_t` pointer and store it in `tc`.
    - Check if the `magic` field of `tc` is equal to `FD_TXNCACHE_MAGIC`; if not, log a warning and return NULL.
    - Use memory fences to ensure memory operations are completed, then set the `magic` field of `tc` to zero.
    - Return the pointer `tc` cast to a `void *`.
- **Output**: A pointer to the transaction cache object if successful, or NULL if any checks fail.
- **Functions called**:
    - [`fd_txncache_align`](#fd_txncache_align)


---
### fd\_txncache\_remove\_blockcache\_idx<!-- {{#callable:fd_txncache_remove_blockcache_idx}} -->
The `fd_txncache_remove_blockcache_idx` function removes a block cache entry at a specified index from a transaction cache, updates overflow tracking, and frees associated transaction pages.
- **Inputs**:
    - `tc`: A pointer to the transaction cache (`fd_txncache_t`) from which a block cache entry is to be removed.
    - `idx`: The index (`ulong`) of the block cache entry to be removed.
- **Control Flow**:
    - Retrieve the block cache, probed entries, and free transaction pages from the transaction cache using helper functions.
    - Calculate the hash index for the block cache entry to be removed using the block hash and the maximum number of live slots.
    - Iterate from the calculated hash index to the specified index, decrementing the probed entries count for each index.
    - If a probed entry count reaches zero and the corresponding block cache entry is a tombstone, mark it as empty.
    - Set the `max_slot` of the block cache entry at the specified index to empty or tombstone based on the probed entries count.
    - Copy the pages associated with the block cache entry to the free transaction pages array and update the free pages count.
- **Output**: This function does not return a value; it performs operations directly on the transaction cache structure.
- **Functions called**:
    - [`fd_txncache_get_probed_entries`](#fd_txncache_get_probed_entries)
    - [`fd_txncache_get_txnpages_free`](#fd_txncache_get_txnpages_free)


---
### fd\_txncache\_remove\_slotcache\_idx<!-- {{#callable:fd_txncache_remove_slotcache_idx}} -->
The function `fd_txncache_remove_slotcache_idx` marks a specific slot in the slot cache as a tombstone entry, indicating it is deleted or inactive.
- **Inputs**:
    - `tc`: A pointer to the transaction cache (`fd_txncache_t`) from which the slot cache is to be accessed.
    - `idx`: An unsigned long integer representing the index of the slot cache entry to be marked as a tombstone.
- **Control Flow**:
    - Retrieve the slot cache from the transaction cache using `fd_txncache_get_slotcache` function.
    - Access the slot cache entry at the specified index `idx`.
    - Set the `slot` field of the slot cache entry to `FD_TXNCACHE_TOMBSTONE_ENTRY`, marking it as a tombstone.
- **Output**: The function does not return any value; it performs an in-place modification of the slot cache entry.


---
### fd\_txncache\_purge\_slot<!-- {{#callable:fd_txncache_purge_slot}} -->
The `fd_txncache_purge_slot` function purges entries from a transaction cache that are associated with slots less than or equal to a specified slot number.
- **Inputs**:
    - `tc`: A pointer to the transaction cache (`fd_txncache_t`) from which entries will be purged.
    - `slot`: An unsigned long integer representing the slot number; entries with slots less than or equal to this will be purged.
- **Control Flow**:
    - Initialize counters for not purged, purged, max distance, sum distance, empty entry, and tombstone entry counts.
    - Retrieve the blockcache from the transaction cache using `fd_txncache_get_blockcache`.
    - Iterate over each entry in the blockcache up to `tc->live_slots_max`.
    - For each entry, check if it is empty, a tombstone, or has a max slot greater than the specified slot; update respective counters and continue if true.
    - If the entry does not meet the above conditions, remove it using [`fd_txncache_remove_blockcache_idx`](#fd_txncache_remove_blockcache_idx) and increment the purged count.
    - Calculate the average distance for not purged entries.
    - Log the purging statistics including the number of purged and not purged entries, empty and tombstone entries, max distance, and average distance.
    - Retrieve the slotcache from the transaction cache using `fd_txncache_get_slotcache`.
    - Iterate over each entry in the slotcache up to `tc->live_slots_max`.
    - For each entry, check if it is empty, a tombstone, or has a slot greater than the specified slot; continue if true.
    - If the entry does not meet the above conditions, remove it using [`fd_txncache_remove_slotcache_idx`](#fd_txncache_remove_slotcache_idx).
- **Output**: The function does not return a value; it performs its operations directly on the transaction cache data structure.
- **Functions called**:
    - [`fd_txncache_remove_blockcache_idx`](#fd_txncache_remove_blockcache_idx)
    - [`fd_txncache_remove_slotcache_idx`](#fd_txncache_remove_slotcache_idx)


---
### fd\_txncache\_register\_root\_slot\_private<!-- {{#callable:fd_txncache_register_root_slot_private}} -->
The function `fd_txncache_register_root_slot_private` registers a new root slot in the transaction cache, ensuring it is inserted in the correct order and purging old slots if necessary.
- **Inputs**:
    - `tc`: A pointer to the transaction cache structure (`fd_txncache_t`) where the root slot is to be registered.
    - `slot`: The slot number (`ulong`) to be registered as a root slot in the transaction cache.
- **Control Flow**:
    - Retrieve the current list of root slots using [`fd_txncache_get_root_slots`](#fd_txncache_get_root_slots) function.
    - Iterate through the existing root slots to find the correct position for the new slot or to check if it already exists.
    - If the slot already exists, return immediately without making changes.
    - If the slot should be inserted before an existing slot, break the loop to insert it at the correct position.
    - Check if the current number of root slots has reached the maximum allowed (`root_slots_max`).
    - If the maximum is reached and the new slot is not the smallest, purge the oldest slot and shift the remaining slots to make space for the new slot.
    - If the maximum is reached and the new slot is the smallest, purge the new slot without adding it.
    - If there is space available, insert the new slot at the correct position and increment the root slot count.
- **Output**: The function does not return a value; it modifies the transaction cache structure in place.
- **Functions called**:
    - [`fd_txncache_get_root_slots`](#fd_txncache_get_root_slots)
    - [`fd_txncache_purge_slot`](#fd_txncache_purge_slot)


---
### fd\_txncache\_register\_root\_slot<!-- {{#callable:fd_txncache_register_root_slot}} -->
The `fd_txncache_register_root_slot` function registers a given slot as a root slot in the transaction cache, ensuring thread safety with a write lock.
- **Inputs**:
    - `tc`: A pointer to the `fd_txncache_t` structure representing the transaction cache.
    - `slot`: An unsigned long integer representing the slot to be registered as a root slot.
- **Control Flow**:
    - Acquire a write lock on the transaction cache using `fd_rwlock_write` to ensure exclusive access.
    - Call the helper function [`fd_txncache_register_root_slot_private`](#fd_txncache_register_root_slot_private) to perform the actual registration of the root slot.
    - Release the write lock using `fd_rwlock_unwrite` to allow other operations on the transaction cache.
- **Output**: This function does not return a value; it performs its operation directly on the transaction cache structure.
- **Functions called**:
    - [`fd_txncache_register_root_slot_private`](#fd_txncache_register_root_slot_private)


---
### fd\_txncache\_register\_constipated\_slot<!-- {{#callable:fd_txncache_register_constipated_slot}} -->
The function `fd_txncache_register_constipated_slot` registers a slot as constipated in the transaction cache, ensuring it does not exceed the maximum allowed constipated slots.
- **Inputs**:
    - `tc`: A pointer to the `fd_txncache_t` structure representing the transaction cache.
    - `slot`: An unsigned long integer representing the slot to be registered as constipated.
- **Control Flow**:
    - Acquire a write lock on the transaction cache using `fd_rwlock_write` to ensure thread safety.
    - Check if the current count of constipated slots has reached the maximum allowed (`constipated_slots_max`).
    - If the maximum is exceeded, log an error message using `FD_LOG_ERR`.
    - Retrieve the array of constipated slots using [`fd_txncache_get_constipated_slots`](#fd_txncache_get_constipated_slots).
    - Add the provided slot to the constipated slots array and increment the count of constipated slots.
    - Release the write lock on the transaction cache using `fd_rwlock_unwrite`.
- **Output**: The function does not return a value; it modifies the state of the transaction cache by adding a slot to the constipated slots list.
- **Functions called**:
    - [`fd_txncache_get_constipated_slots`](#fd_txncache_get_constipated_slots)


---
### fd\_txncache\_flush\_constipated\_slots<!-- {{#callable:fd_txncache_flush_constipated_slots}} -->
The function `fd_txncache_flush_constipated_slots` registers all previously constipated slots into the status cache and resets the constipation state.
- **Inputs**:
    - `tc`: A pointer to an `fd_txncache_t` structure representing the transaction cache to be operated on.
- **Control Flow**:
    - Acquire a write lock on the transaction cache using `fd_rwlock_write` to ensure exclusive access.
    - Retrieve the list of constipated slots using [`fd_txncache_get_constipated_slots`](#fd_txncache_get_constipated_slots).
    - Iterate over each constipated slot and register it as a root slot using [`fd_txncache_register_root_slot_private`](#fd_txncache_register_root_slot_private).
    - Reset the count of constipated slots to zero.
    - Set the `is_constipated` flag of the transaction cache to zero, indicating that the cache is no longer constipated.
    - Release the write lock using `fd_rwlock_unwrite`.
- **Output**: This function does not return a value; it modifies the state of the transaction cache `tc` by registering constipated slots and updating its constipation status.
- **Functions called**:
    - [`fd_txncache_get_constipated_slots`](#fd_txncache_get_constipated_slots)
    - [`fd_txncache_register_root_slot_private`](#fd_txncache_register_root_slot_private)


---
### fd\_txncache\_root\_slots<!-- {{#callable:fd_txncache_root_slots}} -->
The `fd_txncache_root_slots` function copies the root slots from a transaction cache to an output array while ensuring thread safety with a write lock.
- **Inputs**:
    - `tc`: A pointer to an `fd_txncache_t` structure representing the transaction cache.
    - `out_slots`: A pointer to an array of `ulong` where the root slots will be copied.
- **Control Flow**:
    - Acquire a write lock on the transaction cache using `fd_rwlock_write` to ensure thread safety.
    - Retrieve the root slots from the transaction cache using [`fd_txncache_get_root_slots`](#fd_txncache_get_root_slots).
    - Copy the root slots to the `out_slots` array using `memcpy`, with the size determined by `tc->root_slots_max`.
    - Release the write lock using `fd_rwlock_unwrite`.
- **Output**: The function does not return a value; it modifies the `out_slots` array in place.
- **Functions called**:
    - [`fd_txncache_get_root_slots`](#fd_txncache_get_root_slots)


---
### fd\_txncache\_find\_blockhash<!-- {{#callable:fd_txncache_find_blockhash}} -->
The `fd_txncache_find_blockhash` function searches for a blockhash in a transaction cache and returns its status, potentially inserting it if not found and allowed.
- **Inputs**:
    - `tc`: A constant pointer to an `fd_txncache_t` structure representing the transaction cache.
    - `blockhash`: A constant array of 32 unsigned characters representing the blockhash to be searched.
    - `is_insert`: An unsigned integer flag indicating whether to insert the blockhash if it is not found.
    - `out_blockcache`: A pointer to a pointer of `fd_txncache_private_blockcache_t` where the found or new blockcache entry will be stored.
- **Control Flow**:
    - Calculate the hash of the blockhash using `FD_LOAD` and initialize necessary pointers and variables.
    - Iterate over the transaction cache's live slots to find the blockhash or an empty/tombstone entry.
    - If an empty entry is found, return it as the found empty entry, or if a tombstone is found and insertion is allowed, mark it for potential use.
    - If a temporary entry is encountered, pause until it is resolved.
    - If the blockhash matches an entry, return it as found, and if inserting, undo any probed entry changes.
    - If no suitable entry is found, return the first tombstone if available, otherwise indicate the cache is full.
- **Output**: Returns an integer indicating the result of the search: `FD_TXNCACHE_FIND_FOUND` if the blockhash is found, `FD_TXNCACHE_FIND_FOUNDEMPTY` if an empty entry is found, or `FD_TXNCACHE_FIND_FULL` if the cache is full.
- **Functions called**:
    - [`fd_txncache_get_probed_entries_const`](#fd_txncache_get_probed_entries_const)


---
### fd\_txncache\_find\_slot<!-- {{#callable:fd_txncache_find_slot}} -->
The `fd_txncache_find_slot` function searches for a slot in a transaction cache and returns a pointer to the slot cache entry, indicating whether the slot was found, empty, or the cache is full.
- **Inputs**:
    - `tc`: A constant pointer to a `fd_txncache_t` structure representing the transaction cache.
    - `slot`: An unsigned long integer representing the slot number to search for in the cache.
    - `is_insert`: An unsigned integer flag indicating whether the function is being called in the context of an insertion (non-zero) or not (zero).
    - `out_slotcache`: A pointer to a pointer of `fd_txncache_private_slotcache_t` where the function will store the address of the found slot cache entry.
- **Control Flow**:
    - Retrieve the slot cache array from the transaction cache using `fd_txncache_get_slotcache_const` function.
    - Iterate over the maximum number of live slots in the transaction cache.
    - Calculate the index in the slot cache array using the current slot and iteration index, modulo the maximum number of live slots.
    - Check if the current slot cache entry is empty (`FD_TXNCACHE_EMPTY_ENTRY`); if so, set `out_slotcache` to this entry and return `FD_TXNCACHE_FIND_FOUNDEMPTY`.
    - If the current slot cache entry is a tombstone (`FD_TXNCACHE_TOMBSTONE_ENTRY`) and `is_insert` is true, set `out_slotcache` to this entry and return `FD_TXNCACHE_FIND_FOUNDEMPTY`; otherwise, continue to the next iteration.
    - If the current slot cache entry is a temporary entry (`FD_TXNCACHE_TEMP_ENTRY`), pause and wait for it to be released.
    - Use a memory fence to ensure proper ordering of operations.
    - If the current slot cache entry matches the requested slot, set `out_slotcache` to this entry and return `FD_TXNCACHE_FIND_FOUND`.
    - If no suitable entry is found after iterating through all live slots, return `FD_TXNCACHE_FIND_FULL`.
- **Output**: An integer indicating the result of the search: `FD_TXNCACHE_FIND_FOUND` if the slot was found, `FD_TXNCACHE_FIND_FOUNDEMPTY` if an empty or tombstone entry was found, or `FD_TXNCACHE_FIND_FULL` if the cache is full.


---
### fd\_txncache\_find\_slot\_blockhash<!-- {{#callable:fd_txncache_find_slot_blockhash}} -->
The function `fd_txncache_find_slot_blockhash` searches for a slot block cache entry matching a given blockhash within a slot cache and returns its status.
- **Inputs**:
    - `slotcache`: A pointer to a `fd_txncache_private_slotcache_t` structure representing the slot cache to search within.
    - `blockhash`: A constant array of 32 unsigned characters representing the blockhash to search for.
    - `out_slotblockcache`: A pointer to a pointer to a `fd_txncache_private_slotblockcache_t` structure where the found slot block cache entry will be stored.
- **Control Flow**:
    - Load the initial hash value from the blockhash input.
    - Iterate over a fixed range of 300 possible slot block cache indices.
    - For each index, calculate the slot block cache index using the hash value and the current iteration index.
    - Check if the `txnhash_offset` of the current slot block cache entry is `ULONG_MAX`, indicating an empty entry, and if so, store the entry in `out_slotblockcache` and return `FD_TXNCACHE_FIND_FOUNDEMPTY`.
    - If the `txnhash_offset` is `ULONG_MAX-1UL`, indicating a temporary state, pause and wait for it to change.
    - Use a memory fence to ensure proper ordering of operations.
    - Compare the blockhash of the current slot block cache entry with the input blockhash; if they match, store the entry in `out_slotblockcache` and return `FD_TXNCACHE_FIND_FOUND`.
    - If no matching or empty entry is found after 300 iterations, return `FD_TXNCACHE_FIND_FULL`.
- **Output**: Returns an integer indicating the result of the search: `FD_TXNCACHE_FIND_FOUNDEMPTY` if an empty entry is found, `FD_TXNCACHE_FIND_FOUND` if a matching entry is found, or `FD_TXNCACHE_FIND_FULL` if the cache is full.


---
### fd\_txncache\_ensure\_blockcache<!-- {{#callable:fd_txncache_ensure_blockcache}} -->
The `fd_txncache_ensure_blockcache` function ensures that a blockcache entry for a given blockhash exists in the transaction cache, creating it if necessary.
- **Inputs**:
    - `tc`: A pointer to the transaction cache (`fd_txncache_t`) where the blockcache entry should be ensured.
    - `blockhash`: A constant array of 32 unsigned characters representing the blockhash for which the blockcache entry is to be ensured.
    - `out_blockcache`: A pointer to a pointer of `fd_txncache_private_blockcache_t` where the address of the ensured blockcache entry will be stored.
- **Control Flow**:
    - The function enters an infinite loop to repeatedly attempt to find or create the blockcache entry.
    - It calls [`fd_txncache_find_blockhash`](#fd_txncache_find_blockhash) to search for the blockhash in the transaction cache.
    - If the blockhash is found (`FD_TXNCACHE_FIND_FOUND`), it returns 1, indicating success.
    - If the transaction cache is full (`FD_TXNCACHE_FIND_FULL`), it returns 0, indicating failure.
    - If the blockhash is not found, it attempts to create a new blockcache entry using atomic compare-and-swap operations to set the `max_slot` to a temporary entry value.
    - If successful, it initializes the blockcache entry with the given blockhash, resets the heads and pages, and sets `max_slot` to a high unreserved value before returning 1.
    - If the atomic operation fails, it pauses briefly and retries.
- **Output**: Returns 1 if the blockcache entry is successfully ensured or found, and 0 if the transaction cache is full and the entry cannot be created.
- **Functions called**:
    - [`fd_txncache_find_blockhash`](#fd_txncache_find_blockhash)


---
### fd\_txncache\_ensure\_slotcache<!-- {{#callable:fd_txncache_ensure_slotcache}} -->
The `fd_txncache_ensure_slotcache` function ensures that a slotcache entry for a given slot exists in the transaction cache, initializing it if necessary.
- **Inputs**:
    - `tc`: A pointer to the transaction cache (`fd_txncache_t`) structure.
    - `slot`: The slot number (`ulong`) for which the slotcache entry is to be ensured.
    - `out_slotcache`: A pointer to a pointer of type `fd_txncache_private_slotcache_t`, where the function will store the address of the ensured slotcache entry.
- **Control Flow**:
    - The function enters an infinite loop to repeatedly attempt to find or create the slotcache entry.
    - It calls [`fd_txncache_find_slot`](#fd_txncache_find_slot) to search for the slotcache entry for the given slot.
    - If the entry is found (`FD_TXNCACHE_FIND_FOUND`), it returns 1, indicating success.
    - If the slotcache is full (`FD_TXNCACHE_FIND_FULL`), it returns 0, indicating failure.
    - If the entry is not found, it attempts to initialize a new entry by using atomic compare-and-swap operations to set the slot to a temporary entry value.
    - If successful, it initializes the blockcache array within the slotcache to indicate empty entries and sets the slot to the specified value.
    - If the atomic operations fail, it pauses briefly and retries.
- **Output**: Returns 1 if the slotcache entry is successfully ensured or found, and 0 if the slotcache is full and cannot accommodate a new entry.
- **Functions called**:
    - [`fd_txncache_find_slot`](#fd_txncache_find_slot)


---
### fd\_txncache\_ensure\_slotblockcache<!-- {{#callable:fd_txncache_ensure_slotblockcache}} -->
The function `fd_txncache_ensure_slotblockcache` ensures that a slotblockcache entry for a given blockhash exists in the slotcache, creating it if necessary.
- **Inputs**:
    - `slotcache`: A pointer to the `fd_txncache_private_slotcache_t` structure where the slotblockcache is to be ensured.
    - `blockhash`: A constant array of 32 unsigned characters representing the blockhash for which the slotblockcache is to be ensured.
    - `out_slotblockcache`: A pointer to a pointer of `fd_txncache_private_slotblockcache_t` where the resulting slotblockcache will be stored.
- **Control Flow**:
    - The function enters an infinite loop to repeatedly attempt to find or create the slotblockcache entry.
    - It calls [`fd_txncache_find_slot_blockhash`](#fd_txncache_find_slot_blockhash) to search for the slotblockcache entry corresponding to the given blockhash.
    - If the entry is found (`FD_TXNCACHE_FIND_FOUND`), it returns 1, indicating success.
    - If the slotblockcache is full (`FD_TXNCACHE_FIND_FULL`), it returns 0, indicating failure.
    - If the entry is not found, it attempts to create a new entry using an atomic compare-and-swap operation on `txnhash_offset`.
    - If the compare-and-swap is successful, it initializes the new slotblockcache entry with the given blockhash and resets its heads and `txnhash_offset`.
    - The function then returns 1, indicating the slotblockcache entry was successfully ensured.
- **Output**: The function returns an integer: 1 if the slotblockcache entry was successfully found or created, or 0 if the slotblockcache is full and no entry could be created.
- **Functions called**:
    - [`fd_txncache_find_slot_blockhash`](#fd_txncache_find_slot_blockhash)


---
### fd\_txncache\_ensure\_txnpage<!-- {{#callable:fd_txncache_ensure_txnpage}} -->
The `fd_txncache_ensure_txnpage` function ensures that a transaction page is available for a given blockcache, allocating a new page if necessary and possible.
- **Inputs**:
    - `tc`: A pointer to the transaction cache (`fd_txncache_t`) structure, which manages transaction pages and caches.
    - `blockcache`: A pointer to the blockcache (`fd_txncache_private_blockcache_t`) structure, which contains transaction pages related to a specific blockhash.
- **Control Flow**:
    - Retrieve the current count of pages (`page_cnt`) from the blockcache.
    - Check if `page_cnt` exceeds the maximum allowed pages per blockhash (`txnpages_per_blockhash_max`); if so, return `NULL`.
    - Get the transaction pages array from the transaction cache (`tc`).
    - If there are existing pages (`page_cnt > 0`), check if the last page has free space; if so, return that page.
    - If `page_cnt` equals the maximum allowed, return `NULL`.
    - Attempt to reserve a new page index in the blockcache using an atomic compare-and-swap operation.
    - If successful, decrement the free pages count in the transaction cache atomically, ensuring a free page is available.
    - Retrieve the index of a free transaction page and initialize it.
    - Update the blockcache with the new page index and increment the page count.
    - Return the newly allocated transaction page.
- **Output**: A pointer to a `fd_txncache_private_txnpage_t` structure representing the ensured or newly allocated transaction page, or `NULL` if no page could be ensured or allocated.
- **Functions called**:
    - [`fd_txncache_get_txnpages_free`](#fd_txncache_get_txnpages_free)


---
### fd\_txncache\_insert\_txn<!-- {{#callable:fd_txncache_insert_txn}} -->
The `fd_txncache_insert_txn` function inserts a transaction into a transaction cache, updating the block and slot caches accordingly.
- **Inputs**:
    - `tc`: A pointer to the transaction cache structure (`fd_txncache_t`).
    - `blockcache`: A pointer to the block cache structure (`fd_txncache_private_blockcache_t`) associated with the transaction.
    - `slotblockcache`: A pointer to the slot block cache structure (`fd_txncache_private_slotblockcache_t`) associated with the transaction.
    - `txnpage`: A pointer to the transaction page structure (`fd_txncache_private_txnpage_t`) where the transaction will be inserted.
    - `txn`: A constant pointer to the transaction data (`fd_txncache_insert_t`) to be inserted.
- **Control Flow**:
    - Retrieve the array of transaction pages from the transaction cache and calculate the index of the current transaction page.
    - Enter an infinite loop to attempt inserting the transaction.
    - Check if there is free space in the transaction page; if not, return 0 indicating failure.
    - Attempt to atomically decrement the free space counter in the transaction page; if unsuccessful, retry.
    - Calculate the transaction index within the page and load the transaction hash offset from the block cache.
    - Copy the transaction hash and set the result and slot in the transaction entry.
    - Enter a loop to update the block cache's hash table with the new transaction index, retrying if necessary until successful.
    - Enter a loop to update the slot block cache's hash table with the new transaction index, retrying if necessary until successful.
    - Enter a loop to update the maximum slot in the block cache if the transaction's slot is greater, retrying if necessary until successful.
    - Return 1 indicating successful insertion.
- **Output**: Returns 1 if the transaction is successfully inserted, or 0 if there is no free space in the transaction page.


---
### fd\_txncache\_insert\_batch<!-- {{#callable:fd_txncache_insert_batch}} -->
The `fd_txncache_insert_batch` function inserts a batch of transactions into a transaction cache, ensuring necessary caches are available and handling potential failures.
- **Inputs**:
    - `tc`: A pointer to the transaction cache (`fd_txncache_t`) where transactions will be inserted.
    - `txns`: A constant pointer to an array of transactions (`fd_txncache_insert_t`) to be inserted into the cache.
    - `txns_cnt`: The number of transactions in the `txns` array to be inserted.
- **Control Flow**:
    - Acquire a read lock on the transaction cache to ensure thread safety during the insertion process.
    - Iterate over each transaction in the `txns` array.
    - For each transaction, ensure the existence of a block cache for the transaction's block hash using [`fd_txncache_ensure_blockcache`](#fd_txncache_ensure_blockcache). If it fails, log a warning and exit with failure.
    - Ensure the existence of a slot cache for the transaction's slot using [`fd_txncache_ensure_slotcache`](#fd_txncache_ensure_slotcache). If it fails, log a warning and exit with failure.
    - Ensure the existence of a slot block cache for the transaction's block hash within the slot cache using [`fd_txncache_ensure_slotblockcache`](#fd_txncache_ensure_slotblockcache). If it fails, log a warning and exit with failure.
    - Attempt to insert the transaction into the cache by ensuring a transaction page is available using [`fd_txncache_ensure_txnpage`](#fd_txncache_ensure_txnpage). If it fails, log a warning and exit with failure.
    - Use [`fd_txncache_insert_txn`](#fd_txncache_insert_txn) to insert the transaction into the cache. If successful, proceed to the next transaction; otherwise, retry until successful.
    - Release the read lock on the transaction cache after all transactions are processed.
- **Output**: Returns 1 on successful insertion of all transactions, or 0 if any insertion fails.
- **Functions called**:
    - [`fd_txncache_ensure_blockcache`](#fd_txncache_ensure_blockcache)
    - [`fd_txncache_ensure_slotcache`](#fd_txncache_ensure_slotcache)
    - [`fd_txncache_ensure_slotblockcache`](#fd_txncache_ensure_slotblockcache)
    - [`fd_txncache_ensure_txnpage`](#fd_txncache_ensure_txnpage)
    - [`fd_txncache_insert_txn`](#fd_txncache_insert_txn)


---
### fd\_txncache\_query\_batch<!-- {{#callable:fd_txncache_query_batch}} -->
The `fd_txncache_query_batch` function queries a batch of transaction cache entries to determine if they exist and meet certain conditions, updating the results accordingly.
- **Inputs**:
    - `tc`: A pointer to the transaction cache (`fd_txncache_t`) to be queried.
    - `queries`: A constant pointer to an array of `fd_txncache_query_t` structures representing the queries to be executed.
    - `queries_cnt`: An unsigned long integer representing the number of queries in the `queries` array.
    - `query_func_ctx`: A pointer to a context that is passed to the `query_func` callback function.
    - `query_func`: A pointer to a function that takes a slot and a context as arguments and returns an integer, used to apply additional conditions to the query results.
    - `out_results`: A pointer to an integer array where the results of the queries will be stored, with each element corresponding to a query in the `queries` array.
- **Control Flow**:
    - Acquire a read lock on the transaction cache to ensure thread-safe access.
    - Retrieve the transaction pages from the transaction cache.
    - Iterate over each query in the `queries` array.
    - Initialize the result for the current query to 0 (not found).
    - For each query, attempt to find the corresponding blockhash in the transaction cache.
    - If the blockhash is not found, continue to the next query.
    - Calculate the hash offset and head hash for the transaction hash in the query.
    - Iterate through the linked list of transactions in the blockcache that match the head hash.
    - For each transaction, compare the transaction hash with the query's transaction hash.
    - If a match is found and the `query_func` is either not provided or returns true, set the result for the current query to 1 (found) and break out of the loop.
    - Release the read lock on the transaction cache.
- **Output**: The function does not return a value but updates the `out_results` array with 1 for queries that find a matching transaction and 0 otherwise.
- **Functions called**:
    - [`fd_txncache_find_blockhash`](#fd_txncache_find_blockhash)


---
### fd\_txncache\_snapshot<!-- {{#callable:fd_txncache_snapshot}} -->
The `fd_txncache_snapshot` function creates a snapshot of the transaction cache by writing transaction entries to a provided write function.
- **Inputs**:
    - `tc`: A pointer to the transaction cache (`fd_txncache_t`) from which the snapshot is to be taken.
    - `ctx`: A context pointer that is passed to the write function, typically used to maintain state or additional data needed during the write operation.
    - `write`: A function pointer to a write method that takes a data buffer, its size, and a context pointer, and writes the data to a desired output.
- **Control Flow**:
    - Check if the write function is provided; if not, log a warning and return 1.
    - Acquire a read lock on the transaction cache to ensure thread-safe access.
    - Retrieve the transaction pages and root slots from the transaction cache.
    - Iterate over each root slot in the transaction cache.
    - For each root slot, find the corresponding slot cache; if not found, continue to the next slot.
    - Iterate over each slot block cache within the slot cache.
    - For each slot block cache, check if the transaction hash offset is valid; if not, continue to the next block cache.
    - Iterate over each transaction in the slot block cache's map.
    - For each transaction, create a snapshot entry with the slot, transaction index, and result, and copy the block hash and transaction hash into the entry.
    - Use the write function to write the snapshot entry to the output; if an error occurs, release the read lock and return the error code.
    - Release the read lock on the transaction cache after processing all entries.
    - Return 0 to indicate successful completion.
- **Output**: Returns 0 on successful snapshot creation, or an error code if the write function fails during the process.
- **Functions called**:
    - [`fd_txncache_get_root_slots`](#fd_txncache_get_root_slots)
    - [`fd_txncache_find_slot`](#fd_txncache_find_slot)


---
### fd\_txncache\_set\_txnhash\_offset<!-- {{#callable:fd_txncache_set_txnhash_offset}} -->
The function `fd_txncache_set_txnhash_offset` sets the transaction hash offset for a given blockhash and slot in a transaction cache.
- **Inputs**:
    - `tc`: A pointer to the transaction cache (`fd_txncache_t`) where the transaction hash offset needs to be set.
    - `slot`: An unsigned long integer representing the slot for which the transaction hash offset is to be set.
    - `blockhash`: An array of 32 unsigned characters representing the blockhash for which the transaction hash offset is to be set.
    - `txnhash_offset`: An unsigned long integer representing the transaction hash offset to be set.
- **Control Flow**:
    - Acquire a read lock on the transaction cache using `fd_rwlock_read` to ensure thread safety.
    - Attempt to ensure the existence of a blockcache for the given blockhash using [`fd_txncache_ensure_blockcache`](#fd_txncache_ensure_blockcache); if unsuccessful, go to `unlock_fail`.
    - Set the `txnhash_offset` for the blockcache to the provided `txnhash_offset`.
    - Attempt to ensure the existence of a slotcache for the given slot using [`fd_txncache_ensure_slotcache`](#fd_txncache_ensure_slotcache); if unsuccessful, go to `unlock_fail`.
    - Attempt to ensure the existence of a slotblockcache for the given blockhash within the slotcache using [`fd_txncache_ensure_slotblockcache`](#fd_txncache_ensure_slotblockcache); if unsuccessful, go to `unlock_fail`.
    - Set the `txnhash_offset` for the slotblockcache to the provided `txnhash_offset`.
    - Release the read lock on the transaction cache using `fd_rwlock_unread`.
    - Return 0 to indicate success.
    - In case of failure at any step, release the read lock and return 1.
- **Output**: The function returns an integer: 0 on success and 1 on failure.
- **Functions called**:
    - [`fd_txncache_ensure_blockcache`](#fd_txncache_ensure_blockcache)
    - [`fd_txncache_ensure_slotcache`](#fd_txncache_ensure_slotcache)
    - [`fd_txncache_ensure_slotblockcache`](#fd_txncache_ensure_slotblockcache)


---
### fd\_txncache\_is\_rooted\_slot<!-- {{#callable:fd_txncache_is_rooted_slot}} -->
The function `fd_txncache_is_rooted_slot` checks if a given slot is a rooted slot in the transaction cache.
- **Inputs**:
    - `tc`: A pointer to the transaction cache structure (`fd_txncache_t`) which contains the rooted slots information.
    - `slot`: An unsigned long integer representing the slot number to be checked if it is rooted.
- **Control Flow**:
    - Acquire a read lock on the transaction cache to ensure thread-safe access.
    - Retrieve the array of rooted slots using [`fd_txncache_get_root_slots`](#fd_txncache_get_root_slots).
    - Iterate over the rooted slots up to the count of rooted slots (`tc->root_slots_cnt`).
    - For each rooted slot, check if it matches the given slot; if so, release the lock and return 1 indicating the slot is rooted.
    - If a rooted slot is found that is greater than the given slot, break the loop as further slots will also be greater.
    - Release the read lock on the transaction cache.
    - Return 0 indicating the slot is not rooted.
- **Output**: Returns an integer: 1 if the slot is rooted, 0 otherwise.
- **Functions called**:
    - [`fd_txncache_get_root_slots`](#fd_txncache_get_root_slots)


---
### fd\_txncache\_get\_entries<!-- {{#callable:fd_txncache_get_entries}} -->
The `fd_txncache_get_entries` function retrieves transaction cache entries for rooted slots and populates them into a provided data structure.
- **Inputs**:
    - `tc`: A pointer to the transaction cache structure (`fd_txncache_t`) from which entries are to be retrieved.
    - `slot_deltas`: A pointer to a `fd_bank_slot_deltas_t` structure where the retrieved slot deltas will be stored.
    - `spad`: A pointer to a `fd_spad_t` structure used for memory allocation during the process.
- **Control Flow**:
    - Acquire a read lock on the transaction cache to ensure thread-safe access.
    - Initialize the `slot_deltas` structure with the number of rooted slots and allocate memory for storing slot deltas.
    - Retrieve the transaction pages and root slots from the transaction cache.
    - Iterate over each rooted slot to populate the `slot_deltas` structure with slot information and transaction status pairs.
    - For each slot, find the corresponding slot cache and iterate over its block caches to gather transaction status information.
    - Allocate memory for storing transaction status pairs and populate them with transaction hash and result data.
    - Release the read lock on the transaction cache.
- **Output**: Returns 0 on successful retrieval and population of transaction cache entries.
- **Functions called**:
    - [`fd_txncache_get_root_slots`](#fd_txncache_get_root_slots)
    - [`fd_txncache_find_slot`](#fd_txncache_find_slot)


---
### fd\_txncache\_get\_is\_constipated<!-- {{#callable:fd_txncache_get_is_constipated}} -->
The function `fd_txncache_get_is_constipated` checks if the transaction cache is in a constipated state.
- **Inputs**:
    - `tc`: A pointer to an `fd_txncache_t` structure, representing the transaction cache to be checked.
- **Control Flow**:
    - Acquire a read lock on the transaction cache's lock to ensure thread-safe access.
    - Retrieve the `is_constipated` status from the transaction cache structure.
    - Release the read lock on the transaction cache's lock.
    - Return the `is_constipated` status.
- **Output**: Returns an integer indicating whether the transaction cache is constipated (non-zero) or not (zero).


---
### fd\_txncache\_set\_is\_constipated<!-- {{#callable:fd_txncache_set_is_constipated}} -->
The function `fd_txncache_set_is_constipated` sets the `is_constipated` status of a transaction cache to a specified value.
- **Inputs**:
    - `tc`: A pointer to an `fd_txncache_t` structure representing the transaction cache whose constipation status is to be set.
    - `is_constipated`: An integer value indicating whether the transaction cache should be marked as constipated (non-zero) or not (zero).
- **Control Flow**:
    - Acquire a read lock on the transaction cache's lock using `fd_rwlock_read` to ensure thread-safe access.
    - Set the `is_constipated` field of the transaction cache structure to the value of `is_constipated`.
    - Release the read lock using `fd_rwlock_unread` to allow other threads to access the transaction cache.
    - Return 0 to indicate successful execution.
- **Output**: The function returns an integer value of 0, indicating successful execution.


