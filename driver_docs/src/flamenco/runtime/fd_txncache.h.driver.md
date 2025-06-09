# Purpose
The provided C header file defines the interface for a transaction cache (txn cache) used in a concurrent environment to manage the results of executed transactions. This txn cache is designed to efficiently handle high-throughput operations, such as insertion and querying of transaction results, which are crucial for systems that process a large number of transactions per second, potentially over a million. The cache supports serialization of its state into a binary format for snapshotting, allowing the state to be shared with other nodes and restored from snapshots. The design emphasizes concurrent, lockless operations for insertion and querying, while other operations that require locking are minimized to maintain performance.

The file defines several key structures and functions that facilitate the management of transaction data. It includes structures for inserting and querying transactions, as well as for handling snapshot entries. The functions provided allow for the creation, joining, and deletion of a txn cache, as well as operations to register root and constipated slots, insert and query transaction batches, and manage the cache's state for snapshotting. The header also defines constants that configure the cache's behavior, such as the maximum number of rooted and live slots, and the maximum transactions per slot. This file is intended to be included in other C source files, providing a public API for managing transaction caches in a distributed system, likely within a blockchain or similar high-performance transaction processing environment.
# Imports and Dependencies

---
- `../fd_flamenco_base.h`
- `../types/fd_types.h`
- `math.h`


# Global Variables

---
### fd\_txncache\_new
- **Type**: `function pointer`
- **Description**: The `fd_txncache_new` function is a global function pointer that initializes a transaction cache in a specified shared memory region. It takes parameters for the maximum number of rooted slots, live slots, transactions per slot, and constipated slots, and returns a pointer to the initialized memory region on success or NULL on failure.
- **Use**: This function is used to allocate and format a memory region for a transaction cache, setting up the necessary structures for concurrent transaction insertion and querying.


---
### fd\_txncache\_join
- **Type**: `fd_txncache_t *`
- **Description**: The `fd_txncache_join` is a function that returns a pointer to a `fd_txncache_t` structure. This function is used to join a caller to a transaction cache, which is a concurrent map for saving the result (status) of transactions that have executed.
- **Use**: This variable is used to provide a local handle to a transaction cache, allowing the caller to perform operations such as insertion and querying of transaction results.


---
### fd\_txncache\_leave
- **Type**: `function pointer`
- **Description**: `fd_txncache_leave` is a function that allows a caller to leave their current local join to a transaction cache (`fd_txncache_t`). It returns a pointer to the memory region holding the state on success, or NULL on failure, logging details in the latter case.
- **Use**: This function is used to safely disconnect a caller from a transaction cache, ensuring that the memory region is properly managed and returned to the caller.


---
### fd\_txncache\_delete
- **Type**: `function pointer`
- **Description**: The `fd_txncache_delete` is a function pointer that is used to unformat a memory region holding a transaction cache. It is designed to be called when the transaction cache is no longer needed, ensuring that the memory can be safely reclaimed or reused.
- **Use**: This function is used to delete a transaction cache by unformatting the memory region it occupies, returning ownership of the memory to the caller.


# Data Structures

---
### fd\_txncache\_insert
- **Type**: `struct`
- **Members**:
    - `blockhash`: A pointer to an unsigned character array representing the block hash.
    - `txnhash`: A pointer to an unsigned character array representing the transaction hash.
    - `slot`: An unsigned long integer representing the slot number.
    - `result`: A pointer to an unsigned character array representing the result of the transaction.
- **Description**: The `fd_txncache_insert` structure is used to represent an insertion entry in a transaction cache, which is part of a concurrent map designed to store and manage the results of executed transactions. This structure holds the block hash, transaction hash, slot number, and the result of the transaction, facilitating efficient insertion and query operations within the transaction cache system.


---
### fd\_txncache\_insert\_t
- **Type**: `struct`
- **Members**:
    - `blockhash`: A pointer to an unsigned character array representing the block hash associated with the transaction.
    - `txnhash`: A pointer to an unsigned character array representing the transaction hash.
    - `slot`: An unsigned long integer representing the slot number in which the transaction was executed.
    - `result`: A pointer to an unsigned character array representing the result or status of the transaction.
- **Description**: The `fd_txncache_insert_t` structure is used to represent an insertion entry in a transaction cache, which is a concurrent map designed to store and query the results of executed transactions. This structure holds the block hash, transaction hash, slot number, and the result of the transaction, facilitating efficient insertion and retrieval operations within the transaction cache system.


---
### fd\_txncache\_query
- **Type**: `struct`
- **Members**:
    - `blockhash`: A pointer to an unsigned character array representing the block hash.
    - `txnhash`: A pointer to an unsigned character array representing the transaction hash.
- **Description**: The `fd_txncache_query` structure is used to represent a query in the transaction cache system, specifically identifying a transaction by its block hash and transaction hash. This structure is part of a larger system designed to efficiently manage and query transaction statuses in a concurrent and lockless manner, supporting operations such as insertion and querying of transaction results.


---
### fd\_txncache\_query\_t
- **Type**: `struct`
- **Members**:
    - `blockhash`: A pointer to a constant unsigned character array representing the block hash.
    - `txnhash`: A pointer to a constant unsigned character array representing the transaction hash.
- **Description**: The `fd_txncache_query_t` structure is used to represent a query in the transaction cache system, specifically for querying the status of transactions. It contains pointers to the block hash and transaction hash, which are used to identify the specific transaction being queried. This structure is part of a larger system designed to efficiently manage and query transaction statuses in a concurrent and lockless manner, ensuring that transactions are not executed multiple times.


---
### fd\_txncache\_snapshot\_entry
- **Type**: `struct`
- **Members**:
    - `slot`: Represents the slot number associated with the transaction.
    - `blockhash`: A 32-byte array storing the hash of the block containing the transaction.
    - `txnhash`: A 20-byte array storing the hash of the transaction itself.
    - `txn_idx`: An index indicating the position of the transaction within the block.
    - `result`: A byte representing the result or status of the transaction.
- **Description**: The `fd_txncache_snapshot_entry` structure is used to represent a snapshot entry in a transaction cache, capturing essential details about a transaction such as its slot, block hash, transaction hash, index within the block, and the result of the transaction. This structure is part of a larger system designed to efficiently manage and query transaction results, supporting operations like serialization for snapshot responses and restoration from snapshots.


---
### fd\_txncache\_snapshot\_entry\_t
- **Type**: `struct`
- **Members**:
    - `slot`: Represents the slot number associated with the transaction.
    - `blockhash`: An array of 32 unsigned characters representing the block hash.
    - `txnhash`: An array of 20 unsigned characters representing the transaction hash.
    - `txn_idx`: An unsigned long integer representing the transaction index.
    - `result`: An unsigned character representing the result of the transaction.
- **Description**: The `fd_txncache_snapshot_entry_t` structure is used to represent a snapshot entry in a transaction cache, capturing the state of a transaction at a specific slot. It includes the slot number, block hash, transaction hash, transaction index, and the result of the transaction. This structure is essential for serializing the state of transactions for snapshot responses, allowing the state to be shared with other nodes and restored from snapshots. Each field in the structure provides critical information needed to uniquely identify and describe the transaction's status within the cache.


---
### fd\_txncache\_t
- **Type**: `typedef struct fd_txncache_private fd_txncache_t;`
- **Members**:
    - `fd_txncache_private`: An opaque structure representing the internal state and data of the transaction cache.
- **Description**: The `fd_txncache_t` is an opaque data structure used to manage a transaction cache in a concurrent and lockless manner, designed for high-performance insertion and querying of transaction results. It supports serialization for snapshotting and restoration, and is optimized for memory efficiency while handling potentially millions of transactions per second. The structure is sensitive to both CPU and memory constraints, utilizing a hash map-based approach to store transaction data efficiently.


# Functions

---
### fd\_txncache\_max\_constipated\_slots\_est<!-- {{#callable:fd_txncache_max_constipated_slots_est}} -->
The function `fd_txncache_max_constipated_slots_est` estimates the maximum number of constipated slots based on a given stall duration in seconds.
- **Inputs**:
    - `stall_duration_secs`: An unsigned long integer representing the duration of the stall in seconds.
- **Control Flow**:
    - Convert the input `stall_duration_secs` to a double and multiply by 0.4 to estimate the number of constipated slots as a double.
    - Use the `ceil` function to round up the estimated number of constipated slots to the nearest whole number.
    - Cast the result to an unsigned long integer and return it.
- **Output**: The function returns an unsigned long integer representing the estimated maximum number of constipated slots.


# Function Declarations (Public API)

---
### fd\_txncache\_align<!-- {{#callable_declaration:fd_txncache_align}} -->
Returns the required memory alignment for a transaction cache.
- **Description**: Use this function to determine the memory alignment needed for a transaction cache. This is important when allocating memory for the cache to ensure that it is properly aligned for optimal performance and correctness. The function is constant and does not depend on any input parameters, making it straightforward to use whenever you need to allocate or manage memory for a transaction cache.
- **Inputs**: None
- **Output**: The function returns an unsigned long integer representing the required memory alignment for a transaction cache.
- **See also**: [`fd_txncache_align`](fd_txncache.c.driver.md#fd_txncache_align)  (Implementation)


---
### fd\_txncache\_footprint<!-- {{#callable_declaration:fd_txncache_footprint}} -->
Calculate the memory footprint required for a transaction cache.
- **Description**: This function calculates the memory footprint needed to allocate a transaction cache based on the specified parameters. It should be used when planning memory allocation for a transaction cache to ensure sufficient space is available. The function requires valid input values, where the number of live slots must be greater than or equal to the number of rooted slots, and both must be powers of two. If any of these conditions are not met, the function returns zero, indicating an invalid configuration.
- **Inputs**:
    - `max_rooted_slots`: The maximum number of rooted slots; must be at least 1.
    - `max_live_slots`: The maximum number of live slots; must be at least 1 and greater than or equal to max_rooted_slots.
    - `max_txn_per_slot`: The maximum number of transactions per slot; must be at least 1 and a power of two.
    - `max_constipated_slots`: The maximum number of constipated slots; no specific constraints are mentioned.
- **Output**: Returns the calculated memory footprint in bytes, or 0 if the input parameters are invalid.
- **See also**: [`fd_txncache_footprint`](fd_txncache.c.driver.md#fd_txncache_footprint)  (Implementation)


---
### fd\_txncache\_new<!-- {{#callable_declaration:fd_txncache_new}} -->
Initialize a transaction cache in a shared memory region.
- **Description**: This function sets up a transaction cache in a specified shared memory region, allowing for concurrent insertion and querying of transaction results. It is essential to ensure that the shared memory pointer is non-null and properly aligned according to the required alignment for a transaction cache. The function also requires valid, non-zero values for the maximum number of rooted slots, live slots, transactions per slot, and constipated slots. The number of live slots must be greater than or equal to the number of rooted slots, and both the number of live slots and transactions per slot must be powers of two. If any of these conditions are not met, the function will return NULL, indicating failure.
- **Inputs**:
    - `shmem`: A pointer to the shared memory region where the transaction cache will be initialized. Must not be null and must be aligned according to fd_txncache_align(). The caller retains ownership of this memory.
    - `max_rooted_slots`: The maximum number of rooted slots the cache can handle. Must be greater than zero.
    - `max_live_slots`: The maximum number of live slots the cache can handle. Must be greater than zero and a power of two. Must also be greater than or equal to max_rooted_slots.
    - `max_txn_per_slot`: The maximum number of transactions per slot. Must be greater than zero and a power of two.
    - `max_constipated_slots`: The maximum number of constipated slots the cache can handle. Must be greater than zero.
- **Output**: Returns a pointer to the initialized transaction cache on success, or NULL on failure if any preconditions are not met.
- **See also**: [`fd_txncache_new`](fd_txncache.c.driver.md#fd_txncache_new)  (Implementation)


---
### fd\_txncache\_join<!-- {{#callable_declaration:fd_txncache_join}} -->
Joins a caller to a transaction cache.
- **Description**: This function is used to join a caller to a transaction cache, allowing them to interact with it. It should be called with a valid pointer to the memory region holding the transaction cache state. The function checks for null pointers, proper alignment, and a valid magic number to ensure the integrity of the transaction cache before joining. If any of these checks fail, the function logs a warning and returns NULL. This function is typically called after the transaction cache has been initialized and before any operations are performed on it.
- **Inputs**:
    - `shtc`: A pointer to the memory region holding the transaction cache state. It must not be null, must be properly aligned according to fd_txncache_align(), and must contain a valid magic number. If these conditions are not met, the function logs a warning and returns NULL.
- **Output**: Returns a local handle to the transaction cache on success, or NULL on failure.
- **See also**: [`fd_txncache_join`](fd_txncache.c.driver.md#fd_txncache_join)  (Implementation)


---
### fd\_txncache\_leave<!-- {{#callable_declaration:fd_txncache_leave}} -->
Leaves the current local join to a transaction cache.
- **Description**: This function is used to leave the current local join to a transaction cache, effectively ending the caller's association with the cache. It should be called when the caller no longer needs to interact with the transaction cache. The function returns a pointer to the memory region holding the state of the transaction cache on success, or NULL if the operation fails, logging a warning if the provided transaction cache pointer is NULL. This function does not require the caller to be joined on return.
- **Inputs**:
    - `tc`: A pointer to a transaction cache (fd_txncache_t). Must not be NULL. If NULL, the function logs a warning and returns NULL.
- **Output**: Returns a pointer to the memory region holding the state of the transaction cache on success, or NULL on failure.
- **See also**: [`fd_txncache_leave`](fd_txncache.c.driver.md#fd_txncache_leave)  (Implementation)


---
### fd\_txncache\_delete<!-- {{#callable_declaration:fd_txncache_delete}} -->
Unformats a memory region holding a transaction cache.
- **Description**: Use this function to unformat a memory region that was previously formatted to hold a transaction cache. It should be called when the transaction cache is no longer needed, and it is important to ensure that no threads are joined to the transaction cache at the time of calling. This function returns ownership of the memory region back to the caller upon successful execution. It logs a warning and returns NULL if the provided pointer is NULL, misaligned, or if the transaction cache's magic number is incorrect.
- **Inputs**:
    - `shtc`: A pointer to the first byte of the memory region holding the transaction cache. It must not be NULL, must be properly aligned according to fd_txncache_align(), and must point to a valid transaction cache with the correct magic number. The caller retains ownership of the memory region.
- **Output**: Returns a pointer to the memory region on success, or NULL on failure if the input is invalid or the transaction cache is not properly formatted.
- **See also**: [`fd_txncache_delete`](fd_txncache.c.driver.md#fd_txncache_delete)  (Implementation)


---
### fd\_txncache\_register\_root\_slot<!-- {{#callable_declaration:fd_txncache_register_root_slot}} -->
Registers a root slot in the transaction cache.
- **Description**: This function is used to register a root slot within a transaction cache, which is essential for maintaining the state of transactions that have been executed. It should be called when a slot is confirmed as rooted, ensuring that the transaction cache can manage and serialize its state for snapshot responses. The function temporarily locks the transaction cache to prevent concurrent insertions and queries during the registration process, ensuring data consistency. It is important to ensure that the transaction cache is properly initialized and that the slot number is valid before calling this function.
- **Inputs**:
    - `tc`: A pointer to a transaction cache (fd_txncache_t). Must not be null. The caller retains ownership.
    - `slot`: An unsigned long integer representing the slot to be registered as rooted. Must be a valid slot number.
- **Output**: None
- **See also**: [`fd_txncache_register_root_slot`](fd_txncache.c.driver.md#fd_txncache_register_root_slot)  (Implementation)


---
### fd\_txncache\_register\_constipated\_slot<!-- {{#callable_declaration:fd_txncache_register_constipated_slot}} -->
Registers a slot as constipated in the transaction cache.
- **Description**: Use this function to mark a specific slot as constipated in the transaction cache, which prevents older root slots from being purged and newer root slots from being rooted until the constipated slots are flushed. This function should be called when you need to temporarily hold the state of certain slots, such as during snapshot generation. Ensure that the transaction cache has not exceeded its maximum allowed constipated slots before calling this function, as exceeding this limit will result in an error.
- **Inputs**:
    - `tc`: A pointer to an fd_txncache_t structure representing the transaction cache. Must not be null, and the caller retains ownership.
    - `slot`: The slot number to be marked as constipated. Must be a valid slot number within the range of the transaction cache.
- **Output**: None
- **See also**: [`fd_txncache_register_constipated_slot`](fd_txncache.c.driver.md#fd_txncache_register_constipated_slot)  (Implementation)


---
### fd\_txncache\_flush\_constipated\_slots<!-- {{#callable_declaration:fd_txncache_flush_constipated_slots}} -->
Flushes constipated slots in the transaction cache.
- **Description**: Use this function to register all previously constipated slots in the transaction cache and update their status. It should be called when you want to transition constipated slots to a registered state, effectively unconstipating them. This operation will temporarily lock the transaction cache to ensure thread safety, preventing concurrent insertions and queries during its execution. Ensure that the transaction cache is in a constipated state before calling this function.
- **Inputs**:
    - `tc`: A pointer to a `fd_txncache_t` structure representing the transaction cache. Must not be null. The caller retains ownership of the transaction cache.
- **Output**: None
- **See also**: [`fd_txncache_flush_constipated_slots`](fd_txncache.c.driver.md#fd_txncache_flush_constipated_slots)  (Implementation)


---
### fd\_txncache\_root\_slots<!-- {{#callable_declaration:fd_txncache_root_slots}} -->
Retrieve the list of live slots currently tracked by the transaction cache.
- **Description**: This function retrieves the list of live slots currently tracked by the transaction cache and writes them into the provided output array. It should be called when you need to obtain the current set of live slots from the transaction cache. The function temporarily locks the entire transaction cache structure, causing a brief pause in insertion and query operations. Ensure that the output array has sufficient space to hold the maximum number of root slots, as specified by the transaction cache configuration.
- **Inputs**:
    - `tc`: A pointer to a transaction cache object. It must not be null and should point to a valid, initialized transaction cache.
    - `out_slots`: A pointer to an array of unsigned long integers where the live slots will be written. The array must have space for at least the maximum number of root slots as defined by the transaction cache configuration. The caller retains ownership of this array.
- **Output**: The function writes the list of live slots into the provided out_slots array. If there are fewer slots than the maximum, the remaining entries in the array are set to ULONG_MAX. The function does not return a value.
- **See also**: [`fd_txncache_root_slots`](fd_txncache.c.driver.md#fd_txncache_root_slots)  (Implementation)


---
### fd\_txncache\_snapshot<!-- {{#callable_declaration:fd_txncache_snapshot}} -->
Writes the current state of a transaction cache to a binary format using a provided write function.
- **Description**: This function is used to serialize the current state of a transaction cache into a binary format, which can be served to other nodes via snapshot responses. It requires a write function to handle the serialized data. The function assumes that there are no concurrent inserts occurring on the transaction cache at the root slots during the snapshotting process, as this could result in incomplete data in the snapshot. However, it will not cause data corruption. This operation is efficient and does not pause insertion or query operations.
- **Inputs**:
    - `tc`: A pointer to a transaction cache (fd_txncache_t). It must be a valid, initialized transaction cache object.
    - `ctx`: A context pointer that is passed to the write function. It can be used to maintain state or pass additional information required by the write function.
    - `write`: A function pointer that takes a pointer to data, the size of the data, and a context pointer. It must not be null. The function should return 0 on success and a non-zero value on failure. If the write function fails, the snapshot operation will terminate and return the error code.
- **Output**: Returns 0 on success, or a non-zero error code if the write function fails.
- **See also**: [`fd_txncache_snapshot`](fd_txncache.c.driver.md#fd_txncache_snapshot)  (Implementation)


---
### fd\_txncache\_insert\_batch<!-- {{#callable_declaration:fd_txncache_insert_batch}} -->
Inserts a batch of transaction results into a transaction cache.
- **Description**: Use this function to insert multiple transaction results into a transaction cache efficiently. It is designed for high-performance concurrent operations, allowing it to be used alongside other insertions and queries without locking the entire structure. The function assumes that the transaction cache is properly initialized and has sufficient capacity to accommodate the new entries. It returns a success or failure status, where failure typically indicates that the cache is full, which should not occur if the cache is correctly sized.
- **Inputs**:
    - `tc`: A pointer to a transaction cache (fd_txncache_t). Must not be null and should point to a valid, initialized transaction cache.
    - `txns`: A pointer to an array of transaction results (fd_txncache_insert_t) to be inserted. The function does not retain ownership of this memory after the call returns.
    - `txns_cnt`: The number of transaction results in the txns array. Must be a non-negative value.
- **Output**: Returns 1 on successful insertion of all transactions, or 0 if the insertion fails due to the cache being full.
- **See also**: [`fd_txncache_insert_batch`](fd_txncache.c.driver.md#fd_txncache_insert_batch)  (Implementation)


---
### fd\_txncache\_query\_batch<!-- {{#callable_declaration:fd_txncache_query_batch}} -->
Queries a batch of transactions in the transaction cache.
- **Description**: Use this function to check the presence of multiple transactions in a transaction cache by matching their blockhash and txnhash. It is suitable for high-performance, concurrent operations and can be used alongside other queries and insertions. The function requires a transaction cache, a list of queries, and an output array for results. Optionally, a user-defined function can be provided to further filter transactions based on their slot. Ensure that the output array is large enough to hold results for all queries.
- **Inputs**:
    - `tc`: A pointer to a transaction cache (fd_txncache_t). Must not be null.
    - `queries`: A pointer to an array of fd_txncache_query_t structures representing the transactions to query. Must not be null.
    - `queries_cnt`: The number of queries in the queries array. Must be non-zero.
    - `query_func_ctx`: A context pointer passed to the query_func. Can be null if query_func does not require context.
    - `query_func`: An optional function pointer that takes a slot and context, returning 1 if the transaction should be considered present. Can be null.
    - `out_results`: A pointer to an array of integers where results will be stored. Must be at least as large as queries_cnt. Each entry will be set to 1 if the corresponding transaction is present, otherwise 0.
- **Output**: None
- **See also**: [`fd_txncache_query_batch`](fd_txncache.c.driver.md#fd_txncache_query_batch)  (Implementation)


---
### fd\_txncache\_set\_txnhash\_offset<!-- {{#callable_declaration:fd_txncache_set_txnhash_offset}} -->
Sets the transaction hash offset for a specific blockhash and slot in the transaction cache.
- **Description**: This function is used to set the offset value for a transaction hash within the blockcache and slotblockcache of a transaction cache, primarily during snapshot restoration. It should be called when you need to update the transaction hash offset for a specific blockhash and slot. The function requires a valid transaction cache handle and will return an error if the specified cache entry is not found. Ensure that the transaction cache is properly initialized and that the blockhash and slot provided are valid and exist within the cache.
- **Inputs**:
    - `tc`: A pointer to a valid fd_txncache_t structure representing the transaction cache. Must not be null.
    - `slot`: An unsigned long representing the slot for which the transaction hash offset is being set. Must correspond to a valid slot in the transaction cache.
    - `blockhash`: An array of 32 unsigned characters representing the blockhash. Must not be null and should correspond to a valid blockhash in the transaction cache.
    - `txnhash_offset`: An unsigned long representing the offset to be set for the transaction hash. This value is used to update the cache entry.
- **Output**: Returns 0 on success, indicating the offset was set correctly, or 1 if the cache entry is not found.
- **See also**: [`fd_txncache_set_txnhash_offset`](fd_txncache.c.driver.md#fd_txncache_set_txnhash_offset)  (Implementation)


---
### fd\_txncache\_is\_rooted\_slot<!-- {{#callable_declaration:fd_txncache_is_rooted_slot}} -->
Check if a slot is rooted in the transaction cache.
- **Description**: Use this function to determine whether a specific slot is considered rooted within the transaction cache. This is useful for understanding the state of transactions associated with that slot, particularly in contexts where rooted slots have special significance, such as in snapshot generation or transaction validation. The function requires a valid transaction cache handle and a slot number to check. It is a read-only operation and does not modify the transaction cache.
- **Inputs**:
    - `tc`: A pointer to a valid fd_txncache_t structure representing the transaction cache. Must not be null.
    - `slot`: An unsigned long integer representing the slot number to check. There are no specific constraints on the value, but it should be within the range of slots managed by the transaction cache.
- **Output**: Returns 1 if the specified slot is rooted, and 0 otherwise.
- **See also**: [`fd_txncache_is_rooted_slot`](fd_txncache.c.driver.md#fd_txncache_is_rooted_slot)  (Implementation)


---
### fd\_txncache\_get\_entries<!-- {{#callable_declaration:fd_txncache_get_entries}} -->
Converts the rooted state of the transaction cache into a format compatible with Agave.
- **Description**: This function is used to transform the rooted state of a transaction cache into an `fd_bank_slot_deltas_t` structure, which is the format required for Agave-compatible snapshots. It should be called when there is a need to generate a snapshot of the transaction cache's rooted state. The function assumes that the transaction cache is properly initialized and that the provided `fd_bank_slot_deltas_t` and `fd_spad_t` structures are valid and ready to be populated. It locks the transaction cache for reading during the operation to ensure consistency.
- **Inputs**:
    - `tc`: A pointer to an `fd_txncache_t` structure representing the transaction cache. It must be a valid, initialized transaction cache and must not be null.
    - `slot_deltas`: A pointer to an `fd_bank_slot_deltas_t` structure where the function will store the converted rooted state. It must be a valid pointer and must not be null.
    - `spad`: A pointer to an `fd_spad_t` structure used for memory allocation during the conversion process. It must be a valid pointer and must not be null.
- **Output**: Returns 0 on success. The `slot_deltas` structure is populated with the converted data.
- **See also**: [`fd_txncache_get_entries`](fd_txncache.c.driver.md#fd_txncache_get_entries)  (Implementation)


---
### fd\_txncache\_get\_is\_constipated<!-- {{#callable_declaration:fd_txncache_get_is_constipated}} -->
Check if the transaction cache is in a constipated state.
- **Description**: Use this function to determine whether the transaction cache is currently marked as constipated. This state is relevant when the cache is being used to generate a snapshot, as it prevents older root slots from being purged. The function should be called when you need to verify the cache's state before performing operations that depend on whether the cache is constipated or not. It is a read-only operation and does not modify the state of the transaction cache.
- **Inputs**:
    - `tc`: A pointer to an fd_txncache_t structure representing the transaction cache. Must not be null. The function assumes the caller has appropriate access to the transaction cache.
- **Output**: Returns an integer indicating the constipated state of the transaction cache: 1 if constipated, 0 otherwise.
- **See also**: [`fd_txncache_get_is_constipated`](fd_txncache.c.driver.md#fd_txncache_get_is_constipated)  (Implementation)


---
### fd\_txncache\_set\_is\_constipated<!-- {{#callable_declaration:fd_txncache_set_is_constipated}} -->
Set the constipated state of a transaction cache.
- **Description**: Use this function to update the constipated state of a transaction cache, which is a condition where the cache temporarily halts certain operations. This function should be called when you need to change the constipated status, typically during operations like snapshot generation where the cache state should remain unchanged. Ensure that the transaction cache is properly initialized and accessible before calling this function.
- **Inputs**:
    - `tc`: A pointer to a `fd_txncache_t` structure representing the transaction cache. Must not be null, and the cache should be properly initialized and accessible.
    - `is_constipated`: An integer indicating the new constipated state. Typically, 0 means not constipated, and non-zero means constipated. The function will set this state directly in the cache.
- **Output**: Returns 0 to indicate the operation was successful.
- **See also**: [`fd_txncache_set_is_constipated`](fd_txncache.c.driver.md#fd_txncache_set_is_constipated)  (Implementation)


