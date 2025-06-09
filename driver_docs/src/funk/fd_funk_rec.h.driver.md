# Purpose
The provided C header file, `fd_funk_rec.h`, defines a set of APIs and data structures for managing "funk" records within a transactional system. This file is part of a larger library and is not intended to be included directly; instead, it should be accessed through `fd_funk.h`. The primary purpose of this file is to facilitate the creation, modification, querying, and management of records within transactions, ensuring thread safety and efficient handling of concurrent operations. The file defines a `fd_funk_rec_t` structure, which represents a record, and includes fields for transaction and record management, such as transaction IDs, record keys, and flags for record interpretation. The file also provides constants and macros for record alignment, footprint, and flag management, such as the `FD_FUNK_REC_FLAG_ERASE` for marking records as tombstones.

The header file includes a variety of functions for interacting with funk records, such as [`fd_funk_rec_modify`](#fd_funk_rec_modify), [`fd_funk_rec_publish`](#fd_funk_rec_publish), and [`fd_funk_rec_remove`](#fd_funk_rec_remove), among others. These functions allow for the preparation, modification, and removal of records, as well as querying records within transactions. The file also defines iterators and utility functions for managing and verifying the integrity of the record map. The APIs are designed to be thread-safe, allowing for concurrent operations across multiple threads. Additionally, the file includes mechanisms for handling record flags, such as setting and retrieving erase data, and provides a framework for indexing and mapping records by their transaction ID and key pairs. Overall, this header file is a crucial component of a transactional record management system, providing the necessary tools and structures for efficient and safe record handling.
# Imports and Dependencies

---
- `fd_funk_txn.h`
- `../util/tmpl/fd_pool_para.c`
- `../util/tmpl/fd_map_chain_para.c`


# Global Variables

---
### fd\_funk\_rec\_modify
- **Type**: `fd_funk_rec_t *`
- **Description**: The `fd_funk_rec_modify` function is a global function that attempts to modify a funk record corresponding to a given key within a specified transaction. If the record does not exist, it returns NULL. If the transaction is NULL, the function operates on the last published transaction. On success, it returns a mutable pointer to the funk record.
- **Use**: This function is used to modify records in a transactional context, ensuring thread safety and proper handling of record contention.


---
### fd\_funk\_rec\_query\_try
- **Type**: `fd_funk_rec_t const *`
- **Description**: The `fd_funk_rec_query_try` function is a global function that attempts to query a record in an in-preparation transaction or the last published transaction if the transaction is NULL. It returns a constant pointer to the `fd_funk_rec_t` structure representing the record if successful, or NULL if the record is not found or the inputs are invalid.
- **Use**: This function is used to retrieve a record from a transaction based on a given key, allowing the caller to access the record's data for read-only purposes.


---
### fd\_funk\_rec\_query\_try\_global
- **Type**: `fd_funk_rec_t const *`
- **Description**: The `fd_funk_rec_query_try_global` function is a global function that attempts to query a record in a transaction or its ancestors based on a given key. It returns a pointer to the record if found, or NULL if the record is not found or is marked with the ERASE flag.
- **Use**: This function is used to retrieve records from a transaction or its ancestors, setting `txn_out` to the transaction where the record was found.


---
### fd\_funk\_rec\_query\_copy
- **Type**: `fd_funk_rec_t const *`
- **Description**: The `fd_funk_rec_query_copy` function is a global function that queries an in-preparation transaction for a record matching a specified key. It returns a pointer to a copy of the record's contents, which are allocated using a specified allocator (`valloc`). If the query fails, it returns NULL, and the size of the record is output through `sz_out`. This function is part of a larger API for managing 'funk' records, which are data structures used to track transactions and records in a system.
- **Use**: This function is used to safely copy the contents of a record from an in-preparation transaction into allocated space, providing a pointer to the copied data.


---
### fd\_funk\_rec\_prepare
- **Type**: `fd_funk_rec_t *`
- **Description**: The `fd_funk_rec_prepare` function is a global function that prepares a new record for insertion into a funk record map. It allocates a record from the pool and initializes it, allowing the application to fill in the new value before it is published.
- **Use**: This function is used to allocate and initialize a new record in preparation for insertion into a funk record map.


---
### fd\_funk\_rec\_clone
- **Type**: `fd_funk_rec_t *`
- **Description**: The `fd_funk_rec_clone` function is a global function that returns a pointer to a `fd_funk_rec_t` structure. It is used to copy a record from an ancestor transaction to create a new record in the given transaction. This function is not thread-safe and should not be used concurrently with other funk read/write operations.
- **Use**: This function is used to clone a record from an ancestor transaction into a new record in the current transaction, allowing for modifications before publishing.


---
### fd\_funk\_all\_iter\_ele\_const
- **Type**: `function`
- **Description**: `fd_funk_all_iter_ele_const` is a function that returns a constant pointer to a `fd_funk_rec_t` structure. This function is used to access the current element in an iteration over all funk record objects in all funk transactions.
- **Use**: This function is used within an iteration loop to retrieve a constant pointer to the current funk record being iterated over.


---
### fd\_funk\_all\_iter\_ele
- **Type**: `fd_funk_rec_t *`
- **Description**: The `fd_funk_all_iter_ele` is a function that returns a pointer to a `fd_funk_rec_t` structure, which represents a funk record. This function is used to access the current element in an iteration over all funk records using an iterator of type `fd_funk_all_iter_t`. The function is part of a set of APIs designed to manage and manipulate funk records in a thread-safe manner.
- **Use**: This function is used to retrieve the current funk record from an iterator during iteration over all funk records.


# Data Structures

---
### fd\_funk\_rec
- **Type**: `struct`
- **Members**:
    - `pair`: Transaction id and record key pair.
    - `map_next`: Internal use by map.
    - `map_hash`: Internal use by map.
    - `prev_idx`: Record map index of previous record in its transaction.
    - `next_idx`: Record map index of next record in its transaction.
    - `accounts_lru_prev_idx`: Record map idx of the next record in the accounts LRU dlist.
    - `accounts_lru_next_idx`: Record map idx of the prev record in the accounts LRU dlist.
    - `txn_cidx`: Compressed transaction map index.
    - `tag`: Internal use only.
    - `flags`: Flags that indicate how to interpret a record.
    - `val_sz`: Num bytes in record value, in [0,val_max].
    - `val_max`: Max byte in record value, in [0,FD_FUNK_REC_VAL_MAX], 0 if erase flag set or val_gaddr is 0.
    - `val_gaddr`: Wksp gaddr on record value if any, 0 if erase flag set or val_max is 0.
- **Description**: The `fd_funk_rec` structure is a complex data structure used to manage records within a transactional system. It includes fields for transaction and record identification, internal mapping, and linked list management for transaction records. The structure also reserves fields for future use in a Least Recently Used (LRU) cache mechanism. Additionally, it contains fields for managing the size and location of record values, with specific flags to indicate the state and interpretation of the record. The structure is aligned to a specified boundary to optimize memory access and is designed to be used within a larger system that handles transactional data operations.


---
### fd\_funk\_rec\_t
- **Type**: `struct`
- **Members**:
    - `pair`: Transaction id and record key pair.
    - `map_next`: Internal use by map for next record index.
    - `map_hash`: Internal use by map for hash value.
    - `prev_idx`: Record map index of previous record in its transaction.
    - `next_idx`: Record map index of next record in its transaction.
    - `accounts_lru_prev_idx`: Record map index of the next record in the accounts LRU doubly linked list.
    - `accounts_lru_next_idx`: Record map index of the previous record in the accounts LRU doubly linked list.
    - `txn_cidx`: Compressed transaction map index or compressed FD_FUNK_TXN_IDX if in the last published transaction.
    - `tag`: Internal use only for tagging purposes.
    - `flags`: Flags that indicate how to interpret a record, including the ERASE flag.
    - `val_sz`: Number of bytes in the record value, ranging from 0 to val_max.
    - `val_max`: Maximum number of bytes in the record value, 0 if the erase flag is set or val_gaddr is 0.
    - `val_gaddr`: Workspace global address of the record value, 0 if the erase flag is set or val_max is 0.
- **Description**: The `fd_funk_rec_t` structure represents a funk record, which is part of a transactional system for managing records. It includes fields for managing the record's position and state within a transaction, such as transaction id and record key pair, map indices for linking records, and flags for interpreting the record's state. The structure also includes fields for managing the record's value, including its size, maximum size, and global address. The structure is aligned to 64 bytes and is designed to be used within a map for efficient record management and querying.


---
### \_fd\_funk\_rec\_prepare
- **Type**: `struct`
- **Members**:
    - `rec`: A pointer to a funk record.
    - `rec_head_idx`: A pointer to the index of the head of the record list.
    - `rec_tail_idx`: A pointer to the index of the tail of the record list.
    - `txn_lock`: A pointer to a transaction lock.
- **Description**: The `_fd_funk_rec_prepare` structure is used to represent a new funk record that has been prepared but not yet inserted into the map. It contains pointers to the record itself, the head and tail indices of the record list, and a transaction lock. This structure is part of the process of preparing a record for insertion, allowing for the initialization and setup of the record before it is published into the record map.


---
### fd\_funk\_rec\_prepare\_t
- **Type**: `struct`
- **Members**:
    - `rec`: A pointer to a `fd_funk_rec_t` structure representing the prepared record.
    - `rec_head_idx`: A pointer to a `uint` representing the index of the head of the record list.
    - `rec_tail_idx`: A pointer to a `uint` representing the index of the tail of the record list.
    - `txn_lock`: A pointer to a `uchar` used for transaction locking.
- **Description**: The `fd_funk_rec_prepare_t` structure is used to represent a new record that has been prepared but not yet inserted into the map. It contains pointers to the record itself, indices for managing the record list, and a transaction lock to ensure thread safety during the preparation phase. This structure is part of the process of preparing a record for insertion, which involves allocating and initializing the record before it is published into the record map.


---
### fd\_funk\_all\_iter
- **Type**: `struct`
- **Members**:
    - `rec_map`: A map of funk records used for iteration.
    - `chain_cnt`: The total number of chains in the record map.
    - `chain_idx`: The current index of the chain being iterated over.
    - `rec_map_iter`: An iterator for traversing the record map.
- **Description**: The `fd_funk_all_iter` structure is designed to facilitate iteration over all funk record objects across all transactions in a funk database. It maintains state information necessary for traversing the record map, including the total number of chains, the current chain index, and an iterator for the record map. This structure is used in conjunction with specific functions to initialize, check completion, and advance the iteration process.


---
### fd\_funk\_all\_iter\_t
- **Type**: `struct`
- **Members**:
    - `rec_map`: A map of funk records used for iteration.
    - `chain_cnt`: The total number of chains in the record map.
    - `chain_idx`: The current index of the chain being iterated over.
    - `rec_map_iter`: An iterator for traversing the record map.
- **Description**: The `fd_funk_all_iter_t` structure is designed to facilitate iteration over all funk record objects across all transactions in a funk database. It maintains state information necessary for traversing the record map, including the current chain index and an iterator for the map. This structure is not optimized for performance and assumes no concurrent write operations are performed on the funk database during its use.


# Functions

---
### fd\_funk\_rec\_idx\_is\_null<!-- {{#callable:fd_funk_rec_idx_is_null}} -->
The function `fd_funk_rec_idx_is_null` checks if a given record index is equal to the constant `FD_FUNK_REC_IDX_NULL` and returns 1 if true, otherwise 0.
- **Inputs**:
    - `idx`: An unsigned integer representing the record index to be checked against `FD_FUNK_REC_IDX_NULL`.
- **Control Flow**:
    - The function compares the input `idx` with the constant `FD_FUNK_REC_IDX_NULL`.
    - If `idx` is equal to `FD_FUNK_REC_IDX_NULL`, the function returns 1.
    - If `idx` is not equal to `FD_FUNK_REC_IDX_NULL`, the function returns 0.
- **Output**: An integer value, 1 if the index is `FD_FUNK_REC_IDX_NULL`, otherwise 0.


---
### fd\_funk\_rec\_pair<!-- {{#callable:fd_funk_rec_pair}} -->
The `fd_funk_rec_pair` function returns a pointer to the transaction ID and record key pair of a given funk record.
- **Inputs**:
    - `rec`: A pointer to a constant `fd_funk_rec_t` structure representing a funk record.
- **Control Flow**:
    - The function takes a single input, `rec`, which is a pointer to a constant `fd_funk_rec_t` structure.
    - It returns the address of the `pair` member of the `fd_funk_rec_t` structure, which contains the transaction ID and record key pair.
- **Output**: A constant pointer to an `fd_funk_xid_key_pair_t` structure, representing the transaction ID and record key pair of the given funk record.


---
### fd\_funk\_rec\_xid<!-- {{#callable:fd_funk_rec_xid}} -->
The `fd_funk_rec_xid` function retrieves the transaction ID associated with a given funk record.
- **Inputs**:
    - `rec`: A pointer to a constant `fd_funk_rec_t` structure representing a funk record.
- **Control Flow**:
    - The function takes a single input, `rec`, which is a pointer to a constant `fd_funk_rec_t` structure.
    - It accesses the `pair` member of the `fd_funk_rec_t` structure, which is of type `fd_funk_xid_key_pair_t`.
    - It returns the `xid` member of the `pair`, which represents the transaction ID associated with the record.
- **Output**: A constant pointer to `fd_funk_txn_xid_t`, representing the transaction ID of the given funk record.


---
### fd\_funk\_rec\_key<!-- {{#callable:fd_funk_rec_key}} -->
The `fd_funk_rec_key` function retrieves the record key from a given funk record.
- **Inputs**:
    - `rec`: A pointer to a constant `fd_funk_rec_t` structure representing a funk record.
- **Control Flow**:
    - The function takes a single input parameter, `rec`, which is a pointer to a constant `fd_funk_rec_t` structure.
    - It accesses the `pair` member of the `fd_funk_rec_t` structure, which is of type `fd_funk_xid_key_pair_t`.
    - It then returns the `key` member of the `pair`, which is a pointer to a constant `fd_funk_rec_key_t`.
- **Output**: A pointer to a constant `fd_funk_rec_key_t`, representing the key of the given funk record.


# Function Declarations (Public API)

---
### fd\_funk\_rec\_modify<!-- {{#callable_declaration:fd_funk_rec_modify}} -->
Attempts to modify a record in a transaction.
- **Description**: This function is used to modify a record identified by a key within a specified transaction. If the record does not exist, the function returns NULL. It is thread-safe and can be used concurrently with other operations on the same funk instance. The function blocks if there is contention for the record or related records. It must be followed by a call to `fd_funk_rec_modify_publish` to commit changes. The function handles records with the ERASE flag, and users should check for this flag when accessing records.
- **Inputs**:
    - `funk`: A pointer to the funk instance, which must be a current local join. If NULL, the function returns NULL.
    - `txn`: A pointer to the transaction in which the record is to be modified. It can be NULL, in which case the last published transaction is used. The transaction must be in the caller's address space.
    - `key`: A pointer to the record key, which must be in the caller's address space. If NULL, the function returns NULL.
    - `query`: A pointer to a query object that will store the query result for later validity testing. It must not be NULL.
- **Output**: Returns a mutable pointer to the funk record on success, or NULL if the record does not exist.
- **See also**: [`fd_funk_rec_modify`](fd_funk_rec.c.driver.md#fd_funk_rec_modify)  (Implementation)


---
### fd\_funk\_rec\_modify\_publish<!-- {{#callable_declaration:fd_funk_rec_modify_publish}} -->
Commits modifications to a funk record.
- **Description**: Use this function to finalize and commit any changes made to a funk record after calling fd_funk_rec_modify. It is essential to call this function to release the lock on the record and its associated hash chain, ensuring that the modifications are properly published. This function should be called only after successfully modifying a record with fd_funk_rec_modify.
- **Inputs**:
    - `query`: A pointer to an fd_funk_rec_query_t structure that holds the query information for the record being modified. This must not be null and should be the same query used in the preceding fd_funk_rec_modify call.
- **Output**: None
- **See also**: [`fd_funk_rec_modify_publish`](fd_funk_rec.c.driver.md#fd_funk_rec_modify_publish)  (Implementation)


---
### fd\_funk\_rec\_query\_try<!-- {{#callable_declaration:fd_funk_rec_query_try}} -->
Queries a transaction for a record by key.
- **Description**: Use this function to query an in-preparation transaction for a record with a specific key. If the transaction is NULL, the query will be performed on the last published transaction. The function returns a pointer to the record if found, or NULL if the record does not exist or if any input parameters are invalid. The function is thread-safe and assumes no concurrent operations on the provided funk, transaction, or key. The query parameter is used to store the query state for later validation. Be aware that records with the ERASE flag set will still be returned, and the application should handle such cases appropriately.
- **Inputs**:
    - `funk`: A pointer to the funk instance. Must not be NULL and should be a current local join.
    - `txn`: A pointer to the transaction to query, or NULL to query the last published transaction. If not NULL, it must point to an in-preparation transaction.
    - `key`: A pointer to the record key to query. Must not be NULL and should be in the caller's address space.
    - `query`: A pointer to a query object that will store the query state. Must not be NULL.
- **Output**: Returns a pointer to the record if found, or NULL if the record does not exist or if any input parameters are invalid.
- **See also**: [`fd_funk_rec_query_try`](fd_funk_rec.c.driver.md#fd_funk_rec_query_try)  (Implementation)


---
### fd\_funk\_rec\_query\_test<!-- {{#callable_declaration:fd_funk_rec_query_test}} -->
Checks if a prior query still has a valid result.
- **Description**: Use this function to verify the validity of a previously executed query on a funk record. It is typically used in a loop to ensure that the record data read optimistically is still valid before proceeding with further operations. This function is thread-safe and can be called concurrently across threads.
- **Inputs**:
    - `query`: A pointer to a fd_funk_rec_query_t structure that holds the state of a previous query. Must not be null.
- **Output**: Returns an integer indicating success if the query result is still valid, or an error code if it is not.
- **See also**: [`fd_funk_rec_query_test`](fd_funk_rec.c.driver.md#fd_funk_rec_query_test)  (Implementation)


---
### fd\_funk\_rec\_query\_try\_global<!-- {{#callable_declaration:fd_funk_rec_query_try_global}} -->
Queries a record in a transaction and its ancestors by key.
- **Description**: This function attempts to find a record with the specified key within the given transaction and its ancestor transactions, returning the most recent matching record. It is useful when you need to access a record that might not be present in the current transaction but exists in one of its ancestors. The function is thread-safe and can be used concurrently across threads. If the record is found, the transaction where it was found is returned via the `txn_out` parameter. If the record has the ERASE flag set, the function returns NULL but still sets `txn_out` to the relevant transaction. Ensure that `funk`, `key`, and `query` are not NULL before calling this function.
- **Inputs**:
    - `funk`: A pointer to the funk instance, representing the context in which the query is performed. Must not be NULL.
    - `txn`: A pointer to the transaction in which to start the query. Can be NULL, in which case the query starts from the last published transaction.
    - `key`: A pointer to the record key to query. Must not be NULL.
    - `txn_out`: A pointer to a location where the function will store the transaction where the record was found. Can be NULL if the caller is not interested in this information.
    - `query`: A pointer to a query object that will be used to store query state for later validity testing. Must not be NULL.
- **Output**: Returns a pointer to the record if found and not erased, otherwise NULL. If the record is erased, NULL is returned but `txn_out` is still set to the transaction where the record was found.
- **See also**: [`fd_funk_rec_query_try_global`](fd_funk_rec.c.driver.md#fd_funk_rec_query_try_global)  (Implementation)


---
### fd\_funk\_rec\_query\_copy<!-- {{#callable_declaration:fd_funk_rec_query_copy}} -->
Copies a record's contents into allocated memory.
- **Description**: This function queries the specified transaction for a record matching the given key and copies its contents into memory allocated using the provided allocator. It is useful when a safe, independent copy of a record's data is needed. The function returns a pointer to the allocated memory containing the record's data, or NULL if the record is not found or an error occurs. The size of the copied data is stored in the provided size output parameter. Ensure that the allocator is capable of handling the memory allocation requests, and be prepared to handle a NULL return value indicating failure.
- **Inputs**:
    - `funk`: A pointer to the funk instance to query. Must not be NULL and should be a valid, current local join.
    - `txn`: A pointer to the transaction to query, or NULL to query the last published transaction. If not NULL, it must point to an in-preparation transaction.
    - `key`: A pointer to the record key to query. Must not be NULL and should point to a valid record key.
    - `valloc`: An allocator used to allocate memory for the record copy. Must be capable of handling allocation requests.
    - `sz_out`: A pointer to a ulong where the size of the copied record will be stored. Must not be NULL.
- **Output**: Returns a pointer to the allocated memory containing the record's data, or NULL if the record is not found or an error occurs. The size of the copied data is stored in sz_out.
- **See also**: [`fd_funk_rec_query_copy`](fd_funk_rec.c.driver.md#fd_funk_rec_query_copy)  (Implementation)


---
### fd\_funk\_rec\_prepare<!-- {{#callable_declaration:fd_funk_rec_prepare}} -->
Prepares a new record for insertion into a Funk transaction.
- **Description**: This function allocates and initializes a new record for a specified transaction or the last published transaction if no transaction is provided. It should be used when you need to prepare a record for insertion, allowing you to set the record's value before finalizing the insertion with a separate publish call. The function requires valid pointers for the Funk instance, record key, and preparation structure. If any of these are null, or if the transaction is invalid or frozen, the function will return null and optionally set an error code.
- **Inputs**:
    - `funk`: A pointer to the Funk instance where the record will be prepared. Must not be null.
    - `txn`: A pointer to the transaction in which the record is being prepared. Can be null to use the last published transaction.
    - `key`: A pointer to the record key. Must not be null.
    - `prepare`: A pointer to a preparation structure that will be filled with details about the prepared record. Must not be null.
    - `opt_err`: An optional pointer to an integer where an error code will be stored if the function fails. Can be null.
- **Output**: Returns a pointer to the prepared record on success, or null on failure. If null is returned, opt_err may contain an error code.
- **See also**: [`fd_funk_rec_prepare`](fd_funk_rec.c.driver.md#fd_funk_rec_prepare)  (Implementation)


---
### fd\_funk\_rec\_publish<!-- {{#callable_declaration:fd_funk_rec_publish}} -->
Inserts a prepared record into the record map.
- **Description**: This function is used to finalize the insertion of a record that has been prepared using `fd_funk_rec_prepare`. It should be called once the record's value is correctly set and ready to be added to the record map. The function ensures thread safety by acquiring a lock on the transaction during the insertion process. It is important to ensure that the `prepare` structure is properly initialized and that the transaction lock is not already held by another operation before calling this function.
- **Inputs**:
    - `funk`: A pointer to an `fd_funk_t` structure representing the funk context. Must not be null.
    - `prepare`: A pointer to an `fd_funk_rec_prepare_t` structure that contains the prepared record and associated metadata. Must not be null and should be properly initialized by `fd_funk_rec_prepare`.
- **Output**: None
- **See also**: [`fd_funk_rec_publish`](fd_funk_rec.c.driver.md#fd_funk_rec_publish)  (Implementation)


---
### fd\_funk\_rec\_cancel<!-- {{#callable_declaration:fd_funk_rec_cancel}} -->
Returns a prepared record to the pool without inserting it.
- **Description**: Use this function to cancel the preparation of a new record that was previously prepared but should not be inserted into the record map. This is useful when a prepared record is no longer needed or if an error occurs during preparation. The function must be called with a valid prepared record and a valid funk context. It is thread-safe and can be used in concurrent environments.
- **Inputs**:
    - `funk`: A pointer to an fd_funk_t structure representing the funk context. Must not be null. The caller retains ownership.
    - `prepare`: A pointer to an fd_funk_rec_prepare_t structure representing the prepared record to be canceled. Must not be null. The caller retains ownership.
- **Output**: None
- **See also**: [`fd_funk_rec_cancel`](fd_funk_rec.c.driver.md#fd_funk_rec_cancel)  (Implementation)


---
### fd\_funk\_rec\_clone<!-- {{#callable_declaration:fd_funk_rec_clone}} -->
Clones a record from an ancestor transaction into a new record in the current transaction.
- **Description**: Use this function to create a new record in the current transaction by copying an existing record from an ancestor transaction. This function is not thread-safe and should not be used concurrently with other funk read/write operations. It is important to handle the case where the record does not exist in any ancestor transaction, as this will result in a NULL return. After cloning, the new record can be modified and must be published to be finalized.
- **Inputs**:
    - `funk`: A pointer to the funk instance. Must be a valid, non-null pointer to a current local join.
    - `txn`: A pointer to the transaction in which the new record will be created. Must be a valid, non-null pointer to an in-preparation transaction.
    - `key`: A pointer to the key of the record to be cloned. Must be a valid, non-null pointer.
    - `prepare`: A pointer to a fd_funk_rec_prepare_t structure used to prepare the new record. Must be a valid, non-null pointer.
    - `opt_err`: An optional pointer to an integer where error codes will be stored. Can be null if error codes are not needed.
- **Output**: Returns a pointer to the newly created record on success, or NULL if the record could not be cloned.
- **See also**: [`fd_funk_rec_clone`](fd_funk_rec.c.driver.md#fd_funk_rec_clone)  (Implementation)


---
### fd\_funk\_rec\_try\_clone\_safe<!-- {{#callable_declaration:fd_funk_rec_try_clone_safe}} -->
Safely clones a record from an ancestor transaction into the current transaction.
- **Description**: Use this function to atomically clone a record from the youngest ancestor transaction into the current transaction if it does not already exist. It ensures thread safety by acquiring necessary locks and checks for the existence of the record in the current transaction before proceeding. This function is useful when you need to ensure that a record is available in the current transaction context, potentially with a specified alignment and minimum size for its value. It should be called when you need to clone a record safely without interfering with other concurrent operations.
- **Inputs**:
    - `funk`: A pointer to the fd_funk_t structure representing the current funk context. Must not be null.
    - `txn`: A pointer to the fd_funk_txn_t structure representing the current transaction. Must not be null.
    - `key`: A pointer to the fd_funk_rec_key_t structure representing the key of the record to be cloned. Must not be null.
    - `align`: An unsigned long specifying the desired alignment for the record's value. If 0, default alignment is used.
    - `min_sz`: An unsigned long specifying the minimum size for the record's value. The function ensures the value is at least this size.
- **Output**: None
- **See also**: [`fd_funk_rec_try_clone_safe`](fd_funk_rec.c.driver.md#fd_funk_rec_try_clone_safe)  (Implementation)


---
### fd\_funk\_rec\_remove<!-- {{#callable_declaration:fd_funk_rec_remove}} -->
Removes a record from a transaction in the funk system.
- **Description**: This function is used to remove a record identified by a key from a specified transaction within the funk system. It can be called with a transaction to remove a record from an in-preparation transaction or with a null transaction to remove from the last published transaction. The function ensures that the transaction or the last published state is not frozen before proceeding. If the record is successfully removed, a tombstone is left behind to track the removal. This function is thread-safe and should be used when you need to ensure that a record is no longer part of a transaction or its descendants. It returns an error code if the operation fails due to invalid inputs, frozen state, or if the record does not exist.
- **Inputs**:
    - `funk`: A pointer to the funk system from which the record is to be removed. Must not be null.
    - `txn`: A pointer to the transaction from which the record is to be removed. Can be null to indicate the last published transaction.
    - `key`: A pointer to the key identifying the record to be removed. Must not be null.
    - `rec_out`: A pointer to a location where the function will store a pointer to the removed record, if not null.
    - `erase_data`: An unsigned long value used to store metadata in the record's flags upon removal.
- **Output**: Returns FD_FUNK_SUCCESS (0) on success, or a negative FD_FUNK_ERR_* code on failure, indicating the type of error encountered.
- **See also**: [`fd_funk_rec_remove`](fd_funk_rec.c.driver.md#fd_funk_rec_remove)  (Implementation)


---
### fd\_funk\_rec\_hard\_remove<!-- {{#callable_declaration:fd_funk_rec_hard_remove}} -->
Completely removes a record from the Funk database without leaving a tombstone.
- **Description**: Use this function to permanently remove a record from the Funk database, ensuring that no trace of the record remains. This operation is irreversible and should be used with caution, as it may expose older versions of the record from parent transactions, effectively reverting updates. The function always succeeds and should be used when it is necessary to completely eliminate a record from the system.
- **Inputs**:
    - `funk`: A pointer to the fd_funk_t structure representing the Funk database. Must not be null.
    - `txn`: A pointer to the fd_funk_txn_t structure representing the transaction context. Can be null, in which case the operation is performed on the last published transaction.
    - `key`: A pointer to the fd_funk_rec_key_t structure representing the key of the record to be removed. Must not be null.
- **Output**: None
- **See also**: [`fd_funk_rec_hard_remove`](fd_funk_rec.c.driver.md#fd_funk_rec_hard_remove)  (Implementation)


---
### fd\_funk\_rec\_set\_erase\_data<!-- {{#callable_declaration:fd_funk_rec_set_erase_data}} -->
Sets the erase data in a funk record's flags.
- **Description**: Use this function to set the erase data in the flags of a funk record. This is typically done when you want to mark a record for erasure in a transaction. The function modifies the record's flags to include the specified erase data, which is stored in the five most significant bytes of the flags. Ensure that the record is valid and that the erase data is within the acceptable range before calling this function.
- **Inputs**:
    - `rec`: A pointer to the fd_funk_rec_t structure representing the funk record. Must not be null, and the record should be valid and properly initialized.
    - `erase_data`: An unsigned long value containing the erase data to set. Only the five least significant bytes are used, and they are shifted into the most significant bytes of the record's flags.
- **Output**: None
- **See also**: [`fd_funk_rec_set_erase_data`](fd_funk_rec.c.driver.md#fd_funk_rec_set_erase_data)  (Implementation)


---
### fd\_funk\_rec\_get\_erase\_data<!-- {{#callable_declaration:fd_funk_rec_get_erase_data}} -->
Retrieves the erase data from a funk record's flags.
- **Description**: Use this function to extract the erase data stored in the flags of a funk record. This is useful when you need to access metadata associated with erased records. The function assumes that the record is valid and that the erase flag is set, as the erase data is only meaningful in this context. Ensure that the record pointer is not null before calling this function.
- **Inputs**:
    - `rec`: A pointer to a constant fd_funk_rec_t structure representing the funk record. Must not be null. The record should have the ERASE flag set for the erase data to be meaningful.
- **Output**: Returns an unsigned long containing the erase data extracted from the record's flags.
- **See also**: [`fd_funk_rec_get_erase_data`](fd_funk_rec.c.driver.md#fd_funk_rec_get_erase_data)  (Implementation)


---
### fd\_funk\_rec\_forget<!-- {{#callable_declaration:fd_funk_rec_forget}} -->
Removes a list of tombstones from the funk record system.
- **Description**: This function is used to free up space in the main index by removing tombstone records that have been marked for erasure and published. It should be called when you want to permanently forget records that are no longer needed. The function requires that all records in the list have been previously removed and published. It is important to ensure that the `funk` and `recs` parameters are valid and that the records belong to the specified `funk` instance.
- **Inputs**:
    - `funk`: A pointer to the `fd_funk_t` instance representing the funk record system. Must not be null.
    - `recs`: An array of pointers to `fd_funk_rec_t` records that are to be forgotten. Each record must be a tombstone that has been removed and published.
    - `recs_cnt`: The number of records in the `recs` array. Must be a non-negative value.
- **Output**: Returns `FD_FUNK_SUCCESS` on successful removal of all specified tombstones, or an error code such as `FD_FUNK_ERR_INVAL` or `FD_FUNK_ERR_KEY` if the operation fails due to invalid inputs or records not being in the correct state.
- **See also**: [`fd_funk_rec_forget`](fd_funk_rec.c.driver.md#fd_funk_rec_forget)  (Implementation)


---
### fd\_funk\_all\_iter\_new<!-- {{#callable_declaration:fd_funk_all_iter_new}} -->
Initialize an iterator for traversing all funk records.
- **Description**: Use this function to initialize an iterator that will traverse all records in a given funk instance. This function must be called before using the iterator in any traversal operations. The iterator will be set up to skip over any null records automatically. Ensure that no other threads are performing write operations on the funk instance during the iterator's lifetime to avoid undefined behavior.
- **Inputs**:
    - `funk`: A pointer to an fd_funk_t instance representing the funk database to iterate over. Must not be null. The caller retains ownership.
    - `iter`: A pointer to an fd_funk_all_iter_t instance where the iterator state will be stored. Must not be null. The caller is responsible for managing the memory of this iterator.
- **Output**: None
- **See also**: [`fd_funk_all_iter_new`](fd_funk_rec.c.driver.md#fd_funk_all_iter_new)  (Implementation)


---
### fd\_funk\_all\_iter\_done<!-- {{#callable_declaration:fd_funk_all_iter_done}} -->
Checks if the iteration over all funk records is complete.
- **Description**: Use this function to determine if an iteration over all funk records has reached the end. It should be called after initializing the iterator with `fd_funk_all_iter_new` and during iteration to check if there are more records to process. This function is useful in loop conditions to ensure that the iteration stops when all records have been visited.
- **Inputs**:
    - `iter`: A pointer to an `fd_funk_all_iter_t` structure representing the current state of the iteration. Must not be null. The function checks the internal state of this iterator to determine if the iteration is complete.
- **Output**: Returns a non-zero value if the iteration is complete, and zero if there are more records to iterate over.
- **See also**: [`fd_funk_all_iter_done`](fd_funk_rec.c.driver.md#fd_funk_all_iter_done)  (Implementation)


---
### fd\_funk\_all\_iter\_next<!-- {{#callable_declaration:fd_funk_all_iter_next}} -->
Advances the iterator to the next record, skipping null entries.
- **Description**: Use this function to move an iterator to the next valid record in a collection of funk records. It should be called in a loop to iterate over all records. The function automatically skips over any null entries, ensuring that the iterator always points to a valid record or the end of the collection. This function assumes that the iterator has been properly initialized and is not used concurrently with other write operations on the funk records.
- **Inputs**:
    - `iter`: A pointer to an fd_funk_all_iter_t structure representing the current state of the iterator. Must not be null. The iterator should be initialized before calling this function, and the caller retains ownership.
- **Output**: None
- **See also**: [`fd_funk_all_iter_next`](fd_funk_rec.c.driver.md#fd_funk_all_iter_next)  (Implementation)


---
### fd\_funk\_all\_iter\_ele\_const<!-- {{#callable_declaration:fd_funk_all_iter_ele_const}} -->
Retrieve the current record from the iterator.
- **Description**: Use this function to access the current record pointed to by the iterator in a read-only manner. It is typically used within an iteration loop over all funk records. The iterator must be properly initialized and not at the end of the iteration. This function is thread-safe and can be used concurrently with other read operations.
- **Inputs**:
    - `iter`: A pointer to an fd_funk_all_iter_t structure representing the current state of the iteration. Must not be null and should be properly initialized before use.
- **Output**: Returns a constant pointer to the current fd_funk_rec_t record in the iteration. If the iterator is at the end, the behavior is undefined.
- **See also**: [`fd_funk_all_iter_ele_const`](fd_funk_rec.c.driver.md#fd_funk_all_iter_ele_const)  (Implementation)


---
### fd\_funk\_all\_iter\_ele<!-- {{#callable_declaration:fd_funk_all_iter_ele}} -->
Retrieves the current record from an iterator.
- **Description**: Use this function to obtain the current record from a funk record iterator. It is typically called within an iteration loop to access each record in turn. The iterator must be properly initialized and not at the end of the iteration. This function provides a mutable pointer to the record, allowing modifications if needed. Ensure that the iterator is valid and not null before calling this function.
- **Inputs**:
    - `iter`: A pointer to an fd_funk_all_iter_t structure representing the iterator. It must be initialized and valid. The function assumes the iterator is not null and is currently pointing to a valid record.
- **Output**: Returns a pointer to the current fd_funk_rec_t record in the iterator, allowing for modifications.
- **See also**: [`fd_funk_all_iter_ele`](fd_funk_rec.c.driver.md#fd_funk_all_iter_ele)  (Implementation)


---
### fd\_funk\_rec\_verify<!-- {{#callable_declaration:fd_funk_rec_verify}} -->
Verifies the integrity of the record map in a funk instance.
- **Description**: Use this function to ensure that the record map within a given funk instance is consistent and intact. It should be called as part of a broader verification process, typically after verifying the workspace, transaction map, and record map of the funk instance. This function checks the linkage and flags of records, ensuring they are correctly associated with transactions, either published or in preparation. It logs warnings if any inconsistencies are found and returns an error code in such cases.
- **Inputs**:
    - `funk`: A pointer to a fd_funk_t instance representing the funk whose record map is to be verified. Must not be null. The caller retains ownership.
- **Output**: Returns FD_FUNK_SUCCESS if the record map is intact, or FD_FUNK_ERR_INVAL if inconsistencies are found, with details logged.
- **See also**: [`fd_funk_rec_verify`](fd_funk_rec.c.driver.md#fd_funk_rec_verify)  (Implementation)


