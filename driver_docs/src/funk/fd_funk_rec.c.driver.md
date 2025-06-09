# Purpose
The provided C source code file is part of a larger system that manages a record map implementation, specifically for handling transactional records within a database-like structure. This file defines and implements various functions for querying, modifying, preparing, publishing, and removing records in a transactional context. The code utilizes a pool and map structure to manage records and their associated keys, ensuring efficient access and manipulation. The file includes mechanisms for handling transactions, including cloning records, managing transaction locks, and ensuring data consistency across different transaction states. The code is designed to be integrated into a larger system, as indicated by the inclusion of external templates and utility functions.

Key technical components of this file include the use of macros to define pool and map characteristics, such as element types and hashing functions, which are then used to include template implementations from external files. The file provides a comprehensive API for interacting with records, including functions for querying records globally or within specific transactions, modifying records, and handling record lifecycle events like publishing and cancellation. The code also includes error handling and logging mechanisms to ensure robustness and traceability. Overall, this file is a critical component of a transactional record management system, providing essential functionality for managing records in a concurrent and transactional environment.
# Imports and Dependencies

---
- `fd_funk.h`
- `../util/tmpl/fd_pool_para.c`
- `../util/tmpl/fd_map_chain_para.c`


# Functions

---
### fd\_funk\_rec\_key\_set\_pair<!-- {{#callable:fd_funk_rec_key_set_pair}} -->
The `fd_funk_rec_key_set_pair` function initializes a key pair with a transaction ID and a record key, either setting the transaction ID to a root value or copying it from a given transaction.
- **Inputs**:
    - `key_pair`: A pointer to an `fd_funk_xid_key_pair_t` structure where the transaction ID and record key will be set.
    - `txn`: A constant pointer to an `fd_funk_txn_t` structure representing the transaction; if NULL, the transaction ID is set to root.
    - `key`: A constant pointer to an `fd_funk_rec_key_t` structure representing the record key to be copied into the key pair.
- **Control Flow**:
    - Check if the `txn` pointer is NULL.
    - If `txn` is NULL, set the transaction ID in `key_pair` to root using [`fd_funk_txn_xid_set_root`](fd_funk_base.h.driver.md#fd_funk_txn_xid_set_root).
    - If `txn` is not NULL, copy the transaction ID from `txn` to `key_pair` using [`fd_funk_txn_xid_copy`](fd_funk_base.h.driver.md#fd_funk_txn_xid_copy).
    - Copy the record key from `key` to `key_pair` using [`fd_funk_rec_key_copy`](fd_funk_base.h.driver.md#fd_funk_rec_key_copy).
- **Output**: The function does not return a value; it modifies the `key_pair` structure in place.
- **Functions called**:
    - [`fd_funk_txn_xid_set_root`](fd_funk_base.h.driver.md#fd_funk_txn_xid_set_root)
    - [`fd_funk_txn_xid_copy`](fd_funk_base.h.driver.md#fd_funk_txn_xid_copy)
    - [`fd_funk_rec_key_copy`](fd_funk_base.h.driver.md#fd_funk_rec_key_copy)


---
### fd\_funk\_rec\_query\_try<!-- {{#callable:fd_funk_rec_query_try}} -->
The `fd_funk_rec_query_try` function attempts to query a record in a transactional record map, handling potential errors and returning a constant pointer to the record if successful.
- **Inputs**:
    - `funk`: A pointer to an `fd_funk_t` structure representing the transactional record map context.
    - `txn`: A constant pointer to an `fd_funk_txn_t` structure representing the transaction context, or NULL for the root transaction.
    - `key`: A constant pointer to an `fd_funk_rec_key_t` structure representing the key of the record to query.
    - `query`: A pointer to an `fd_funk_rec_query_t` structure where the query result will be stored.
- **Control Flow**:
    - If FD_FUNK_HANDHOLDING is defined, check if `funk`, `key`, or `query` are NULL, or if `txn` is invalid, returning NULL if any checks fail.
    - Initialize a `fd_funk_xid_key_pair_t` structure with the transaction and key using [`fd_funk_rec_key_set_pair`](#fd_funk_rec_key_set_pair).
    - Enter an infinite loop to attempt querying the record map using `fd_funk_rec_map_query_try`.
    - If the query is successful (`FD_MAP_SUCCESS`), break the loop.
    - If the query returns a key error (`FD_MAP_ERR_KEY`), return NULL.
    - If the query returns a retry error (`FD_MAP_ERR_AGAIN`), continue the loop to retry.
    - Log a critical error and exit if any other error is encountered.
    - Return the constant pointer to the queried record using `fd_funk_rec_map_query_ele_const`.
- **Output**: A constant pointer to an `fd_funk_rec_t` structure representing the queried record, or NULL if the record could not be found or an error occurred.
- **Functions called**:
    - [`fd_funk_txn_valid`](fd_funk_txn.c.driver.md#fd_funk_txn_valid)
    - [`fd_funk_rec_key_set_pair`](#fd_funk_rec_key_set_pair)


---
### fd\_funk\_rec\_modify<!-- {{#callable:fd_funk_rec_modify}} -->
The `fd_funk_rec_modify` function attempts to modify a record in a record map associated with a transaction and returns the modified record if successful.
- **Inputs**:
    - `funk`: A pointer to an `fd_funk_t` structure representing the context or environment in which the record map exists.
    - `txn`: A constant pointer to an `fd_funk_txn_t` structure representing the transaction context for the modification; can be NULL to indicate the root transaction.
    - `key`: A constant pointer to an `fd_funk_rec_key_t` structure representing the key of the record to be modified.
    - `query`: A pointer to an `fd_funk_rec_query_t` structure used to store the result of the query operation.
- **Control Flow**:
    - Retrieve the record map from the `funk` context using `fd_funk_rec_map` function.
    - Set up a key pair using [`fd_funk_rec_key_set_pair`](#fd_funk_rec_key_set_pair) with the transaction and key provided.
    - Attempt to modify the record in the map using `fd_funk_rec_map_modify_try` with blocking flag.
    - If the error returned is `FD_MAP_ERR_KEY`, return NULL indicating the key was not found.
    - If the error is not `FD_MAP_SUCCESS`, log a critical error and terminate.
    - Retrieve the modified record using `fd_funk_rec_map_query_ele` and return it.
- **Output**: Returns a pointer to the modified `fd_funk_rec_t` record if successful, or NULL if the key was not found.
- **Functions called**:
    - [`fd_funk_rec_key_set_pair`](#fd_funk_rec_key_set_pair)


---
### fd\_funk\_rec\_modify\_publish<!-- {{#callable:fd_funk_rec_modify_publish}} -->
The `fd_funk_rec_modify_publish` function tests modifications to a record query in a record map.
- **Inputs**:
    - `query`: A pointer to an `fd_funk_rec_query_t` structure representing the record query to be tested for modifications.
- **Control Flow**:
    - The function calls `fd_funk_rec_map_modify_test` with the provided `query` as an argument.
    - No other operations or conditions are performed within this function.
- **Output**: The function does not return any value; it performs an operation on the `query` input.


---
### fd\_funk\_rec\_query\_try\_global<!-- {{#callable:fd_funk_rec_query_try_global}} -->
The `fd_funk_rec_query_try_global` function attempts to find a record in a global context by traversing a hash chain and checking transaction ancestry.
- **Inputs**:
    - `funk`: A pointer to the `fd_funk_t` structure representing the database context.
    - `txn`: A pointer to the `fd_funk_txn_t` structure representing the transaction context, or NULL for the root context.
    - `key`: A pointer to the `fd_funk_rec_key_t` structure representing the key of the record to query.
    - `txn_out`: A pointer to a `fd_funk_txn_t` pointer where the transaction containing the record will be stored if found.
    - `query`: A pointer to a `fd_funk_rec_query_t` structure where query results will be stored.
- **Control Flow**:
    - Check for NULL pointers in `funk`, `key`, and `query`, and validate `txn` if provided, returning NULL if any checks fail.
    - Set up a key pair using the transaction and key, and compute the hash and chain index for the record map.
    - Initialize the query structure and iterate over the hash chain to find a matching record key and hash.
    - For each matching record, traverse the transaction ancestry from `txn` to the root, checking if the record belongs to any transaction in the path.
    - If a match is found, update `txn_out` and `query` with the transaction and record details, and return the record.
    - If no match is found, return NULL.
- **Output**: A pointer to the `fd_funk_rec_t` structure representing the found record, or NULL if no matching record is found.
- **Functions called**:
    - [`fd_funk_txn_valid`](fd_funk_txn.c.driver.md#fd_funk_txn_valid)
    - [`fd_funk_rec_key_set_pair`](#fd_funk_rec_key_set_pair)
    - [`fd_funk_rec_key_eq`](fd_funk_base.h.driver.md#fd_funk_rec_key_eq)
    - [`fd_funk_txn_xid_eq`](fd_funk_base.h.driver.md#fd_funk_txn_xid_eq)
    - [`fd_funk_txn_xid_eq_root`](fd_funk_base.h.driver.md#fd_funk_txn_xid_eq_root)


---
### fd\_funk\_rec\_query\_copy<!-- {{#callable:fd_funk_rec_query_copy}} -->
The `fd_funk_rec_query_copy` function attempts to find a record in a transactional record map, copies its value to a newly allocated memory, and returns a pointer to this copy.
- **Inputs**:
    - `funk`: A pointer to an `fd_funk_t` structure representing the transactional record map.
    - `txn`: A constant pointer to an `fd_funk_txn_t` structure representing the transaction context, or NULL for the root transaction.
    - `key`: A constant pointer to an `fd_funk_rec_key_t` structure representing the key of the record to query.
    - `valloc`: An `fd_valloc_t` allocator used for memory allocation and deallocation.
    - `sz_out`: A pointer to an `ulong` where the size of the copied record value will be stored.
- **Control Flow**:
    - Initialize `sz_out` to `ULONG_MAX` and set up a key pair using [`fd_funk_rec_key_set_pair`](#fd_funk_rec_key_set_pair).
    - Enter an infinite loop to repeatedly attempt querying the record map using `fd_funk_rec_map_query_try`.
    - If the query returns `FD_MAP_ERR_KEY`, free any previously allocated memory and return NULL.
    - If the query returns `FD_MAP_ERR_AGAIN`, continue the loop to retry the query.
    - If the query returns any other error, log a critical error and terminate.
    - Retrieve the record from the query result and determine its size using [`fd_funk_val_sz`](fd_funk_val.h.driver.md#fd_funk_val_sz).
    - If the current allocated memory is insufficient, free it and allocate new memory using `fd_valloc_malloc`.
    - Copy the record's value into the allocated memory using `memcpy`.
    - Update `sz_out` with the size of the copied value.
    - If the query test indicates success, return the pointer to the copied value.
- **Output**: A pointer to the copied record value, or NULL if the record is not found.
- **Functions called**:
    - [`fd_funk_rec_key_set_pair`](#fd_funk_rec_key_set_pair)
    - [`fd_funk_val_sz`](fd_funk_val.h.driver.md#fd_funk_val_sz)
    - [`fd_funk_val`](fd_funk_val.h.driver.md#fd_funk_val)
    - [`fd_funk_wksp`](fd_funk.h.driver.md#fd_funk_wksp)
    - [`fd_funk_rec_query_test`](#fd_funk_rec_query_test)


---
### fd\_funk\_rec\_query\_test<!-- {{#callable:fd_funk_rec_query_test}} -->
The `fd_funk_rec_query_test` function checks the validity of a record query by delegating to `fd_funk_rec_map_query_test`.
- **Inputs**:
    - `query`: A pointer to an `fd_funk_rec_query_t` structure representing the record query to be tested.
- **Control Flow**:
    - The function takes a single argument, `query`, which is a pointer to a record query structure.
    - It calls the function `fd_funk_rec_map_query_test` with `query` as its argument.
    - The result of `fd_funk_rec_map_query_test` is returned directly.
- **Output**: The function returns an integer that indicates the result of the query test, as determined by `fd_funk_rec_map_query_test`.


---
### fd\_funk\_rec\_prepare<!-- {{#callable:fd_funk_rec_prepare}} -->
The `fd_funk_rec_prepare` function prepares a record for modification or creation in a transactional context, ensuring the record is not part of a frozen transaction and acquiring necessary resources.
- **Inputs**:
    - `funk`: A pointer to the `fd_funk_t` structure representing the main context or environment for the operation.
    - `txn`: A pointer to the `fd_funk_txn_t` structure representing the transaction context, or `NULL` if modifying the last published record.
    - `key`: A constant pointer to the `fd_funk_rec_key_t` structure representing the key of the record to be prepared.
    - `prepare`: A pointer to the `fd_funk_rec_prepare_t` structure where preparation details will be stored.
    - `opt_err`: An optional pointer to an integer where error codes will be stored if an error occurs.
- **Control Flow**:
    - Check if handholding is enabled and validate input pointers, returning an error if any are invalid.
    - Determine if the operation is on the last published record or a specific transaction, and check if the transaction is frozen, returning an error if it is.
    - Acquire a record from the record pool, storing it in the `prepare` structure and logging an error if the pool is corrupt.
    - If a record is successfully acquired, initialize its transaction ID, indices, and lock pointers based on whether a transaction is specified or not.
    - Copy the provided key into the record, initialize its value, and set default flags and indices.
    - If no record is acquired, store an error code indicating a record acquisition failure.
    - Return the prepared record.
- **Output**: Returns a pointer to the prepared `fd_funk_rec_t` record, or `NULL` if preparation fails.
- **Functions called**:
    - [`fd_funk_txn_valid`](fd_funk_txn.c.driver.md#fd_funk_txn_valid)
    - [`fd_funk_last_publish_is_frozen`](fd_funk.h.driver.md#fd_funk_last_publish_is_frozen)
    - [`fd_funk_txn_is_frozen`](fd_funk_txn.h.driver.md#fd_funk_txn_is_frozen)
    - [`fd_funk_txn_xid_set_root`](fd_funk_base.h.driver.md#fd_funk_txn_xid_set_root)
    - [`fd_funk_txn_cidx`](fd_funk_txn.h.driver.md#fd_funk_txn_cidx)
    - [`fd_funk_txn_xid_copy`](fd_funk_base.h.driver.md#fd_funk_txn_xid_copy)
    - [`fd_funk_rec_key_copy`](fd_funk_base.h.driver.md#fd_funk_rec_key_copy)
    - [`fd_funk_val_init`](fd_funk_val.h.driver.md#fd_funk_val_init)


---
### fd\_funk\_rec\_publish<!-- {{#callable:fd_funk_rec_publish}} -->
The `fd_funk_rec_publish` function publishes a prepared record into the Funk database by updating linked list indices and inserting the record into the record map.
- **Inputs**:
    - `funk`: A pointer to the `fd_funk_t` structure representing the Funk database context.
    - `prepare`: A pointer to the `fd_funk_rec_prepare_t` structure containing the prepared record and associated transaction information.
- **Control Flow**:
    - Acquire a lock on the transaction using an atomic compare-and-swap operation to ensure exclusive access.
    - Calculate the index of the record in the record pool and update the tail index of the record list to point to this new record.
    - Set the previous index of the new record to the current tail index and the next index to null.
    - If the previous index is null, update the head index to point to the new record; otherwise, update the next index of the previous record to point to the new record.
    - Insert the record into the record map with blocking behavior, logging a critical error if the insertion fails.
    - Release the transaction lock by setting it to zero.
- **Output**: This function does not return a value; it performs operations to publish a record in the Funk database.
- **Functions called**:
    - [`fd_funk_rec_idx_is_null`](fd_funk_rec.h.driver.md#fd_funk_rec_idx_is_null)


---
### fd\_funk\_rec\_cancel<!-- {{#callable:fd_funk_rec_cancel}} -->
The `fd_funk_rec_cancel` function cancels a prepared record operation by flushing the record's value and releasing it back to the record pool.
- **Inputs**:
    - `funk`: A pointer to an `fd_funk_t` structure, which represents the context or environment in which the record operation is being performed.
    - `prepare`: A pointer to an `fd_funk_rec_prepare_t` structure, which contains information about the prepared record operation that is to be canceled.
- **Control Flow**:
    - Call [`fd_funk_val_flush`](fd_funk_val.h.driver.md#fd_funk_val_flush) to flush the value of the record associated with `prepare` using the allocator and workspace from `funk`.
    - Call `fd_funk_rec_pool_release` to release the record back to the record pool, indicating that it is no longer in use.
- **Output**: This function does not return a value; it performs its operations directly on the provided structures.
- **Functions called**:
    - [`fd_funk_val_flush`](fd_funk_val.h.driver.md#fd_funk_val_flush)


---
### fd\_funk\_rec\_txn\_publish<!-- {{#callable:fd_funk_rec_txn_publish}} -->
The `fd_funk_rec_txn_publish` function updates the linked list of records in a transaction and attempts to insert the record into a transaction-specific map.
- **Inputs**:
    - `funk`: A pointer to an `fd_funk_t` structure representing the current state of the record pool and map.
    - `prepare`: A pointer to an `fd_funk_rec_prepare_t` structure containing the prepared record and indices for the head and tail of the record list.
- **Control Flow**:
    - Retrieve the record from the `prepare` structure and calculate its index in the record pool.
    - Update the tail index to point to the new record and set the previous index of the new record to the old tail index.
    - Set the next index of the new record to `FD_FUNK_REC_IDX_NULL`.
    - If the previous index is null, update the head index to the new record index; otherwise, update the next index of the previous record to the new record index.
    - Attempt to insert the record into the transaction-specific map using `fd_funk_rec_map_txn_insert`.
    - Log a critical error if the map insertion fails.
- **Output**: The function does not return a value; it modifies the state of the record pool and map in place.
- **Functions called**:
    - [`fd_funk_rec_idx_is_null`](fd_funk_rec.h.driver.md#fd_funk_rec_idx_is_null)


---
### fd\_funk\_rec\_try\_clone\_safe<!-- {{#callable:fd_funk_rec_try_clone_safe}} -->
The `fd_funk_rec_try_clone_safe` function attempts to safely clone a record in a transactional context, ensuring atomicity and consistency with the global state.
- **Inputs**:
    - `funk`: A pointer to the `fd_funk_t` structure representing the transactional context.
    - `txn`: A pointer to the `fd_funk_txn_t` structure representing the current transaction.
    - `key`: A constant pointer to the `fd_funk_rec_key_t` structure representing the key of the record to be cloned.
    - `align`: An unsigned long specifying the alignment requirement for the new record's value.
    - `min_sz`: An unsigned long specifying the minimum size for the new record's value.
- **Control Flow**:
    - Define a maximum transaction key count and allocate memory for transaction management.
    - Perform a global query to find the record version from the current transaction or its ancestors.
    - If the record exists in the current transaction, return immediately.
    - If the record is found globally, prepare to clone it by initializing a transaction map with the current and ancestor keys.
    - Attempt to start a transaction on the record map with the prepared keys.
    - Check if the record has already been created; if so, exit the transaction gracefully.
    - If the record hasn't been created, prepare a new record and allocate memory for its value, ensuring it meets the minimum size requirement.
    - If a global record exists, copy its data into the new record's value.
    - Publish the new record transactionally and finalize the transaction map.
- **Output**: The function does not return a value; it performs operations to clone a record safely within a transactional context.
- **Functions called**:
    - [`fd_funk_rec_query_try_global`](#fd_funk_rec_query_try_global)
    - [`fd_funk_rec_query_test`](#fd_funk_rec_query_test)
    - [`fd_funk_rec_key_set_pair`](#fd_funk_rec_key_set_pair)
    - [`fd_funk_rec_prepare`](#fd_funk_rec_prepare)
    - [`fd_funk_val_truncate`](fd_funk_val.c.driver.md#fd_funk_val_truncate)
    - [`fd_funk_alloc`](fd_funk.h.driver.md#fd_funk_alloc)
    - [`fd_funk_wksp`](fd_funk.h.driver.md#fd_funk_wksp)
    - [`fd_funk_val`](fd_funk_val.h.driver.md#fd_funk_val)
    - [`fd_funk_rec_txn_publish`](#fd_funk_rec_txn_publish)


---
### fd\_funk\_rec\_clone<!-- {{#callable:fd_funk_rec_clone}} -->
The `fd_funk_rec_clone` function clones a record from a global transaction context into a new record within a specified transaction context.
- **Inputs**:
    - `funk`: A pointer to the `fd_funk_t` structure representing the database context.
    - `txn`: A pointer to the `fd_funk_txn_t` structure representing the transaction context in which the new record will be created.
    - `key`: A constant pointer to the `fd_funk_rec_key_t` structure representing the key of the record to be cloned.
    - `prepare`: A pointer to the `fd_funk_rec_prepare_t` structure used for preparing the new record.
    - `opt_err`: An optional pointer to an integer where error codes can be stored.
- **Control Flow**:
    - Call [`fd_funk_rec_prepare`](#fd_funk_rec_prepare) to prepare a new record in the specified transaction context.
    - If preparation fails, return `NULL`.
    - Enter a loop to attempt cloning the record from the global context.
    - Call [`fd_funk_rec_query_try_global`](#fd_funk_rec_query_try_global) to find the existing record in the global context.
    - If the record is not found, set an error code, cancel the preparation, and return `NULL`.
    - Allocate a buffer for the new record's value using [`fd_funk_val_truncate`](fd_funk_val.c.driver.md#fd_funk_val_truncate).
    - If buffer allocation fails, cancel the preparation and return `NULL`.
    - Copy the value from the old record to the new record's buffer.
    - If the query test indicates success, return the new record; otherwise, repeat the loop.
- **Output**: Returns a pointer to the newly cloned `fd_funk_rec_t` record, or `NULL` if cloning fails.
- **Functions called**:
    - [`fd_funk_rec_prepare`](#fd_funk_rec_prepare)
    - [`fd_funk_rec_query_try_global`](#fd_funk_rec_query_try_global)
    - [`fd_funk_rec_cancel`](#fd_funk_rec_cancel)
    - [`fd_funk_wksp`](fd_funk.h.driver.md#fd_funk_wksp)
    - [`fd_funk_val_truncate`](fd_funk_val.c.driver.md#fd_funk_val_truncate)
    - [`fd_funk_alloc`](fd_funk.h.driver.md#fd_funk_alloc)
    - [`fd_funk_val`](fd_funk_val.h.driver.md#fd_funk_val)
    - [`fd_funk_rec_query_test`](#fd_funk_rec_query_test)


---
### fd\_funk\_rec\_hard\_remove<!-- {{#callable:fd_funk_rec_hard_remove}} -->
The `fd_funk_rec_hard_remove` function removes a record from a transaction or the main database, ensuring proper locking and updating of linked list indices.
- **Inputs**:
    - `funk`: A pointer to the `fd_funk_t` structure representing the main database context.
    - `txn`: A pointer to the `fd_funk_txn_t` structure representing the transaction context, or NULL if operating on the main database.
    - `key`: A constant pointer to the `fd_funk_rec_key_t` structure representing the key of the record to be removed.
- **Control Flow**:
    - Initialize a key pair using [`fd_funk_rec_key_set_pair`](#fd_funk_rec_key_set_pair) with the transaction and key.
    - Determine the lock to use based on whether the transaction is NULL or not.
    - Acquire the lock using an atomic compare-and-swap operation, spinning until successful.
    - Enter a loop to attempt to remove the record from the map using `fd_funk_rec_map_remove`.
    - If the removal returns `FD_MAP_ERR_AGAIN`, retry the operation.
    - If the removal returns `FD_MAP_ERR_KEY`, release the lock and return as the key does not exist.
    - If the removal is successful, retrieve the record using `fd_funk_rec_map_query_ele`.
    - Update the linked list indices for the record's previous and next elements, adjusting either the transaction or main database indices as appropriate.
    - Release the lock by setting it to 0.
    - Flush the record's value and release the record back to the pool.
- **Output**: The function does not return a value; it performs the removal operation and updates the database state accordingly.
- **Functions called**:
    - [`fd_funk_rec_key_set_pair`](#fd_funk_rec_key_set_pair)
    - [`fd_funk_rec_idx_is_null`](fd_funk_rec.h.driver.md#fd_funk_rec_idx_is_null)
    - [`fd_funk_val_flush`](fd_funk_val.h.driver.md#fd_funk_val_flush)


---
### fd\_funk\_rec\_remove<!-- {{#callable:fd_funk_rec_remove}} -->
The `fd_funk_rec_remove` function removes a record from a Funk database, marking it as erased and optionally returning the record and setting erase data.
- **Inputs**:
    - `funk`: A pointer to the Funk database structure (`fd_funk_t`) from which the record is to be removed.
    - `txn`: A pointer to the transaction (`fd_funk_txn_t`) within which the record is to be removed, or `NULL` if modifying the last published transaction.
    - `key`: A constant pointer to the record key (`fd_funk_rec_key_t`) identifying the record to be removed.
    - `rec_out`: A pointer to a pointer to a record (`fd_funk_rec_t **`) where the removed record will be stored, or `NULL` if not needed.
    - `erase_data`: An unsigned long integer containing data to be stored in the record's erase data field.
- **Control Flow**:
    - Check if `funk` or `key` is `NULL`, returning `FD_FUNK_ERR_INVAL` if so.
    - If `txn` is provided, validate it; return `FD_FUNK_ERR_INVAL` if invalid.
    - Check if the transaction or last published state is frozen, returning `FD_FUNK_ERR_FROZEN` if so.
    - Set up a key pair using [`fd_funk_rec_key_set_pair`](#fd_funk_rec_key_set_pair) for querying the record map.
    - Attempt to query the record map for the record using `fd_funk_rec_map_query_try`, handling errors appropriately.
    - Retrieve the record from the query result and store it in `rec_out` if provided.
    - Atomically check and set the record's erase flag using a compare-and-swap operation.
    - Flush the record's value using [`fd_funk_val_flush`](fd_funk_val.h.driver.md#fd_funk_val_flush) and set the erase data using [`fd_funk_rec_set_erase_data`](#fd_funk_rec_set_erase_data).
    - Return `FD_FUNK_SUCCESS` to indicate successful removal.
- **Output**: Returns an integer status code, `FD_FUNK_SUCCESS` on success, or an error code such as `FD_FUNK_ERR_INVAL`, `FD_FUNK_ERR_FROZEN`, or `FD_FUNK_ERR_KEY` on failure.
- **Functions called**:
    - [`fd_funk_txn_valid`](fd_funk_txn.c.driver.md#fd_funk_txn_valid)
    - [`fd_funk_last_publish_is_frozen`](fd_funk.h.driver.md#fd_funk_last_publish_is_frozen)
    - [`fd_funk_txn_is_frozen`](fd_funk_txn.h.driver.md#fd_funk_txn_is_frozen)
    - [`fd_funk_rec_key_set_pair`](#fd_funk_rec_key_set_pair)
    - [`fd_funk_val_flush`](fd_funk_val.h.driver.md#fd_funk_val_flush)
    - [`fd_funk_rec_set_erase_data`](#fd_funk_rec_set_erase_data)


---
### fd\_funk\_rec\_set\_erase\_data<!-- {{#callable:fd_funk_rec_set_erase_data}} -->
The `fd_funk_rec_set_erase_data` function sets the erase data in the flags of a record by encoding it into the most significant 40 bits of the flags field.
- **Inputs**:
    - `rec`: A pointer to an `fd_funk_rec_t` structure representing the record whose flags are to be modified.
    - `erase_data`: An unsigned long integer containing the erase data to be encoded into the record's flags.
- **Control Flow**:
    - The function takes the `erase_data` input and masks it to ensure it only uses the least significant 40 bits.
    - It then shifts this masked value to the left by the number of bits required to position it in the most significant 40 bits of the `flags` field.
    - The shifted value is then ORed with the current `flags` value of the record, effectively setting the erase data in the designated bits.
- **Output**: The function does not return a value; it modifies the `flags` field of the `fd_funk_rec_t` structure pointed to by `rec`.


---
### fd\_funk\_rec\_get\_erase\_data<!-- {{#callable:fd_funk_rec_get_erase_data}} -->
The function `fd_funk_rec_get_erase_data` extracts and returns the erase data from the flags of a given record.
- **Inputs**:
    - `rec`: A pointer to a constant `fd_funk_rec_t` structure representing the record from which to extract the erase data.
- **Control Flow**:
    - The function takes a pointer to a constant `fd_funk_rec_t` structure as input.
    - It shifts the `flags` field of the record right by the number of bits in an unsigned long minus 40.
    - It then applies a bitwise AND operation with the mask `0xFFFFFFFFFFUL` to extract the 40-bit erase data.
    - The extracted erase data is returned as an unsigned long.
- **Output**: The function returns an unsigned long representing the 40-bit erase data extracted from the record's flags.


---
### fd\_funk\_rec\_forget<!-- {{#callable:fd_funk_rec_forget}} -->
The `fd_funk_rec_forget` function removes records from a record map if they are marked as erased and belong to a published transaction.
- **Inputs**:
    - `funk`: A pointer to an `fd_funk_t` structure representing the context or environment in which the records exist.
    - `recs`: An array of pointers to `fd_funk_rec_t` structures, representing the records to be forgotten.
    - `recs_cnt`: An unsigned long integer representing the number of records in the `recs` array.
- **Control Flow**:
    - If handholding is enabled, check if `funk` is NULL and return `FD_FUNK_ERR_INVAL` if true.
    - If handholding is enabled, retrieve the maximum number of records from `funk->shmem->rec_max`.
    - Iterate over each record in the `recs` array.
    - For each record, if handholding is enabled, calculate the record index and check if it is out of bounds or misaligned, returning `FD_FUNK_ERR_INVAL` if true.
    - Retrieve the transaction index from the record's `txn_cidx` and check if it is not null or if the record is not marked as erased, returning `FD_FUNK_ERR_KEY` if true.
    - Attempt to remove the record from the record map in a loop until successful, handling `FD_MAP_ERR_AGAIN` by retrying, and returning `FD_FUNK_ERR_KEY` if the key is not found.
    - If the removal is successful, update the linked list pointers for the previous and next records in the pool.
    - Flush the record's value and release the record back to the pool.
    - Return `FD_FUNK_SUCCESS` after processing all records.
- **Output**: Returns an integer status code, `FD_FUNK_SUCCESS` on success, or an error code such as `FD_FUNK_ERR_INVAL` or `FD_FUNK_ERR_KEY` on failure.
- **Functions called**:
    - [`fd_funk_txn_idx`](fd_funk_txn.h.driver.md#fd_funk_txn_idx)
    - [`fd_funk_txn_idx_is_null`](fd_funk_txn.h.driver.md#fd_funk_txn_idx_is_null)
    - [`fd_funk_rec_pair`](fd_funk_rec.h.driver.md#fd_funk_rec_pair)
    - [`fd_funk_rec_idx_is_null`](fd_funk_rec.h.driver.md#fd_funk_rec_idx_is_null)
    - [`fd_funk_val_flush`](fd_funk_val.h.driver.md#fd_funk_val_flush)


---
### fd\_funk\_all\_iter\_skip\_nulls<!-- {{#callable:fd_funk_all_iter_skip_nulls}} -->
The function `fd_funk_all_iter_skip_nulls` advances an iterator over a record map, skipping over any null or completed entries.
- **Inputs**:
    - `iter`: A pointer to an `fd_funk_all_iter_t` structure, which represents the current state of iteration over a record map.
- **Control Flow**:
    - Check if the current chain index of the iterator is equal to the total number of chains; if so, return immediately as there are no more chains to iterate over.
    - Enter a loop that continues as long as the current record map iterator indicates completion (i.e., there are no more records in the current chain).
    - Increment the chain index to move to the next chain.
    - If the chain index reaches the total number of chains, break out of the loop as there are no more chains to process.
    - Otherwise, update the record map iterator to point to the start of the next chain.
- **Output**: The function does not return a value; it modifies the iterator in place to skip over null or completed entries.


---
### fd\_funk\_all\_iter\_new<!-- {{#callable:fd_funk_all_iter_new}} -->
The `fd_funk_all_iter_new` function initializes an iterator for iterating over all records in a `fd_funk_t` record map, skipping any null entries.
- **Inputs**:
    - `funk`: A pointer to an `fd_funk_t` structure, which contains the record map to be iterated over.
    - `iter`: A pointer to an `fd_funk_all_iter_t` structure, which will be initialized to iterate over the records in the `fd_funk_t` record map.
- **Control Flow**:
    - The function begins by copying the record map from the `funk` structure to the `iter` structure.
    - It retrieves the total number of chains in the record map and assigns it to `iter->chain_cnt`.
    - The chain index is initialized to 0, and the record map iterator is initialized to the first chain in the record map.
    - The function calls [`fd_funk_all_iter_skip_nulls`](#fd_funk_all_iter_skip_nulls) to advance the iterator past any null entries.
- **Output**: The function does not return a value; it initializes the `iter` structure to iterate over the records in the `funk` record map.
- **Functions called**:
    - [`fd_funk_all_iter_skip_nulls`](#fd_funk_all_iter_skip_nulls)


---
### fd\_funk\_all\_iter\_done<!-- {{#callable:fd_funk_all_iter_done}} -->
The `fd_funk_all_iter_done` function checks if an iterator has completed iterating over all chains in a record map.
- **Inputs**:
    - `iter`: A pointer to an `fd_funk_all_iter_t` structure representing the iterator to be checked.
- **Control Flow**:
    - The function compares the `chain_idx` of the iterator with `chain_cnt`.
    - If `chain_idx` is equal to `chain_cnt`, it indicates that the iteration is complete.
- **Output**: The function returns an integer value, which is non-zero (true) if the iteration is complete, and zero (false) otherwise.


---
### fd\_funk\_all\_iter\_next<!-- {{#callable:fd_funk_all_iter_next}} -->
The `fd_funk_all_iter_next` function advances an iterator to the next non-null record in a record map.
- **Inputs**:
    - `iter`: A pointer to an `fd_funk_all_iter_t` structure, which represents the current state of the iteration over a record map.
- **Control Flow**:
    - The function calls `fd_funk_rec_map_iter_next` to advance the `rec_map_iter` to the next record in the map.
    - It then calls [`fd_funk_all_iter_skip_nulls`](#fd_funk_all_iter_skip_nulls) to skip over any null records, ensuring the iterator points to a valid record or the end of the map.
- **Output**: The function does not return a value; it modifies the `iter` structure in place to point to the next valid record.
- **Functions called**:
    - [`fd_funk_all_iter_skip_nulls`](#fd_funk_all_iter_skip_nulls)


---
### fd\_funk\_all\_iter\_ele\_const<!-- {{#callable:fd_funk_all_iter_ele_const}} -->
The function `fd_funk_all_iter_ele_const` retrieves the current element from an iterator over all records in a record map, returning it as a constant pointer.
- **Inputs**:
    - `iter`: A pointer to an `fd_funk_all_iter_t` structure, which represents an iterator over all records in a record map.
- **Control Flow**:
    - The function calls `fd_funk_rec_map_iter_ele_const` with the `rec_map_iter` member of the `iter` structure.
    - It directly returns the result of this call, which is a constant pointer to the current record element.
- **Output**: A constant pointer to an `fd_funk_rec_t` structure, representing the current element in the iterator.


---
### fd\_funk\_all\_iter\_ele<!-- {{#callable:fd_funk_all_iter_ele}} -->
The `fd_funk_all_iter_ele` function retrieves the current element from an iterator over all records in a record map.
- **Inputs**:
    - `iter`: A pointer to an `fd_funk_all_iter_t` structure, which represents an iterator over all records in a record map.
- **Control Flow**:
    - The function calls `fd_funk_rec_map_iter_ele` with `iter->rec_map_iter` as the argument.
    - It returns the result of the `fd_funk_rec_map_iter_ele` function call.
- **Output**: A pointer to an `fd_funk_rec_t` structure, representing the current record element in the iteration.


---
### fd\_funk\_rec\_verify<!-- {{#callable:fd_funk_rec_verify}} -->
The `fd_funk_rec_verify` function verifies the integrity and consistency of records and transactions within a `fd_funk_t` structure.
- **Inputs**:
    - `funk`: A pointer to an `fd_funk_t` structure, which contains the record map, record pool, and transaction pool to be verified.
- **Control Flow**:
    - Initialize local variables for record map, record pool, and transaction pool from the `funk` structure.
    - Define a macro `TEST` to log a warning and return an error if a condition is not met.
    - Verify the integrity of the record map and record pool using `fd_funk_rec_map_verify` and `fd_funk_rec_pool_verify`.
    - Iterate over all records in the record map to ensure each record is linked to a valid transaction and has sane flags.
    - Clear all record tags in the record pool to prepare for linkage verification.
    - Verify forward linkage by iterating through records starting from the head index, checking each record's transaction index and tag, and ensuring correct forward links.
    - Verify reverse linkage by iterating through records starting from the tail index, checking each record's transaction index and tag, and ensuring correct backward links.
    - Return `FD_FUNK_SUCCESS` if all checks pass.
- **Output**: Returns `FD_FUNK_SUCCESS` if all verifications pass, otherwise returns `FD_FUNK_ERR_INVAL` if any verification fails.
- **Functions called**:
    - [`fd_funk_rec_xid`](fd_funk_rec.h.driver.md#fd_funk_rec_xid)
    - [`fd_funk_txn_idx`](fd_funk_txn.h.driver.md#fd_funk_txn_idx)
    - [`fd_funk_txn_idx_is_null`](fd_funk_txn.h.driver.md#fd_funk_txn_idx_is_null)
    - [`fd_funk_txn_xid_eq_root`](fd_funk_base.h.driver.md#fd_funk_txn_xid_eq_root)
    - [`fd_funk_rec_idx_is_null`](fd_funk_rec.h.driver.md#fd_funk_rec_idx_is_null)
    - [`fd_funk_rec_query_try_global`](#fd_funk_rec_query_try_global)
    - [`fd_funk_txn_all_iter_new`](fd_funk_txn.c.driver.md#fd_funk_txn_all_iter_new)
    - [`fd_funk_txn_all_iter_done`](fd_funk_txn.c.driver.md#fd_funk_txn_all_iter_done)
    - [`fd_funk_txn_all_iter_next`](fd_funk_txn.c.driver.md#fd_funk_txn_all_iter_next)
    - [`fd_funk_txn_all_iter_ele_const`](fd_funk_txn.c.driver.md#fd_funk_txn_all_iter_ele_const)


