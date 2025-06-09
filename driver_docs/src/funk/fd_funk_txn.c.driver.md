# Purpose
This C source code file provides a comprehensive implementation for managing transactions within a system, specifically focusing on transaction mapping, preparation, cancellation, and publishing. The code is part of a larger system, likely a database or a transaction management system, as indicated by the use of terms like "transaction," "map," and "pool." The file includes several key components: a transaction pool and map, functions for starting and ending read/write operations, and various transaction management functions such as preparation, cancellation, and publishing. The code is structured to handle transactions in a hierarchical manner, allowing for operations on individual transactions as well as their relationships with parent and child transactions.

The file defines a set of functions that operate on transactions, including starting and ending read/write locks, preparing transactions, and managing transaction lifecycles through cancellation and publishing. It uses macros to define transaction pool and map structures, which are then included from template files, suggesting a modular design approach. The code also includes functions for iterating over all transactions and verifying the integrity of the transaction system. The presence of functions like [`fd_funk_txn_prepare`](#fd_funk_txn_prepare), [`fd_funk_txn_cancel`](#fd_funk_txn_cancel), and [`fd_funk_txn_publish`](#fd_funk_txn_publish) indicates that the file provides a public API for transaction management, which can be used by other parts of the system to interact with the transaction subsystem. The file is intended to be part of a larger application, as it includes headers and template files from other directories, and it defines a static lock for transaction operations, indicating a focus on concurrency control.
# Imports and Dependencies

---
- `fd_funk.h`
- `../util/tmpl/fd_pool_para.c`
- `../util/tmpl/fd_map_chain_para.c`
- `../flamenco/fd_rwlock.h`


# Global Variables

---
### funk\_txn\_lock
- **Type**: `fd_rwlock_t[1]`
- **Description**: The `funk_txn_lock` is a static array of one `fd_rwlock_t` element, initialized to zero. It is used to manage read and write locks for transaction operations in the `fd_funk` module.
- **Use**: This variable is used to synchronize access to transaction operations, ensuring thread safety by allowing only one write or multiple reads at a time.


---
### fd\_funk\_txn\_start\_read
- **Type**: `function`
- **Description**: The `fd_funk_txn_start_read` function is responsible for initiating a read lock on the transaction lock `funk_txn_lock`. This is part of a transaction management system where read and write operations are synchronized using read-write locks.
- **Use**: This function is used to acquire a read lock on the transaction lock to ensure safe concurrent read operations.


---
### fd\_funk\_txn\_end\_read
- **Type**: `function`
- **Description**: The `fd_funk_txn_end_read` function is responsible for ending a read transaction on a `fd_funk_t` object by releasing a read lock. It uses the `fd_rwlock_unread` function to release the lock on the `funk_txn_lock`.
- **Use**: This function is used to signal the end of a read operation on a transaction, ensuring that the read lock is properly released.


---
### fd\_funk\_txn\_start\_write
- **Type**: `function`
- **Description**: The `fd_funk_txn_start_write` function is responsible for acquiring a write lock on the `funk_txn_lock` to ensure exclusive access to a shared resource during a transaction write operation. This function is part of a transaction management system that uses read-write locks to control access to shared data structures.
- **Use**: This function is used to initiate a write transaction by acquiring a write lock, preventing other transactions from reading or writing until the lock is released.


---
### fd\_funk\_txn\_end\_write
- **Type**: `function`
- **Description**: The `fd_funk_txn_end_write` function is responsible for ending a write transaction by releasing a write lock on the transaction lock `funk_txn_lock`. This function is part of a transaction management system that uses read-write locks to ensure safe concurrent access to shared resources.
- **Use**: This function is used to release the write lock on a transaction, allowing other operations to proceed.


# Functions

---
### fd\_funk\_txn\_prepare<!-- {{#callable:fd_funk_txn_prepare}} -->
The `fd_funk_txn_prepare` function prepares a new transaction in the Funk system, ensuring it is valid and not already in use, and then adds it to the transaction map.
- **Inputs**:
    - `funk`: A pointer to the `fd_funk_t` structure representing the Funk system context.
    - `parent`: A pointer to the parent transaction (`fd_funk_txn_t`) or NULL if there is no parent.
    - `xid`: A constant pointer to the transaction ID (`fd_funk_txn_xid_t`) for the new transaction.
    - `verbose`: An integer flag indicating whether to log warnings (non-zero value) or not (zero value).
- **Control Flow**:
    - Check if `funk` and `xid` are non-NULL and valid; log warnings if `verbose` is set and return NULL if checks fail.
    - Verify that the `xid` is not the root or the last published transaction; log warnings and return NULL if checks fail.
    - Check if the `xid` is already in use in the transaction map; log warnings and return NULL if it is.
    - Determine the parent index and child head/tail indices based on whether a parent transaction is provided.
    - Acquire a new transaction from the transaction pool; log warnings and return NULL if the pool is exhausted.
    - Copy the `xid` to the new transaction and calculate its index in the pool.
    - Set up the new transaction's family links, including parent, sibling, and child indices.
    - Insert the new transaction into the transaction map with blocking flag set.
    - Return the pointer to the newly prepared transaction.
- **Output**: Returns a pointer to the newly prepared `fd_funk_txn_t` transaction, or NULL if preparation fails.
- **Functions called**:
    - [`fd_funk_txn_valid`](#fd_funk_txn_valid)
    - [`fd_funk_txn_xid_eq_root`](fd_funk_base.h.driver.md#fd_funk_txn_xid_eq_root)
    - [`fd_funk_txn_xid_eq`](fd_funk_base.h.driver.md#fd_funk_txn_xid_eq)
    - [`fd_funk_txn_xid_copy`](fd_funk_base.h.driver.md#fd_funk_txn_xid_copy)
    - [`fd_funk_txn_idx`](fd_funk_txn.h.driver.md#fd_funk_txn_idx)
    - [`fd_funk_txn_idx_is_null`](fd_funk_txn.h.driver.md#fd_funk_txn_idx_is_null)
    - [`fd_funk_txn_cidx`](fd_funk_txn.h.driver.md#fd_funk_txn_cidx)


---
### fd\_funk\_txn\_cancel\_childless<!-- {{#callable:fd_funk_txn_cancel_childless}} -->
The `fd_funk_txn_cancel_childless` function cancels a transaction that has no child transactions by removing all its associated records and updating sibling and parent pointers accordingly.
- **Inputs**:
    - `funk`: A pointer to an `fd_funk_t` structure representing the transaction system context.
    - `txn_idx`: An unsigned long integer representing the index of the transaction to be canceled.
- **Control Flow**:
    - Initialize workspace, allocator, record map, record pool, transaction map, and transaction pool from the `funk` structure.
    - Retrieve the transaction to be canceled using `txn_idx` and iterate over its records to remove them from the record map and release them back to the pool.
    - Check for memory corruption by validating record indices and transaction indices during the iteration.
    - Update sibling pointers to remove the transaction from its sibling list, adjusting the parent's child pointers if necessary.
    - Remove the transaction from the transaction map and release it back to the transaction pool if the removal is successful.
- **Output**: This function does not return a value; it performs operations directly on the data structures provided.
- **Functions called**:
    - [`fd_funk_rec_idx_is_null`](fd_funk_rec.h.driver.md#fd_funk_rec_idx_is_null)
    - [`fd_funk_txn_idx`](fd_funk_txn.h.driver.md#fd_funk_txn_idx)
    - [`fd_funk_txn_cidx`](fd_funk_txn.h.driver.md#fd_funk_txn_cidx)
    - [`fd_funk_rec_pair`](fd_funk_rec.h.driver.md#fd_funk_rec_pair)
    - [`fd_funk_val_flush`](fd_funk_val.h.driver.md#fd_funk_val_flush)
    - [`fd_funk_txn_idx_is_null`](fd_funk_txn.h.driver.md#fd_funk_txn_idx_is_null)
    - [`fd_funk_txn_xid`](fd_funk_txn.h.driver.md#fd_funk_txn_xid)


---
### fd\_funk\_txn\_cancel\_family<!-- {{#callable:fd_funk_txn_cancel_family}} -->
The `fd_funk_txn_cancel_family` function cancels a transaction and all its descendants in a depth-first order, returning the number of transactions canceled.
- **Inputs**:
    - `funk`: A pointer to the `fd_funk_t` structure, representing the transaction management context.
    - `tag`: An unsigned long integer used to tag transactions during the cancellation process.
    - `txn_idx`: An unsigned long integer representing the index of the transaction to be canceled.
- **Control Flow**:
    - Initialize `cancel_cnt` to 0 and `parent_stack_idx` to `FD_FUNK_TXN_IDX_NULL`.
    - Enter an infinite loop to process transactions.
    - Retrieve the transaction at `txn_idx` and set its tag to the provided `tag`.
    - Determine the index of the youngest child transaction using [`fd_funk_txn_idx`](fd_funk_txn.h.driver.md#fd_funk_txn_idx).
    - If the transaction is childless (youngest index is null), call [`fd_funk_txn_cancel_childless`](#fd_funk_txn_cancel_childless) to cancel it and increment `cancel_cnt`.
    - Update `txn_idx` to `parent_stack_idx` to pop the parent stack; if the stack is empty, break the loop.
    - If the transaction has children, update its `stack_cidx` to the current `parent_stack_idx`, set `parent_stack_idx` to `txn_idx`, and recurse into the youngest child by updating `txn_idx` to `youngest_idx`.
- **Output**: Returns the number of transactions canceled as an unsigned long integer.
- **Functions called**:
    - [`fd_funk_txn_idx`](fd_funk_txn.h.driver.md#fd_funk_txn_idx)
    - [`fd_funk_txn_idx_is_null`](fd_funk_txn.h.driver.md#fd_funk_txn_idx_is_null)
    - [`fd_funk_txn_cancel_childless`](#fd_funk_txn_cancel_childless)
    - [`fd_funk_txn_cidx`](fd_funk_txn.h.driver.md#fd_funk_txn_cidx)


---
### fd\_funk\_txn\_cancel<!-- {{#callable:fd_funk_txn_cancel}} -->
The `fd_funk_txn_cancel` function cancels a specified transaction and all its descendants in a transaction tree, returning the number of transactions canceled.
- **Inputs**:
    - `funk`: A pointer to an `fd_funk_t` structure representing the transaction system context.
    - `txn`: A pointer to an `fd_funk_txn_t` structure representing the transaction to be canceled.
    - `verbose`: An integer flag indicating whether to log warnings if the function encounters invalid inputs.
- **Control Flow**:
    - If `FD_FUNK_HANDHOLDING` is defined, the function checks if `funk` is NULL and logs a warning if `verbose` is true, returning 0 if so.
    - It checks if the transaction `txn` is valid using [`fd_funk_txn_valid`](#fd_funk_txn_valid), logging a warning and returning 0 if invalid and `verbose` is true.
    - Calculates the transaction index `txn_idx` by subtracting the base address of the transaction pool from the transaction pointer.
    - Calls [`fd_funk_txn_cancel_family`](#fd_funk_txn_cancel_family) with the transaction index and an incremented cycle tag to cancel the transaction and its descendants.
- **Output**: Returns the number of transactions canceled as an unsigned long integer.
- **Functions called**:
    - [`fd_funk_txn_valid`](#fd_funk_txn_valid)
    - [`fd_funk_txn_cancel_family`](#fd_funk_txn_cancel_family)


---
### fd\_funk\_txn\_oldest\_sibling<!-- {{#callable:fd_funk_txn_oldest_sibling}} -->
The `fd_funk_txn_oldest_sibling` function returns the index of the oldest sibling transaction in the family of a given transaction index.
- **Inputs**:
    - `funk`: A pointer to an `fd_funk_t` structure, which represents the transaction management context.
    - `txn_idx`: An unsigned long integer representing the index of the transaction whose oldest sibling is to be found.
- **Control Flow**:
    - Retrieve the parent index of the transaction at `txn_idx` using [`fd_funk_txn_idx`](fd_funk_txn.h.driver.md#fd_funk_txn_idx) on its `parent_cidx` field.
    - Check if the parent index is null using [`fd_funk_txn_idx_is_null`](fd_funk_txn.h.driver.md#fd_funk_txn_idx_is_null).
    - If the parent index is null, return the index of the oldest child of the root (Funk) using [`fd_funk_txn_idx`](fd_funk_txn.h.driver.md#fd_funk_txn_idx) on `funk->shmem->child_head_cidx`.
    - If the parent index is not null, return the index of the oldest child of the parent transaction using [`fd_funk_txn_idx`](fd_funk_txn.h.driver.md#fd_funk_txn_idx) on the parent's `child_head_cidx`.
- **Output**: Returns an unsigned long integer representing the index of the oldest sibling transaction.
- **Functions called**:
    - [`fd_funk_txn_idx`](fd_funk_txn.h.driver.md#fd_funk_txn_idx)
    - [`fd_funk_txn_idx_is_null`](fd_funk_txn.h.driver.md#fd_funk_txn_idx_is_null)


---
### fd\_funk\_txn\_cancel\_sibling\_list<!-- {{#callable:fd_funk_txn_cancel_sibling_list}} -->
The `fd_funk_txn_cancel_sibling_list` function cancels a list of sibling transactions from a given starting index to the youngest sibling, optionally skipping a specified sibling, and returns the number of transactions canceled.
- **Inputs**:
    - `funk`: A pointer to the `fd_funk_t` structure, which contains the transaction pool and other related data.
    - `tag`: An unsigned long integer used to tag transactions during the cancellation process.
    - `sibling_idx`: An unsigned long integer representing the index of the starting sibling transaction to be canceled.
    - `skip_idx`: An unsigned long integer representing the index of a sibling transaction to be skipped during cancellation; if set to `FD_FUNK_TXN_IDX_NULL`, no sibling is skipped.
- **Control Flow**:
    - Initialize `cancel_stack_idx` to `FD_FUNK_TXN_IDX_NULL` to keep track of transactions to be canceled.
    - Enter a loop to traverse siblings starting from `sibling_idx`, tagging each sibling with `tag`.
    - If the current sibling index is not `skip_idx`, push it onto the cancel stack by updating its `stack_cidx` and setting `cancel_stack_idx` to the current sibling index.
    - Retrieve the next younger sibling index using `sibling->sibling_next_cidx`; if it is `FD_FUNK_TXN_IDX_NULL`, break the loop.
    - Initialize `cancel_cnt` to zero to count the number of canceled transactions.
    - Enter a loop to cancel transactions on the cancel stack until it is empty.
    - In each iteration, pop a transaction from the cancel stack, update `cancel_stack_idx`, and call [`fd_funk_txn_cancel_family`](#fd_funk_txn_cancel_family) to cancel the transaction and its descendants, incrementing `cancel_cnt` by the number of canceled transactions.
- **Output**: The function returns an unsigned long integer representing the total number of transactions canceled.
- **Functions called**:
    - [`fd_funk_txn_cidx`](fd_funk_txn.h.driver.md#fd_funk_txn_cidx)
    - [`fd_funk_txn_idx`](fd_funk_txn.h.driver.md#fd_funk_txn_idx)
    - [`fd_funk_txn_idx_is_null`](fd_funk_txn.h.driver.md#fd_funk_txn_idx_is_null)
    - [`fd_funk_txn_cancel_family`](#fd_funk_txn_cancel_family)


---
### fd\_funk\_txn\_cancel\_siblings<!-- {{#callable:fd_funk_txn_cancel_siblings}} -->
The `fd_funk_txn_cancel_siblings` function cancels all sibling transactions of a given transaction within a transaction pool, excluding the transaction itself.
- **Inputs**:
    - `funk`: A pointer to an `fd_funk_t` structure representing the transaction pool.
    - `txn`: A pointer to an `fd_funk_txn_t` structure representing the transaction whose siblings are to be canceled.
    - `verbose`: An integer flag indicating whether to log warnings if the function encounters invalid inputs.
- **Control Flow**:
    - If `FD_FUNK_HANDHOLDING` is defined, the function checks if `funk` or `txn` is NULL or invalid, logging warnings if `verbose` is true, and returns 0 if any check fails.
    - Calculate the index of the transaction `txn` within the transaction pool `funk->txn_pool`.
    - Determine the index of the oldest sibling of the transaction using [`fd_funk_txn_oldest_sibling`](#fd_funk_txn_oldest_sibling).
    - Call [`fd_funk_txn_cancel_sibling_list`](#fd_funk_txn_cancel_sibling_list) to cancel all siblings from the oldest sibling to the youngest, excluding the transaction itself, and return the number of canceled transactions.
- **Output**: Returns the number of sibling transactions that were successfully canceled.
- **Functions called**:
    - [`fd_funk_txn_valid`](#fd_funk_txn_valid)
    - [`fd_funk_txn_oldest_sibling`](#fd_funk_txn_oldest_sibling)
    - [`fd_funk_txn_cancel_sibling_list`](#fd_funk_txn_cancel_sibling_list)


---
### fd\_funk\_txn\_cancel\_children<!-- {{#callable:fd_funk_txn_cancel_children}} -->
The `fd_funk_txn_cancel_children` function cancels all child transactions of a given transaction or all root-level transactions if no specific transaction is provided.
- **Inputs**:
    - `funk`: A pointer to the `fd_funk_t` structure representing the transaction system.
    - `txn`: A pointer to the `fd_funk_txn_t` structure representing the transaction whose children are to be canceled, or `NULL` to cancel all root-level transactions.
    - `verbose`: An integer flag indicating whether to log warnings for invalid inputs.
- **Control Flow**:
    - Check if `FD_FUNK_HANDHOLDING` is defined to perform input validation; log warnings if `funk` is `NULL` or `txn` is invalid when `verbose` is true.
    - Determine the index of the oldest child transaction: if `txn` is `NULL`, use the root-level child head index; otherwise, use the child head index of the specified transaction.
    - Check if the oldest child index is null, indicating no children to cancel, and return 0 if so.
    - Call [`fd_funk_txn_cancel_sibling_list`](#fd_funk_txn_cancel_sibling_list) to cancel all sibling transactions starting from the oldest child index, incrementing the cycle tag, and passing `FD_FUNK_TXN_IDX_NULL` to cancel all siblings.
- **Output**: Returns the number of transactions canceled as an unsigned long integer.
- **Functions called**:
    - [`fd_funk_txn_valid`](#fd_funk_txn_valid)
    - [`fd_funk_txn_idx`](fd_funk_txn.h.driver.md#fd_funk_txn_idx)
    - [`fd_funk_txn_idx_is_null`](fd_funk_txn.h.driver.md#fd_funk_txn_idx_is_null)
    - [`fd_funk_txn_cancel_sibling_list`](#fd_funk_txn_cancel_sibling_list)


---
### fd\_funk\_txn\_cancel\_all<!-- {{#callable:fd_funk_txn_cancel_all}} -->
The `fd_funk_txn_cancel_all` function cancels all outstanding transactions in the given `fd_funk_t` instance.
- **Inputs**:
    - `funk`: A pointer to an `fd_funk_t` structure representing the transaction context in which all transactions are to be canceled.
    - `verbose`: An integer flag indicating whether to log warnings and errors verbosely.
- **Control Flow**:
    - The function calls [`fd_funk_txn_cancel_children`](#fd_funk_txn_cancel_children) with `funk`, `NULL`, and `verbose` as arguments.
    - [`fd_funk_txn_cancel_children`](#fd_funk_txn_cancel_children) is responsible for canceling all child transactions of the given `funk` context.
    - The function returns the result of [`fd_funk_txn_cancel_children`](#fd_funk_txn_cancel_children), which is the number of transactions canceled.
- **Output**: The function returns an `ulong` representing the number of transactions that were successfully canceled.
- **Functions called**:
    - [`fd_funk_txn_cancel_children`](#fd_funk_txn_cancel_children)


---
### fd\_funk\_txn\_update<!-- {{#callable:fd_funk_txn_update}} -->
The `fd_funk_txn_update` function merges records from one transaction into another, updating or removing records as necessary, and then clears the source transaction's record list.
- **Inputs**:
    - `funk`: A pointer to the `fd_funk_t` structure, which contains workspace, allocator, record map, record pool, and transaction pool information.
    - `_dst_rec_head_idx`: A pointer to the head index of the destination record list, which will be updated during the merge.
    - `_dst_rec_tail_idx`: A pointer to the tail index of the destination record list, which will be updated during the merge.
    - `dst_txn_idx`: The index of the destination transaction where records will be merged.
    - `dst_xid`: A constant pointer to the transaction ID of the destination transaction.
    - `txn_idx`: The index of the source transaction whose records are to be merged into the destination.
- **Control Flow**:
    - Initialize pointers to workspace, allocator, record map, record pool, and transaction pool from the `funk` structure.
    - Retrieve the transaction from the transaction pool using `txn_idx` and start iterating over its records using `rec_head_idx`.
    - For each record, check if a record with the same key and `dst_xid` already exists in the destination using a map query loop.
    - If a record exists, remove it from the destination list, update the head or tail pointers if necessary, flush its value, and release it back to the pool.
    - Update the current record's transaction ID to `dst_xid` and set its transaction index to `dst_txn_idx`.
    - Add the current record to the destination list, updating the head or tail pointers as necessary.
    - Continue to the next record in the source transaction until all records are processed.
    - Clear the record list of the source transaction by setting its head and tail indices to null.
- **Output**: The function does not return a value; it modifies the destination record list and clears the source transaction's record list in place.
- **Functions called**:
    - [`fd_funk_rec_idx_is_null`](fd_funk_rec.h.driver.md#fd_funk_rec_idx_is_null)
    - [`fd_funk_xid_key_pair_init`](fd_funk_base.h.driver.md#fd_funk_xid_key_pair_init)
    - [`fd_funk_val_flush`](fd_funk_val.h.driver.md#fd_funk_val_flush)
    - [`fd_funk_txn_cidx`](fd_funk_txn.h.driver.md#fd_funk_txn_cidx)


---
### fd\_funk\_txn\_publish\_funk\_child<!-- {{#callable:fd_funk_txn_publish_funk_child}} -->
The function `fd_funk_txn_publish_funk_child` publishes a transaction that is a child of a given funk, applying updates, canceling competing transactions, and reassigning child transactions.
- **Inputs**:
    - `funk`: A pointer to the `fd_funk_t` structure representing the funk context.
    - `tag`: An unsigned long integer used as a tag for marking transactions.
    - `txn_idx`: An unsigned long integer representing the index of the transaction to be published.
- **Control Flow**:
    - Call [`fd_funk_txn_update`](#fd_funk_txn_update) to apply updates from the transaction at `txn_idx` to the last published transactions.
    - Determine the oldest sibling index using [`fd_funk_txn_oldest_sibling`](#fd_funk_txn_oldest_sibling) and cancel all competing transaction histories with [`fd_funk_txn_cancel_sibling_list`](#fd_funk_txn_cancel_sibling_list).
    - Retrieve the transaction at `txn_idx` and iterate over its children, updating their parent to be the funk and tagging them with the provided `tag`.
    - Update the funk's shared memory to reflect the new head and tail indices of the child transactions.
    - Copy the transaction ID of the published transaction to the funk's last published ID.
    - Attempt to remove the transaction from the transaction map; if successful, release the transaction back to the pool.
    - Return `FD_FUNK_SUCCESS` to indicate successful completion.
- **Output**: Returns `FD_FUNK_SUCCESS` on successful execution, indicating the transaction was published without errors.
- **Functions called**:
    - [`fd_funk_txn_update`](#fd_funk_txn_update)
    - [`fd_funk_root`](fd_funk.h.driver.md#fd_funk_root)
    - [`fd_funk_txn_oldest_sibling`](#fd_funk_txn_oldest_sibling)
    - [`fd_funk_txn_cancel_sibling_list`](#fd_funk_txn_cancel_sibling_list)
    - [`fd_funk_txn_idx`](fd_funk_txn.h.driver.md#fd_funk_txn_idx)
    - [`fd_funk_txn_idx_is_null`](fd_funk_txn.h.driver.md#fd_funk_txn_idx_is_null)
    - [`fd_funk_txn_cidx`](fd_funk_txn.h.driver.md#fd_funk_txn_cidx)
    - [`fd_funk_txn_xid_copy`](fd_funk_base.h.driver.md#fd_funk_txn_xid_copy)
    - [`fd_funk_txn_xid`](fd_funk_txn.h.driver.md#fd_funk_txn_xid)


---
### fd\_funk\_txn\_publish<!-- {{#callable:fd_funk_txn_publish}} -->
The `fd_funk_txn_publish` function publishes a transaction and its ancestors in a transaction tree, updating the shared memory state and canceling competing transaction histories.
- **Inputs**:
    - `funk`: A pointer to the `fd_funk_t` structure representing the transaction context.
    - `txn`: A pointer to the `fd_funk_txn_t` structure representing the transaction to be published.
    - `verbose`: An integer flag indicating whether to log warnings for invalid inputs.
- **Control Flow**:
    - Check if `funk` and `txn` are valid pointers, logging warnings if `verbose` is enabled and returning 0 if invalid.
    - Calculate the transaction index `txn_idx` from the transaction pointer `txn`.
    - Increment the cycle tag in the shared memory and assign it to `tag`.
    - Initialize `publish_stack_idx` to `FD_FUNK_TXN_IDX_NULL`.
    - Enter a loop to tag the transaction and its ancestors, pushing them onto a stack until a root transaction is reached.
    - Initialize `publish_cnt` to 0.
    - Enter another loop to publish each transaction from the stack, incrementing `publish_cnt` for each successful publish.
    - Return the count of published transactions `publish_cnt`.
- **Output**: Returns the number of transactions successfully published as an unsigned long integer.
- **Functions called**:
    - [`fd_funk_txn_valid`](#fd_funk_txn_valid)
    - [`fd_funk_txn_idx`](fd_funk_txn.h.driver.md#fd_funk_txn_idx)
    - [`fd_funk_txn_idx_is_null`](fd_funk_txn.h.driver.md#fd_funk_txn_idx_is_null)
    - [`fd_funk_txn_cidx`](fd_funk_txn.h.driver.md#fd_funk_txn_cidx)
    - [`fd_funk_txn_publish_funk_child`](#fd_funk_txn_publish_funk_child)


---
### fd\_funk\_txn\_publish\_into\_parent<!-- {{#callable:fd_funk_txn_publish_into_parent}} -->
The `fd_funk_txn_publish_into_parent` function publishes a transaction into its parent transaction or the root, updating record lists and adjusting child-parent relationships accordingly.
- **Inputs**:
    - `funk`: A pointer to the `fd_funk_t` structure representing the transaction system.
    - `txn`: A pointer to the `fd_funk_txn_t` structure representing the transaction to be published.
    - `verbose`: An integer flag indicating whether to log warnings for invalid inputs.
- **Control Flow**:
    - Check if `funk` and `txn` are valid pointers if `FD_FUNK_HANDHOLDING` is defined, logging warnings if `verbose` is true.
    - Retrieve the transaction index `txn_idx` from the transaction pool using the `txn` pointer.
    - Find the oldest sibling transaction index using [`fd_funk_txn_oldest_sibling`](#fd_funk_txn_oldest_sibling) and cancel all sibling transactions except the current one using [`fd_funk_txn_cancel_sibling_list`](#fd_funk_txn_cancel_sibling_list).
    - Determine if the transaction has a parent by checking `parent_cidx`.
    - If the transaction has no parent, publish it to the root by updating the root's record list and inheriting the transaction's children to the root.
    - If the transaction has a parent, update the parent's record list with the transaction's records and inherit the transaction's children to the parent.
    - Adjust the parent pointers of the transaction's children to point to the transaction's grandparent (or root if no grandparent).
    - Remove the transaction from the transaction map and release it back to the pool if the removal is successful.
- **Output**: Returns `FD_FUNK_SUCCESS` on successful publishing of the transaction into its parent or root.
- **Functions called**:
    - [`fd_funk_txn_valid`](#fd_funk_txn_valid)
    - [`fd_funk_txn_oldest_sibling`](#fd_funk_txn_oldest_sibling)
    - [`fd_funk_txn_cancel_sibling_list`](#fd_funk_txn_cancel_sibling_list)
    - [`fd_funk_txn_idx`](fd_funk_txn.h.driver.md#fd_funk_txn_idx)
    - [`fd_funk_txn_idx_is_null`](fd_funk_txn.h.driver.md#fd_funk_txn_idx_is_null)
    - [`fd_funk_txn_update`](#fd_funk_txn_update)
    - [`fd_funk_root`](fd_funk.h.driver.md#fd_funk_root)
    - [`fd_funk_txn_cidx`](fd_funk_txn.h.driver.md#fd_funk_txn_cidx)
    - [`fd_funk_txn_xid`](fd_funk_txn.h.driver.md#fd_funk_txn_xid)


---
### fd\_funk\_txn\_first\_rec<!-- {{#callable:fd_funk_txn_first_rec}} -->
The `fd_funk_txn_first_rec` function retrieves the first record in a given transaction or the first record in the shared memory if the transaction is NULL.
- **Inputs**:
    - `funk`: A pointer to an `fd_funk_t` structure, which contains the shared memory and record pool information.
    - `txn`: A constant pointer to an `fd_funk_txn_t` structure representing the transaction whose first record is to be retrieved; it can be NULL.
- **Control Flow**:
    - Check if the `txn` pointer is NULL.
    - If `txn` is NULL, set `rec_idx` to the head index of the records in the shared memory (`funk->shmem->rec_head_idx`).
    - If `txn` is not NULL, set `rec_idx` to the head index of the records in the transaction (`txn->rec_head_idx`).
    - Check if `rec_idx` is a null index using [`fd_funk_rec_idx_is_null`](fd_funk_rec.h.driver.md#fd_funk_rec_idx_is_null).
    - If `rec_idx` is null, return NULL.
    - If `rec_idx` is not null, return a pointer to the record at `rec_idx` in the record pool (`funk->rec_pool->ele + rec_idx`).
- **Output**: A constant pointer to an `fd_funk_rec_t` structure representing the first record in the transaction or NULL if there are no records.
- **Functions called**:
    - [`fd_funk_rec_idx_is_null`](fd_funk_rec.h.driver.md#fd_funk_rec_idx_is_null)


---
### fd\_funk\_txn\_last\_rec<!-- {{#callable:fd_funk_txn_last_rec}} -->
The `fd_funk_txn_last_rec` function retrieves the last record in a transaction or the last published record if the transaction is NULL.
- **Inputs**:
    - `funk`: A pointer to an `fd_funk_t` structure, which represents the context or environment in which the transaction operates.
    - `txn`: A pointer to a constant `fd_funk_txn_t` structure, representing the transaction whose last record is to be retrieved; if NULL, the function retrieves the last published record.
- **Control Flow**:
    - Check if the `txn` pointer is NULL.
    - If `txn` is NULL, set `rec_idx` to the last published record index from `funk->shmem->rec_tail_idx`.
    - If `txn` is not NULL, set `rec_idx` to the last record index of the transaction from `txn->rec_tail_idx`.
    - Check if `rec_idx` is a null index using [`fd_funk_rec_idx_is_null`](fd_funk_rec.h.driver.md#fd_funk_rec_idx_is_null).
    - If `rec_idx` is null, return NULL.
    - If `rec_idx` is not null, return the record at the index `rec_idx` from the record pool `funk->rec_pool->ele`.
- **Output**: A pointer to a constant `fd_funk_rec_t` structure representing the last record in the transaction or the last published record, or NULL if there are no records.
- **Functions called**:
    - [`fd_funk_rec_idx_is_null`](fd_funk_rec.h.driver.md#fd_funk_rec_idx_is_null)


---
### fd\_funk\_txn\_next\_rec<!-- {{#callable:fd_funk_txn_next_rec}} -->
The function `fd_funk_txn_next_rec` retrieves the next record in a transaction's record list, returning NULL if there are no more records.
- **Inputs**:
    - `funk`: A pointer to an `fd_funk_t` structure, representing the transaction context.
    - `rec`: A pointer to a constant `fd_funk_rec_t` structure, representing the current record in the transaction.
- **Control Flow**:
    - Retrieve the index of the next record from the current record's `next_idx` field.
    - Check if the retrieved index is null using [`fd_funk_rec_idx_is_null`](fd_funk_rec.h.driver.md#fd_funk_rec_idx_is_null); if it is, return NULL indicating no more records.
    - If the index is not null, return a pointer to the next record in the record pool by adding the index to the base address of the record pool.
- **Output**: A pointer to the next `fd_funk_rec_t` record in the transaction, or NULL if there are no more records.
- **Functions called**:
    - [`fd_funk_rec_idx_is_null`](fd_funk_rec.h.driver.md#fd_funk_rec_idx_is_null)


---
### fd\_funk\_txn\_prev\_rec<!-- {{#callable:fd_funk_txn_prev_rec}} -->
The `fd_funk_txn_prev_rec` function retrieves the previous record in a transaction's record list, if it exists.
- **Inputs**:
    - `funk`: A pointer to an `fd_funk_t` structure, representing the transaction context.
    - `rec`: A pointer to a constant `fd_funk_rec_t` structure, representing the current record from which the previous record is to be retrieved.
- **Control Flow**:
    - Retrieve the `prev_idx` from the `rec` structure, which indicates the index of the previous record.
    - Check if `prev_idx` is null using [`fd_funk_rec_idx_is_null`](fd_funk_rec.h.driver.md#fd_funk_rec_idx_is_null); if it is null, return `NULL`.
    - If `prev_idx` is not null, return a pointer to the previous record by accessing the record pool in `funk` using the `prev_idx`.
- **Output**: Returns a pointer to the previous `fd_funk_rec_t` record if it exists, otherwise returns `NULL`.
- **Functions called**:
    - [`fd_funk_rec_idx_is_null`](fd_funk_rec.h.driver.md#fd_funk_rec_idx_is_null)


---
### fd\_funk\_generate\_xid<!-- {{#callable:fd_funk_generate_xid}} -->
The `fd_funk_generate_xid` function generates a unique transaction identifier (XID) for a transaction in the Firedancer system.
- **Inputs**: None
- **Control Flow**:
    - Declare a variable `xid` of type `fd_funk_txn_xid_t`.
    - Initialize a static thread-local variable `seq` to 0, which will be used to ensure uniqueness across function calls.
    - Calculate the first element of `xid.ul` using a combination of CPU ID, thread ID, and an incrementing sequence number, each multiplied by large constants to ensure uniqueness.
    - Calculate the second element of `xid.ul` using the current tick count multiplied by a large constant.
    - Return the generated `xid`.
- **Output**: The function returns a `fd_funk_txn_xid_t` structure containing a unique transaction identifier.


---
### fd\_funk\_txn\_all\_iter\_skip\_nulls<!-- {{#callable:fd_funk_txn_all_iter_skip_nulls}} -->
The function `fd_funk_txn_all_iter_skip_nulls` advances an iterator over a transaction map to skip over null or completed entries.
- **Inputs**:
    - `iter`: A pointer to an `fd_funk_txn_all_iter_t` structure, which contains the state of the iteration over the transaction map.
- **Control Flow**:
    - Check if the current chain index is equal to the chain count; if so, return immediately as there are no more chains to iterate over.
    - Enter a loop that continues as long as the current transaction map iterator indicates completion (i.e., no more transactions in the current chain).
    - Increment the chain index to move to the next chain.
    - If the chain index reaches the chain count, break out of the loop as there are no more chains to process.
    - Update the transaction map iterator to point to the start of the next chain.
- **Output**: The function does not return a value; it modifies the iterator in place to skip over null or completed entries in the transaction map.


---
### fd\_funk\_txn\_all\_iter\_new<!-- {{#callable:fd_funk_txn_all_iter_new}} -->
The `fd_funk_txn_all_iter_new` function initializes an iterator for iterating over all transactions in a transaction map.
- **Inputs**:
    - `funk`: A pointer to an `fd_funk_t` structure representing the transaction context containing the transaction map to iterate over.
    - `iter`: A pointer to an `fd_funk_txn_all_iter_t` structure that will be initialized to iterate over all transactions in the transaction map.
- **Control Flow**:
    - The function begins by copying the transaction map from the `funk` structure to the `iter` structure.
    - It retrieves the number of chains in the transaction map using `fd_funk_txn_map_chain_cnt` and stores it in `iter->chain_cnt`.
    - The `chain_idx` is initialized to 0, indicating the start of the iteration.
    - The function initializes the transaction map iterator using `fd_funk_txn_map_iter` starting at chain index 0 and assigns it to `iter->txn_map_iter`.
    - Finally, it calls [`fd_funk_txn_all_iter_skip_nulls`](#fd_funk_txn_all_iter_skip_nulls) to skip any null entries in the transaction map, preparing the iterator for use.
- **Output**: The function does not return a value; it initializes the `iter` structure for use in iterating over transactions.
- **Functions called**:
    - [`fd_funk_txn_all_iter_skip_nulls`](#fd_funk_txn_all_iter_skip_nulls)


---
### fd\_funk\_txn\_all\_iter\_done<!-- {{#callable:fd_funk_txn_all_iter_done}} -->
The function `fd_funk_txn_all_iter_done` checks if an iterator has completed iterating over all transaction chains.
- **Inputs**:
    - `iter`: A pointer to an `fd_funk_txn_all_iter_t` structure, which represents the iterator over all transaction chains.
- **Control Flow**:
    - The function checks if the current chain index (`iter->chain_idx`) is equal to the total number of chains (`iter->chain_cnt`).
- **Output**: Returns an integer value: 1 if the iterator has completed iterating over all chains, otherwise 0.


---
### fd\_funk\_txn\_all\_iter\_next<!-- {{#callable:fd_funk_txn_all_iter_next}} -->
The `fd_funk_txn_all_iter_next` function advances an iterator to the next transaction in a transaction map, skipping any null entries.
- **Inputs**:
    - `iter`: A pointer to an `fd_funk_txn_all_iter_t` structure, which represents the current state of the transaction iterator.
- **Control Flow**:
    - The function calls `fd_funk_txn_map_iter_next` to advance the `txn_map_iter` field of the iterator to the next transaction in the map.
    - It then calls [`fd_funk_txn_all_iter_skip_nulls`](#fd_funk_txn_all_iter_skip_nulls) to skip over any null entries in the transaction map, ensuring the iterator points to a valid transaction.
- **Output**: This function does not return a value; it modifies the iterator in place to point to the next valid transaction.
- **Functions called**:
    - [`fd_funk_txn_all_iter_skip_nulls`](#fd_funk_txn_all_iter_skip_nulls)


---
### fd\_funk\_txn\_all\_iter\_ele\_const<!-- {{#callable:fd_funk_txn_all_iter_ele_const}} -->
The function `fd_funk_txn_all_iter_ele_const` retrieves a constant pointer to the current transaction element from an iterator over all transactions.
- **Inputs**:
    - `iter`: A pointer to an `fd_funk_txn_all_iter_t` structure, which is an iterator over all transactions.
- **Control Flow**:
    - The function calls `fd_funk_txn_map_iter_ele_const` with the `txn_map_iter` member of the `iter` structure.
    - It returns the result of this call, which is a constant pointer to the current transaction element.
- **Output**: A constant pointer to an `fd_funk_txn_t` structure, representing the current transaction element in the iterator.


---
### fd\_funk\_txn\_all\_iter\_ele<!-- {{#callable:fd_funk_txn_all_iter_ele}} -->
The `fd_funk_txn_all_iter_ele` function retrieves the current transaction element from an iterator over all transactions.
- **Inputs**:
    - `iter`: A pointer to an `fd_funk_txn_all_iter_t` structure, which is an iterator over all transactions.
- **Control Flow**:
    - The function calls `fd_funk_txn_map_iter_ele` with `iter->txn_map_iter` as the argument.
    - It returns the result of the `fd_funk_txn_map_iter_ele` function call.
- **Output**: A pointer to an `fd_funk_txn_t` structure representing the current transaction element in the iterator.


---
### fd\_funk\_txn\_verify<!-- {{#callable:fd_funk_txn_verify}} -->
The `fd_funk_txn_verify` function verifies the integrity of a transaction map and pool within a `fd_funk_t` structure by checking for cycles and ensuring proper parent-child relationships.
- **Inputs**:
    - `funk`: A pointer to a `fd_funk_t` structure that contains the transaction map and pool to be verified.
- **Control Flow**:
    - Initialize pointers to the transaction map and pool from the `funk` structure and determine the maximum number of transactions.
    - Retrieve indices for the head and tail of the child transactions and the last published transaction ID from the shared memory of `funk`.
    - Define macros `TEST` and `IS_VALID` to facilitate condition checking and validation of transaction indices.
    - Verify the transaction map and pool using `fd_funk_txn_map_verify` and `fd_funk_txn_pool_verify` functions, returning an error if verification fails.
    - Tag all transactions in the pool as not visited by setting their `tag` field to 0.
    - Traverse all transactions from oldest to youngest, marking them as visited and checking for cycles and valid parent-child relationships.
    - Repeat the traversal from youngest to oldest to verify reverse link integrity, ensuring that all transactions are properly linked and tagged.
- **Output**: Returns `FD_FUNK_SUCCESS` if all verifications pass, otherwise returns `FD_FUNK_ERR_INVAL` if any verification fails.
- **Functions called**:
    - [`fd_funk_txn_idx`](fd_funk_txn.h.driver.md#fd_funk_txn_idx)
    - [`fd_funk_txn_idx_is_null`](fd_funk_txn.h.driver.md#fd_funk_txn_idx_is_null)
    - [`fd_funk_txn_cidx`](fd_funk_txn.h.driver.md#fd_funk_txn_cidx)


---
### fd\_funk\_txn\_valid<!-- {{#callable:fd_funk_txn_valid}} -->
The `fd_funk_txn_valid` function checks if a given transaction is valid within the context of a transaction pool and map.
- **Inputs**:
    - `funk`: A pointer to an `fd_funk_t` structure representing the transaction context, including the transaction pool and map.
    - `txn`: A pointer to an `fd_funk_txn_t` structure representing the transaction to be validated.
- **Control Flow**:
    - Calculate the index of the transaction (`txn_idx`) by subtracting the base address of the transaction pool's elements from the transaction pointer.
    - Retrieve the maximum number of transactions (`txn_max`) allowed in the transaction pool.
    - Check if the transaction index is out of bounds or if the transaction pointer does not match the calculated index; if so, return 0 indicating invalidity.
    - Initialize a query object for transaction map querying.
    - Attempt to query the transaction map with the transaction's ID; if the query fails, return 0 indicating invalidity.
    - Check if the queried transaction element matches the provided transaction; if not, return 0 indicating invalidity.
    - If all checks pass, return 1 indicating the transaction is valid.
- **Output**: Returns an integer: 1 if the transaction is valid, 0 otherwise.


