# Purpose
This C source code file implements a transaction management system, providing functionality for creating, managing, and manipulating transactions and records within a transactional context. The code is structured around several key components: transactions (`txn_t`), records (`rec_t`), and a central management structure (`funk_t`). The file includes functions for preparing, canceling, and publishing transactions, as well as for querying, inserting, and removing records. The code is designed to handle nested transactions, allowing for complex transactional hierarchies where transactions can have parent-child relationships and records can be associated with specific transactions.

The file defines a set of static functions for internal operations, such as mapping and unmapping transactions and records, which are crucial for maintaining the integrity of the transaction and record lists. The public API functions, such as [`txn_prepare`](#txn_prepare), [`txn_cancel`](#txn_cancel), [`txn_publish`](#txn_publish), [`rec_query`](#rec_query), and [`rec_insert`](#rec_insert), provide the primary interface for interacting with the transaction system. These functions allow for the creation and manipulation of transactions and records, supporting operations like transaction preparation, cancellation, and record insertion. The code also includes utility functions for generating unique transaction IDs and comparing keys, which are essential for ensuring the uniqueness and integrity of transactions and records. Overall, this file provides a comprehensive implementation of a transactional system, suitable for use in applications requiring robust transaction management capabilities.
# Imports and Dependencies

---
- `test_funk_common.h`
- `stdlib.h`


# Functions

---
### txn\_unmap<!-- {{#callable:txn_unmap}} -->
The `txn_unmap` function removes a transaction from a doubly linked list and frees its memory.
- **Inputs**:
    - `funk`: A pointer to a `funk_t` structure, which represents the context or environment containing the transaction map and count.
    - `txn`: A pointer to a `txn_t` structure, representing the transaction to be removed from the map and freed.
- **Control Flow**:
    - Retrieve the previous and next transactions in the map using `txn->map_prev` and `txn->map_next`.
    - If there is a previous transaction (`prev` is not NULL), set its `map_next` to the next transaction; otherwise, update the head of the transaction map in `funk` to the next transaction.
    - If there is a next transaction (`next` is not NULL), set its `map_prev` to the previous transaction; otherwise, update the tail of the transaction map in `funk` to the previous transaction.
    - Decrement the transaction count in `funk`.
    - Free the memory allocated for the transaction `txn`.
- **Output**: The function does not return any value; it performs operations on the linked list and frees memory.


---
### txn\_leave<!-- {{#callable:txn_leave}} -->
The `txn_leave` function removes a transaction from its parent's child list or from the root transaction list if it has no parent.
- **Inputs**:
    - `funk`: A pointer to a `funk_t` structure, representing the root transaction context.
    - `txn`: A pointer to a `txn_t` structure, representing the transaction to be removed from its sibling list.
- **Control Flow**:
    - Determine the head and tail pointers for the sibling list based on whether the transaction has a parent or not.
    - Retrieve the previous and next siblings of the transaction.
    - If the transaction has a previous sibling, update its `sibling_next` pointer to skip the current transaction; otherwise, update the head of the list to the next sibling.
    - If the transaction has a next sibling, update its `sibling_prev` pointer to skip the current transaction; otherwise, update the tail of the list to the previous sibling.
    - Return the transaction pointer.
- **Output**: Returns a pointer to the `txn_t` structure that was removed from the sibling list.


---
### rec\_leave<!-- {{#callable:rec_leave}} -->
The `rec_leave` function removes a record from a linked list, updating the head and tail pointers as necessary.
- **Inputs**:
    - `funk`: A pointer to a `funk_t` structure, which represents the context or environment containing the record list.
    - `rec`: A pointer to a `rec_t` structure, representing the record to be removed from the list.
- **Control Flow**:
    - Determine the head and tail pointers based on whether the record is part of a transaction or the main funk list.
    - Retrieve the previous and next records linked to the current record.
    - If there is a previous record, update its next pointer to skip the current record; otherwise, update the head pointer to the next record.
    - If there is a next record, update its previous pointer to skip the current record; otherwise, update the tail pointer to the previous record.
    - Return the record that was removed.
- **Output**: The function returns a pointer to the `rec_t` structure that was removed from the list.


---
### rec\_unmap<!-- {{#callable:rec_unmap}} -->
The `rec_unmap` function removes a record from a doubly linked list and frees its memory.
- **Inputs**:
    - `funk`: A pointer to a `funk_t` structure, which represents the context or environment containing the record map and count.
    - `rec`: A pointer to a `rec_t` structure, which is the record to be removed from the map and freed.
- **Control Flow**:
    - Retrieve the previous and next records in the map using `rec->map_prev` and `rec->map_next`.
    - If `map_prev` is not NULL, set `map_prev->map_next` to `map_next`; otherwise, set `funk->rec_map_head` to `map_next`.
    - If `map_next` is not NULL, set `map_next->map_prev` to `map_prev`; otherwise, set `funk->rec_map_tail` to `map_prev`.
    - Decrement the record count in `funk` by one.
    - Free the memory allocated for `rec`.
- **Output**: The function does not return any value; it performs operations on the input structures and frees memory.


---
### txn\_prepare<!-- {{#callable:txn_prepare}} -->
The `txn_prepare` function initializes a new transaction, links it into the transaction map and family structure, and returns the newly created transaction.
- **Inputs**:
    - `funk`: A pointer to a `funk_t` structure, which represents the context or environment in which the transaction is being prepared.
    - `parent`: A pointer to a `txn_t` structure representing the parent transaction, or `NULL` if the transaction has no parent.
    - `xid`: An unsigned long integer representing the unique transaction identifier for the new transaction.
- **Control Flow**:
    - Allocate memory for a new `txn_t` structure and check for successful allocation.
    - Initialize the transaction's `xid`, `rec_head`, and `rec_tail` fields.
    - Link the new transaction into the `funk`'s transaction map by updating pointers to maintain the doubly linked list structure.
    - Increment the transaction count in the `funk` structure.
    - Determine the appropriate head and tail pointers for the transaction's family based on whether it has a parent.
    - Link the new transaction into its family structure, updating sibling pointers and the parent's child pointers if applicable.
    - Return the pointer to the newly created transaction.
- **Output**: Returns a pointer to the newly created `txn_t` structure representing the prepared transaction.


---
### txn\_cancel<!-- {{#callable:txn_cancel}} -->
The `txn_cancel` function cancels a transaction by unmapping and freeing all its associated records and then removing the transaction from its parent and the global transaction map.
- **Inputs**:
    - `funk`: A pointer to a `funk_t` structure, which represents the global transaction and record management context.
    - `txn`: A pointer to a `txn_t` structure, which represents the transaction to be canceled.
- **Control Flow**:
    - Initialize a pointer `rec` to the head of the transaction's record list (`txn->rec_head`).
    - Iterate over each record in the transaction's record list.
    - For each record, store the next record in a temporary variable `next`, unmap the current record using [`rec_unmap`](#rec_unmap), and then move to the next record.
    - After all records are unmapped, call [`txn_cancel_children`](test_funk_common.h.driver.md#txn_cancel_children) to cancel any child transactions of the current transaction.
    - Call [`txn_leave`](#txn_leave) to remove the transaction from its parent's child list and return the transaction.
    - Finally, call [`txn_unmap`](#txn_unmap) to remove the transaction from the global transaction map and free its memory.
- **Output**: The function does not return any value; it performs operations to cancel and clean up the specified transaction and its associated records.
- **Functions called**:
    - [`rec_unmap`](#rec_unmap)
    - [`txn_unmap`](#txn_unmap)
    - [`txn_leave`](#txn_leave)
    - [`txn_cancel_children`](test_funk_common.h.driver.md#txn_cancel_children)


---
### txn\_publish<!-- {{#callable:txn_publish}} -->
The [`txn_publish`](#txn_publish) function finalizes a transaction by publishing its records, updating the transaction hierarchy, and cleaning up resources.
- **Inputs**:
    - `funk`: A pointer to a `funk_t` structure, which represents the context or environment in which transactions and records are managed.
    - `txn`: A pointer to a `txn_t` structure, representing the transaction to be published.
    - `cnt`: An unsigned long integer representing the current count of published transactions, which is incremented by the function.
- **Control Flow**:
    - If the transaction has a parent, recursively call [`txn_publish`](#txn_publish) on the parent transaction, updating the count.
    - Iterate over each record in the transaction's record list.
    - For each record, check if a root record with the same key exists; if so, remove the old version of the record.
    - Update the record's pointers to integrate it into the global record list managed by `funk`.
    - Call [`txn_cancel_siblings`](test_funk_common.h.driver.md#txn_cancel_siblings) to cancel any sibling transactions of the current transaction.
    - Update the parent pointers of all child transactions to NULL and adjust the child list in `funk`.
    - Set `funk->last_publish` to the transaction's ID (`xid`).
    - Unmap the transaction from the transaction map using [`txn_unmap`](#txn_unmap).
- **Output**: Returns the incremented count of published transactions as an unsigned long integer.
- **Functions called**:
    - [`txn_publish`](#txn_publish)
    - [`rec_query`](#rec_query)
    - [`rec_unmap`](#rec_unmap)
    - [`rec_leave`](#rec_leave)
    - [`txn_cancel_siblings`](test_funk_common.h.driver.md#txn_cancel_siblings)
    - [`txn_unmap`](#txn_unmap)


---
### txn\_merge<!-- {{#callable:txn_merge}} -->
The `txn_merge` function merges all records from a child transaction into its parent transaction, effectively transferring ownership of the records and removing the child transaction.
- **Inputs**:
    - `funk`: A pointer to a `funk_t` structure, which represents the transactional context or environment.
    - `txn`: A pointer to a `txn_t` structure, representing the child transaction to be merged into its parent.
- **Control Flow**:
    - Retrieve the parent transaction of the given child transaction `txn`.
    - Iterate over each record in the child transaction's record list.
    - For each record, check if a corresponding record exists in the parent transaction using [`rec_query`](#rec_query).
    - If a corresponding record exists in the parent, remove the old version using [`rec_unmap`](#rec_unmap) and [`rec_leave`](#rec_leave).
    - Update the record's transaction pointer to the parent transaction and adjust its previous and next pointers to insert it into the parent's record list.
    - If the parent transaction's record list is empty, set the current record as the head; otherwise, append it to the tail.
    - Continue this process for all records in the child transaction.
    - Finally, unmap the child transaction using [`txn_unmap`](#txn_unmap) and [`txn_leave`](#txn_leave), effectively deleting it.
- **Output**: The function does not return any value; it modifies the parent transaction by merging records from the child transaction and deletes the child transaction.
- **Functions called**:
    - [`rec_query`](#rec_query)
    - [`rec_unmap`](#rec_unmap)
    - [`rec_leave`](#rec_leave)
    - [`txn_unmap`](#txn_unmap)
    - [`txn_leave`](#txn_leave)


---
### rec\_query<!-- {{#callable:rec_query}} -->
The `rec_query` function searches for a record with a specified key within a transaction or a global context and returns it if found.
- **Inputs**:
    - `funk`: A pointer to a `funk_t` structure, representing the global context or database.
    - `txn`: A pointer to a `txn_t` structure, representing the transaction context in which to search for the record; if NULL, the search is performed in the global context.
    - `key`: An unsigned long integer representing the key of the record to search for.
- **Control Flow**:
    - Initialize `rec` to point to the head of the record list in the transaction if `txn` is not NULL, otherwise to the head of the global record list in `funk`.
    - Iterate through the linked list of records starting from `rec`.
    - For each record, check if the record's key matches the specified `key`.
    - If a matching record is found, break out of the loop.
    - Return the found record or NULL if no matching record is found.
- **Output**: A pointer to the `rec_t` structure representing the record with the specified key, or NULL if no such record is found.


---
### rec\_query\_global<!-- {{#callable:rec_query_global}} -->
The `rec_query_global` function searches for a record with a specified key in a transaction and its parent transactions recursively, returning the first match found.
- **Inputs**:
    - `funk`: A pointer to a `funk_t` structure, which represents the context or environment in which transactions and records are managed.
    - `txn`: A pointer to a `txn_t` structure, representing the current transaction context to start the search from.
    - `key`: An unsigned long integer representing the key of the record to search for.
- **Control Flow**:
    - The function enters a loop that continues as long as `txn` is not NULL.
    - Within the loop, it calls [`rec_query`](#rec_query) to search for a record with the specified key in the current transaction `txn`.
    - If a record is found, it immediately returns this record.
    - If no record is found, it moves to the parent transaction by setting `txn` to `txn->parent`.
    - Once the loop exits (when `txn` becomes NULL), it performs a final search in the global context (no specific transaction) by calling [`rec_query`](#rec_query) with `txn` set to NULL.
    - The function returns the result of this final search, which could be a record or NULL if no record was found.
- **Output**: A pointer to a `rec_t` structure representing the record with the specified key, or NULL if no such record is found in the transaction hierarchy or globally.
- **Functions called**:
    - [`rec_query`](#rec_query)


---
### rec\_insert<!-- {{#callable:rec_insert}} -->
The `rec_insert` function inserts a new record with a specified key into a transaction or global record map, handling any previous erasures and updating the linked list structure accordingly.
- **Inputs**:
    - `funk`: A pointer to a `funk_t` structure representing the global state or context in which the record is being inserted.
    - `txn`: A pointer to a `txn_t` structure representing the transaction context in which the record is being inserted, or NULL if the record is being inserted globally.
    - `key`: An unsigned long integer representing the key of the record to be inserted.
- **Control Flow**:
    - The function first queries for an existing record with the given key in the specified transaction or globally using [`rec_query`](#rec_query).
    - If a record is found and it is marked for erasure, the erasure is undone by setting `erase` to 0, and the record is returned.
    - If a record is found but not marked for erasure, an error is logged indicating a user error.
    - If no record is found, a new `rec_t` record is allocated and initialized with the given key, `erase` set to 0, and `val` set to 0.
    - The new record is added to the end of the global record map linked list, updating the `map_prev` and `map_next` pointers accordingly.
    - The global record count `rec_cnt` is incremented.
    - The new record is then added to the end of the transaction's record list (or the global list if no transaction is specified), updating the `prev` and `next` pointers accordingly.
    - The function returns the newly inserted record.
- **Output**: A pointer to the newly inserted `rec_t` record.
- **Functions called**:
    - [`rec_query`](#rec_query)


---
### rec\_remove<!-- {{#callable:rec_remove}} -->
The `rec_remove` function marks a record for deletion by setting its `erase` flag to 1.
- **Inputs**:
    - `funk`: A pointer to a `funk_t` structure, which represents the context or environment in which the record exists. It is not used in the function body.
    - `rec`: A pointer to a `rec_t` structure, which represents the record to be marked for deletion.
- **Control Flow**:
    - The function takes two parameters: a `funk_t` pointer and a `rec_t` pointer.
    - The `funk` parameter is explicitly cast to void to indicate it is unused.
    - The `erase` field of the `rec` structure is set to 1, marking the record for deletion.
- **Output**: The function does not return any value; it modifies the `rec` structure in place.


---
### funk\_new<!-- {{#callable:funk_new}} -->
The `funk_new` function allocates and initializes a new `funk_t` structure for managing transactions and records.
- **Inputs**: None
- **Control Flow**:
    - Allocate memory for a `funk_t` structure using `malloc` and cast it to `funk_t *`.
    - Check if the memory allocation was successful; if not, log an error message indicating insufficient memory.
    - Initialize the `last_publish` field to `0UL`.
    - Set the `child_head`, `child_tail`, `txn_map_head`, `txn_map_tail`, `rec_head`, `rec_tail`, `rec_map_head`, and `rec_map_tail` pointers to `NULL`.
    - Initialize the `txn_cnt` and `rec_cnt` counters to `0UL`.
    - Return the pointer to the newly allocated and initialized `funk_t` structure.
- **Output**: A pointer to the newly allocated and initialized `funk_t` structure.


---
### funk\_delete<!-- {{#callable:funk_delete}} -->
The `funk_delete` function deallocates all resources associated with a `funk_t` object, including its records and the object itself.
- **Inputs**:
    - `funk`: A pointer to a `funk_t` object that is to be deleted.
- **Control Flow**:
    - Call [`txn_cancel_children`](test_funk_common.h.driver.md#txn_cancel_children) to cancel all child transactions associated with the `funk` object.
    - Initialize a pointer `rec` to the head of the record map in the `funk` object.
    - Iterate over each record in the record map, freeing each record and moving to the next record in the map.
    - After all records are freed, free the `funk` object itself.
- **Output**: The function does not return any value; it performs cleanup and deallocation of resources.
- **Functions called**:
    - [`txn_cancel_children`](test_funk_common.h.driver.md#txn_cancel_children)


---
### xid\_unique<!-- {{#callable:xid_unique}} -->
The `xid_unique` function generates a unique transaction identifier by incrementing a static counter.
- **Inputs**: None
- **Control Flow**:
    - Declare a static unsigned long integer `xid` initialized to 0.
    - Increment the `xid` variable by 1.
    - Return the incremented value of `xid`.
- **Output**: The function returns an unsigned long integer representing a unique transaction identifier.


---
### key\_eq<!-- {{#callable:key_eq}} -->
The `key_eq` function checks if a given record key matches a specified key value.
- **Inputs**:
    - `key`: A pointer to a `fd_funk_rec_key_t` structure representing the record key to be compared.
    - `_key`: An unsigned long integer representing the key value to compare against.
- **Control Flow**:
    - A temporary `fd_funk_rec_key_t` array `tmp` of size 1 is declared.
    - The function [`key_set`](test_funk_common.h.driver.md#key_set) is called with `tmp` and `_key` to set the key value in `tmp`.
    - The function [`fd_funk_rec_key_eq`](fd_funk_base.h.driver.md#fd_funk_rec_key_eq) is called with `key` and the result of [`key_set`](test_funk_common.h.driver.md#key_set) to check for equality.
    - The result of [`fd_funk_rec_key_eq`](fd_funk_base.h.driver.md#fd_funk_rec_key_eq) is returned as the output of `key_eq`.
- **Output**: An integer indicating whether the record key matches the specified key value (non-zero if equal, zero if not).
- **Functions called**:
    - [`fd_funk_rec_key_eq`](fd_funk_base.h.driver.md#fd_funk_rec_key_eq)
    - [`key_set`](test_funk_common.h.driver.md#key_set)


