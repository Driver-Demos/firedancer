# Purpose
The provided C header file, `fd_funk_txn.h`, defines a set of APIs and data structures for managing transactions within a system referred to as "funk." This file is not intended to be included directly by users; instead, it is meant to be accessed through a higher-level header, `fd_funk.h`. The primary focus of this file is to facilitate the preparation, publication, and cancellation of transactions, which are represented by the `fd_funk_txn_t` structure. This structure is designed to be opaque, with its internal details exposed to allow for inlining of operations, thereby optimizing performance.

Key components of this file include definitions for transaction alignment and footprint, mechanisms for handling transaction indices, and a detailed structure for managing transaction relationships such as parent-child and sibling connections. The file also provides concurrency control functions to manage read and write locks during transaction operations, ensuring thread safety. Additionally, it includes utility functions for querying transaction states, accessing transaction records, and iterating over all transactions. The file is fortified against transaction map memory corruption, with critical logging in place to handle such scenarios. Overall, this header file is a comprehensive toolkit for managing complex transaction workflows within the funk system, providing both low-level access and high-level operations to ensure robust transaction management.
# Imports and Dependencies

---
- `fd_funk_base.h`
- `../util/tmpl/fd_pool_para.c`
- `../util/tmpl/fd_map_chain_para.c`


# Global Variables

---
### fd\_funk\_txn\_first\_rec
- **Type**: `function`
- **Description**: The `fd_funk_txn_first_rec` function returns a pointer to the first (oldest) record in a given transaction. It takes two parameters: a pointer to a `fd_funk_t` structure representing the funk and a constant pointer to a `fd_funk_txn_t` structure representing the transaction. If the transaction has no records, the function returns NULL.
- **Use**: This function is used to access the first record in a transaction, facilitating operations that need to iterate over or access transaction records in order.


---
### fd\_funk\_txn\_last\_rec
- **Type**: `function`
- **Description**: The `fd_funk_txn_last_rec` function returns a pointer to the last (newest) record in a given transaction. If the transaction has no records, it returns NULL.
- **Use**: This function is used to access the most recent record in a transaction, facilitating operations that require knowledge of the latest transaction state.


---
### fd\_funk\_txn\_next\_rec
- **Type**: `function`
- **Description**: The `fd_funk_txn_next_rec` function is a global function that returns a pointer to the next record in a transaction. It takes two parameters: a pointer to a `fd_funk_t` structure representing the transaction context and a pointer to a `fd_funk_rec_t` structure representing the current record. If there are no more records, it returns NULL.
- **Use**: This function is used to iterate over records in a transaction, moving from the current record to the next one.


---
### fd\_funk\_txn\_prev\_rec
- **Type**: `fd_funk_rec_t const *`
- **Description**: The `fd_funk_txn_prev_rec` is a function that returns a pointer to the previous record in a transaction. It takes two parameters: a pointer to a `fd_funk_t` structure and a constant pointer to a `fd_funk_rec_t` structure, which represents the current record. If there are no more records, it returns NULL.
- **Use**: This function is used to iterate backwards through the records of a transaction, allowing access to the previous record in the sequence.


---
### fd\_funk\_txn\_prepare
- **Type**: `fd_funk_txn_t *`
- **Description**: The `fd_funk_txn_prepare` function is a global function that initiates the preparation of a new transaction in the context of a 'funk' (a transaction management system). It returns a pointer to an in-preparation transaction object of type `fd_funk_txn_t`. The function takes a pointer to the funk, a pointer to the parent transaction, a pointer to a transaction ID, and a verbosity flag as parameters.
- **Use**: This function is used to create a new transaction that is a child of the specified parent transaction or the root if no parent is provided, ensuring the transaction ID is unique among in-preparation and last published transactions.


---
### fd\_funk\_txn\_all\_iter\_ele\_const
- **Type**: `fd_funk_txn_t const *`
- **Description**: The function `fd_funk_txn_all_iter_ele_const` returns a constant pointer to a `fd_funk_txn_t` structure, which represents an in-preparation funk transaction. This function is part of an iterator mechanism for traversing all funk transaction objects.
- **Use**: This function is used to access the current transaction element in a read-only manner during iteration over all transactions using `fd_funk_txn_all_iter_t`.


---
### fd\_funk\_txn\_all\_iter\_ele
- **Type**: `fd_funk_txn_t *`
- **Description**: The function `fd_funk_txn_all_iter_ele` returns a pointer to a `fd_funk_txn_t` structure, which represents an in-preparation funk transaction. This function is part of an iterator mechanism that allows traversal over all funk transaction objects.
- **Use**: This function is used to access the current transaction element in an iteration over all transactions using a `fd_funk_txn_all_iter_t` iterator.


# Data Structures

---
### fd\_funk\_txn\_private
- **Type**: `struct`
- **Members**:
    - `xid`: Transaction id, unique among all in-prepare and the last published transaction, ideally globally unique.
    - `map_next`: Internal use by map for managing transaction order.
    - `map_hash`: Internal use by map for hashing transactions.
    - `parent_cidx`: Compressed map index of the in-prep parent transaction, or FD_FUNK_TXN_IDX_NULL if a funk child.
    - `child_head_cidx`: Compressed map index of the oldest child transaction, or FD_FUNK_TXN_IDX_NULL if childless.
    - `child_tail_cidx`: Compressed map index of the youngest child transaction, or FD_FUNK_TXN_IDX_NULL if childless.
    - `sibling_prev_cidx`: Compressed map index of the older sibling transaction, or FD_FUNK_TXN_IDX_NULL if oldest sibling.
    - `sibling_next_cidx`: Compressed map index of the younger sibling transaction, or FD_FUNK_TXN_IDX_NULL if youngest sibling.
    - `stack_cidx`: Internal use by funk for managing transaction stack.
    - `tag`: Internal use by funk for tagging transactions.
    - `rec_head_idx`: Record map index of the first record, or FD_FUNK_REC_IDX_NULL if none.
    - `rec_tail_idx`: Record map index of the last record, or FD_FUNK_REC_IDX_NULL if none.
    - `lock`: Internal use by funk for synchronizing modifications to the transaction object.
- **Description**: The `fd_funk_txn_private` structure is a complex data structure used to manage transactions within a funk system. It contains fields that are managed by both the transaction map and the funk itself, allowing for the organization and manipulation of transaction hierarchies. The structure includes identifiers for transaction uniqueness, indices for managing parent-child and sibling relationships, and internal fields for synchronization and tagging. This structure is crucial for handling in-preparation transactions, ensuring they are properly indexed, synchronized, and managed within the system.


---
### fd\_funk\_txn\_t
- **Type**: `struct`
- **Members**:
    - `xid`: Transaction id, unique among all in-prepare and the last published transaction, ideally globally unique.
    - `map_next`: Internal use by map for managing transaction order.
    - `map_hash`: Internal use by map for hashing transactions.
    - `parent_cidx`: Compressed map index of the in-prep parent transaction, or FD_FUNK_TXN_IDX_NULL if a funk child.
    - `child_head_cidx`: Compressed map index of the oldest child transaction, or FD_FUNK_TXN_IDX_NULL if childless.
    - `child_tail_cidx`: Compressed map index of the youngest child transaction, or FD_FUNK_TXN_IDX_NULL if childless.
    - `sibling_prev_cidx`: Compressed map index of the older sibling transaction, or FD_FUNK_TXN_IDX_NULL if the oldest sibling.
    - `sibling_next_cidx`: Compressed map index of the younger sibling transaction, or FD_FUNK_TXN_IDX_NULL if the youngest sibling.
    - `stack_cidx`: Internal use by funk for managing transaction stack.
    - `tag`: Internal use by funk for tagging transactions.
    - `rec_head_idx`: Record map index of the first record, or FD_FUNK_REC_IDX_NULL if none.
    - `rec_tail_idx`: Record map index of the last record, or FD_FUNK_REC_IDX_NULL if none.
    - `lock`: Internal use by funk for synchronizing modifications to the transaction object.
- **Description**: The `fd_funk_txn_t` structure is an opaque handle representing an in-preparation funk transaction. It is designed to manage the state and relationships of transactions within a transactional system, including parent-child and sibling relationships, as well as internal indexing for efficient transaction management. The structure includes fields for transaction identification, internal mapping, and synchronization, facilitating operations such as transaction preparation, publishing, and cancellation. The alignment and footprint of the structure are defined to optimize memory usage and access speed.


---
### fd\_funk\_rec\_t
- **Type**: `typedef struct`
- **Members**:
    - `fd_funk_rec_t`: A typedef for a structure named fd_funk_rec, which is likely used to represent a record in a transaction.
- **Description**: The fd_funk_rec_t is a typedef for a structure named fd_funk_rec, which is not defined in the provided code. It is likely used to represent a record within a transaction in the context of the funk transaction management system. The structure is referenced in various functions that deal with records in transactions, such as retrieving the first or last record in a transaction. However, without the actual definition of fd_funk_rec, the specific fields and their purposes within the structure remain unspecified.


---
### fd\_funk\_txn\_all\_iter
- **Type**: `struct`
- **Members**:
    - `txn_map`: A map of transactions used for indexing and managing transactions.
    - `chain_cnt`: The count of transaction chains being iterated over.
    - `chain_idx`: The current index within the transaction chains being iterated.
    - `txn_map_iter`: An iterator for traversing the transaction map.
- **Description**: The `fd_funk_txn_all_iter` structure is designed to facilitate iteration over all transaction objects within a transaction map. It maintains state information necessary for traversing the transaction chains, including the total number of chains (`chain_cnt`), the current position within these chains (`chain_idx`), and an iterator (`txn_map_iter`) for the transaction map itself. This structure is essential for operations that require examining or processing each transaction in a collection, providing a systematic way to access each transaction in sequence.


---
### fd\_funk\_txn\_all\_iter\_t
- **Type**: `struct`
- **Members**:
    - `txn_map`: A map of transactions used for iteration.
    - `chain_cnt`: The count of chains in the transaction map.
    - `chain_idx`: The current index of the chain being iterated over.
    - `txn_map_iter`: An iterator for traversing the transaction map.
- **Description**: The `fd_funk_txn_all_iter_t` structure is designed to facilitate iteration over all transaction objects within a funk transaction map. It maintains the state of the iteration, including the transaction map itself, the number of chains, the current chain index, and an iterator for the transaction map. This structure is used in conjunction with functions that initialize, check completion, and advance the iteration process, allowing users to traverse and access each transaction in the map efficiently.


# Functions

---
### fd\_funk\_txn\_cidx<!-- {{#callable:fd_funk_txn_cidx}} -->
The `fd_funk_txn_cidx` function converts an unsigned long index to a compressed unsigned integer index.
- **Inputs**:
    - `idx`: An unsigned long integer representing the index to be converted to a compressed index.
- **Control Flow**:
    - The function takes a single input parameter `idx` of type `ulong`.
    - It performs a type cast of `idx` from `ulong` to `uint`.
    - The function returns the result of this type cast.
- **Output**: The function returns a `uint` which is the compressed version of the input `ulong` index.


---
### fd\_funk\_txn\_idx<!-- {{#callable:fd_funk_txn_idx}} -->
The `fd_funk_txn_idx` function converts a 32-bit unsigned integer index to a 64-bit unsigned long integer.
- **Inputs**:
    - `idx`: A 32-bit unsigned integer representing the index to be converted.
- **Control Flow**:
    - The function takes a single input parameter, `idx`, which is a 32-bit unsigned integer.
    - It performs a type cast of `idx` to a 64-bit unsigned long integer.
    - The function returns the result of this type cast.
- **Output**: A 64-bit unsigned long integer that is the result of casting the input `idx`.


---
### fd\_funk\_txn\_idx\_is\_null<!-- {{#callable:fd_funk_txn_idx_is_null}} -->
The function `fd_funk_txn_idx_is_null` checks if a given transaction index is equal to a predefined null index value.
- **Inputs**:
    - `idx`: An unsigned long integer representing the transaction index to be checked.
- **Control Flow**:
    - The function compares the input `idx` with the constant `FD_FUNK_TXN_IDX_NULL`.
    - If `idx` is equal to `FD_FUNK_TXN_IDX_NULL`, the function returns 1.
    - If `idx` is not equal to `FD_FUNK_TXN_IDX_NULL`, the function returns 0.
- **Output**: The function returns an integer: 1 if the index is null, and 0 otherwise.


---
### fd\_funk\_txn\_xid<!-- {{#callable:fd_funk_txn_xid}} -->
The `fd_funk_txn_xid` function returns a pointer to the transaction ID of a given in-preparation transaction.
- **Inputs**:
    - `txn`: A pointer to a constant `fd_funk_txn_t` structure representing an in-preparation transaction.
- **Control Flow**:
    - The function takes a single argument, `txn`, which is a pointer to a constant `fd_funk_txn_t` structure.
    - It returns the address of the `xid` field within the `fd_funk_txn_t` structure pointed to by `txn`.
- **Output**: A pointer to a constant `fd_funk_txn_xid_t`, which is the transaction ID of the given in-preparation transaction.


---
### fd\_funk\_txn\_is\_frozen<!-- {{#callable:fd_funk_txn_is_frozen}} -->
The `fd_funk_txn_is_frozen` function checks if a given transaction has any children, indicating it is 'frozen'.
- **Inputs**:
    - `txn`: A pointer to a `fd_funk_txn_t` structure representing the transaction to be checked.
- **Control Flow**:
    - The function retrieves the child head index of the transaction using `txn->child_head_cidx`.
    - It converts this compressed index to a full index using [`fd_funk_txn_idx`](#fd_funk_txn_idx).
    - It checks if this index is null using [`fd_funk_txn_idx_is_null`](#fd_funk_txn_idx_is_null).
    - The function returns the negation of the null check result, indicating the transaction is frozen if the index is not null.
- **Output**: Returns an integer: 1 if the transaction is frozen (has children), 0 otherwise.
- **Functions called**:
    - [`fd_funk_txn_idx_is_null`](#fd_funk_txn_idx_is_null)
    - [`fd_funk_txn_idx`](#fd_funk_txn_idx)


---
### fd\_funk\_txn\_is\_only\_child<!-- {{#callable:fd_funk_txn_is_only_child}} -->
The function `fd_funk_txn_is_only_child` checks if a given transaction is an only child, meaning it has no siblings.
- **Inputs**:
    - `txn`: A pointer to a constant `fd_funk_txn_t` structure representing the transaction to be checked.
- **Control Flow**:
    - The function retrieves the previous sibling index of the transaction using `txn->sibling_prev_cidx` and converts it to a full index using [`fd_funk_txn_idx`](#fd_funk_txn_idx).
    - It checks if this index is null using [`fd_funk_txn_idx_is_null`](#fd_funk_txn_idx_is_null), which returns 1 if the index is null and 0 otherwise.
    - Similarly, it retrieves the next sibling index using `txn->sibling_next_cidx`, converts it, and checks if it is null.
    - The function returns the bitwise AND of the results of the two null checks, which will be 1 if both sibling indices are null, indicating the transaction is an only child.
- **Output**: The function returns an integer value: 1 if the transaction is an only child (no siblings), and 0 otherwise.
- **Functions called**:
    - [`fd_funk_txn_idx_is_null`](#fd_funk_txn_idx_is_null)
    - [`fd_funk_txn_idx`](#fd_funk_txn_idx)


# Function Declarations (Public API)

---
### fd\_funk\_generate\_xid<!-- {{#callable_declaration:fd_funk_generate_xid}} -->
Generate a globally unique pseudo-random transaction ID.
- **Description**: This function generates a transaction ID that is intended to be globally unique and pseudo-random. It is useful in scenarios where unique identification of transactions is necessary, such as in distributed systems or databases. The function does not require any input parameters and can be called whenever a new transaction ID is needed. The generated ID is based on a combination of CPU and thread identifiers, a sequence number, and a timestamp, ensuring a high degree of uniqueness.
- **Inputs**: None
- **Output**: Returns a `fd_funk_txn_xid_t` structure containing the generated unique transaction ID.
- **See also**: [`fd_funk_generate_xid`](fd_funk_txn.c.driver.md#fd_funk_generate_xid)  (Implementation)


---
### fd\_funk\_txn\_first\_rec<!-- {{#callable_declaration:fd_funk_txn_first_rec}} -->
Return the first record in a transaction.
- **Description**: Use this function to retrieve the first (oldest) record associated with a given transaction. It is useful when you need to iterate over or access records in a transaction starting from the oldest. If the transaction has no records, the function will return NULL. This function can be called with a NULL transaction pointer, in which case it will return the first record of the entire funk.
- **Inputs**:
    - `funk`: A pointer to an fd_funk_t structure representing the funk context. Must not be null.
    - `txn`: A pointer to a constant fd_funk_txn_t structure representing the transaction. Can be null, in which case the function returns the first record of the entire funk.
- **Output**: A pointer to the first fd_funk_rec_t record in the transaction, or NULL if there are no records.
- **See also**: [`fd_funk_txn_first_rec`](fd_funk_txn.c.driver.md#fd_funk_txn_first_rec)  (Implementation)


---
### fd\_funk\_txn\_last\_rec<!-- {{#callable_declaration:fd_funk_txn_last_rec}} -->
Return the last record in a transaction.
- **Description**: Use this function to retrieve the last (newest) record associated with a given transaction. It is useful when you need to access the most recent changes or additions made in a transaction. If the transaction has no records, the function will return NULL. This function can be called with a NULL transaction pointer, in which case it will return the last record of the entire funk.
- **Inputs**:
    - `funk`: A pointer to an fd_funk_t structure representing the funk context. Must not be null.
    - `txn`: A pointer to a constant fd_funk_txn_t structure representing the transaction. Can be null, in which case the function returns the last record of the entire funk.
- **Output**: A pointer to the last record in the transaction, or NULL if there are no records.
- **See also**: [`fd_funk_txn_last_rec`](fd_funk_txn.c.driver.md#fd_funk_txn_last_rec)  (Implementation)


---
### fd\_funk\_txn\_next\_rec<!-- {{#callable_declaration:fd_funk_txn_next_rec}} -->
Return the next record in a transaction.
- **Description**: Use this function to iterate over records in a transaction, starting from a given record. It is useful for traversing records sequentially. The function must be called with a valid transaction context and a non-null record pointer. If the provided record is the last one in the transaction, the function will return NULL, indicating there are no more records to process.
- **Inputs**:
    - `funk`: A pointer to an fd_funk_t structure representing the transaction context. It must be a valid, non-null pointer.
    - `rec`: A pointer to an fd_funk_rec_t structure representing the current record in the transaction. It must be a valid, non-null pointer.
- **Output**: Returns a pointer to the next record in the transaction if available, or NULL if there are no more records.
- **See also**: [`fd_funk_txn_next_rec`](fd_funk_txn.c.driver.md#fd_funk_txn_next_rec)  (Implementation)


---
### fd\_funk\_txn\_prev\_rec<!-- {{#callable_declaration:fd_funk_txn_prev_rec}} -->
Retrieve the previous record in a transaction.
- **Description**: Use this function to navigate backwards through the records of a transaction. It is useful when you need to iterate over records in reverse order. The function requires a valid transaction context and a non-null record pointer. If the provided record is the first in the transaction, the function will return NULL, indicating there are no previous records.
- **Inputs**:
    - `funk`: A pointer to the transaction context, which must be valid and properly initialized. The caller retains ownership and must ensure it is not null.
    - `rec`: A pointer to the current record from which the previous record is sought. It must not be null and should point to a valid record within the transaction.
- **Output**: Returns a pointer to the previous record if it exists, or NULL if the provided record is the first in the transaction.
- **See also**: [`fd_funk_txn_prev_rec`](fd_funk_txn.c.driver.md#fd_funk_txn_prev_rec)  (Implementation)


---
### fd\_funk\_txn\_prepare<!-- {{#callable_declaration:fd_funk_txn_prepare}} -->
Starts preparation of a new transaction.
- **Description**: This function initiates the preparation of a new transaction within a given funk context. It can be used to create a transaction that is either a child of an existing in-preparation transaction or a direct child of the funk if no parent is specified. The transaction ID must be unique among all in-preparation transactions, the root transaction, and the last published transaction. The function returns a pointer to the newly prepared transaction on success or NULL on failure. It is important to ensure that the funk is a current local join and that the transaction ID is not already in use. If verbose is enabled, warnings will be logged for any failure reasons.
- **Inputs**:
    - `funk`: A pointer to the funk context in which the transaction is being prepared. Must not be null.
    - `parent`: A pointer to the parent transaction, or null if the transaction should be a direct child of the funk. If provided, it must point to a valid in-preparation transaction.
    - `xid`: A pointer to the transaction ID to be used for the new transaction. Must not be null and must be unique among all in-preparation transactions, the root transaction, and the last published transaction.
    - `verbose`: An integer flag indicating whether to log warnings on failure. Non-zero values enable verbose logging.
- **Output**: Returns a pointer to the newly prepared transaction on success, or NULL on failure.
- **See also**: [`fd_funk_txn_prepare`](fd_funk_txn.c.driver.md#fd_funk_txn_prepare)  (Implementation)


---
### fd\_funk\_txn\_cancel<!-- {{#callable_declaration:fd_funk_txn_cancel}} -->
Cancels an in-preparation transaction and its descendants.
- **Description**: Use this function to cancel a specified in-preparation transaction and all of its in-preparation descendants, effectively removing them from the transaction map and freeing associated resources. This function should be called when a transaction is no longer needed or if it should be aborted. It requires a valid funk context and a valid transaction pointer. If the transaction's parent becomes childless as a result, it will be unfrozen. Ensure that the funk context is properly initialized and that the transaction is valid before calling this function. Verbose logging can be enabled to provide warnings in case of invalid inputs.
- **Inputs**:
    - `funk`: A pointer to a valid fd_funk_t structure representing the current funk context. Must not be null.
    - `txn`: A pointer to a valid fd_funk_txn_t structure representing the transaction to be canceled. Must not be null and must point to an in-preparation transaction.
    - `verbose`: An integer flag to enable verbose logging. If non-zero, warnings will be logged for invalid inputs.
- **Output**: Returns the number of transactions canceled, or 0 if the operation fails due to invalid inputs.
- **See also**: [`fd_funk_txn_cancel`](fd_funk_txn.c.driver.md#fd_funk_txn_cancel)  (Implementation)


---
### fd\_funk\_txn\_cancel\_siblings<!-- {{#callable_declaration:fd_funk_txn_cancel_siblings}} -->
Cancels the siblings of a specified transaction.
- **Description**: Use this function to cancel all sibling transactions of a given in-preparation transaction, along with their descendants. This is useful when you want to eliminate competing transaction histories that share the same parent as the specified transaction. The function requires a valid funk context and a valid transaction pointer. It should be called with write access to the funk. If the provided funk or transaction is invalid, the function will return 0 and, if verbose is enabled, log a warning message.
- **Inputs**:
    - `funk`: A pointer to a valid fd_funk_t structure representing the current funk context. Must not be null.
    - `txn`: A pointer to a valid fd_funk_txn_t structure representing the transaction whose siblings are to be canceled. Must not be null and must point to an in-preparation transaction.
    - `verbose`: An integer flag indicating whether to log warnings on invalid input. Non-zero values enable logging.
- **Output**: Returns the number of transactions canceled, or 0 if the operation fails due to invalid input.
- **See also**: [`fd_funk_txn_cancel_siblings`](fd_funk_txn.c.driver.md#fd_funk_txn_cancel_siblings)  (Implementation)


---
### fd\_funk\_txn\_cancel\_children<!-- {{#callable_declaration:fd_funk_txn_cancel_children}} -->
Cancels all children of a specified transaction.
- **Description**: Use this function to cancel all in-preparation child transactions of a specified transaction, or all children of the root if the transaction is NULL. This function should be called when you need to remove all descendant transactions from the preparation state, effectively cleaning up the transaction tree under the specified node. It must be called with a valid funk context and, if specified, a valid transaction. Ensure that the write lock is held on the funk context before calling this function to maintain concurrency control. Verbose logging can be enabled to receive warnings about invalid inputs.
- **Inputs**:
    - `funk`: A pointer to a valid fd_funk_t structure representing the current funk context. Must not be NULL.
    - `txn`: A pointer to a valid fd_funk_txn_t structure representing the transaction whose children are to be canceled, or NULL to cancel all children of the root transaction. The transaction must be in preparation.
    - `verbose`: An integer flag to enable verbose logging. If non-zero, warnings will be logged for invalid inputs.
- **Output**: Returns the number of transactions that were successfully canceled.
- **See also**: [`fd_funk_txn_cancel_children`](fd_funk_txn.c.driver.md#fd_funk_txn_cancel_children)  (Implementation)


---
### fd\_funk\_txn\_cancel\_all<!-- {{#callable_declaration:fd_funk_txn_cancel_all}} -->
Cancels all in-preparation transactions in the funk.
- **Description**: Use this function to cancel all transactions that are currently in preparation within the specified funk, leaving only the last published transaction intact. This function is useful when you need to reset the state of the funk by removing all pending transactions. It should be called when you want to ensure that no in-preparation transactions remain. The function requires a write lock on the funk to ensure thread safety. If verbose is enabled, it will log warnings about any issues encountered during the cancellation process.
- **Inputs**:
    - `funk`: A pointer to the fd_funk_t structure representing the funk whose in-preparation transactions are to be cancelled. Must not be null.
    - `verbose`: An integer flag indicating whether to log warnings about the cancellation process. Non-zero values enable logging.
- **Output**: Returns the number of transactions that were successfully cancelled.
- **See also**: [`fd_funk_txn_cancel_all`](fd_funk_txn.c.driver.md#fd_funk_txn_cancel_all)  (Implementation)


---
### fd\_funk\_txn\_publish<!-- {{#callable_declaration:fd_funk_txn_publish}} -->
Publishes a transaction and its ancestors, cancelling competing histories.
- **Description**: Use this function to publish an in-preparation transaction and any of its ancestors within a transactional system. This operation will cancel any competing transaction histories, ensuring that the published transaction becomes part of the main transaction history. It is essential to ensure that the `funk` and `txn` parameters are valid and that the function is called within a properly initialized transactional context. If `verbose` is non-zero, warnings will be logged for invalid inputs.
- **Inputs**:
    - `funk`: A pointer to a `fd_funk_t` structure representing the transactional context. Must not be null. The caller retains ownership.
    - `txn`: A pointer to a `fd_funk_txn_t` structure representing the transaction to be published. Must be a valid in-preparation transaction. The caller retains ownership.
    - `verbose`: An integer flag indicating whether to log warnings for invalid inputs. Non-zero enables logging.
- **Output**: Returns the number of transactions published. If inputs are invalid, returns 0.
- **See also**: [`fd_funk_txn_publish`](fd_funk_txn.c.driver.md#fd_funk_txn_publish)  (Implementation)


---
### fd\_funk\_txn\_publish\_into\_parent<!-- {{#callable_declaration:fd_funk_txn_publish_into_parent}} -->
Publishes a transaction into its parent, cancelling any competing sibling transactions.
- **Description**: This function is used to publish an in-preparation transaction into its immediate parent transaction within a transactional system. It should be called when you want to finalize a transaction by merging it with its parent, effectively making it part of the parent's transaction history. This operation will cancel any sibling transactions that compete with the given transaction, ensuring that only the desired transaction path is preserved. The function requires a valid transaction and a valid funk context, and it must be called with write access to the funk. If verbose logging is enabled, warnings will be logged for invalid inputs.
- **Inputs**:
    - `funk`: A pointer to a valid fd_funk_t structure representing the transactional context. Must not be null. The caller retains ownership.
    - `txn`: A pointer to a valid fd_funk_txn_t structure representing the transaction to be published. Must not be null and must be a valid in-preparation transaction.
    - `verbose`: An integer flag indicating whether to log warnings for invalid inputs. Non-zero values enable logging.
- **Output**: Returns FD_FUNK_SUCCESS on successful publication or an error code if the operation fails.
- **See also**: [`fd_funk_txn_publish_into_parent`](fd_funk_txn.c.driver.md#fd_funk_txn_publish_into_parent)  (Implementation)


---
### fd\_funk\_txn\_all\_iter\_new<!-- {{#callable_declaration:fd_funk_txn_all_iter_new}} -->
Initialize an iterator for all transactions in a funk.
- **Description**: Use this function to initialize an iterator that will traverse all transactions within a given funk. This function sets up the iterator to start from the beginning of the transaction map, skipping any null entries. It must be called before using the iterator with functions like `fd_funk_txn_all_iter_done` or `fd_funk_txn_all_iter_next`. Ensure that the `funk` parameter is a valid, initialized funk object and that `iter` is a valid pointer to an `fd_funk_txn_all_iter_t` structure.
- **Inputs**:
    - `funk`: A pointer to a valid `fd_funk_t` structure representing the funk whose transactions are to be iterated over. Must not be null.
    - `iter`: A pointer to an `fd_funk_txn_all_iter_t` structure where the iterator state will be initialized. Must not be null.
- **Output**: None
- **See also**: [`fd_funk_txn_all_iter_new`](fd_funk_txn.c.driver.md#fd_funk_txn_all_iter_new)  (Implementation)


---
### fd\_funk\_txn\_all\_iter\_done<!-- {{#callable_declaration:fd_funk_txn_all_iter_done}} -->
Checks if the transaction iterator has completed iterating over all transactions.
- **Description**: Use this function to determine if the iteration over all transactions in a funk transaction map is complete. It should be called after initializing the iterator with `fd_funk_txn_all_iter_new` and during iteration to check if the end has been reached. This function is essential for controlling loop termination when iterating over transactions.
- **Inputs**:
    - `iter`: A pointer to an `fd_funk_txn_all_iter_t` structure representing the transaction iterator. It must be initialized with `fd_funk_txn_all_iter_new` before use. The function expects a valid pointer and does not handle null pointers.
- **Output**: Returns a non-zero value if the iterator has completed iterating over all transactions, and zero if there are more transactions to iterate over.
- **See also**: [`fd_funk_txn_all_iter_done`](fd_funk_txn.c.driver.md#fd_funk_txn_all_iter_done)  (Implementation)


---
### fd\_funk\_txn\_all\_iter\_next<!-- {{#callable_declaration:fd_funk_txn_all_iter_next}} -->
Advance the iterator to the next transaction, skipping null entries.
- **Description**: Use this function to move a transaction iterator to the next valid transaction in a sequence. It is typically called in a loop to iterate over all transactions. The function automatically skips over any null entries, ensuring that the iterator always points to a valid transaction or the end of the sequence. This function should be used after initializing the iterator with `fd_funk_txn_all_iter_new` and before checking for completion with `fd_funk_txn_all_iter_done`.
- **Inputs**:
    - `iter`: A pointer to an `fd_funk_txn_all_iter_t` structure representing the current state of the transaction iterator. Must not be null. The iterator should have been initialized with `fd_funk_txn_all_iter_new` before calling this function.
- **Output**: None
- **See also**: [`fd_funk_txn_all_iter_next`](fd_funk_txn.c.driver.md#fd_funk_txn_all_iter_next)  (Implementation)


---
### fd\_funk\_txn\_all\_iter\_ele\_const<!-- {{#callable_declaration:fd_funk_txn_all_iter_ele_const}} -->
Retrieve the current transaction element from an iterator.
- **Description**: Use this function to access the current transaction element pointed to by the iterator during iteration over all transactions. This function is typically used within a loop that iterates over transactions using the provided iterator functions. It is important to ensure that the iterator is properly initialized and not at the end of the iteration before calling this function.
- **Inputs**:
    - `iter`: A pointer to an `fd_funk_txn_all_iter_t` iterator. It must be initialized and valid, and must not be null. The function assumes the iterator is not at the end of the iteration.
- **Output**: Returns a constant pointer to the current `fd_funk_txn_t` transaction element. The pointer is valid as long as the iterator is not modified or invalidated.
- **See also**: [`fd_funk_txn_all_iter_ele_const`](fd_funk_txn.c.driver.md#fd_funk_txn_all_iter_ele_const)  (Implementation)


---
### fd\_funk\_txn\_all\_iter\_ele<!-- {{#callable_declaration:fd_funk_txn_all_iter_ele}} -->
Retrieve the current transaction element from an iterator.
- **Description**: Use this function to obtain the current transaction element pointed to by the iterator. This is typically used within an iteration loop over all transactions. The iterator must be properly initialized and not at the end of the iteration. The function returns a pointer to the transaction element, allowing for further operations on the transaction.
- **Inputs**:
    - `iter`: A pointer to an `fd_funk_txn_all_iter_t` structure, representing the iterator over all transactions. It must be initialized and valid. The function assumes the iterator is not at the end of the iteration.
- **Output**: Returns a pointer to the current `fd_funk_txn_t` transaction element. The pointer is valid as long as the iterator is valid and has not reached the end of the iteration.
- **See also**: [`fd_funk_txn_all_iter_ele`](fd_funk_txn.c.driver.md#fd_funk_txn_all_iter_ele)  (Implementation)


---
### fd\_funk\_txn\_verify<!-- {{#callable_declaration:fd_funk_txn_verify}} -->
Verifies the integrity of a transaction map.
- **Description**: Use this function to ensure that the transaction map within a `fd_funk_t` structure is intact and free from corruption. It is typically called as part of a larger verification process, such as `fd_funk_verify`. The function checks the validity of transaction indices and the integrity of parent-child relationships within the transaction map. It returns an error code if any issues are detected, logging details of the failure. This function should be called when the transaction map's integrity is in question or as part of routine checks.
- **Inputs**:
    - `funk`: A pointer to a `fd_funk_t` structure representing the transaction map to be verified. Must not be null. The caller retains ownership of the structure.
- **Output**: Returns `FD_FUNK_SUCCESS` if the transaction map is intact, or `FD_FUNK_ERR_INVAL` if any issues are detected.
- **See also**: [`fd_funk_txn_verify`](fd_funk_txn.c.driver.md#fd_funk_txn_verify)  (Implementation)


---
### fd\_funk\_txn\_valid<!-- {{#callable_declaration:fd_funk_txn_valid}} -->
Checks if a transaction is valid within a funk context.
- **Description**: Use this function to determine if a given transaction pointer refers to a valid in-preparation transaction within the specified funk context. This is useful for verifying transaction integrity before performing operations that depend on the transaction's validity. The function assumes that the transaction is part of the transaction pool associated with the funk and that the funk is properly initialized and joined locally.
- **Inputs**:
    - `funk`: A pointer to a constant fd_funk_t structure representing the funk context. It must not be null and should be a valid, initialized funk instance.
    - `txn`: A pointer to a constant fd_funk_txn_t structure representing the transaction to be validated. It must not be null and should point to a transaction within the funk's transaction pool.
- **Output**: Returns 1 if the transaction is valid, and 0 if it is not.
- **See also**: [`fd_funk_txn_valid`](fd_funk_txn.c.driver.md#fd_funk_txn_valid)  (Implementation)


