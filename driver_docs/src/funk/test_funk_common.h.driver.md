# Purpose
This C header file provides a "mini-funk" implementation designed for reference and testing purposes. It defines a set of data structures and functions that manage transactions (`txn_t`) and records (`rec_t`) within a broader structure called `funk_t`. The primary focus of this code is to facilitate the creation, manipulation, and querying of transactions and records, which are organized in a hierarchical manner. The `txn_t` structure represents a transaction, which can have parent and child relationships, allowing for complex transaction hierarchies. The `rec_t` structure represents a record associated with a transaction, and it includes fields for linking records in a doubly linked list and a map. The `funk_t` structure acts as a container for managing collections of transactions and records, maintaining head and tail pointers for linked lists and maps, as well as counters for the number of transactions and records.

The file defines a public API for interacting with these structures, including functions for preparing, canceling, and publishing transactions, as well as querying, inserting, and removing records. Additionally, it provides utility functions for testing, such as generating unique transaction IDs and setting or comparing keys. The use of inline functions and macros like `FD_FN_PURE` suggests an emphasis on performance and purity of functions, which are likely intended to be used in performance-critical or testing scenarios. Overall, this header file serves as a foundational component for managing transactional data in a controlled and testable manner, with a clear focus on hierarchical transaction management and record manipulation.
# Imports and Dependencies

---
- `fd_funk_base.h`


# Global Variables

---
### txn\_prepare
- **Type**: `txn_t *`
- **Description**: The `txn_prepare` function is a global function that returns a pointer to a `txn_t` structure. It is used to prepare a new transaction within the context of a given `funk_t` instance, potentially as a child of an existing transaction (`parent`) and with a specified transaction identifier (`xid`).
- **Use**: This function is used to initialize and prepare a new transaction in the mini-funk system, linking it to the provided parent transaction and assigning it a unique transaction ID.


---
### rec\_query
- **Type**: `rec_t *`
- **Description**: The `rec_query` function is a global function that returns a pointer to a `rec_t` structure. It is used to query a record within a transactional context, given a specific key. The function is marked as `FD_FN_PURE`, indicating that it has no side effects and its return value depends only on its parameters.
- **Use**: This function is used to retrieve a record from a transactional data structure based on a given key.


---
### rec\_query\_global
- **Type**: `rec_t *`
- **Description**: The `rec_query_global` function is a global function that returns a pointer to a `rec_t` structure. It is used to query a record in a global context, given a `funk_t` structure, a `txn_t` transaction, and a key of type `ulong`. The function is marked with `FD_FN_PURE`, indicating it has no side effects and its return value depends only on its parameters.
- **Use**: This function is used to retrieve a record from a global context based on the provided transaction and key.


---
### rec\_insert
- **Type**: `rec_t *`
- **Description**: The `rec_insert` function is a global function that returns a pointer to a `rec_t` structure. It is used to insert a new record into a data structure managed by the `funk_t` and `txn_t` structures, using a specified key.
- **Use**: This function is used to add a new record to the data structure, associating it with a transaction and a unique key.


---
### funk\_new
- **Type**: `funk_t *`
- **Description**: The `funk_new` variable is a function that returns a pointer to a `funk_t` structure. The `funk_t` structure represents a 'mini-funk' system, which is a simplified transaction and record management system for testing and reference purposes.
- **Use**: This function is used to create and initialize a new instance of the `funk_t` structure, which can then be used to manage transactions and records.


# Data Structures

---
### txn\_t
- **Type**: `struct`
- **Members**:
    - `xid`: A unique identifier for the transaction.
    - `parent`: A pointer to the parent transaction in a transaction hierarchy.
    - `child_head`: A pointer to the first child transaction in a list of child transactions.
    - `child_tail`: A pointer to the last child transaction in a list of child transactions.
    - `sibling_prev`: A pointer to the previous sibling transaction in a list of sibling transactions.
    - `sibling_next`: A pointer to the next sibling transaction in a list of sibling transactions.
    - `map_prev`: A pointer to the previous transaction in a map of transactions.
    - `map_next`: A pointer to the next transaction in a map of transactions.
    - `rec_head`: A pointer to the first record associated with the transaction.
    - `rec_tail`: A pointer to the last record associated with the transaction.
- **Description**: The `txn_t` structure represents a transaction in a hierarchical transaction system, where each transaction can have a parent, multiple children, and siblings. It maintains pointers to its parent, children, and siblings, as well as pointers to the head and tail of a list of records associated with the transaction. This structure is used to manage and navigate through a complex transaction hierarchy, allowing for operations such as preparing, canceling, and publishing transactions.


---
### rec\_t
- **Type**: `struct`
- **Members**:
    - `txn`: A pointer to a transaction structure associated with the record.
    - `key`: An unsigned long integer representing the key of the record.
    - `prev`: A pointer to the previous record in a linked list.
    - `next`: A pointer to the next record in a linked list.
    - `map_prev`: A pointer to the previous record in a map-based linked list.
    - `map_next`: A pointer to the next record in a map-based linked list.
    - `erase`: An integer flag indicating whether the record is marked for erasure.
    - `val`: An unsigned integer representing the value associated with the record.
- **Description**: The `rec_t` structure represents a record in a transactional system, containing pointers to associated transactions and linked list nodes for both standard and map-based lists. It includes a key for identification, a value for data storage, and an erase flag to indicate if the record should be removed. This structure is designed to facilitate efficient record management within a transactional context, supporting operations such as insertion, removal, and querying.


---
### rec
- **Type**: `struct`
- **Members**:
    - `txn`: A pointer to a transaction structure associated with the record.
    - `key`: An unsigned long integer representing the unique key of the record.
    - `prev`: A pointer to the previous record in a linked list.
    - `next`: A pointer to the next record in a linked list.
    - `map_prev`: A pointer to the previous record in a map-based linked list.
    - `map_next`: A pointer to the next record in a map-based linked list.
    - `erase`: An integer flag indicating whether the record is marked for erasure.
    - `val`: An unsigned integer representing the value associated with the record.
- **Description**: The 'rec' structure is a compound data type used to represent a record in a transactional system. It contains pointers to manage its position within both a standard linked list and a map-based linked list, allowing for efficient traversal and manipulation of records. The structure also includes a key for uniquely identifying the record, a transaction pointer to associate the record with a specific transaction, and a value field to store data. Additionally, an 'erase' flag is used to mark records for deletion, facilitating cleanup operations.


---
### txn
- **Type**: `struct`
- **Members**:
    - `xid`: A unique identifier for the transaction.
    - `parent`: A pointer to the parent transaction in a transaction hierarchy.
    - `child_head`: A pointer to the first child transaction in a list of child transactions.
    - `child_tail`: A pointer to the last child transaction in a list of child transactions.
    - `sibling_prev`: A pointer to the previous sibling transaction in a list of sibling transactions.
    - `sibling_next`: A pointer to the next sibling transaction in a list of sibling transactions.
    - `map_prev`: A pointer to the previous transaction in a map of transactions.
    - `map_next`: A pointer to the next transaction in a map of transactions.
    - `rec_head`: A pointer to the first record associated with the transaction.
    - `rec_tail`: A pointer to the last record associated with the transaction.
- **Description**: The 'txn' structure represents a transaction in a hierarchical transaction system, where each transaction can have a parent, multiple children, and siblings. It maintains pointers to its position within a transaction map and a list of records associated with it, allowing for complex transaction management and navigation within a transaction tree.


---
### funk
- **Type**: `struct`
- **Members**:
    - `last_publish`: Stores the timestamp of the last publish operation.
    - `child_head`: Pointer to the head of the child transaction list.
    - `child_tail`: Pointer to the tail of the child transaction list.
    - `txn_map_head`: Pointer to the head of the transaction map list.
    - `txn_map_tail`: Pointer to the tail of the transaction map list.
    - `txn_cnt`: Holds the count of transactions.
    - `rec_head`: Pointer to the head of the record list.
    - `rec_tail`: Pointer to the tail of the record list.
    - `rec_map_head`: Pointer to the head of the record map list.
    - `rec_map_tail`: Pointer to the tail of the record map list.
    - `rec_cnt`: Holds the count of records.
- **Description**: The `funk` structure is a central data structure used to manage transactions and records in a mini-funk system. It maintains pointers to the head and tail of both transaction and record lists, as well as their respective map lists, allowing for efficient traversal and management of these elements. Additionally, it keeps track of the number of transactions and records, and records the timestamp of the last publish operation, which is crucial for maintaining the state and consistency of the system.


---
### funk\_t
- **Type**: `struct`
- **Members**:
    - `last_publish`: Stores the timestamp or identifier of the last publish operation.
    - `child_head`: Points to the first child transaction in a linked list of transactions.
    - `child_tail`: Points to the last child transaction in a linked list of transactions.
    - `txn_map_head`: Points to the first transaction in a map of transactions.
    - `txn_map_tail`: Points to the last transaction in a map of transactions.
    - `txn_cnt`: Holds the count of transactions currently managed by the funk.
    - `rec_head`: Points to the first record in a linked list of records.
    - `rec_tail`: Points to the last record in a linked list of records.
    - `rec_map_head`: Points to the first record in a map of records.
    - `rec_map_tail`: Points to the last record in a map of records.
    - `rec_cnt`: Holds the count of records currently managed by the funk.
- **Description**: The `funk_t` structure is a central data structure used to manage transactions and records in a 'mini-funk' system. It maintains linked lists and maps of transactions and records, allowing for efficient traversal and management of these elements. The structure includes pointers to the head and tail of both transaction and record lists/maps, as well as counters to keep track of the number of transactions and records. This setup facilitates operations such as insertion, deletion, and querying of transactions and records, supporting the overall functionality of the mini-funk system.


# Functions

---
### txn\_is\_frozen<!-- {{#callable:txn_is_frozen}} -->
The `txn_is_frozen` function checks if a transaction has any child transactions, indicating it is 'frozen'.
- **Inputs**:
    - `txn`: A pointer to a `txn_t` structure representing the transaction to be checked.
- **Control Flow**:
    - The function accesses the `child_head` member of the `txn` structure.
    - It returns a boolean value indicating whether `child_head` is non-null, using the double negation `!!` to convert it to an integer (0 or 1).
- **Output**: An integer value (0 or 1) indicating whether the transaction is frozen (1 if it has child transactions, 0 otherwise).


---
### txn\_is\_only\_child<!-- {{#callable:txn_is_only_child}} -->
The function `txn_is_only_child` checks if a transaction is the only child in its sibling list.
- **Inputs**:
    - `txn`: A pointer to a `txn_t` structure representing the transaction to be checked.
- **Control Flow**:
    - The function checks if both `sibling_prev` and `sibling_next` pointers of the `txn` are NULL.
    - If both pointers are NULL, it indicates that the transaction has no siblings and is the only child.
- **Output**: Returns an integer value: 1 if the transaction is the only child (i.e., has no siblings), and 0 otherwise.


---
### txn\_ancestor<!-- {{#callable:txn_ancestor}} -->
The `txn_ancestor` function traverses up the transaction hierarchy to find the nearest ancestor transaction that is not the only child of its parent.
- **Inputs**:
    - `txn`: A pointer to a `txn_t` structure representing the starting transaction from which to find the ancestor.
- **Control Flow**:
    - Enter an infinite loop to traverse the transaction hierarchy upwards.
    - Check if the current transaction is not the only child using [`txn_is_only_child`](#txn_is_only_child); if it is not, break the loop.
    - Check if the current transaction has no parent; if so, return `NULL` as there is no ancestor to find.
    - Move to the parent transaction and continue the loop.
    - Once the loop is exited, return the current transaction as it is the ancestor.
- **Output**: A pointer to the nearest ancestor `txn_t` that is not the only child of its parent, or `NULL` if no such ancestor exists.
- **Functions called**:
    - [`txn_is_only_child`](#txn_is_only_child)


---
### txn\_descendant<!-- {{#callable:txn_descendant}} -->
The `txn_descendant` function returns the deepest descendant transaction in a hierarchy where each transaction is the only child of its parent.
- **Inputs**:
    - `txn`: A pointer to a `txn_t` structure representing the starting transaction from which to find the deepest descendant.
- **Control Flow**:
    - Check if the input transaction is not the only child; if so, return NULL.
    - Enter a loop to traverse down the hierarchy of transactions.
    - In each iteration, check if the current transaction has a child and if that child is the only child of its parent.
    - If both conditions are met, move to the child transaction and continue the loop.
    - If either condition fails, break the loop.
    - Return the current transaction, which is the deepest descendant where each transaction is the only child of its parent.
- **Output**: A pointer to the deepest descendant `txn_t` structure, or NULL if the input transaction is not the only child.
- **Functions called**:
    - [`txn_is_only_child`](#txn_is_only_child)


---
### txn\_cancel\_children<!-- {{#callable:txn_cancel_children}} -->
The `txn_cancel_children` function cancels all child transactions of a given transaction or the root transaction in a funk structure.
- **Inputs**:
    - `funk`: A pointer to a `funk_t` structure, representing the transaction management context.
    - `txn`: A pointer to a `txn_t` structure, representing the parent transaction whose child transactions are to be canceled; if NULL, the root transactions in the funk are targeted.
- **Control Flow**:
    - Determine the starting child transaction: if `txn` is provided, start with `txn->child_head`; otherwise, start with `funk->child_head`.
    - Enter a loop that continues as long as there is a child transaction to process.
    - Within the loop, store the next sibling of the current child transaction in a temporary variable `next`.
    - Call [`txn_cancel`](test_funk_common.c.driver.md#txn_cancel) to cancel the current child transaction.
    - Move to the next child transaction by setting `child` to `next`.
- **Output**: Returns the original `txn` pointer, allowing for potential chaining or further operations on the transaction.
- **Functions called**:
    - [`txn_cancel`](test_funk_common.c.driver.md#txn_cancel)


---
### txn\_cancel\_siblings<!-- {{#callable:txn_cancel_siblings}} -->
The `txn_cancel_siblings` function cancels all sibling transactions of a given transaction within a transaction hierarchy.
- **Inputs**:
    - `funk`: A pointer to a `funk_t` structure representing the transaction system context.
    - `txn`: A pointer to a `txn_t` structure representing the transaction whose siblings are to be canceled.
- **Control Flow**:
    - Determine the starting child transaction based on whether the given transaction has a parent or not.
    - Iterate over each sibling transaction starting from the determined child transaction.
    - For each sibling transaction, check if it is not the same as the given transaction.
    - If it is not the same, call [`txn_cancel`](test_funk_common.c.driver.md#txn_cancel) to cancel the sibling transaction.
    - Move to the next sibling transaction in the list.
    - Continue until all siblings have been processed.
- **Output**: Returns a pointer to the original `txn_t` transaction passed as input.
- **Functions called**:
    - [`txn_cancel`](test_funk_common.c.driver.md#txn_cancel)


---
### funk\_is\_frozen<!-- {{#callable:funk_is_frozen}} -->
The `funk_is_frozen` function checks if a `funk_t` structure has any child transactions.
- **Inputs**:
    - `funk`: A pointer to a `funk_t` structure, representing a 'funk' object that may contain child transactions.
- **Control Flow**:
    - The function checks the `child_head` member of the `funk_t` structure.
    - It returns a boolean value indicating whether `child_head` is non-null, which implies the presence of child transactions.
- **Output**: An integer value, where a non-zero value indicates that the `funk_t` structure has child transactions, and zero indicates it does not.


---
### funk\_descendant<!-- {{#callable:funk_descendant}} -->
The `funk_descendant` function returns the deepest descendant transaction of the first child transaction of a given funk structure, or NULL if there are no child transactions.
- **Inputs**:
    - `funk`: A pointer to a `funk_t` structure, representing the root of a transaction tree.
- **Control Flow**:
    - Check if the `funk` structure has a `child_head` (i.e., it has at least one child transaction).
    - If `child_head` exists, call [`txn_descendant`](#txn_descendant) on `funk->child_head` to find the deepest descendant transaction.
    - If `child_head` does not exist, return NULL.
- **Output**: A pointer to the deepest descendant `txn_t` structure of the first child transaction, or NULL if there are no child transactions.
- **Functions called**:
    - [`txn_descendant`](#txn_descendant)


---
### xid\_set<!-- {{#callable:xid_set}} -->
The `xid_set` function initializes a transaction ID structure with a given ID and its double.
- **Inputs**:
    - `xid`: A pointer to a `fd_funk_txn_xid_t` structure where the transaction ID will be set.
    - `_xid`: An unsigned long integer representing the transaction ID to be set.
- **Control Flow**:
    - The function assigns the value of `_xid` to the first element of the `ul` array in the `xid` structure.
    - The function assigns the value of `_xid` doubled to the second element of the `ul` array in the `xid` structure.
    - The function returns the pointer to the `xid` structure.
- **Output**: A pointer to the `fd_funk_txn_xid_t` structure with the transaction ID set.


---
### xid\_eq<!-- {{#callable:xid_eq}} -->
The `xid_eq` function checks if a transaction ID (`xid`) is equal to a given unsigned long integer (`_xid`) by converting the integer to a transaction ID format and comparing them.
- **Inputs**:
    - `xid`: A pointer to a `fd_funk_txn_xid_t` structure representing the transaction ID to be compared.
    - `_xid`: An unsigned long integer representing the transaction ID to compare against.
- **Control Flow**:
    - A temporary `fd_funk_txn_xid_t` structure `tmp` is declared to hold the converted transaction ID.
    - The `_xid` is converted into a `fd_funk_txn_xid_t` format using the [`xid_set`](#xid_set) function, storing the result in `tmp`.
    - The [`fd_funk_txn_xid_eq`](fd_funk_base.h.driver.md#fd_funk_txn_xid_eq) function is called to compare the original `xid` with the converted `tmp`, and the result is returned.
- **Output**: An integer indicating whether the two transaction IDs are equal (non-zero if equal, zero if not).
- **Functions called**:
    - [`fd_funk_txn_xid_eq`](fd_funk_base.h.driver.md#fd_funk_txn_xid_eq)
    - [`xid_set`](#xid_set)


---
### key\_set<!-- {{#callable:key_set}} -->
The `key_set` function initializes a `fd_funk_rec_key_t` structure with specific transformations of a given unsigned long integer.
- **Inputs**:
    - `key`: A pointer to a `fd_funk_rec_key_t` structure that will be initialized.
    - `_key`: An unsigned long integer used to set the values in the `fd_funk_rec_key_t` structure.
- **Control Flow**:
    - The function assigns the first element of the `key->ul` array to `_key`.
    - The second element of the `key->ul` array is set to `_key + _key`.
    - The third element of the `key->ul` array is set to `_key * _key`.
    - The fourth element of the `key->ul` array is set to `-_key`.
    - The fifth element of the `key->ul` array is set to `_key * 3U`.
    - The function returns the pointer to the `fd_funk_rec_key_t` structure.
- **Output**: The function returns a pointer to the initialized `fd_funk_rec_key_t` structure.


# Function Declarations (Public API)

---
### txn\_prepare<!-- {{#callable_declaration:txn_prepare}} -->
Creates and initializes a new transaction.
- **Description**: This function is used to create a new transaction within a given funk context, optionally associating it with a parent transaction. It initializes the transaction with the specified transaction ID (xid) and links it into the funk's transaction map and the parent's child list if a parent is provided. This function should be called when a new transaction is needed, and it returns a pointer to the newly created transaction. The caller is responsible for managing the memory of the returned transaction. Ensure that the funk context is properly initialized before calling this function.
- **Inputs**:
    - `funk`: A pointer to a funk_t structure representing the context in which the transaction is created. Must not be null.
    - `parent`: A pointer to a txn_t structure representing the parent transaction, or null if the transaction has no parent. The caller retains ownership.
    - `xid`: An unsigned long integer representing the unique transaction ID for the new transaction. It should be unique within the context of the funk.
- **Output**: Returns a pointer to the newly created txn_t structure representing the transaction. If memory allocation fails, the function logs an error and does not return.
- **See also**: [`txn_prepare`](test_funk_common.c.driver.md#txn_prepare)  (Implementation)


---
### txn\_cancel<!-- {{#callable_declaration:txn_cancel}} -->
Cancels a transaction and its associated records.
- **Description**: Use this function to cancel a transaction and all its associated records within a given funk context. This function should be called when a transaction needs to be aborted and its changes should not be committed. It will also recursively cancel any child transactions associated with the given transaction. Ensure that the transaction is valid and has been previously prepared before calling this function. This function does not return a value and does not provide feedback on the success of the cancellation.
- **Inputs**:
    - `funk`: A pointer to a funk_t structure representing the context in which the transaction exists. Must not be null. The caller retains ownership.
    - `txn`: A pointer to a txn_t structure representing the transaction to be canceled. Must not be null. The transaction should be valid and previously prepared.
- **Output**: None
- **See also**: [`txn_cancel`](test_funk_common.c.driver.md#txn_cancel)  (Implementation)


---
### txn\_publish<!-- {{#callable_declaration:txn_publish}} -->
Publishes a transaction and its ancestors to the global state.
- **Description**: This function is used to publish a transaction and all its ancestor transactions to the global state within a 'funk' context. It should be called when you want to make the changes in a transaction permanent and visible globally. The function processes the transaction's records, updates the global state, and cancels any sibling transactions. It also updates the parent-child relationships among transactions. The function must be called with a valid transaction that is part of the 'funk' context, and it assumes that the transaction and its ancestors are ready to be published.
- **Inputs**:
    - `funk`: A pointer to a 'funk_t' structure representing the context in which the transaction operates. Must not be null.
    - `txn`: A pointer to a 'txn_t' structure representing the transaction to be published. Must not be null and should be part of the 'funk' context.
    - `cnt`: An unsigned long integer representing the initial count of published transactions. It is used to accumulate the number of transactions published, including ancestors.
- **Output**: Returns the total count of transactions published, including the specified transaction and its ancestors.
- **See also**: [`txn_publish`](test_funk_common.c.driver.md#txn_publish)  (Implementation)


---
### rec\_query<!-- {{#callable_declaration:rec_query}} -->
Searches for a record with a specified key in a transaction or funk.
- **Description**: Use this function to locate a record with a given key within the context of a transaction or the broader funk structure. If a transaction is provided, the search is limited to the records associated with that transaction; otherwise, the search is conducted across the records in the funk. This function is useful for retrieving records when you have a specific key and need to determine if a corresponding record exists. It is important to ensure that the `funk` parameter is not null, as this is required for the function to operate correctly.
- **Inputs**:
    - `funk`: A pointer to a `funk_t` structure representing the collection of records. Must not be null.
    - `txn`: A pointer to a `txn_t` structure representing a transaction. Can be null, in which case the search is performed on the funk's records.
    - `key`: An unsigned long integer representing the key of the record to search for.
- **Output**: Returns a pointer to the `rec_t` structure if a record with the specified key is found; otherwise, returns null.
- **See also**: [`rec_query`](test_funk_common.c.driver.md#rec_query)  (Implementation)


---
### rec\_query\_global<!-- {{#callable_declaration:rec_query_global}} -->
Searches for a record with a given key in a transaction and its ancestors.
- **Description**: Use this function to retrieve a record associated with a specific key within a transaction and its ancestor transactions. It is useful when you need to find a record that may have been modified or created in any of the ancestor transactions. The function traverses up the transaction hierarchy, starting from the given transaction, until it finds the record or reaches the top of the hierarchy. It is important to ensure that the transaction hierarchy is properly set up before calling this function.
- **Inputs**:
    - `funk`: A pointer to a funk_t structure representing the context in which the transaction operates. Must not be null.
    - `txn`: A pointer to a txn_t structure representing the starting transaction for the search. Can be null, in which case the search will start from the top-level context.
    - `key`: An unsigned long integer representing the key of the record to search for. There are no specific constraints on the value of the key.
- **Output**: Returns a pointer to the rec_t structure representing the found record, or null if no record with the specified key is found in the transaction or its ancestors.
- **See also**: [`rec_query_global`](test_funk_common.c.driver.md#rec_query_global)  (Implementation)


---
### rec\_insert<!-- {{#callable_declaration:rec_insert}} -->
Inserts a new record into the funk data structure.
- **Description**: This function is used to insert a new record with a specified key into the given funk data structure, optionally associating it with a transaction. It should be called when a new record needs to be added, and it handles the case where a record with the same key already exists by undoing any previous erase operation. The function assumes that the funk and transaction (if provided) are properly initialized. It returns a pointer to the newly inserted or updated record. The function will log an error if memory allocation fails or if an unexpected condition occurs.
- **Inputs**:
    - `funk`: A pointer to a funk_t structure representing the data structure where the record will be inserted. Must not be null.
    - `txn`: A pointer to a txn_t structure representing the transaction with which the record is associated. Can be null if no transaction is involved.
    - `key`: An unsigned long integer representing the key of the record to be inserted. The key should be unique within the context of the funk and transaction.
- **Output**: Returns a pointer to the rec_t structure representing the newly inserted or updated record.
- **See also**: [`rec_insert`](test_funk_common.c.driver.md#rec_insert)  (Implementation)


---
### rec\_remove<!-- {{#callable_declaration:rec_remove}} -->
Marks a record for removal.
- **Description**: Use this function to mark a record as erased within a transactional context. This function sets the `erase` flag of the specified record to indicate that it should be considered removed. It is typically used in scenarios where records are managed within a transaction system, and marking a record for removal is part of the transaction's operations. Ensure that the `rec` parameter is a valid pointer to a record that is part of the transaction system before calling this function.
- **Inputs**:
    - `funk`: A pointer to a `funk_t` structure representing the transactional context. This parameter is not used in the function, but it is required to maintain consistency with the API's function signature. The caller retains ownership.
    - `rec`: A pointer to a `rec_t` structure representing the record to be marked for removal. Must not be null. The function sets the `erase` flag of this record to 1.
- **Output**: None
- **See also**: [`rec_remove`](test_funk_common.c.driver.md#rec_remove)  (Implementation)


---
### funk\_new<!-- {{#callable_declaration:funk_new}} -->
Allocate and initialize a new funk_t structure.
- **Description**: Use this function to create a new instance of a funk_t structure, which is used for managing transactions and records in a testing or reference context. This function allocates memory for the structure and initializes its fields to default values. It is important to ensure that there is sufficient memory available before calling this function, as it will log an error if memory allocation fails. The caller is responsible for managing the memory of the returned structure, including freeing it when it is no longer needed.
- **Inputs**: None
- **Output**: Returns a pointer to a newly allocated and initialized funk_t structure, or logs an error if memory allocation fails.
- **See also**: [`funk_new`](test_funk_common.c.driver.md#funk_new)  (Implementation)


---
### funk\_delete<!-- {{#callable_declaration:funk_delete}} -->
Deletes a funk instance and all its associated resources.
- **Description**: Use this function to properly dispose of a funk instance when it is no longer needed. It ensures that all resources associated with the funk, including its records and transactions, are freed. This function should be called to prevent memory leaks after you are done using a funk instance. Ensure that no other operations are performed on the funk after calling this function, as it invalidates the funk instance.
- **Inputs**:
    - `funk`: A pointer to the funk_t instance to be deleted. Must not be null. The caller relinquishes ownership, and the function will free all associated resources. Passing a null pointer results in undefined behavior.
- **Output**: None
- **See also**: [`funk_delete`](test_funk_common.c.driver.md#funk_delete)  (Implementation)


---
### xid\_unique<!-- {{#callable_declaration:xid_unique}} -->
Generates a unique transaction identifier.
- **Description**: This function provides a unique identifier for transactions, ensuring that each call returns a distinct value. It is useful in scenarios where unique transaction IDs are required, such as in database operations or transaction management systems. The function does not require any parameters and can be called repeatedly to obtain new unique identifiers. It is important to note that the function is not thread-safe, so concurrent calls from multiple threads may result in duplicate identifiers.
- **Inputs**: None
- **Output**: Returns a unique unsigned long integer representing a transaction identifier.
- **See also**: [`xid_unique`](test_funk_common.c.driver.md#xid_unique)  (Implementation)


---
### key\_eq<!-- {{#callable_declaration:key_eq}} -->
Compare a record key with a given key value.
- **Description**: Use this function to determine if a record key matches a specified key value. It is useful in scenarios where you need to verify the equality of a record's key against a given key. The function expects a valid record key and a key value to compare against. It is important to ensure that the provided record key is not null to avoid undefined behavior.
- **Inputs**:
    - `key`: A pointer to a constant fd_funk_rec_key_t structure representing the record key to be compared. Must not be null.
    - `_key`: An unsigned long integer representing the key value to compare against the record key.
- **Output**: Returns an integer indicating whether the record key matches the given key value (non-zero if equal, zero if not).
- **See also**: [`key_eq`](test_funk_common.c.driver.md#key_eq)  (Implementation)


