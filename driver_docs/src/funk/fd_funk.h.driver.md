# Purpose
The provided C header file defines the structure and functionality of a system called "Funk," which is a hybrid between a database and a version control system, specifically designed for high-performance blockchain applications. The primary purpose of Funk is to manage a flat table of records, where each record is a transaction ID (xid) and key-value pair. The system is optimized for fast O(1) indexing and operations, making it suitable for environments where performance and concurrency are critical, such as blockchain applications. Funk supports complex transaction models, allowing for the creation, updating, and deletion of records within transactions, and it maintains a history of all database records up to any given transaction. This history is represented as a tree of transactions, which is particularly useful in blockchain scenarios where multiple speculative transaction paths may exist before consensus is reached.

The file outlines the technical components and operations of Funk, including memory management, transaction handling, and record operations. It provides a detailed description of the data structures used, such as `fd_funk_shmem_private` and `fd_funk_private`, which manage shared memory and transaction/record maps. The header file also defines several functions for creating, joining, and managing Funk instances, as well as accessing and manipulating records and transactions. The system is designed to be highly concurrent, with thread-safe operations for record management, while transaction-level operations require single-threaded access. Additionally, Funk is built to be persistent and relocatable, allowing for seamless process restarts and remote inspections. The file serves as a comprehensive guide for developers to understand and utilize the Funk system in their applications, providing both the API and the underlying implementation details necessary for integration and optimization.
# Imports and Dependencies

---
- `fd_funk_val.h`


# Global Variables

---
### fd\_funk\_new
- **Type**: `function`
- **Description**: The `fd_funk_new` function is a constructor for creating a new instance of a 'funk', which is a hybrid database and version control system designed for high-performance blockchain applications. It initializes a shared memory region for the funk, setting up the necessary metadata and structures to manage transactions and records. The function takes parameters for shared memory, workspace tag, seed for hashing, and maximum numbers of transactions and records.
- **Use**: This function is used to initialize and allocate resources for a new funk instance, setting up its environment for managing transactions and records.


---
### fd\_funk\_join
- **Type**: `fd_funk_t *`
- **Description**: The `fd_funk_join` function returns a pointer to a `fd_funk_t` structure, which represents a local join to a funk instance. This function is used to connect a caller to a funk instance, allowing the caller to interact with the funk's data and operations.
- **Use**: This variable is used to manage and access a funk instance, enabling operations on the database and version control system designed for high-performance blockchain applications.


---
### fd\_funk\_leave
- **Type**: `function pointer`
- **Description**: The `fd_funk_leave` function is a global function that facilitates leaving a join on a funk instance. It takes a pointer to a `fd_funk_t` structure and an optional pointer to a pointer for the shared memory region backing the funk.
- **Use**: This function is used to properly leave a funk join, ensuring that resources are released and the caller is no longer associated with the funk instance.


---
### fd\_funk\_delete
- **Type**: `function pointer`
- **Description**: `fd_funk_delete` is a function pointer that points to a function designed to unformat a workspace allocation used as a funk, freeing all workspace allocations associated with that funk. It assumes that no one is or will be joined to the funk during its execution.
- **Use**: This function is used to clean up and release resources associated with a funk instance, ensuring that the workspace memory is properly freed.


# Data Structures

---
### fd\_funk\_shmem\_private
- **Type**: `struct`
- **Members**:
    - `magic`: A magic number used to verify the integrity of the structure, expected to be equal to FD_FUNK_MAGIC.
    - `funk_gaddr`: The workspace global address of this structure in the backing workspace, must be non-zero.
    - `wksp_tag`: A positive tag used for workspace allocations.
    - `seed`: An arbitrary seed used for various hashing functions.
    - `cycle_tag`: The next cycle tag to use, utilized internally for data integrity checks.
    - `txn_max`: The maximum number of transactions that can be in preparation, constrained by FD_FUNK_TXN_IDX_NULL.
    - `txn_map_gaddr`: The workspace global address of the transaction map used by this funk, must be non-zero.
    - `txn_pool_gaddr`: The workspace global address of the transaction pool.
    - `txn_ele_gaddr`: The workspace global address of the transaction elements.
    - `child_head_cidx`: Compressed index of the oldest child transaction, or FD_FUNK_TXN_IDX_NULL if there are no children.
    - `child_tail_cidx`: Compressed index of the youngest child transaction, or FD_FUNK_TXN_IDX_NULL if there are no children.
    - `root`: An array containing the transaction ID of the root transaction.
    - `last_publish`: An array containing the transaction ID of the last published transaction.
    - `rec_max`: The maximum number of records that can exist in this funk.
    - `rec_map_gaddr`: The workspace global address of the record map used by this funk, must be non-zero.
    - `rec_pool_gaddr`: The workspace global address of the record pool.
    - `rec_ele_gaddr`: The workspace global address of the record elements.
    - `rec_head_idx`: Index of the first record in the record map, or FD_FUNK_REC_IDX_NULL if none.
    - `rec_tail_idx`: Index of the last record in the record map, or FD_FUNK_REC_IDX_NULL if none.
    - `alloc_gaddr`: The workspace global address of the allocator used for record values, must be non-zero.
    - `lock`: A lock used for synchronizing modifications to the funk object.
- **Description**: The `fd_funk_shmem_private` structure is a core component of the Funk system, which is a hybrid database and version control system designed for high-performance blockchain applications. This structure manages metadata and maps for transactions and records, facilitating the preparation and publication of transactions. It includes fields for managing transaction and record limits, workspace addresses, and synchronization locks. The structure supports complex transaction trees and is optimized for concurrent access and memory efficiency, making it suitable for blockchain environments where speculative work on multiple transaction histories is common.


---
### fd\_funk\_private
- **Type**: `struct`
- **Members**:
    - `shmem`: A pointer to shared memory associated with the funk instance.
    - `txn_map`: An array of transaction maps, each representing a single transaction.
    - `txn_pool`: An array of transaction pools, each managing a pool of transactions.
    - `rec_map`: An array of record maps, each representing a single record.
    - `rec_pool`: An array of record pools, each managing a pool of records.
    - `wksp`: A pointer to the workspace used by the funk instance.
    - `alloc`: A pointer to the allocator used for dynamic memory allocation within the funk instance.
- **Description**: The `fd_funk_private` structure is a core component of the Funk system, which is a hybrid database and version control system designed for high-performance blockchain applications. This structure encapsulates the essential elements required to manage transactions and records within the Funk system, including pointers to shared memory, transaction maps and pools, record maps and pools, and workspace and allocator references. It is aligned to `FD_FUNK_JOIN_ALIGN` to ensure optimal memory access patterns. The structure facilitates the management of transactions and records, allowing for efficient indexing and manipulation of data in a concurrent, multi-threaded environment.


# Functions

---
### fd\_funk\_wksp<!-- {{#callable:fd_funk_wksp}} -->
The `fd_funk_wksp` function returns the workspace associated with a given funk instance.
- **Inputs**:
    - `funk`: A pointer to a constant `fd_funk_t` structure representing the funk instance whose workspace is to be retrieved.
- **Control Flow**:
    - The function takes a single input, a pointer to a constant `fd_funk_t` structure.
    - It accesses the `wksp` member of the `fd_funk_t` structure pointed to by `funk`.
    - The function returns the value of the `wksp` member, which is a pointer to the workspace associated with the funk instance.
- **Output**: A pointer to the `fd_wksp_t` structure representing the workspace associated with the given funk instance.


---
### fd\_funk\_wksp\_tag<!-- {{#callable:fd_funk_wksp_tag}} -->
The `fd_funk_wksp_tag` function retrieves the workspace allocation tag used by a `fd_funk_t` instance for its workspace allocations.
- **Inputs**:
    - `funk`: A pointer to an `fd_funk_t` structure, representing a current local join to a funk instance.
- **Control Flow**:
    - Access the `shmem` member of the `fd_funk_t` structure pointed to by `funk`.
    - Return the `wksp_tag` member of the `fd_funk_shmem_private` structure, which is pointed to by the `shmem` member.
- **Output**: Returns an `ulong` representing the workspace allocation tag, which is a positive value.


---
### fd\_funk\_seed<!-- {{#callable:fd_funk_seed}} -->
The `fd_funk_seed` function retrieves the hash seed used by a funk instance for various hashing operations.
- **Inputs**:
    - `funk`: A pointer to an `fd_funk_t` structure, representing a funk instance that is currently joined.
- **Control Flow**:
    - The function accesses the `shmem` member of the `fd_funk_t` structure pointed to by `funk`.
    - It then retrieves the `seed` value from the `shmem` structure, which is used for hashing functions.
- **Output**: The function returns an `ulong` representing the hash seed of the funk instance.


---
### fd\_funk\_txn\_max<!-- {{#callable:fd_funk_txn_max}} -->
The `fd_funk_txn_max` function returns the maximum number of transactions that can be in preparation for a given `fd_funk_t` instance.
- **Inputs**:
    - `funk`: A pointer to an `fd_funk_t` structure, representing the funk instance for which the maximum number of in-preparation transactions is queried.
- **Control Flow**:
    - The function accesses the `txn_pool` member of the `fd_funk_t` structure pointed to by `funk`.
    - It retrieves the `ele_max` member from the `txn_pool`, which represents the maximum number of transactions that can be in preparation.
- **Output**: The function returns an `ulong` value representing the maximum number of transactions that can be in preparation for the given funk instance.


---
### fd\_funk\_root<!-- {{#callable:fd_funk_root}} -->
The `fd_funk_root` function returns a pointer to the transaction ID of the root transaction in a `fd_funk_t` instance.
- **Inputs**:
    - `funk`: A pointer to a `fd_funk_t` structure, representing the current local join of a funk instance.
- **Control Flow**:
    - The function accesses the `shmem` member of the `fd_funk_t` structure pointed to by `funk`.
    - It retrieves the `root` member from the `shmem` structure, which is an array containing the transaction ID of the root transaction.
    - The function returns a pointer to this `root` transaction ID.
- **Output**: A constant pointer to `fd_funk_txn_xid_t`, representing the transaction ID of the root transaction.


---
### fd\_funk\_last\_publish<!-- {{#callable:fd_funk_last_publish}} -->
The `fd_funk_last_publish` function returns a pointer to the transaction ID of the last published transaction in a `fd_funk_t` instance.
- **Inputs**:
    - `funk`: A pointer to a `fd_funk_t` structure, representing the current local join of a funk instance.
- **Control Flow**:
    - The function accesses the `last_publish` field of the `shmem` member within the `fd_funk_t` structure pointed to by `funk`.
    - It returns the address of the `last_publish` field, which contains the transaction ID of the last published transaction.
- **Output**: A constant pointer to `fd_funk_txn_xid_t`, representing the transaction ID of the last published transaction.


---
### fd\_funk\_last\_publish\_is\_frozen<!-- {{#callable:fd_funk_last_publish_is_frozen}} -->
The function `fd_funk_last_publish_is_frozen` checks if the last published transaction in a funk instance is frozen, indicating it has child transactions.
- **Inputs**:
    - `funk`: A pointer to a constant `fd_funk_t` structure representing the funk instance to be checked.
- **Control Flow**:
    - The function retrieves the compressed transaction index of the head child transaction from the `funk` structure's shared memory.
    - It checks if this index is not equal to `FD_FUNK_TXN_IDX_NULL`, which would indicate that there are child transactions present.
    - If the index is not null, the function returns 1, indicating the last published transaction is frozen; otherwise, it returns 0.
- **Output**: The function returns an integer: 1 if the last published transaction is frozen (has children), and 0 if it is not frozen (childless).
- **Functions called**:
    - [`fd_funk_txn_idx`](fd_funk_txn.h.driver.md#fd_funk_txn_idx)


---
### fd\_funk\_rec\_max<!-- {{#callable:fd_funk_rec_max}} -->
The `fd_funk_rec_max` function returns the maximum number of records that can be held in a given `fd_funk_t` instance.
- **Inputs**:
    - `funk`: A pointer to an `fd_funk_t` structure, representing the funk instance whose record capacity is being queried.
- **Control Flow**:
    - The function accesses the `rec_pool` member of the `fd_funk_t` structure pointed to by `funk`.
    - It retrieves the `ele_max` field from the `rec_pool`, which indicates the maximum number of records that can be stored.
- **Output**: The function returns an `ulong` representing the maximum number of records that the funk instance can hold.


---
### fd\_funk\_alloc<!-- {{#callable:fd_funk_alloc}} -->
The `fd_funk_alloc` function returns a pointer to the allocator used by a given `fd_funk_t` instance.
- **Inputs**:
    - `funk`: A pointer to an `fd_funk_t` structure, representing a local join to a funk instance.
- **Control Flow**:
    - The function is a simple inline function that directly accesses the `alloc` member of the `fd_funk_t` structure pointed to by `funk`.
    - It returns the value of `funk->alloc`, which is a pointer to the `fd_alloc_t` allocator associated with the funk instance.
- **Output**: A pointer to the `fd_alloc_t` allocator used by the specified funk instance.


---
### fd\_funk\_rec\_is\_full<!-- {{#callable:fd_funk_rec_is_full}} -->
The `fd_funk_rec_is_full` function checks if the record pool in a funk instance is empty, indicating that no more records can be allocated.
- **Inputs**:
    - `funk`: A pointer to an `fd_funk_t` structure representing the funk instance whose record pool is being checked.
- **Control Flow**:
    - The function calls `fd_funk_rec_pool_is_empty` with the `rec_pool` member of the `funk` structure.
    - It returns the result of the `fd_funk_rec_pool_is_empty` function call, which is an integer indicating whether the record pool is empty.
- **Output**: An integer value: 1 if the record pool is empty (indicating no more records can be allocated), and 0 otherwise.


---
### fd\_funk\_txn\_is\_full<!-- {{#callable:fd_funk_txn_is_full}} -->
The `fd_funk_txn_is_full` function checks if the transaction pool in a `fd_funk_t` instance is empty, indicating that no more in-preparation transactions are allowed.
- **Inputs**:
    - `funk`: A pointer to an `fd_funk_t` structure, representing the funk instance whose transaction pool is being checked.
- **Control Flow**:
    - The function calls `fd_funk_txn_pool_is_empty` with the `txn_pool` member of the `funk` structure.
    - It returns the result of `fd_funk_txn_pool_is_empty`, which is a boolean indicating if the transaction pool is empty.
- **Output**: An integer value, where 1 indicates the transaction pool is full (no more transactions can be prepared) and 0 indicates it is not full.


# Function Declarations (Public API)

---
### fd\_funk\_align<!-- {{#callable_declaration:fd_funk_align}} -->
Return the alignment requirement for a funk instance.
- **Description**: This function provides the alignment requirement for a funk instance, which is necessary for ensuring that memory allocations for funk instances are correctly aligned. This is important for performance and correctness, especially in systems with specific alignment constraints. The alignment value is a constant and should be used whenever allocating memory for a funk instance to ensure proper alignment.
- **Inputs**: None
- **Output**: Returns the alignment requirement as an unsigned long integer, which is a power of 2.
- **See also**: [`fd_funk_align`](fd_funk.c.driver.md#fd_funk_align)  (Implementation)


---
### fd\_funk\_footprint<!-- {{#callable_declaration:fd_funk_footprint}} -->
Calculate the memory footprint required for a funk instance.
- **Description**: Use this function to determine the amount of memory needed to store a funk instance and its auxiliary data structures, based on the maximum number of transactions and records. This is useful for allocating sufficient workspace memory before initializing a funk instance. The function returns zero if the maximum number of records exceeds the allowable limit, indicating an invalid configuration.
- **Inputs**:
    - `txn_max`: The maximum number of transactions that can be in preparation. Must be a non-negative integer.
    - `rec_max`: The maximum number of records that can be held. Must be a non-negative integer and not exceed UINT_MAX. If rec_max exceeds UINT_MAX, the function returns zero.
- **Output**: Returns the total memory footprint in bytes required for the specified configuration, or zero if the configuration is invalid.
- **See also**: [`fd_funk_footprint`](fd_funk.c.driver.md#fd_funk_footprint)  (Implementation)


---
### fd\_funk\_new<!-- {{#callable_declaration:fd_funk_new}} -->
Creates a new funk instance in shared memory.
- **Description**: This function initializes a new funk instance within a specified shared memory region, which must be part of a workspace. It is designed for high-performance blockchain applications, providing a hybrid database and version control system. The function requires a valid workspace tag and ensures that the shared memory is properly aligned and part of a workspace. It sets up the maximum number of transactions and records that the funk can handle, based on the provided parameters. The function returns a pointer to the initialized funk instance on success or NULL if any preconditions are not met, such as invalid alignment, null pointers, or exceeding maximum limits for transactions or records.
- **Inputs**:
    - `shmem`: Pointer to the shared memory region where the funk will be created. Must not be null and must be aligned according to fd_funk_align(). The memory must be part of a workspace.
    - `wksp_tag`: A positive ulong value used to tag workspace allocations. Must not be zero.
    - `seed`: An arbitrary ulong value used as a seed for hashing functions within the funk.
    - `txn_max`: The maximum number of transactions that can be in preparation. Must be less than or equal to FD_FUNK_TXN_IDX_NULL.
    - `rec_max`: The maximum number of records that the funk can hold. Must be less than or equal to UINT_MAX.
- **Output**: Returns a pointer to the initialized funk instance on success, or NULL if any input validation fails.
- **See also**: [`fd_funk_new`](fd_funk.c.driver.md#fd_funk_new)  (Implementation)


---
### fd\_funk\_join<!-- {{#callable_declaration:fd_funk_join}} -->
Joins the caller to a funk instance.
- **Description**: This function is used to join a caller to a funk instance, allowing the caller to interact with the funk's data structures. It requires a local memory region for the join and a pointer to the shared memory backing the funk. The function checks for valid alignment and ensures the shared memory is part of a workspace with the correct magic number. It initializes the local join structure and sets up necessary data structures for transaction and record management. This function must be called before any operations on the funk instance and should be matched with a corresponding leave call to properly release resources.
- **Inputs**:
    - `ljoin`: A pointer to a memory region in the caller's address space where the local join will be established. Must not be null.
    - `shfunk`: A pointer to the shared memory region backing the funk. Must be aligned according to fd_funk_align() and part of a workspace. Must not be null.
- **Output**: Returns a pointer to the local join on success, or NULL on failure if any preconditions are not met, logging details of the failure.
- **See also**: [`fd_funk_join`](fd_funk.c.driver.md#fd_funk_join)  (Implementation)


---
### fd\_funk\_leave<!-- {{#callable_declaration:fd_funk_leave}} -->
Leaves a funk join and optionally retrieves the shared memory region.
- **Description**: This function is used to leave a previously established join to a funk instance, effectively ending the caller's association with the funk. It should be called when the caller no longer needs to interact with the funk, ensuring that resources are properly released. If the `opt_shfunk` parameter is provided, it will be set to point to the shared memory region backing the funk, allowing the caller to retain a reference to it. This function must be called only when the caller is currently joined to a funk instance. If the `funk` parameter is null, the function logs a warning and returns null, indicating that the operation could not be completed.
- **Inputs**:
    - `funk`: A pointer to the fd_funk_t instance representing the current join. Must not be null. If null, the function logs a warning and returns null.
    - `opt_shfunk`: An optional pointer to a void pointer where the shared memory region will be stored. If provided, it will be set to the shared memory region of the funk. If null, no shared memory region is returned.
- **Output**: Returns a pointer to the memory region used for the join on success, or null if the operation fails (e.g., if funk is null).
- **See also**: [`fd_funk_leave`](fd_funk.c.driver.md#fd_funk_leave)  (Implementation)


---
### fd\_funk\_delete<!-- {{#callable_declaration:fd_funk_delete}} -->
Unformats and deletes a funk instance from a workspace.
- **Description**: Use this function to remove a funk instance from a workspace, freeing all associated resources. It should be called when the funk is no longer needed and no threads are joined to it. The function checks for null pointers, alignment, and workspace membership, logging warnings for any issues. It returns the memory address of the funk on success or NULL on failure.
- **Inputs**:
    - `shfunk`: A pointer to the funk instance to be deleted. It must not be null, must be properly aligned, and must be part of a workspace. The caller retains ownership of the pointer.
- **Output**: Returns the pointer to the funk instance on success, or NULL if the deletion fails due to invalid input or other issues.
- **See also**: [`fd_funk_delete`](fd_funk.c.driver.md#fd_funk_delete)  (Implementation)


---
### fd\_funk\_delete\_fast<!-- {{#callable_declaration:fd_funk_delete_fast}} -->
Deletes a funk instance and frees associated workspace allocations.
- **Description**: Use this function to delete a funk instance and free all workspace allocations associated with it. This function is optimized for cases where the funk was created with a unique workspace tag, ensuring that all allocations with this tag are freed. It is important to ensure that no other allocations in the workspace share this tag, as they will also be freed. This function should be called when the funk instance is no longer needed and no other threads are joined to it.
- **Inputs**:
    - `shfunk`: A pointer to the shared memory region representing the funk instance. Must not be null, must be aligned according to fd_funk_align(), and must be part of a workspace. If these conditions are not met, warnings are logged.
- **Output**: None
- **See also**: [`fd_funk_delete_fast`](fd_funk.c.driver.md#fd_funk_delete_fast)  (Implementation)


---
### fd\_funk\_verify<!-- {{#callable_declaration:fd_funk_verify}} -->
Verifies the integrity of a funk instance.
- **Description**: Use this function to check the integrity of a funk instance, ensuring that its internal structures and metadata are consistent and valid. This function should be called when there is a need to validate the state of a funk instance, such as after initialization or before performing critical operations. It assumes that the funk instance is a current local join and will return an error if the instance is invalid or if the input is null.
- **Inputs**:
    - `join`: A pointer to a fd_funk_t structure representing the funk instance to be verified. Must not be null and should be a current local join. If null, the function returns an error.
- **Output**: Returns FD_FUNK_SUCCESS if the funk instance is valid, or FD_FUNK_ERR_INVAL if it is not.
- **See also**: [`fd_funk_verify`](fd_funk.c.driver.md#fd_funk_verify)  (Implementation)


