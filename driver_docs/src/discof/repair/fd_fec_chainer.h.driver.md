# Purpose
The provided C header file defines an API for managing Forward Error Correction (FEC) sets in a networked environment where data packets may arrive asynchronously and out-of-order. This API, referred to as the "FEC chainer," is designed to validate, reorder, and deliver FEC sets in the correct sequence to the calling application. The chainer handles the complexities of network transmission, such as forks and equivocation, by organizing FEC sets into a tree-like structure backed by maps that categorize elements as non-leaves, leaves, or orphans. The chainer uses a unique keying scheme to identify FEC sets, allowing for efficient querying and management of the data.

The file includes several components that facilitate the chainer's functionality, such as structures for FEC elements, maps for ancestry, frontier, and orphaned FEC sets, and mechanisms for handling parent-child relationships between FEC sets. It also provides functions for initializing, querying, and inserting FEC sets into the chainer, ensuring that the data is processed and delivered in order. The chainer is designed to be robust against protocol violations like equivocation, although it relies on the consensus module to handle such anomalies fully. This header file is intended to be included in other C files, providing a public API for managing FEC sets in distributed systems.
# Imports and Dependencies

---
- `../../ballet/shred/fd_shred.h`
- `../../util/tmpl/fd_pool.c`
- `../../util/tmpl/fd_map_chain.c`
- `../../util/tmpl/fd_map_dynamic.c`
- `../../util/tmpl/fd_set.c`
- `../../util/tmpl/fd_deque_dynamic.c`


# Global Variables

---
### fd\_fec\_chainer\_new
- **Type**: `function pointer`
- **Description**: `fd_fec_chainer_new` is a function that initializes a memory region for use as a Forward Error Correction (FEC) chainer. It takes a pointer to shared memory, a maximum number of FEC elements, and a seed value as parameters.
- **Use**: This function is used to set up a memory region to be used by the FEC chainer for managing and processing FEC sets.


---
### fd\_fec\_chainer\_join
- **Type**: `fd_fec_chainer_t *`
- **Description**: The `fd_fec_chainer_join` is a function that returns a pointer to an `fd_fec_chainer_t` structure. This function is used to join the caller to an FEC chainer, which is a data structure designed to manage Forward Error Correction (FEC) sets received asynchronously and out-of-order over a network.
- **Use**: This function is used to obtain a local pointer to an FEC chainer, allowing the caller to interact with the chainer for operations such as inserting and querying FEC sets.


---
### fd\_fec\_chainer\_leave
- **Type**: `function pointer`
- **Description**: `fd_fec_chainer_leave` is a function that allows a caller to leave a current local join to a Forward Error Correction (FEC) chainer. It takes a pointer to an `fd_fec_chainer_t` structure as its parameter and returns a pointer to the underlying shared memory region on success, or NULL on failure.
- **Use**: This function is used to safely disconnect from an FEC chainer, ensuring that resources are properly released and the shared memory region is returned to the caller.


---
### fd\_fec\_chainer\_delete
- **Type**: `function pointer`
- **Description**: `fd_fec_chainer_delete` is a function that unformats a memory region used as a chainer, assuming no one is currently joined to the region. It returns a pointer to the underlying shared memory region or NULL if the operation is used in error, such as when the input is not a valid chainer.
- **Use**: This function is used to delete a chainer, transferring ownership of the memory region back to the caller.


---
### fd\_fec\_chainer\_init
- **Type**: `fd_fec_ele_t *`
- **Description**: The `fd_fec_chainer_init` function initializes a Forward Error Correction (FEC) chainer element for a given slot and Merkle root. It returns a pointer to an `fd_fec_ele_t` structure, which represents an element in the FEC chainer tree structure.
- **Use**: This function is used to set up an FEC chainer element, preparing it for further operations such as insertion and querying within the FEC chainer system.


---
### fd\_fec\_chainer\_insert
- **Type**: `fd_fec_ele_t *`
- **Description**: The `fd_fec_chainer_insert` function is a global function that inserts a new Forward Error Correction (FEC) set into a chainer structure. It takes several parameters including the chainer, slot, fec_set_idx, data count, completion flags, parent offset, and Merkle roots. The function returns a pointer to the newly inserted FEC element or NULL in case of an error.
- **Use**: This function is used to add a new FEC set to the chainer, potentially making one or more FEC sets ready for in-order delivery.


# Data Structures

---
### fd\_fec\_chainer\_t
- **Type**: `struct`
- **Members**:
    - `ancestry`: A map of key to FEC elements representing non-leaves of the FEC tree.
    - `frontier`: A map of key to FEC elements representing the leaves of the FEC tree.
    - `orphaned`: A map of key to FEC elements that are not yet inserted into the tree.
    - `pool`: A pool of FEC nodes backing the maps and tree structure.
    - `parents`: A map of key to parent key for fast O(1) querying of parent FEC sets.
    - `children`: A map of slot to child offsets for fast O(1) querying of child FEC sets.
    - `queue`: A queue of FEC keys used for breadth-first search chaining.
    - `out`: A queue of FEC keys ready to be delivered to the application.
- **Description**: The `fd_fec_chainer_t` structure is designed to manage and process Forward Error Correction (FEC) sets received asynchronously and out-of-order over a network. It organizes FEC sets into a tree-like structure using three maps: ancestry, frontier, and orphaned, to track non-leaves, leaves, and unconnected FEC sets, respectively. The chainer ensures that FEC sets are validated, reordered, and delivered in order to the application. It handles keying of FEC sets using a combination of slot and fec_set_idx, and manages forks and equivocation scenarios. The structure includes mechanisms for querying, inserting, and chaining FEC sets efficiently, leveraging maps and queues for fast operations.


---
### fd\_fec\_ele
- **Type**: `struct`
- **Members**:
    - `key`: A unique map key for identifying the FEC element.
    - `next`: Reserved for use by fd_pool and fd_map_chain for linking elements.
    - `slot`: Represents the slot number associated with the FEC element.
    - `fec_set_idx`: Index of the FEC set within the slot.
    - `data_cnt`: Count of data elements in the FEC set.
    - `data_complete`: Flag indicating if the data in the FEC set is complete.
    - `slot_complete`: Flag indicating if the slot is complete.
    - `parent_off`: Offset to the parent FEC set.
    - `merkle_root`: Merkle root hash of the FEC set.
    - `chained_merkle_root`: Chained Merkle root hash for validation.
- **Description**: The `fd_fec_ele` structure is a fundamental component of the FEC chainer system, designed to manage and organize Forward Error Correction (FEC) sets as they are received asynchronously over a network. Each `fd_fec_ele` instance represents an individual FEC set, uniquely identified by a combination of slot and fec_set_idx, and contains metadata such as data count, completion flags, and Merkle root hashes for integrity verification. The structure facilitates the chaining and validation of FEC sets, ensuring they are processed in the correct order and allowing for efficient querying and management within the chainer's tree-like architecture.


---
### fd\_fec\_ele\_t
- **Type**: `struct`
- **Members**:
    - `key`: A unique map key for the FEC element.
    - `next`: Reserved for use by fd_pool and fd_map_chain.
    - `slot`: The slot number associated with the FEC set.
    - `fec_set_idx`: Index of the FEC set within the slot.
    - `data_cnt`: Count of data shreds in the FEC set.
    - `data_complete`: Indicates if the data in the FEC set is complete.
    - `slot_complete`: Indicates if the slot is complete.
    - `parent_off`: Offset to the parent FEC set.
    - `merkle_root`: Merkle root of the FEC set.
    - `chained_merkle_root`: Chained Merkle root for validation.
- **Description**: The `fd_fec_ele_t` structure represents an element in the FEC chainer, which is used to manage Forward Error Correction (FEC) sets in a networked environment. Each element contains metadata such as a unique key, slot information, and indices to manage its position within the FEC chain. It also includes fields for Merkle root validation to ensure data integrity and fields to track the completion status of data and slots. This structure is integral to the FEC chainer's ability to reorder and validate FEC sets as they are received asynchronously.


---
### fd\_fec\_parent
- **Type**: `struct`
- **Members**:
    - `key`: Represents the unique identifier for the FEC set.
    - `parent_key`: Represents the unique identifier for the parent FEC set.
- **Description**: The `fd_fec_parent` structure is used to map a Forward Error Correction (FEC) set to its immediate predecessor in a sequence of FEC sets. This mapping is crucial for maintaining the order and hierarchy of FEC sets as they are processed asynchronously and potentially out-of-order over a network. The `key` field uniquely identifies an FEC set, while the `parent_key` field identifies its parent, allowing the system to trace the lineage of FEC sets and manage their dependencies effectively.


---
### fd\_fec\_parent\_t
- **Type**: `struct`
- **Members**:
    - `key`: Represents the unique identifier for the FEC parent.
    - `parent_key`: Stores the key of the parent FEC set for quick access.
- **Description**: The `fd_fec_parent_t` structure is used to represent a parent FEC (Forward Error Correction) set in a network communication context. It contains two members: `key`, which uniquely identifies the FEC parent, and `parent_key`, which provides a quick reference to the parent FEC set's key. This structure is part of a larger system designed to manage and chain FEC sets, ensuring they are processed in the correct order despite being received out-of-order over a network.


---
### fd\_fec\_children
- **Type**: `struct`
- **Members**:
    - `slot`: Represents the slot number associated with the FEC children.
    - `child_offs`: An array of offsets indicating the positions of child FEC sets within the slot.
- **Description**: The `fd_fec_children` structure is designed to manage and track the children of a Forward Error Correction (FEC) set within a specific slot. It contains a slot identifier and an array of offsets that point to the positions of child FEC sets, allowing for efficient querying and management of FEC relationships across different slots. This structure is part of a larger system that handles the chaining and ordering of FEC sets received asynchronously over a network.


---
### fd\_fec\_children\_t
- **Type**: `struct`
- **Members**:
    - `slot`: Represents the slot number associated with the FEC children.
    - `child_offs`: An array of offsets indicating the positions of child FEC sets within the slot.
- **Description**: The `fd_fec_children_t` structure is designed to manage and track the children of a Forward Error Correction (FEC) set within a specific slot. It contains a slot identifier and an array of offsets that point to the positions of child FEC sets, allowing for efficient querying and management of FEC relationships in a networked environment. This structure is part of a larger system that handles the chaining and validation of FEC sets received asynchronously over a network.


---
### fd\_fec\_out
- **Type**: `struct`
- **Members**:
    - `slot`: Represents the slot number associated with the FEC set.
    - `parent_off`: Indicates the offset to the parent slot.
    - `fec_set_idx`: Specifies the index of the FEC set within the slot.
    - `data_cnt`: Counts the number of data elements in the FEC set.
    - `data_complete`: Flag indicating if the data in the FEC set is complete.
    - `slot_complete`: Flag indicating if the slot is complete.
    - `err`: Stores error codes related to the FEC set processing.
- **Description**: The `fd_fec_out` structure is used to represent an output FEC (Forward Error Correction) set in a network communication context. It contains fields that track the slot and index of the FEC set, the number of data elements it contains, and flags indicating the completion status of the data and slot. Additionally, it includes an error field to capture any issues encountered during processing. This structure is part of a larger system designed to handle FEC sets received asynchronously and out-of-order, ensuring they are validated, reordered, and delivered in sequence to the application.


---
### fd\_fec\_out\_t
- **Type**: `struct`
- **Members**:
    - `slot`: Represents the slot number associated with the FEC set.
    - `parent_off`: Indicates the offset to the parent FEC set.
    - `fec_set_idx`: Index of the FEC set within the slot.
    - `data_cnt`: Number of data elements in the FEC set.
    - `data_complete`: Flag indicating if the data in the FEC set is complete.
    - `slot_complete`: Flag indicating if the slot is complete.
    - `err`: Error code associated with the FEC set processing.
- **Description**: The `fd_fec_out_t` structure is used to represent an output FEC (Forward Error Correction) set in the FEC chainer system. It contains information about the slot and index of the FEC set, as well as flags indicating the completeness of the data and slot. Additionally, it includes an error code to capture any issues encountered during processing. This structure is part of a queue that delivers FEC sets to the application in the correct order.


---
### fd\_fec\_chainer
- **Type**: `struct`
- **Members**:
    - `ancestry`: Map of key to FEC for non-leaves of the FEC tree.
    - `frontier`: Map of key to FEC for leaves of the FEC tree.
    - `orphaned`: Map of key to FEC for FECs not yet inserted into the tree.
    - `pool`: Pool of FEC nodes backing the maps and tree.
    - `parents`: Map of key to parent key for fast O(1) querying.
    - `children`: Map of slot to child offsets for fast O(1) querying.
    - `queue`: Queue of FEC keys for BFS chaining.
    - `out`: Queue of FEC keys to deliver to the application.
- **Description**: The `fd_fec_chainer` is a complex data structure designed to manage Forward Error Correction (FEC) sets received asynchronously and out-of-order over a network. It organizes FEC sets into a tree-like structure using maps for ancestry, frontier, and orphaned FECs, allowing for efficient validation, reordering, and delivery of these sets in order. The structure supports fast querying and insertion operations, handling forks and equivocation scenarios, and is optimized for chaining FEC sets through breadth-first search (BFS) operations.


# Functions

---
### fd\_fec\_chainer\_align<!-- {{#callable:fd_fec_chainer_align}} -->
The `fd_fec_chainer_align` function returns the required memory alignment for a `fd_fec_chainer_t` structure.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended to be used within the same translation unit and may be inlined by the compiler for performance.
    - It uses the `alignof` operator to determine the alignment requirement of the `fd_fec_chainer_t` type.
    - The function returns this alignment value as an unsigned long integer.
- **Output**: The function returns an unsigned long integer representing the alignment requirement for a `fd_fec_chainer_t` structure.


---
### fd\_fec\_chainer\_footprint<!-- {{#callable:fd_fec_chainer_footprint}} -->
The `fd_fec_chainer_footprint` function calculates the memory footprint required for a FEC chainer structure based on the maximum number of FEC elements.
- **Inputs**:
    - `fec_max`: The maximum number of FEC elements that the chainer is expected to handle.
- **Control Flow**:
    - Calculate the smallest power of two greater than or equal to `fec_max` using `fd_ulong_pow2_up` and find its most significant bit using `fd_ulong_find_msb`, storing the result in `lg_fec_max`.
    - Initialize the layout with `FD_LAYOUT_INIT` and append the alignment and size of `fd_fec_chainer_t`.
    - Append the alignment and footprint of various components (ancestry, frontier, orphaned, pool, parents, children, queue, out) using `FD_LAYOUT_APPEND`, each with their respective alignment and footprint functions, some of which depend on `fec_max` and others on `lg_fec_max`.
    - Finalize the layout with `FD_LAYOUT_FINI` to compute the total footprint.
- **Output**: The function returns an `ulong` representing the total memory footprint required for the FEC chainer structure.
- **Functions called**:
    - [`fd_fec_chainer_align`](#fd_fec_chainer_align)


# Function Declarations (Public API)

---
### fd\_fec\_chainer\_new<!-- {{#callable_declaration:fd_fec_chainer_new}} -->
Initialize a memory region for use as an FEC chainer.
- **Description**: This function prepares a specified memory region to be used as an FEC chainer, which is responsible for managing and ordering FEC sets received asynchronously over a network. It should be called with a valid memory region that is properly aligned and has sufficient footprint to accommodate the specified maximum number of FEC elements. The function returns a pointer to the initialized memory region if successful, or NULL if any preconditions are not met, such as a NULL memory pointer, misalignment, or an invalid maximum FEC count.
- **Inputs**:
    - `shmem`: A pointer to the memory region to be initialized. Must not be NULL and must be aligned according to fd_fec_chainer_align(). The caller retains ownership.
    - `fec_max`: The maximum number of FEC elements the chainer will manage. Must be a valid positive number; otherwise, the function returns NULL.
    - `seed`: A seed value used for initializing internal structures. Any ulong value is acceptable.
- **Output**: Returns a pointer to the initialized memory region on success, or NULL if initialization fails due to invalid input or preconditions.
- **See also**: [`fd_fec_chainer_new`](fd_fec_chainer.c.driver.md#fd_fec_chainer_new)  (Implementation)


---
### fd\_fec\_chainer\_join<!-- {{#callable_declaration:fd_fec_chainer_join}} -->
Joins the caller to an FEC chainer.
- **Description**: This function is used to join a caller to an existing FEC chainer, which is a structure designed to manage and reorder Forward Error Correction (FEC) sets received out-of-order over a network. It should be called with a valid pointer to the memory region backing the chainer. The function returns a pointer to the chainer in the local address space if successful. If the input is null, the function logs a warning and returns null. This function is typically used after the chainer has been initialized and before any operations are performed on it.
- **Inputs**:
    - `shfec_chainer`: A pointer to the memory region backing the FEC chainer. Must not be null. If null, the function logs a warning and returns null.
- **Output**: Returns a pointer to the FEC chainer in the local address space on success, or null if the input is invalid.
- **See also**: [`fd_fec_chainer_join`](fd_fec_chainer.c.driver.md#fd_fec_chainer_join)  (Implementation)


---
### fd\_fec\_chainer\_leave<!-- {{#callable_declaration:fd_fec_chainer_leave}} -->
Leaves a current local join to a FEC chainer.
- **Description**: This function is used to leave a current local join to a FEC chainer, effectively ending the caller's association with the chainer. It should be called when the caller no longer needs to interact with the chainer, allowing for cleanup or reallocation of resources. The function must be called with a valid, non-null pointer to a `fd_fec_chainer_t` structure. If the provided pointer is null, the function logs a warning and returns null, indicating failure.
- **Inputs**:
    - `chainer`: A pointer to a `fd_fec_chainer_t` structure representing the chainer to leave. Must not be null. If null, the function logs a warning and returns null.
- **Output**: Returns a pointer to the underlying shared memory region on success, or null if the input is invalid.
- **See also**: [`fd_fec_chainer_leave`](fd_fec_chainer.c.driver.md#fd_fec_chainer_leave)  (Implementation)


---
### fd\_fec\_chainer\_delete<!-- {{#callable_declaration:fd_fec_chainer_delete}} -->
Unformats a memory region used as a chainer.
- **Description**: This function is used to unformat a memory region that was previously formatted for use as a chainer. It should be called when the chainer is no longer needed, and it is assumed that no other processes are joined to the chainer at the time of the call. The function returns a pointer to the underlying shared memory region, transferring ownership of this memory back to the caller. If the provided pointer is not a valid chainer, the function logs a warning and returns NULL.
- **Inputs**:
    - `shchainer`: A pointer to the memory region used as a chainer. It must be aligned according to the chainer's alignment requirements and must not be NULL. If the pointer is NULL or misaligned, the function logs a warning and returns NULL.
- **Output**: Returns a pointer to the underlying shared memory region if successful, or NULL if the input is invalid.
- **See also**: [`fd_fec_chainer_delete`](fd_fec_chainer.c.driver.md#fd_fec_chainer_delete)  (Implementation)


---
### fd\_fec\_chainer\_init<!-- {{#callable_declaration:fd_fec_chainer_init}} -->
Initializes a new FEC element in the chainer for a given slot.
- **Description**: This function initializes a new FEC element in the provided chainer for the specified slot, setting up the necessary parent-child relationships and inserting the element into the chainer's frontier. It should be called when a new slot is being started in the FEC chainer. The function assumes that the chainer has been properly initialized and that the slot number and Merkle root are valid. It returns a pointer to the newly created FEC element, which can be used for further operations.
- **Inputs**:
    - `chainer`: A pointer to an fd_fec_chainer_t structure. This must be a valid, initialized chainer object. The caller retains ownership.
    - `slot`: An unsigned long integer representing the slot number for which the FEC element is being initialized. It must be a valid slot number.
    - `merkle_root`: An array of unsigned characters with a size of at least FD_SHRED_MERKLE_ROOT_SZ. It represents the Merkle root for the slot and must not be null.
- **Output**: Returns a pointer to the newly initialized fd_fec_ele_t structure representing the FEC element for the specified slot.
- **See also**: [`fd_fec_chainer_init`](fd_fec_chainer.c.driver.md#fd_fec_chainer_init)  (Implementation)


---
### fd\_fec\_chainer\_insert<!-- {{#callable_declaration:fd_fec_chainer_insert}} -->
Inserts a new FEC set into the chainer.
- **Description**: This function is used to insert a new Forward Error Correction (FEC) set into the chainer, which manages and organizes FEC sets received asynchronously and out-of-order. It ensures that the FEC set is unique and properly chains it with its parent and potential children. The function should be called when a new FEC set is available for processing. It returns a pointer to the newly inserted FEC element or NULL if an error occurs, such as a uniqueness conflict. The caller can then check the chainer's output queue for any FEC sets that are ready for in-order delivery.
- **Inputs**:
    - `chainer`: A pointer to an fd_fec_chainer_t structure representing the chainer. Must not be null.
    - `slot`: An unsigned long representing the slot number of the FEC set. It is part of the unique key for the FEC set.
    - `fec_set_idx`: An unsigned integer representing the index of the FEC set within the slot. It is part of the unique key for the FEC set.
    - `data_cnt`: An unsigned short indicating the number of data elements in the FEC set. Must be a valid count of data elements.
    - `data_complete`: An integer flag indicating whether the data in the FEC set is complete. Non-zero for complete, zero otherwise.
    - `slot_complete`: An integer flag indicating whether the slot is complete. Non-zero for complete, zero otherwise.
    - `parent_off`: An unsigned short representing the offset to the parent slot. Used to derive the parent key.
    - `merkle_root`: A constant array of unsigned chars representing the Merkle root of the FEC set. Must have a size of FD_SHRED_MERKLE_ROOT_SZ.
    - `chained_merkle_root`: A constant array of unsigned chars representing the chained Merkle root. Must have a size of FD_SHRED_MERKLE_ROOT_SZ.
- **Output**: Returns a pointer to the newly inserted fd_fec_ele_t on success, or NULL on error (e.g., uniqueness conflict).
- **See also**: [`fd_fec_chainer_insert`](fd_fec_chainer.c.driver.md#fd_fec_chainer_insert)  (Implementation)


