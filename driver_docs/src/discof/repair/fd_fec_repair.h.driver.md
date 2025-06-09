# Purpose
The provided C header file, `fd_fec_repair.h`, defines a set of APIs and data structures for managing the repair of Forward Error Correction (FEC) sets in a distributed system. This file is part of a larger system that deals with the transmission and recovery of data shreds, which are smaller units of data derived from larger blocks and entries. The primary purpose of this code is to facilitate the repair process when some shreds are missing from an FEC set, ensuring that the complete data can be reconstructed even in the presence of transmission errors or data loss.

The file introduces several key components, including structures like `fd_fec_intra_t` and `fd_fec_repair_t`, which are used to track the state of FEC sets and manage the repair process. The `fd_fec_repair_t` structure, in particular, maintains an LRU cache of outstanding block slices that require repair, using a combination of pools, maps, and doubly linked lists to efficiently manage and order these sets. The file also provides functions for creating, joining, and managing these structures, as well as querying and inserting FEC sets into the repair process. This header file is intended to be included in other parts of the system, providing a public API for FEC repair operations, and it relies on several other components from the broader system, such as `fd_disco_base.h`, `fd_reedsol.h`, and `fd_fseq.h`, to perform its functions.
# Imports and Dependencies

---
- `../../disco/fd_disco_base.h`
- `../../ballet/reedsol/fd_reedsol.h`
- `../../tango/fseq/fd_fseq.h`
- `fd_fec_chainer.h`
- `../../util/tmpl/fd_set.c`
- `../../util/tmpl/fd_pool.c`
- `../../util/tmpl/fd_map_chain.c`
- `../../util/tmpl/fd_dlist.c`


# Global Variables

---
### fd\_fec\_repair\_new
- **Type**: `function pointer`
- **Description**: `fd_fec_repair_new` is a function that initializes a memory region for use as a Forward Error Correction (FEC) repair structure. It takes parameters for shared memory, maximum FEC sets, shred tile count, and a seed for initialization.
- **Use**: This function is used to set up a memory region to manage FEC repair operations, ensuring the region is properly formatted and aligned for handling FEC sets.


---
### fd\_fec\_repair\_join
- **Type**: `fd_fec_repair_t *`
- **Description**: The `fd_fec_repair_join` function is a global function that returns a pointer to an `fd_fec_repair_t` structure. This function is used to join the caller to an existing FEC repair instance, which is a data structure used for managing forward-error-correction (FEC) repair processes in a distributed system.
- **Use**: This function is used to obtain a local pointer to an FEC repair instance, allowing the caller to interact with the FEC repair process.


---
### fd\_fec\_repair\_leave
- **Type**: `function pointer`
- **Description**: `fd_fec_repair_leave` is a function that allows a caller to leave a current local join of a Forward Error Correction (FEC) repair structure. It returns a pointer to the underlying shared memory region on success, or NULL on failure, logging details if the operation fails.
- **Use**: This function is used to safely disconnect from an FEC repair structure, ensuring that resources are properly released and the shared memory region is returned to the caller.


---
### fd\_fec\_repair\_delete
- **Type**: `function pointer`
- **Description**: `fd_fec_repair_delete` is a function that unformats a memory region used as a `fd_fec_repair` structure. It assumes that no one is currently joined to the region and returns a pointer to the underlying shared memory region or NULL if used incorrectly.
- **Use**: This function is used to clean up and release the memory associated with a `fd_fec_repair` structure, transferring ownership of the memory back to the caller.


# Data Structures

---
### fd\_fec\_intra
- **Type**: `struct`
- **Members**:
    - `key`: A map key where the 32 most significant bits represent the slot and the 32 least significant bits represent the fec_set_idx.
    - `prev`: Used internally by a doubly linked list (dlist) for navigation.
    - `next`: Used internally by a map chain for navigation.
    - `slot`: The slot of the block that this FEC set is part of.
    - `parent_off`: The offset of the parent slot from the current slot.
    - `fec_set_idx`: The index of the first data shred in the FEC set.
    - `ts`: A timestamp indicating when the first shred was received.
    - `recv_cnt`: The count of shreds received so far, including both data and coding shreds.
    - `data_cnt`: The total count of data shreds in the FEC set.
    - `sig`: An Ed25519 signature identifier for the FEC.
    - `buffered_idx`: The watermark of shreds buffered contiguously, starting at 0.
    - `completes_idx`: Set to UINT_MAX unless the FEC contains a shred with a batch_complete or slot_complete flag.
    - `shred_tile_idx`: The index of the shred tile that this FEC set is part of.
    - `deque_ele_idx`: The index of the element in the corresponding doubly linked list (dlist).
    - `idxs`: A bit vector tracking the indices of received data shreds in the FEC set.
- **Description**: The `fd_fec_intra` structure is designed to track in-progress Forward Error Correction (FEC) sets for the purpose of repairing missing shreds within a given FEC set. It contains various fields to manage the state and metadata of the FEC set, such as the slot and index information, timestamps, and counts of received and total data shreds. Additionally, it includes fields for internal navigation within linked data structures and a signature for identification. The structure is part of a larger system that orchestrates the repair of FEC sets as they are received from a cluster, ensuring data integrity and completeness.


---
### fd\_fec\_intra\_t
- **Type**: `struct`
- **Members**:
    - `key`: A 64-bit map key where the upper 32 bits represent the slot and the lower 32 bits represent the FEC set index.
    - `prev`: Used internally by a doubly linked list (dlist) for tracking previous elements.
    - `next`: Used internally by a map chain for tracking next elements.
    - `slot`: The slot number of the block that this FEC set is part of.
    - `parent_off`: The offset of the parent slot from the current slot.
    - `fec_set_idx`: The index of the first data shred in the FEC set.
    - `ts`: Timestamp indicating when the first shred was received.
    - `recv_cnt`: The count of shreds received so far, including both data and coding shreds.
    - `data_cnt`: The total count of data shreds in the FEC set.
    - `sig`: An Ed25519 signature identifier for the FEC.
    - `buffered_idx`: The watermark index of shreds that have been buffered contiguously, starting at 0.
    - `completes_idx`: Set to UINT_MAX unless the FEC contains a shred with a batch_complete or slot_complete flag.
    - `shred_tile_idx`: The index of the shred tile that this FEC set is part of.
    - `deque_ele_idx`: The index of the element in the corresponding doubly linked list (dlist).
    - `idxs`: A bit vector tracking the indices of received data shreds in the FEC set.
- **Description**: The `fd_fec_intra_t` structure is designed to track in-progress Forward Error Correction (FEC) sets for the purpose of repairing missing shreds within a given FEC set. It maintains various metadata about the FEC set, such as the slot number, FEC set index, and the count of received shreds. Additionally, it includes fields for managing the order and state of shreds, such as timestamps, signature identifiers, and indices for buffered and completed shreds. The structure is part of a larger system that orchestrates the repair of FEC sets as they are received from a cluster, ensuring data integrity and completeness.


---
### fd\_fec\_order
- **Type**: `struct`
- **Members**:
    - `key`: A 64-bit unsigned long where the 32 most significant bits represent the slot and the 32 least significant bits represent the fec_set_idx.
    - `prev`: A 64-bit unsigned long used internally by a doubly linked list (dlist) to point to the previous element.
    - `next`: A 64-bit unsigned long used internally by a doubly linked list (dlist) to point to the next element.
- **Description**: The `fd_fec_order` structure is a simple data structure used to manage the order of Forward Error Correction (FEC) sets within a doubly linked list. It contains a key that uniquely identifies an FEC set by combining a slot and an index, and two pointers, `prev` and `next`, which are used internally to maintain the structure's position within a doubly linked list. This structure is part of a larger system for managing and repairing FEC sets in a distributed environment.


---
### fd\_fec\_order\_t
- **Type**: `struct`
- **Members**:
    - `key`: A 64-bit key where the upper 32 bits represent the slot and the lower 32 bits represent the FEC set index.
    - `prev`: A pointer to the previous element in a doubly linked list, used internally.
    - `next`: A pointer to the next element in a doubly linked list, used internally.
- **Description**: The `fd_fec_order_t` structure is a simple data structure used to manage the order of Forward Error Correction (FEC) sets within a doubly linked list. It contains a key that uniquely identifies an FEC set by combining a slot and an FEC set index, and pointers to the previous and next elements in the list, facilitating the traversal and management of FEC sets in a sequence.


---
### fd\_fec\_repair
- **Type**: `struct`
- **Members**:
    - `fec_max`: The maximum number of in-progress FEC sets each fec_resolver can hold.
    - `shred_tile_cnt`: The number of shred tiles, which determines the size of order pool and dlist lists.
    - `intra_pool`: A pointer to a pool of fd_fec_intra_t structures for managing in-progress FEC sets.
    - `intra_map`: A pointer to a map of fd_fec_intra_t structures for tracking in-progress FEC sets.
    - `order_pool_lst`: A list of pointers to dlist pools, one for each shred tile, to manage FEC set order.
    - `order_dlist_lst`: A list of pointers to dlist structures that maintain the insertion order of FEC sets.
- **Description**: The `fd_fec_repair` structure is designed to manage the repair of Forward Error Correction (FEC) sets in a distributed system. It maintains a pool and map of in-progress FEC sets, allowing for efficient tracking and repair of missing shreds within these sets. The structure is tightly coupled with the `fd_fec_resolver` to ensure that the in-progress FEC sets are mirrored across all resolver tiles. It uses a list of order pools and dlists to maintain the order of FEC sets, ensuring that the repair process follows a FIFO order. The structure is aligned to 128 bytes for performance optimization.


---
### fd\_fec\_repair\_t
- **Type**: `struct`
- **Members**:
    - `fec_max`: Maximum number of FEC sets that can be in progress at any time.
    - `shred_tile_cnt`: Number of shred tiles managed by the repair structure.
    - `intra_pool`: Pointer to a pool of in-progress FEC sets.
    - `intra_map`: Pointer to a map of in-progress FEC sets.
    - `order_pool_lst`: List of pointers to pools maintaining the order of FEC sets.
    - `order_dlist_lst`: List of pointers to doubly linked lists maintaining insertion order of FEC sets.
- **Description**: The `fd_fec_repair_t` structure is designed to manage the repair process of Forward Error Correction (FEC) sets in a distributed system. It maintains an LRU cache of outstanding block slices that require repair, using a combination of pools, maps, and doubly linked lists to track and order the FEC sets. The structure is tightly integrated with the FEC resolver, ensuring that it mirrors the in-progress FEC sets across all resolver tiles. The repair process is managed in a FIFO manner, ensuring that the first slice to enter the cache is the first to be repaired. This structure is crucial for maintaining data integrity and continuity in systems where data shreds are transmitted and may be lost or incomplete.


# Functions

---
### fd\_fec\_repair\_align<!-- {{#callable:fd_fec_repair_align}} -->
The `fd_fec_repair_align` function returns the required memory alignment for a `fd_fec_repair_t` structure.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended to be used within the same translation unit and can be inlined by the compiler for performance.
    - It uses the `alignof` operator to determine the alignment requirement of the `fd_fec_repair_t` type.
    - The function returns this alignment value as an unsigned long integer.
- **Output**: The function returns an unsigned long integer representing the alignment requirement of the `fd_fec_repair_t` type.


---
### fd\_fec\_repair\_footprint<!-- {{#callable:fd_fec_repair_footprint}} -->
The `fd_fec_repair_footprint` function calculates the memory footprint required for a Forward Error Correction (FEC) repair structure based on the maximum number of FECs and the number of shred tiles.
- **Inputs**:
    - `fec_max`: The maximum number of FEC sets that can be in progress at any time.
    - `shred_tile_cnt`: The number of shred tiles, which are groupings of shreds used in FEC sets.
- **Control Flow**:
    - Calculate `total_fecs_pow2` as the next power of two greater than or equal to `fec_max * shred_tile_cnt`.
    - Verify that the footprints for the intra map and pool are greater than zero using `FD_TEST`.
    - Initialize the `footprint` variable using `FD_LAYOUT_APPEND` to account for the alignment and size of `fd_fec_repair_t`.
    - Append to `footprint` the alignment and footprint of the intra pool and map using `FD_LAYOUT_APPEND`.
    - Append to `footprint` the alignment and size of order pool and dlist pointers for each shred tile.
    - Iterate over each shred tile and append the alignment and footprint of the order pool and dlist for each tile.
    - Finalize the footprint calculation using `FD_LAYOUT_FINI` and return the result.
- **Output**: The function returns an `ulong` representing the total memory footprint required for the FEC repair structure.
- **Functions called**:
    - [`fd_fec_repair_align`](#fd_fec_repair_align)


---
### fd\_fec\_repair\_remove<!-- {{#callable:fd_fec_repair_remove}} -->
The `fd_fec_repair_remove` function removes an in-progress FEC set from the repair structure, updating the associated data structures accordingly.
- **Inputs**:
    - `fec_repair`: A pointer to the `fd_fec_repair_t` structure, which manages the FEC repair process.
    - `key`: An unsigned long integer representing the unique key for the FEC set to be removed, where the upper 32 bits are the slot and the lower 32 bits are the FEC set index.
- **Control Flow**:
    - Log the removal action with the slot and FEC set index extracted from the key.
    - Query the `intra_map` to find the `fd_fec_intra_t` element associated with the given key.
    - Assert that the element exists using `FD_TEST`.
    - Retrieve the `shred_tile_idx` and `deque_ele_idx` from the found element.
    - Remove the element from the `intra_map` and release it back to the `intra_pool`.
    - Access the order list and pool for the specific `shred_tile_idx`.
    - Remove the element from the order list using `deque_ele_idx` and release it back to the order pool.
- **Output**: The function does not return a value; it performs operations to remove and clean up an FEC set from the repair structure.


---
### fd\_fec\_repair\_insert<!-- {{#callable:fd_fec_repair_insert}} -->
The `fd_fec_repair_insert` function inserts or updates an in-progress FEC set in the repair map, handling potential evictions and updating the FEC set's state based on received shreds.
- **Inputs**:
    - `fec_repair`: A pointer to the `fd_fec_repair_t` structure, which manages the FEC repair process.
    - `slot`: An unsigned long integer representing the slot of the block this FEC set is part of.
    - `fec_set_idx`: An unsigned integer representing the index of the first data shred in the FEC set.
    - `shred_idx_or_data_cnt`: An unsigned integer that is either the index of the shred or the count of data shreds, depending on the `is_code` flag.
    - `completes`: An integer flag indicating if the FEC set is complete.
    - `is_code`: An integer flag indicating if the shred is a coding shred.
    - `shred_tile_idx`: An unsigned integer representing the index of the shred tile this FEC set is part of.
- **Control Flow**:
    - Check if the `shred_tile_idx` is valid within the `fec_repair` structure.
    - Log the insertion attempt with the slot and FEC set index.
    - Compute a unique key using the slot and FEC set index.
    - Query the `intra_map` for an existing FEC set using the computed key.
    - If no existing FEC set is found, check if the order pool for the `shred_tile_idx` has free elements.
    - If the order pool is full, evict the least recently used FEC set from the order list and release its resources.
    - Acquire a new order element and insert it into the order list.
    - Ensure there is space in the `intra_pool` and acquire a new FEC set element.
    - Initialize the new FEC set element with the provided parameters and insert it into the `intra_map`.
    - If the shred is a coding shred (`is_code` is true), update the `data_cnt` and `completes_idx` of the FEC set.
    - If the shred is a data shred, update the FEC set's indices and potentially mark it as complete.
    - Increment the `recv_cnt` of the FEC set.
    - Advance the `buffered_idx` if possible by checking contiguous shreds.
- **Output**: Returns a pointer to the `fd_fec_intra_t` structure representing the in-progress FEC set.


# Function Declarations (Public API)

---
### fd\_fec\_repair\_new<!-- {{#callable_declaration:fd_fec_repair_new}} -->
Formats a memory region for use as a FEC repair structure.
- **Description**: This function initializes a memory region to be used for forward-error-correction (FEC) repair operations. It should be called with a valid memory region that meets the required alignment and footprint specifications. The function sets up internal structures to manage FEC sets, which are used to repair missing data in a distributed system. It is important to ensure that the memory region is not null and has been allocated with sufficient size and alignment before calling this function. The function returns a pointer to the initialized FEC repair structure.
- **Inputs**:
    - `shmem`: A non-null pointer to a memory region that will be formatted for FEC repair. The memory must be properly aligned and have the required footprint.
    - `fec_max`: The maximum number of pending FECs each resolver can hold. It should be a specific number, typically max_pending_shred_sets + 2.
    - `shred_tile_cnt`: The number of shred tiles, which determines the size of the intra pool and map.
    - `seed`: A seed value used for initializing the intra map, affecting the randomness of the repair process.
- **Output**: Returns a pointer to the initialized fd_fec_repair_t structure on success.
- **See also**: [`fd_fec_repair_new`](fd_fec_repair.c.driver.md#fd_fec_repair_new)  (Implementation)


---
### fd\_fec\_repair\_join<!-- {{#callable_declaration:fd_fec_repair_join}} -->
Joins the caller to an FEC repair instance.
- **Description**: This function is used to join a caller to an existing FEC repair instance, allowing the caller to interact with the repair process. It should be called with a valid pointer to the shared memory region that backs the FEC repair instance. This function is typically used after the FEC repair instance has been initialized and is ready for use. It is important to ensure that the provided pointer is not null and points to a properly formatted FEC repair memory region.
- **Inputs**:
    - `shfec_repair`: A pointer to the shared memory region backing the FEC repair instance. Must not be null and should point to a valid, initialized FEC repair memory region.
- **Output**: Returns a pointer to the FEC repair instance in the local address space on success.
- **See also**: [`fd_fec_repair_join`](fd_fec_repair.c.driver.md#fd_fec_repair_join)  (Implementation)


---
### fd\_fec\_repair\_leave<!-- {{#callable_declaration:fd_fec_repair_leave}} -->
Leaves a current local join of an FEC repair.
- **Description**: This function is used to leave a current local join of a forward-error-correction (FEC) repair. It should be called when the caller no longer needs to be joined to the FEC repair. The function returns a pointer to the underlying shared memory region on success, allowing the caller to manage or release the memory as needed. If the input is NULL, the function logs a warning and returns NULL, indicating that the operation was not successful.
- **Inputs**:
    - `fec_repair`: A pointer to a constant fd_fec_repair_t structure representing the FEC repair to leave. Must not be NULL. If NULL, the function logs a warning and returns NULL.
- **Output**: Returns a pointer to the underlying shared memory region on success, or NULL if the input is NULL.
- **See also**: [`fd_fec_repair_leave`](fd_fec_repair.c.driver.md#fd_fec_repair_leave)  (Implementation)


---
### fd\_fec\_repair\_delete<!-- {{#callable_declaration:fd_fec_repair_delete}} -->
Unformats a memory region used as a FEC repair structure.
- **Description**: This function is used to unformat a memory region that was previously formatted for use as a FEC repair structure. It should be called when the FEC repair structure is no longer needed, and it is assumed that no other processes are joined to the region at the time of the call. The function returns a pointer to the underlying shared memory region, transferring ownership back to the caller. If the provided pointer is not a valid FEC repair structure, the function will log a warning and return NULL.
- **Inputs**:
    - `shmem`: A pointer to the memory region that was used as a FEC repair structure. It must be aligned and formatted correctly as a FEC repair structure. If the pointer is NULL or misaligned, the function logs a warning and returns NULL.
- **Output**: Returns a pointer to the underlying shared memory region if successful, or NULL if the input is invalid.
- **See also**: [`fd_fec_repair_delete`](fd_fec_repair.c.driver.md#fd_fec_repair_delete)  (Implementation)


---
### check\_blind\_fec\_completed<!-- {{#callable_declaration:check_blind_fec_completed}} -->
Determine if a forward-error-correction (FEC) set is complete.
- **Description**: This function checks whether a specific FEC set, identified by a slot and FEC set index, is complete. It is used in the context of repairing FEC sets received from a cluster. The function should be called when you need to verify the completion status of an FEC set, which is part of a larger process of handling and repairing data shreds. The function assumes that the FEC repair and chainer structures are properly initialized and that the slot and FEC set index are valid identifiers for the FEC set in question.
- **Inputs**:
    - `fec_repair`: A pointer to a constant fd_fec_repair_t structure, representing the FEC repair context. Must not be null.
    - `fec_chainer`: A pointer to an fd_fec_chainer_t structure, representing the FEC chainer context. Must not be null.
    - `slot`: An unsigned long integer representing the slot identifier for the FEC set. Must be a valid slot number.
    - `fec_set_idx`: An unsigned integer representing the index of the FEC set within the slot. Must be a valid index.
- **Output**: Returns 1 if the FEC set is complete, otherwise returns 0.
- **See also**: [`check_blind_fec_completed`](fd_fec_repair.c.driver.md#check_blind_fec_completed)  (Implementation)


---
### check\_set\_blind\_fec\_completed<!-- {{#callable_declaration:check_set_blind_fec_completed}} -->
Determine if a forward-error-correction (FEC) set can be marked as complete.
- **Description**: This function checks whether a given FEC set, identified by a slot and FEC set index, can be considered complete based on the buffered and completed indices of the shreds. It is used in scenarios where the repair protocol needs to decide if an FEC set has received enough shreds to be marked as complete, even if not all shreds are present. This function should be called when there is a need to verify the completion status of an FEC set, particularly in the context of repairing missing shreds. The function assumes that the `fec_repair` and `fec_chainer` structures are properly initialized and that the slot and FEC set index are valid.
- **Inputs**:
    - `fec_repair`: A pointer to an `fd_fec_repair_t` structure, which must be properly initialized and not null. It is used to access the intra-map and intra-pool for querying FEC set information.
    - `fec_chainer`: A pointer to an `fd_fec_chainer_t` structure, which must be properly initialized and not null. It is used to query the next FEC set in the sequence.
    - `slot`: An unsigned long integer representing the slot number of the FEC set. It is used as part of the key to identify the FEC set.
    - `fec_set_idx`: An unsigned integer representing the index of the FEC set within the slot. It is used as part of the key to identify the FEC set.
- **Output**: Returns an integer: 1 if the FEC set can be marked as complete, 0 otherwise.
- **See also**: [`check_set_blind_fec_completed`](fd_fec_repair.c.driver.md#check_set_blind_fec_completed)  (Implementation)


