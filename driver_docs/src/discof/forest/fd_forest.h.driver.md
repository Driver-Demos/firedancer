# Purpose
The provided C header file defines the "Forest" API, which is designed to manage and repair blocks in a distributed system, specifically in the context of a cluster environment using Turbine and Gossip protocols. The primary functionality of this API is to ensure that blocks, identified by slots, are fully received by requesting repairs for any missing shreds. The "Forest" structure maintains a tree that records the ancestry of slots and a frontier that models the leaves of the tree, representing the oldest blocks that still need repair. This API is crucial for maintaining data integrity and consistency across multiple forks in a distributed ledger or blockchain system.

The file defines several key components, including the `fd_forest_ele_t` structure, which implements a left-child, right-sibling n-ary tree to manage the relationships between blocks. The `fd_forest_t` structure serves as the top-level container, holding the root of the tree and various memory pools and maps for managing block ancestry, frontier, and orphaned blocks. The API provides functions for constructing, joining, and managing the forest, as well as for inserting shreds and publishing new roots. It also includes utility functions for verifying the integrity of the forest and printing its structure. This header file is intended to be included in other C source files, providing a public API for managing block repair and ancestry in a distributed system.
# Imports and Dependencies

---
- `../../disco/fd_disco_base.h`
- `../../util/tmpl/fd_set.c`
- `../../util/tmpl/fd_pool.c`
- `../../util/tmpl/fd_map_chain.c`


# Global Variables

---
### fd\_forest\_new
- **Type**: `function`
- **Description**: The `fd_forest_new` function is a constructor that formats an unused memory region for use as a forest data structure. It takes a pointer to shared memory (`shmem`), a maximum number of elements (`ele_max`), and a seed value (`seed`) as parameters.
- **Use**: This function is used to initialize a memory region to be used as a forest, setting up the necessary data structures for managing blocks and their ancestry in a distributed system.


---
### fd\_forest\_join
- **Type**: `fd_forest_t *`
- **Description**: The `fd_forest_join` function is a global function that returns a pointer to an `fd_forest_t` structure. This function is used to join a caller to a forest, which is a data structure used for managing and repairing blocks in a distributed system. The function takes a pointer to the memory region backing the forest and returns a pointer in the local address space to the forest on success.
- **Use**: This function is used to establish a local join to a forest, allowing the caller to interact with the forest data structure.


---
### fd\_forest\_leave
- **Type**: `function`
- **Description**: The `fd_forest_leave` function is a global function that allows a caller to leave a current local join of a forest data structure. It takes a constant pointer to an `fd_forest_t` structure as its parameter and returns a pointer to the underlying shared memory region on success, or NULL on failure.
- **Use**: This function is used to safely disconnect from a forest data structure, ensuring that resources are properly released and the shared memory region is returned to the caller.


---
### fd\_forest\_delete
- **Type**: `function pointer`
- **Description**: `fd_forest_delete` is a function that unformats a memory region used as a forest, assuming no one is currently joined to the region. It returns a pointer to the underlying shared memory region or NULL if the operation is used incorrectly, such as when the provided pointer is not a valid forest.
- **Use**: This function is used to delete a forest structure, transferring ownership of the memory region back to the caller.


---
### fd\_forest\_init
- **Type**: `fd_forest_t *`
- **Description**: The `fd_forest_init` function initializes a forest data structure, which is used to manage and repair blocks in a distributed system. It sets up the forest with a specified root, which is the initial slot for the forest, and ensures that the forest is ready for operations such as block repair and ancestry tracking.
- **Use**: This function is used to initialize a forest structure with a given root, preparing it for further operations in the system.


---
### fd\_forest\_fini
- **Type**: `function pointer`
- **Description**: `fd_forest_fini` is a function that finalizes a forest data structure, which is used for managing and repairing blocks in a distributed system. It assumes that the forest is a valid local join and that no other processes are joined to it. The function returns a pointer to the underlying shared memory region.
- **Use**: This function is used to properly close and clean up a forest data structure when it is no longer needed.


---
### fd\_forest\_query
- **Type**: `fd_forest_ele_t *`
- **Description**: The `fd_forest_query` function returns a pointer to an `fd_forest_ele_t` structure, which represents an element in a forest data structure. This function is used to query the forest for a specific element associated with a given slot.
- **Use**: This function is used to retrieve a specific element from the forest data structure based on the provided slot number.


---
### fd\_forest\_data\_shred\_insert
- **Type**: `fd_forest_ele_t *`
- **Description**: The `fd_forest_data_shred_insert` is a function that inserts a new data shred into the forest data structure. It takes several parameters including a pointer to the forest, the slot number, parent offset, shred index, FEC set index, and flags indicating data and slot completion. The function returns a pointer to the newly inserted forest element.
- **Use**: This function is used to add a new data shred to the forest, ensuring the forest structure is updated with the new element and its relationships.


---
### fd\_forest\_publish
- **Type**: `fd_forest_ele_t const *`
- **Description**: The `fd_forest_publish` function returns a pointer to a constant `fd_forest_ele_t` structure. This function is used to publish a specific slot as the new root of the forest, effectively setting the subtree beginning from the specified slot as the new forest tree.
- **Use**: This function is used to update the root of the forest to a specified slot, pruning all elements not in the slot's subtree.


# Data Structures

---
### fd\_forest\_ele
- **Type**: `struct`
- **Members**:
    - `slot`: Represents the map key for the element.
    - `prev`: Used internally by link_orphans for linking operations.
    - `next`: Used internally by fd_pool and fd_map_chain for linking operations.
    - `parent`: Stores the pool index of the parent in the tree or the parent slot when orphaned.
    - `child`: Stores the pool index of the left-child in the tree.
    - `sibling`: Stores the pool index of the right-sibling in the tree.
    - `buffered_idx`: Indicates the highest contiguous buffered shred index.
    - `complete_idx`: Indicates the shred index with SLOT_COMPLETE_FLAG, representing the last shred index in the slot.
    - `cmpl`: Array of fec complete indices.
    - `fecs`: Array of fec set indices.
    - `idxs`: Array of data shred indices.
- **Description**: The `fd_forest_ele` structure is a component of a left-child, right-sibling n-ary tree used in the context of a forest API for repairing blocks in a distributed system. Each element in this structure maintains indices for its left-most child, immediate right sibling, and parent, facilitating the construction and traversal of the tree. The structure also includes fields for managing buffered and complete shred indices, as well as arrays for fec and data shred indices, which are crucial for the block repair process. This design allows for efficient management and repair of blocks as they are discovered and processed in the system.


---
### fd\_forest\_ele\_t
- **Type**: `struct`
- **Members**:
    - `slot`: Represents the map key for the element.
    - `prev`: Used internally by link_orphans for managing links.
    - `next`: Used internally by fd_pool and fd_map_chain for managing links.
    - `parent`: Stores the pool index of the parent in the tree or the parent slot when orphaned.
    - `child`: Stores the pool index of the left-most child in the tree.
    - `sibling`: Stores the pool index of the immediate right sibling in the tree.
    - `buffered_idx`: Indicates the highest contiguous buffered shred index.
    - `complete_idx`: Indicates the shred index with SLOT_COMPLETE_FLAG, marking the last shred index in the slot.
    - `cmpl`: Array of fec complete indices.
    - `fecs`: Array of fec set indices.
    - `idxs`: Array of data shred indices.
- **Description**: The `fd_forest_ele_t` structure is a component of a left-child, right-sibling n-ary tree used in the forest API for managing and repairing blocks in a distributed system. Each element in this structure maintains indices for its left-most child, right sibling, and parent, facilitating tree traversal and manipulation. The structure is designed to be gaddr-safe, allowing operations from processes with separate local forest joins, and includes fields for managing buffered and complete shred indices, as well as arrays for fec and data shred indices.


---
### fd\_forest
- **Type**: `struct`
- **Members**:
    - `root`: Pool index of the root element in the forest.
    - `iter`: Pool index of the iterator used for traversing the forest.
    - `wksp_gaddr`: Global address of the forest in the backing workspace, must be non-zero.
    - `ver_gaddr`: Global address of the version sequence, incremented on write operations.
    - `pool_gaddr`: Global address of the element pool used by the forest.
    - `ancestry_gaddr`: Global address of the ancestry map of the forest.
    - `frontier_gaddr`: Global address of the frontier map, which tracks leaves needing repair.
    - `orphaned_gaddr`: Global address of the orphaned map, which tracks elements orphaned by their parent slots.
    - `magic`: Magic number used to verify the integrity of the forest structure.
- **Description**: The `fd_forest` structure is a top-level data structure used to manage and repair blocks in a distributed system. It maintains a tree structure that records the ancestry of slots and a frontier that models the leaves of the tree, representing the oldest blocks that still need repair. The structure includes various global addresses for managing memory pools and maps, and it uses a magic number for integrity verification. The forest is designed to be fork-aware and supports operations from processes with separate local joins, ensuring that blocks are fully received by requesting repairs for missing parts.


---
### fd\_forest\_t
- **Type**: `struct`
- **Members**:
    - `root`: Pool index of the root element in the forest.
    - `iter`: Pool index of the iterator used for traversing the forest.
    - `wksp_gaddr`: Workspace global address of the forest in the backing workspace, non-zero address.
    - `ver_gaddr`: Workspace global address of the version sequence, incremented on write operations.
    - `pool_gaddr`: Workspace global address of the element pool.
    - `ancestry_gaddr`: Workspace global address of the ancestry map.
    - `frontier_gaddr`: Workspace global address of the frontier map, mapping slots to elements needing repair.
    - `orphaned_gaddr`: Workspace global address of the orphaned map, mapping parent slots to orphaned elements.
    - `magic`: Magic number for verifying the integrity of the forest structure.
- **Description**: The `fd_forest_t` structure is a top-level data structure that manages a tree-like representation of blocks in a distributed system, specifically designed for repairing blocks as they are discovered. It maintains a pool of elements, maps for ancestry, frontier, and orphaned elements, and uses global addresses to manage its components in a shared memory workspace. The structure is initialized with a root element and is designed to ensure that blocks are fully received by requesting repairs for missing parts. It supports operations such as inserting new data shreds, publishing new roots, and verifying the integrity of the forest.


# Functions

---
### fd\_forest\_align<!-- {{#callable:fd_forest_align}} -->
The `fd_forest_align` function returns the required memory alignment for a `fd_forest_t` structure.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended to be used within the same translation unit and may be inlined by the compiler for performance.
    - It uses the `alignof` operator to determine the alignment requirement of the `fd_forest_t` type.
    - The function returns the alignment value obtained from `alignof(fd_forest_t)`.
- **Output**: The function returns an `ulong` representing the alignment requirement for a `fd_forest_t` structure.


---
### fd\_forest\_footprint<!-- {{#callable:fd_forest_footprint}} -->
The `fd_forest_footprint` function calculates the memory footprint required for a forest data structure with a specified maximum number of elements.
- **Inputs**:
    - `ele_max`: The maximum number of elements that the forest can contain.
- **Control Flow**:
    - The function begins by initializing the layout with `FD_LAYOUT_INIT`.
    - It appends the alignment and size of `fd_forest_t` to the layout.
    - It appends the alignment and footprint of the sequence (`fd_fseq`) to the layout.
    - It appends the alignment and footprint of the forest pool, calculated with `ele_max`, to the layout.
    - It appends the alignment and footprint of the forest ancestry, calculated with `ele_max`, to the layout.
    - It appends the alignment and footprint of the forest frontier, calculated with `ele_max`, to the layout.
    - It appends the alignment and footprint of the forest orphaned, calculated with `ele_max`, to the layout.
    - Finally, it appends the alignment of the forest itself and finalizes the layout with `FD_LAYOUT_FINI`.
- **Output**: The function returns an unsigned long integer representing the total memory footprint required for the forest data structure.
- **Functions called**:
    - [`fd_forest_align`](#fd_forest_align)


---
### fd\_forest\_wksp<!-- {{#callable:fd_forest_wksp}} -->
The `fd_forest_wksp` function returns a pointer to the workspace backing a given forest structure.
- **Inputs**:
    - `forest`: A constant pointer to an `fd_forest_t` structure representing the forest whose backing workspace is to be retrieved.
- **Control Flow**:
    - The function calculates the address of the workspace by subtracting the `wksp_gaddr` from the address of the `forest` structure.
    - It casts the resulting address to a pointer of type `fd_wksp_t` and returns it.
- **Output**: A pointer to the `fd_wksp_t` type, representing the workspace backing the given forest.


---
### fd\_forest\_ver<!-- {{#callable:fd_forest_ver}} -->
The `fd_forest_ver` function returns a pointer to the version number sequence of a forest structure in the local address space.
- **Inputs**:
    - `forest`: A pointer to an `fd_forest_t` structure representing the forest whose version number sequence is to be accessed.
- **Control Flow**:
    - The function calls [`fd_forest_wksp`](#fd_forest_wksp) with the `forest` pointer to obtain the workspace associated with the forest.
    - It then calls `fd_wksp_laddr_fast` with the obtained workspace and the `ver_gaddr` from the `forest` structure to get the local address of the version number sequence.
    - Finally, it returns the local address of the version number sequence.
- **Output**: A pointer to an `ulong` representing the local address of the version number sequence of the forest.
- **Functions called**:
    - [`fd_forest_wksp`](#fd_forest_wksp)


---
### fd\_forest\_ver\_const<!-- {{#callable:fd_forest_ver_const}} -->
The `fd_forest_ver_const` function retrieves a constant pointer to the version number sequence of a forest structure in a workspace.
- **Inputs**:
    - `forest`: A constant pointer to an `fd_forest_t` structure representing the forest whose version number sequence is to be accessed.
- **Control Flow**:
    - The function calls [`fd_forest_wksp`](#fd_forest_wksp) with the `forest` pointer to get the local join to the workspace backing the forest.
    - It then calls `fd_wksp_laddr_fast` with the workspace pointer and the `ver_gaddr` from the `forest` structure to get the local address of the version number sequence.
- **Output**: A constant pointer to an `ulong` representing the version number sequence of the forest.
- **Functions called**:
    - [`fd_forest_wksp`](#fd_forest_wksp)


---
### fd\_forest\_pool\_const<!-- {{#callable:fd_forest_pool_const}} -->
The `fd_forest_pool_const` function returns a constant pointer to the element pool of a given forest structure.
- **Inputs**:
    - `forest`: A constant pointer to an `fd_forest_t` structure representing the forest whose element pool is to be accessed.
- **Control Flow**:
    - The function calls [`fd_forest_wksp`](#fd_forest_wksp) with the `forest` argument to obtain the workspace associated with the forest.
    - It then calls `fd_wksp_laddr_fast` with the obtained workspace and the `pool_gaddr` from the `forest` structure to get the local address of the element pool.
    - Finally, it returns the local address as a constant pointer to `fd_forest_ele_t`.
- **Output**: A constant pointer to `fd_forest_ele_t`, representing the element pool of the specified forest.
- **Functions called**:
    - [`fd_forest_wksp`](#fd_forest_wksp)


---
### fd\_forest\_ancestry\_const<!-- {{#callable:fd_forest_ancestry_const}} -->
The `fd_forest_ancestry_const` function returns a constant pointer to the ancestry map of a given forest structure.
- **Inputs**:
    - `forest`: A constant pointer to an `fd_forest_t` structure representing the forest whose ancestry map is to be accessed.
- **Control Flow**:
    - The function calls [`fd_forest_wksp`](#fd_forest_wksp) with the `forest` pointer to obtain the workspace associated with the forest.
    - It then calls `fd_wksp_laddr_fast` with the obtained workspace and the `ancestry_gaddr` from the `forest` structure to compute the local address of the ancestry map.
    - Finally, it returns the computed local address as a constant pointer to `fd_forest_ancestry_t`.
- **Output**: A constant pointer to `fd_forest_ancestry_t`, representing the ancestry map of the given forest in the caller's address space.
- **Functions called**:
    - [`fd_forest_wksp`](#fd_forest_wksp)


---
### fd\_forest\_frontier\_const<!-- {{#callable:fd_forest_frontier_const}} -->
The `fd_forest_frontier_const` function retrieves a constant pointer to the frontier map of a given forest structure.
- **Inputs**:
    - `forest`: A constant pointer to an `fd_forest_t` structure representing the forest whose frontier map is to be accessed.
- **Control Flow**:
    - The function calls [`fd_forest_wksp`](#fd_forest_wksp) with the `forest` pointer to get the workspace associated with the forest.
    - It then calls `fd_wksp_laddr_fast` with the workspace and the `frontier_gaddr` from the `forest` structure to get the local address of the frontier map.
    - The function returns the local address as a constant pointer to `fd_forest_frontier_t`.
- **Output**: A constant pointer to `fd_forest_frontier_t`, representing the frontier map of the forest in the caller's local address space.
- **Functions called**:
    - [`fd_forest_wksp`](#fd_forest_wksp)


---
### fd\_forest\_orphaned\_const<!-- {{#callable:fd_forest_orphaned_const}} -->
The `fd_forest_orphaned_const` function retrieves a constant pointer to the orphaned map of a given forest structure.
- **Inputs**:
    - `forest`: A constant pointer to an `fd_forest_t` structure representing the forest whose orphaned map is to be accessed.
- **Control Flow**:
    - The function calls [`fd_forest_wksp`](#fd_forest_wksp) with the `forest` pointer to get the workspace associated with the forest.
    - It then calls `fd_wksp_laddr_fast` with the workspace and the `orphaned_gaddr` from the `forest` structure to get the local address of the orphaned map.
- **Output**: A constant pointer to the `fd_forest_orphaned_t` structure representing the orphaned map of the forest.
- **Functions called**:
    - [`fd_forest_wksp`](#fd_forest_wksp)


---
### fd\_forest\_root\_slot<!-- {{#callable:fd_forest_root_slot}} -->
The `fd_forest_root_slot` function retrieves the slot number of the root element in a forest data structure, returning `ULONG_MAX` if the root is uninitialized.
- **Inputs**:
    - `forest`: A pointer to a constant `fd_forest_t` structure representing the forest from which the root slot is to be retrieved.
- **Control Flow**:
    - Check if the root index of the forest is equal to the null index of the forest's pool using `fd_forest_pool_idx_null` and [`fd_forest_pool_const`](#fd_forest_pool_const); if true, return `ULONG_MAX` indicating the root is uninitialized.
    - If the root is initialized, retrieve the slot number of the root element from the forest's pool using `fd_forest_pool_ele_const` and return it.
- **Output**: The function returns an `ulong` representing the slot number of the root element in the forest, or `ULONG_MAX` if the root is uninitialized.
- **Functions called**:
    - [`fd_forest_pool_const`](#fd_forest_pool_const)


# Function Declarations (Public API)

---
### fd\_forest\_new<!-- {{#callable_declaration:fd_forest_new}} -->
Formats a memory region for use as a forest.
- **Description**: This function prepares a specified memory region to be used as a forest data structure, which is used for managing and repairing blocks in a distributed system. It should be called with a valid memory region that is properly aligned and has sufficient size to accommodate the forest structure. The function initializes the memory with the necessary components for the forest, including pools and maps for managing elements and their relationships. It is important to ensure that the memory region is part of a workspace and that the maximum number of elements is correctly specified. The function returns a pointer to the initialized memory region or NULL if any preconditions are not met, such as a NULL memory pointer, misalignment, or an invalid element maximum.
- **Inputs**:
    - `shmem`: A pointer to the memory region to be formatted as a forest. Must not be NULL and must be aligned according to fd_forest_align(). The memory must be part of a workspace.
    - `ele_max`: The maximum number of elements the forest can hold. Must be a valid number that results in a non-zero footprint.
    - `seed`: A seed value used for initializing certain components of the forest. Can be any unsigned long value.
- **Output**: Returns a pointer to the initialized memory region on success, or NULL if the input parameters are invalid or preconditions are not met.
- **See also**: [`fd_forest_new`](fd_forest.c.driver.md#fd_forest_new)  (Implementation)


---
### fd\_forest\_join<!-- {{#callable_declaration:fd_forest_join}} -->
Joins the caller to a forest in shared memory.
- **Description**: This function is used to join a caller to a forest data structure that is backed by a shared memory region. It should be called when a process needs to access or manipulate the forest structure in its local address space. The function checks if the provided pointer is non-null, properly aligned, and part of a valid workspace. If any of these conditions are not met, it logs a warning and returns NULL. This function is typically used after the forest has been initialized and formatted in shared memory.
- **Inputs**:
    - `shforest`: A pointer to the shared memory region representing the forest. It must not be null, must be properly aligned according to fd_forest_align(), and must be part of a valid workspace. If these conditions are not met, the function returns NULL.
- **Output**: Returns a pointer to the forest in the local address space on success, or NULL if the input is invalid or the forest is not part of a valid workspace.
- **See also**: [`fd_forest_join`](fd_forest.c.driver.md#fd_forest_join)  (Implementation)


---
### fd\_forest\_leave<!-- {{#callable_declaration:fd_forest_leave}} -->
Leaves a current local join to a forest.
- **Description**: This function is used to leave a current local join to a forest, returning a pointer to the underlying shared memory region if successful. It should be called when a process no longer needs to interact with a forest, allowing for cleanup or further operations on the shared memory. The function logs a warning and returns NULL if the provided forest pointer is NULL, indicating an error in usage.
- **Inputs**:
    - `forest`: A pointer to a constant fd_forest_t structure representing the forest to leave. Must not be NULL; if it is NULL, the function logs a warning and returns NULL.
- **Output**: Returns a pointer to the underlying shared memory region on success, or NULL if the forest pointer is NULL.
- **See also**: [`fd_forest_leave`](fd_forest.c.driver.md#fd_forest_leave)  (Implementation)


---
### fd\_forest\_delete<!-- {{#callable_declaration:fd_forest_delete}} -->
Unformats a memory region used as a forest.
- **Description**: This function is used to unformat a memory region that was previously formatted for use as a forest, effectively deleting the forest structure. It should be called when the forest is no longer needed, and it is assumed that no processes are currently joined to the forest. The function returns a pointer to the underlying shared memory region, transferring ownership of the memory back to the caller. If the provided pointer is null or misaligned, the function logs a warning and returns null.
- **Inputs**:
    - `forest`: A pointer to the memory region used as a forest. It must not be null and must be properly aligned according to the forest's alignment requirements. If the pointer is null or misaligned, the function logs a warning and returns null.
- **Output**: Returns a pointer to the underlying shared memory region if successful, or null if the input is invalid.
- **See also**: [`fd_forest_delete`](fd_forest.c.driver.md#fd_forest_delete)  (Implementation)


---
### fd\_forest\_init<!-- {{#callable_declaration:fd_forest_init}} -->
Initializes a forest with a specified root slot.
- **Description**: This function initializes a forest structure, setting up its root node with the specified root slot. It should be called on a valid, uninitialized forest that has been properly joined in the local address space. The function assumes that no other processes are joined to the forest during initialization. After calling this function, the forest will have a root element, and the version will be incremented. This function is typically called by the process that formatted the forest's memory.
- **Inputs**:
    - `forest`: A pointer to a valid fd_forest_t structure that has been joined in the local address space. It must not be null and should be in an uninitialized state.
    - `root_slot`: An unsigned long integer representing the slot to be used as the root of the forest. This value is used to initialize the root node of the forest.
- **Output**: Returns a pointer to the initialized fd_forest_t structure.
- **See also**: [`fd_forest_init`](fd_forest.c.driver.md#fd_forest_init)  (Implementation)


---
### fd\_forest\_fini<!-- {{#callable_declaration:fd_forest_fini}} -->
Finalize the use of a forest structure.
- **Description**: This function is used to finalize a forest structure, indicating that it is no longer in use. It should be called when the forest is no longer needed and after ensuring that no other processes are joined to it. This function updates the version sequence of the forest to an uninitialized state, signaling that the forest is no longer active. It is important to ensure that the forest is a valid local join and that no other joins are active before calling this function.
- **Inputs**:
    - `forest`: A pointer to the fd_forest_t structure to be finalized. It must be a valid local join and must not be null. The caller retains ownership of the memory, and the function assumes no other processes are joined to this forest.
- **Output**: Returns a pointer to the forest structure that was finalized, allowing the caller to manage the memory as needed.
- **See also**: [`fd_forest_fini`](fd_forest.c.driver.md#fd_forest_fini)  (Implementation)


---
### fd\_forest\_query<!-- {{#callable_declaration:fd_forest_query}} -->
Queries the forest for an element associated with a specific slot.
- **Description**: Use this function to retrieve a pointer to the forest element associated with a given slot. This function is useful when you need to access or manipulate the data related to a specific slot within the forest structure. Ensure that the forest is a valid, initialized local join before calling this function. The slot must be greater than the root slot of the forest, otherwise, the behavior is undefined if handholding is not enabled.
- **Inputs**:
    - `forest`: A pointer to a valid, initialized fd_forest_t structure. The caller must ensure that this is a current local join and not null.
    - `slot`: An unsigned long representing the slot to query. It must be greater than the root slot of the forest. If FD_FOREST_USE_HANDHOLDING is enabled, invalid slots will trigger an error.
- **Output**: Returns a pointer to the fd_forest_ele_t associated with the specified slot, or undefined behavior if the slot is invalid and handholding is not enabled.
- **See also**: [`fd_forest_query`](fd_forest.c.driver.md#fd_forest_query)  (Implementation)


---
### fd\_forest\_data\_shred\_insert<!-- {{#callable_declaration:fd_forest_data_shred_insert}} -->
Inserts a data shred into the forest structure.
- **Description**: This function is used to insert a data shred into a forest structure, which is part of a system for repairing blocks as they are discovered. It should be called when a new shred is available for a specific slot, and the slot is not already present in the forest. The function assumes that the parent slot is already in the forest and that there is a free element in the pool. It updates the forest's internal structures to reflect the new shred and its relationship to existing elements. This function must be called with a valid forest that has been properly initialized.
- **Inputs**:
    - `forest`: A pointer to an initialized fd_forest_t structure. The caller retains ownership and must ensure it is not null.
    - `slot`: The slot number associated with the shred. Must be greater than the root slot of the forest.
    - `parent_off`: The offset from the current slot to its parent slot. Must be a valid offset such that the parent slot is already in the forest.
    - `shred_idx`: The index of the shred within the slot. Must be a valid index for the shred.
    - `fec_set_idx`: The index of the FEC set associated with the shred. Must be a valid index for the FEC set.
    - `data_complete`: An integer flag indicating whether the data is complete. This parameter is currently unused.
    - `slot_complete`: An integer flag indicating whether the slot is complete. Non-zero values indicate completion.
- **Output**: Returns a pointer to the inserted fd_forest_ele_t structure representing the shred in the forest.
- **See also**: [`fd_forest_data_shred_insert`](fd_forest.c.driver.md#fd_forest_data_shred_insert)  (Implementation)


---
### fd\_forest\_publish<!-- {{#callable_declaration:fd_forest_publish}} -->
Publishes a specified slot as the new root of the forest.
- **Description**: This function sets the specified slot as the new root of the forest, effectively pruning all elements not in the subtree of the new root. It should be used when a new root needs to be established in the forest structure, typically after a significant event like a block confirmation. The function assumes that the specified slot is already present in the forest and that it is a valid operation to make it the new root. It is important to ensure that the slot is greater than the current root's slot to maintain the integrity of the forest structure.
- **Inputs**:
    - `forest`: A pointer to an fd_forest_t structure representing the forest. This must be a valid, initialized forest that the caller has joined.
    - `new_root_slot`: An unsigned long representing the slot to be set as the new root. It must be present in the forest and greater than the current root's slot.
- **Output**: Returns a pointer to the new root element of type fd_forest_ele_t const *.
- **See also**: [`fd_forest_publish`](fd_forest.c.driver.md#fd_forest_publish)  (Implementation)


---
### fd\_forest\_verify<!-- {{#callable_declaration:fd_forest_verify}} -->
Checks if the forest is not obviously corrupt.
- **Description**: Use this function to verify the integrity of a forest structure. It should be called when you need to ensure that the forest is correctly initialized and not corrupted. This function is useful for debugging and validation purposes, especially after operations that modify the forest. It must be called with a valid, non-null pointer to a forest that is properly aligned and part of a workspace. The function will return an error if the forest is uninitialized, misaligned, or not part of a workspace.
- **Inputs**:
    - `forest`: A pointer to a constant fd_forest_t structure. It must not be null, must be properly aligned according to fd_forest_align(), and must be part of a workspace. The forest should be initialized and valid; otherwise, the function will return an error.
- **Output**: Returns 0 if the forest is verified successfully, or -1 if the forest is found to be corrupt or invalid.
- **See also**: [`fd_forest_verify`](fd_forest.c.driver.md#fd_forest_verify)  (Implementation)


---
### fd\_forest\_frontier\_print<!-- {{#callable_declaration:fd_forest_frontier_print}} -->
Prints the current frontier of the forest.
- **Description**: Use this function to display the current frontier of a forest, which represents the leaves of the tree that still need to be repaired. This function is useful for debugging or monitoring the state of the forest's frontier. It must be called with a valid, initialized forest that the caller has joined. The function does not modify the forest or its elements.
- **Inputs**:
    - `forest`: A pointer to a constant fd_forest_t structure representing the forest whose frontier is to be printed. The pointer must not be null, and the forest must be a valid, initialized instance that the caller has joined.
- **Output**: None
- **See also**: [`fd_forest_frontier_print`](fd_forest.c.driver.md#fd_forest_frontier_print)  (Implementation)


---
### fd\_forest\_print<!-- {{#callable_declaration:fd_forest_print}} -->
Prints a formatted representation of the forest tree.
- **Description**: Use this function to output a human-readable representation of the forest tree structure. It is useful for debugging and understanding the current state of the forest. The function should be called when a visual representation of the forest's ancestry, frontier, and orphaned elements is needed. It assumes that the forest is a valid, initialized structure and will not print anything if the forest's root is uninitialized (i.e., set to ULONG_MAX).
- **Inputs**:
    - `forest`: A pointer to a constant fd_forest_t structure representing the forest to be printed. The pointer must not be null, and the forest should be properly initialized and joined before calling this function.
- **Output**: None
- **See also**: [`fd_forest_print`](fd_forest.c.driver.md#fd_forest_print)  (Implementation)


