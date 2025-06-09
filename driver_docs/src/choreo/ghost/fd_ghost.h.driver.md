# Purpose
The provided C header file, `fd_ghost.h`, implements Solana's LMD-GHOST ("latest message-driven greedy heaviest-observed subtree") fork choice rule. This rule is a critical component in blockchain consensus algorithms, particularly for determining the best fork in a blockchain by considering the latest votes from validators. The file defines the data structures and functions necessary to manage and traverse a tree of blockchain slots, where each node in the tree represents a slot and tracks the stake weight of votes for that slot and its subtree. The primary data structure is `fd_ghost_t`, which encapsulates the root of the tree, memory pools, and maps for managing nodes and votes. The file also includes a detailed explanation of the LMD-GHOST protocol, emphasizing its greedy, heaviest, observed, and subtree characteristics.

The header file provides a comprehensive API for managing the ghost tree, including functions for creating, joining, and deleting ghost instances, as well as operations for inserting nodes, replaying votes, and publishing new roots. It also includes utility functions for querying nodes, verifying the integrity of the tree, and printing its structure. The file is designed to be included in other C source files, providing a robust and efficient mechanism for implementing the LMD-GHOST fork choice rule in blockchain systems. The use of macros and inline functions ensures that the operations are efficient, while the optional handholding feature allows for additional runtime checks and logging to aid in debugging and development.
# Imports and Dependencies

---
- `../fd_choreo_base.h`
- `../epoch/fd_epoch.h`
- `../../tango/fseq/fd_fseq.h`
- `../../util/tmpl/fd_pool.c`
- `../../util/tmpl/fd_map_chain.c`


# Global Variables

---
### fd\_ghost\_new
- **Type**: `function`
- **Description**: The `fd_ghost_new` function is a constructor that formats an unused memory region for use as a ghost data structure. It takes a pointer to shared memory (`shmem`), a seed for hashing functions (`seed`), and the maximum number of nodes (`node_max`) as parameters.
- **Use**: This function is used to initialize a memory region to be used as a ghost, setting up the necessary structures for managing nodes and votes.


---
### fd\_ghost\_join
- **Type**: `fd_ghost_t *`
- **Description**: The `fd_ghost_join` function returns a pointer to an `fd_ghost_t` structure, which represents the top-level structure for managing the GHOST protocol's in-memory representation. This structure includes metadata, a node pool, and a node map for tracking nodes and votes in the GHOST tree.
- **Use**: This variable is used to join a caller to the GHOST protocol's shared memory region, allowing access to the protocol's data structures and operations.


---
### fd\_ghost\_leave
- **Type**: `function`
- **Description**: The `fd_ghost_leave` function is a global function that is used to leave a current local join of a ghost data structure. It takes a constant pointer to an `fd_ghost_t` structure as its parameter and returns a pointer to the underlying shared memory region on success, or NULL on failure.
- **Use**: This function is used to safely disconnect from a ghost data structure, ensuring that resources are properly released and the shared memory region is returned.


---
### fd\_ghost\_delete
- **Type**: `function pointer`
- **Description**: `fd_ghost_delete` is a function that unformats a memory region used as a ghost, assuming no one is joined to the region. It returns a pointer to the underlying shared memory region or NULL if used incorrectly, transferring ownership of the memory region to the caller.
- **Use**: This function is used to clean up and reclaim the memory region previously used by a ghost structure, ensuring that resources are properly managed and released.


---
### fd\_ghost\_head
- **Type**: `fd_ghost_node_t const *`
- **Description**: The `fd_ghost_head` function returns a pointer to a constant `fd_ghost_node_t` structure. This function is part of the implementation of Solana's LMD-GHOST fork choice rule, which is used to determine the heaviest leaf in a subtree of the ghost tree starting from a given root node.
- **Use**: This function is used to traverse the ghost tree from a specified root node and identify the heaviest leaf node based on the stake weight, aiding in the fork choice decision process.


---
### fd\_ghost\_gca
- **Type**: `fd_ghost_node_t const *`
- **Description**: The `fd_ghost_gca` function returns a pointer to the greatest common ancestor node of two given slots within a ghost tree structure. It is part of the implementation of Solana's LMD-GHOST fork choice rule, which is used to determine the best fork in a blockchain by considering the heaviest observed subtree based on stake weight.
- **Use**: This function is used to find the common ancestor of two slots in the ghost tree, which is essential for operations that require understanding the relationship between different nodes in the tree.


---
### fd\_ghost\_insert
- **Type**: `fd_ghost_node_t *`
- **Description**: The `fd_ghost_insert` variable is a function that returns a pointer to an `fd_ghost_node_t` structure. It is used to insert a new node into the GHOST tree, which is a data structure implementing Solana's LMD-GHOST fork choice rule. The function requires a pointer to an `fd_ghost_t` structure, a parent slot, and a slot number for the new node.
- **Use**: This function is used to add a new node to the GHOST tree, ensuring that the node is correctly linked to its parent and is part of the tree structure.


---
### fd\_ghost\_publish
- **Type**: `fd_ghost_node_t const *`
- **Description**: The `fd_ghost_publish` function returns a pointer to a constant `fd_ghost_node_t` structure. This function is part of the GHOST protocol implementation, which is used to manage and update the state of a blockchain fork choice rule based on the heaviest observed subtree.
- **Use**: This function is used to set a specified slot and its descendants as the new root of the GHOST tree, effectively publishing a new state of the blockchain fork choice.


# Data Structures

---
### fd\_ghost\_node
- **Type**: `struct`
- **Members**:
    - `slot`: The slot number this node is tracking, serving as the map key.
    - `next`: Reserved for internal use by fd_pool, fd_map_chain, and fd_ghost_publish.
    - `weight`: The total stake that has voted (via replay) for this slot or its descendants.
    - `replay_stake`: The stake that has voted (via replay) specifically for this slot.
    - `gossip_stake`: The stake that has voted (via gossip) specifically for this slot.
    - `rooted_stake`: The stake that has rooted this slot.
    - `valid`: Indicates if this node is valid for fork choice (fd_ghost_head).
    - `parent_idx`: Index of the parent node in the node pool.
    - `child_idx`: Index of the left-child node in the node pool.
    - `sibling_idx`: Index of the right-sibling node in the node pool.
- **Description**: The `fd_ghost_node` structure is a component of the LMD-GHOST fork choice rule implementation, used in Solana's protocol. It represents a node in a left-child, right-sibling n-ary tree, where each node tracks voting stakes for a specific slot and its subtree. The structure includes fields for managing the node's position in the tree, the amount of stake from different voting methods, and a validity flag for fork choice decisions. This structure is aligned to 128 bytes for performance reasons and is used in conjunction with memory pools and maps to efficiently manage and query nodes.


---
### fd\_ghost\_node\_t
- **Type**: `struct`
- **Members**:
    - `slot`: The slot number this node is tracking, also used as the map key.
    - `next`: Reserved for internal use by fd_pool, fd_map_chain, and fd_ghost_publish.
    - `weight`: The total amount of stake that has voted for this slot or any of its descendants.
    - `replay_stake`: The amount of stake that has voted for this slot via replay.
    - `gossip_stake`: The amount of stake that has voted for this slot via gossip.
    - `rooted_stake`: The amount of stake that has rooted this slot.
    - `valid`: Indicates whether this node is valid for fork choice.
    - `parent_idx`: Index of the parent node in the node pool.
    - `child_idx`: Index of the left-most child node in the node pool.
    - `sibling_idx`: Index of the immediate right sibling node in the node pool.
- **Description**: The `fd_ghost_node_t` structure represents a node in a left-child, right-sibling n-ary tree used in the implementation of Solana's LMD-GHOST fork choice rule. Each node tracks various types of stake associated with a specific slot, including replay, gossip, and rooted stakes, and maintains indices for its parent, left-most child, and right sibling within a node pool. This structure is designed to support efficient operations and queries in a distributed environment where processes may have separate local views of the tree.


---
### fd\_ghost
- **Type**: `struct`
- **Members**:
    - `magic`: A constant value used to verify the integrity of the structure, expected to be FD_GHOST_MAGIC.
    - `ghost_gaddr`: The global address of this structure in the backing workspace, must be non-zero.
    - `seed`: An arbitrary seed used for various hashing functions within the structure.
    - `root_idx`: The index of the root node in the node pool.
    - `ver_gaddr`: The global address for versioning, used to check the consistency of reads.
    - `node_pool_gaddr`: The global address of the memory pool containing tree nodes.
    - `node_map_gaddr`: The global address of the node map, which supports fast querying of nodes by slot.
- **Description**: The `fd_ghost` structure is a core component of the LMD-GHOST fork choice rule implementation, used in Solana's protocol. It maintains metadata and memory addresses for managing a tree of nodes, where each node represents a slot in the blockchain. The structure includes fields for integrity verification, hashing, and versioning, as well as pointers to a node pool and a node map for efficient node management and querying. The `fd_ghost` structure is aligned to 128 bytes and is designed to be used in a shared memory context, allowing multiple processes to interact with the same data structure efficiently.


---
### fd\_ghost\_t
- **Type**: `struct`
- **Members**:
    - `magic`: A constant value used to verify the integrity and version of the fd_ghost structure.
    - `ghost_gaddr`: The global address of the ghost in the backing workspace, ensuring a non-zero address.
    - `seed`: A seed value used for various hashing functions within the structure.
    - `root_idx`: The index of the root node in the node pool.
    - `ver_gaddr`: The global address of the version sequence, used for consistency checks.
    - `node_pool_gaddr`: The global address of the node pool, which is a memory pool of tree nodes.
    - `node_map_gaddr`: The global address of the node map, which supports fast querying of nodes by slot.
- **Description**: The `fd_ghost_t` structure is a top-level data structure that implements Solana's LMD-GHOST fork choice rule, managing a tree of nodes representing blockchain slots. It contains metadata for integrity checks, addresses for memory pools and maps, and a root index for the tree structure. The structure is designed to be bump-allocated and laid out contiguously in memory, ensuring efficient access and manipulation of the tree nodes and their associated votes. It supports operations such as node insertion, vote replaying, and subtree management, facilitating the implementation of the LMD-GHOST protocol.


# Functions

---
### fd\_ghost\_align<!-- {{#callable:fd_ghost_align}} -->
The `fd_ghost_align` function returns the required memory alignment for a `fd_ghost_t` structure.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended to be used within the same translation unit and may be inlined by the compiler for performance.
    - It uses the `alignof` operator to determine the alignment requirement of the `fd_ghost_t` type.
    - The function returns this alignment value as an unsigned long integer.
- **Output**: The function returns an unsigned long integer representing the alignment requirement of the `fd_ghost_t` type.


---
### fd\_ghost\_footprint<!-- {{#callable:fd_ghost_footprint}} -->
The `fd_ghost_footprint` function calculates the memory footprint required for a ghost structure with a specified maximum number of nodes.
- **Inputs**:
    - `node_max`: The maximum number of nodes that the ghost structure will support.
- **Control Flow**:
    - The function begins by initializing the layout with `FD_LAYOUT_INIT`.
    - It appends the alignment and size of `fd_ghost_t` to the layout.
    - It appends the alignment and footprint of the sequence (`fd_fseq`) to the layout.
    - It appends the alignment and footprint of the ghost node pool, which depends on `node_max`, to the layout.
    - It appends the alignment and footprint of the ghost node map, which also depends on `node_max`, to the layout.
    - Finally, it appends the alignment of the ghost structure itself and finalizes the layout with `FD_LAYOUT_FINI`.
- **Output**: The function returns an `ulong` representing the total memory footprint required for the ghost structure with the specified maximum number of nodes.
- **Functions called**:
    - [`fd_ghost_align`](#fd_ghost_align)


---
### fd\_ghost\_wksp<!-- {{#callable:fd_ghost_wksp}} -->
The `fd_ghost_wksp` function returns a pointer to the workspace backing a given ghost structure.
- **Inputs**:
    - `ghost`: A constant pointer to an `fd_ghost_t` structure representing the ghost whose backing workspace is to be retrieved.
- **Control Flow**:
    - The function takes a pointer to a `fd_ghost_t` structure as input.
    - It calculates the address of the workspace by subtracting the `ghost_gaddr` from the address of the `ghost`.
    - The result is cast to a pointer of type `fd_wksp_t` and returned.
- **Output**: A pointer to an `fd_wksp_t` structure representing the workspace backing the given ghost.


---
### fd\_ghost\_ver<!-- {{#callable:fd_ghost_ver}} -->
The `fd_ghost_ver` function retrieves a pointer to the version sequence number of a given ghost structure.
- **Inputs**:
    - `ghost`: A constant pointer to an `fd_ghost_t` structure, representing the ghost from which the version sequence number is to be retrieved.
- **Control Flow**:
    - The function calls [`fd_ghost_wksp`](#fd_ghost_wksp) with the `ghost` pointer to obtain the workspace associated with the ghost.
    - It then calls `fd_wksp_laddr_fast` with the workspace and the `ver_gaddr` from the `ghost` structure to get the local address of the version sequence number.
- **Output**: A pointer to an `ulong` representing the version sequence number of the ghost.
- **Functions called**:
    - [`fd_ghost_wksp`](#fd_ghost_wksp)


---
### fd\_ghost\_node\_pool\_const<!-- {{#callable:fd_ghost_node_pool_const}} -->
The `fd_ghost_node_pool_const` function retrieves a constant pointer to the node pool of a given ghost structure.
- **Inputs**:
    - `ghost`: A constant pointer to an `fd_ghost_t` structure representing the ghost from which the node pool is to be accessed.
- **Control Flow**:
    - The function calls [`fd_ghost_wksp`](#fd_ghost_wksp) with the `ghost` pointer to get the workspace associated with the ghost.
    - It then calls `fd_wksp_laddr_fast` with the workspace and the `node_pool_gaddr` from the `ghost` structure to get the local address of the node pool.
- **Output**: A constant pointer to the `fd_ghost_node_t` node pool associated with the given ghost.
- **Functions called**:
    - [`fd_ghost_wksp`](#fd_ghost_wksp)


---
### fd\_ghost\_node\_map\_const<!-- {{#callable:fd_ghost_node_map_const}} -->
The `fd_ghost_node_map_const` function retrieves a constant pointer to the node map of a given ghost structure.
- **Inputs**:
    - `ghost`: A constant pointer to an `fd_ghost_t` structure, representing the ghost from which the node map is to be retrieved.
- **Control Flow**:
    - The function calls [`fd_ghost_wksp`](#fd_ghost_wksp) with the `ghost` pointer to get the workspace associated with the ghost.
    - It then calls `fd_wksp_laddr_fast` with the workspace and the `node_map_gaddr` from the `ghost` structure to get the local address of the node map.
- **Output**: A constant pointer to an `fd_ghost_node_map_t`, which is the node map of the specified ghost.
- **Functions called**:
    - [`fd_ghost_wksp`](#fd_ghost_wksp)


---
### fd\_ghost\_root<!-- {{#callable:fd_ghost_root}} -->
The `fd_ghost_root` function retrieves a pointer to the root node of a GHOST tree from a given `fd_ghost_t` structure.
- **Inputs**:
    - `ghost`: A pointer to a constant `fd_ghost_t` structure representing the GHOST tree from which the root node is to be retrieved.
- **Control Flow**:
    - The function calls [`fd_ghost_node_pool_const`](#fd_ghost_node_pool_const) with the `ghost` pointer to get a constant pointer to the node pool.
    - It then calls `fd_ghost_node_pool_ele_const` with the node pool and the `root_idx` from the `ghost` structure to retrieve the root node.
- **Output**: A constant pointer to the `fd_ghost_node_t` structure representing the root node of the GHOST tree.
- **Functions called**:
    - [`fd_ghost_node_pool_const`](#fd_ghost_node_pool_const)


---
### fd\_ghost\_parent<!-- {{#callable:fd_ghost_parent}} -->
The `fd_ghost_parent` function retrieves the parent node of a given child node in a GHOST tree structure.
- **Inputs**:
    - `ghost`: A pointer to a `fd_ghost_t` structure representing the GHOST tree, which must be a current local join.
    - `child`: A pointer to a `fd_ghost_node_t` structure representing the child node whose parent is to be retrieved.
- **Control Flow**:
    - The function calls [`fd_ghost_node_pool_const`](#fd_ghost_node_pool_const) with the `ghost` pointer to get a constant pointer to the node pool.
    - It then accesses the `parent_idx` of the `child` node to find the index of the parent node in the node pool.
    - Finally, it calls `fd_ghost_node_pool_ele_const` with the node pool and the `parent_idx` to retrieve a constant pointer to the parent node.
- **Output**: A constant pointer to the parent node of the specified child node in the GHOST tree.
- **Functions called**:
    - [`fd_ghost_node_pool_const`](#fd_ghost_node_pool_const)


---
### fd\_ghost\_child<!-- {{#callable:fd_ghost_child}} -->
The `fd_ghost_child` function returns a pointer to the left-most child node of a given parent node in a GHOST tree structure.
- **Inputs**:
    - `ghost`: A pointer to a constant `fd_ghost_t` structure representing the GHOST tree.
    - `parent`: A pointer to a constant `fd_ghost_node_t` structure representing the parent node in the GHOST tree.
- **Control Flow**:
    - The function calls [`fd_ghost_node_pool_const`](#fd_ghost_node_pool_const) with `ghost` to get a constant pointer to the node pool.
    - It then accesses the `child_idx` of the `parent` node to find the index of the left-most child.
    - Finally, it calls `fd_ghost_node_pool_ele_const` with the node pool and the `child_idx` to get a pointer to the left-most child node.
- **Output**: A constant pointer to the left-most child node of the specified parent node in the GHOST tree.
- **Functions called**:
    - [`fd_ghost_node_pool_const`](#fd_ghost_node_pool_const)


---
### fd\_ghost\_query<!-- {{#callable:fd_ghost_query}} -->
The `fd_ghost_query` function retrieves a node from a GHOST tree based on a given slot number.
- **Inputs**:
    - `ghost`: A pointer to a constant `fd_ghost_t` structure representing the GHOST tree.
    - `slot`: An unsigned long integer representing the slot number used as the key to query the node.
- **Control Flow**:
    - Retrieve the constant node map from the GHOST structure using [`fd_ghost_node_map_const`](#fd_ghost_node_map_const) function.
    - Retrieve the constant node pool from the GHOST structure using [`fd_ghost_node_pool_const`](#fd_ghost_node_pool_const) function.
    - Query the node map for the node corresponding to the given slot using `fd_ghost_node_map_ele_query_const`, passing the node map, slot, and node pool as arguments.
    - Return the node if found, otherwise return NULL.
- **Output**: A pointer to a constant `fd_ghost_node_t` structure representing the node associated with the given slot, or NULL if the node is not found.
- **Functions called**:
    - [`fd_ghost_node_map_const`](#fd_ghost_node_map_const)
    - [`fd_ghost_node_pool_const`](#fd_ghost_node_pool_const)


# Function Declarations (Public API)

---
### fd\_ghost\_new<!-- {{#callable_declaration:fd_ghost_new}} -->
Formats a memory region for use as a GHOST structure.
- **Description**: This function initializes a specified memory region to be used as a GHOST structure, which implements Solana's LMD-GHOST fork choice rule. It should be called with a valid memory region that is part of a workspace, properly aligned, and has sufficient size to accommodate the GHOST structure for the specified number of nodes. The function returns a pointer to the initialized memory region on success, or NULL if any preconditions are not met, such as a NULL memory pointer, misalignment, or an invalid node count.
- **Inputs**:
    - `shmem`: A pointer to the memory region to be formatted as a GHOST structure. Must not be NULL, must be aligned according to fd_ghost_align(), and must be part of a workspace.
    - `seed`: An arbitrary seed value used for internal hashing functions. It can be any unsigned long value.
    - `node_max`: The maximum number of nodes the GHOST structure should support. Must be a valid value that results in a non-zero footprint.
- **Output**: Returns a pointer to the initialized memory region on success, or NULL if the input parameters are invalid or preconditions are not met.
- **See also**: [`fd_ghost_new`](fd_ghost.c.driver.md#fd_ghost_new)  (Implementation)


---
### fd\_ghost\_join<!-- {{#callable_declaration:fd_ghost_join}} -->
Join a caller to a GHOST data structure.
- **Description**: This function is used to join a caller to a GHOST data structure, which is a part of Solana's fork choice rule implementation. It should be called when a process needs to access or manipulate the GHOST structure in its local address space. The function checks for several preconditions: the input pointer must not be null, it must be properly aligned, it must be part of a workspace, and it must have a valid magic number. If any of these conditions are not met, the function logs a warning and returns null. This function is typically used after the GHOST structure has been initialized and formatted for use.
- **Inputs**:
    - `shghost`: A pointer to the shared memory region representing the GHOST structure. It must not be null, must be properly aligned according to fd_ghost_align(), and must be part of a valid workspace. The GHOST structure must have been initialized with the correct magic number.
- **Output**: Returns a pointer to the GHOST structure in the local address space if successful, or null if any preconditions are not met.
- **See also**: [`fd_ghost_join`](fd_ghost.c.driver.md#fd_ghost_join)  (Implementation)


---
### fd\_ghost\_leave<!-- {{#callable_declaration:fd_ghost_leave}} -->
Leaves a current local join to a ghost.
- **Description**: This function is used to leave a current local join to a ghost, returning a pointer to the underlying shared memory region if successful. It should be called when a process no longer needs to interact with a ghost, allowing for proper cleanup and resource management. The function logs a warning and returns NULL if the provided ghost pointer is NULL, indicating an error in usage.
- **Inputs**:
    - `ghost`: A pointer to a constant fd_ghost_t structure representing the ghost to leave. Must not be NULL, as passing a NULL pointer will result in a warning being logged and a NULL return value.
- **Output**: Returns a pointer to the underlying shared memory region on success, or NULL if the ghost pointer is NULL.
- **See also**: [`fd_ghost_leave`](fd_ghost.c.driver.md#fd_ghost_leave)  (Implementation)


---
### fd\_ghost\_delete<!-- {{#callable_declaration:fd_ghost_delete}} -->
Unformats a memory region used as a ghost.
- **Description**: This function is used to unformat a memory region that was previously formatted for use as a ghost, effectively deleting the ghost structure. It should be called when the ghost is no longer needed and only when no processes are joined to the ghost. The function returns a pointer to the underlying shared memory region, transferring ownership of the memory back to the caller. If the provided pointer is null or misaligned, the function logs a warning and returns null.
- **Inputs**:
    - `ghost`: A pointer to the memory region used as a ghost. It must be non-null and properly aligned according to the ghost's alignment requirements. If the pointer is null or misaligned, the function logs a warning and returns null.
- **Output**: Returns a pointer to the underlying shared memory region if successful, or null if the input is invalid.
- **See also**: [`fd_ghost_delete`](fd_ghost.c.driver.md#fd_ghost_delete)  (Implementation)


---
### fd\_ghost\_init<!-- {{#callable_declaration:fd_ghost_init}} -->
Initialize a ghost structure with a specified root slot.
- **Description**: This function initializes a ghost structure, which must be a valid local join and not currently initialized. It sets up the ghost with a specified root slot, which is typically the snapshot slot or 0 for the genesis slot. This function should be called by the process that formatted the ghost's memory, typically the caller of `fd_ghost_new`. It ensures that the ghost is properly initialized and ready for use, with a root node established in its internal tree structure.
- **Inputs**:
    - `ghost`: A pointer to an `fd_ghost_t` structure that represents the ghost to be initialized. This must not be null and should be a valid local join that is not already initialized.
    - `root`: An unsigned long representing the initial root slot for the ghost. It must not be `FD_SLOT_NULL`, as this would indicate an invalid root.
- **Output**: None
- **See also**: [`fd_ghost_init`](fd_ghost.c.driver.md#fd_ghost_init)  (Implementation)


---
### fd\_ghost\_head<!-- {{#callable_declaration:fd_ghost_head}} -->
Finds the heaviest leaf node starting from a given root in a ghost tree.
- **Description**: This function traverses the ghost tree starting from the specified root node and returns the heaviest leaf node based on the subtree weights. It is used to determine the optimal path in the tree according to the LMD-GHOST protocol. The function assumes that the ghost structure is a valid local join and has been initialized with `fd_ghost_init`. The root node must be valid, and the function will return NULL if the root node is not valid or if no valid path is found.
- **Inputs**:
    - `ghost`: A pointer to a constant `fd_ghost_t` structure representing the ghost tree. It must be a valid local join and initialized.
    - `root`: A pointer to a constant `fd_ghost_node_t` representing the starting node for the traversal. It must not be null and should be a valid node within the ghost tree.
- **Output**: Returns a pointer to the heaviest leaf node found during the traversal, or NULL if the root node is invalid or no valid path is found.
- **See also**: [`fd_ghost_head`](fd_ghost.c.driver.md#fd_ghost_head)  (Implementation)


---
### fd\_ghost\_gca<!-- {{#callable_declaration:fd_ghost_gca}} -->
Finds the greatest common ancestor of two slots in a ghost tree.
- **Description**: Use this function to determine the greatest common ancestor (GCA) of two slots within a ghost tree structure. This is useful in scenarios where you need to find a common point of reference between two nodes in the tree. The function assumes that at least one of the slots is present in the ghost tree. If both slots are present, the function guarantees a non-NULL return value. If either slot is missing and handholding is enabled, the function will log a warning and return NULL.
- **Inputs**:
    - `ghost`: A pointer to a constant fd_ghost_t structure representing the ghost tree. This must be a valid, initialized ghost tree that the caller has joined.
    - `slot1`: An unsigned long representing the first slot to find the GCA for. It should be present in the ghost tree; otherwise, a warning is logged and NULL is returned if handholding is enabled.
    - `slot2`: An unsigned long representing the second slot to find the GCA for. It should be present in the ghost tree; otherwise, a warning is logged and NULL is returned if handholding is enabled.
- **Output**: Returns a pointer to the fd_ghost_node_t structure representing the greatest common ancestor of the two slots if both are present. Returns NULL if either slot is missing and handholding is enabled.
- **See also**: [`fd_ghost_gca`](fd_ghost.c.driver.md#fd_ghost_gca)  (Implementation)


---
### fd\_ghost\_is\_ancestor<!-- {{#callable_declaration:fd_ghost_is_ancestor}} -->
Determine if one slot is an ancestor of another in the ghost tree.
- **Description**: Use this function to check if a given slot is an ancestor of another slot within the ghost tree structure. This is useful for validating relationships between nodes in the tree, particularly in the context of fork choice rules. The function assumes that the ghost structure is properly initialized and that the slots provided are valid within the context of the ghost. If either the ancestor or the slot is not present in the ghost, the function will return 0, indicating that the ancestor relationship does not exist.
- **Inputs**:
    - `ghost`: A pointer to a constant fd_ghost_t structure representing the ghost tree. Must not be null and should be a valid, initialized ghost.
    - `ancestor`: An unsigned long representing the slot number of the potential ancestor node. Should be a valid slot within the ghost tree.
    - `slot`: An unsigned long representing the slot number of the node to check against the ancestor. Should be a valid slot within the ghost tree.
- **Output**: Returns 1 if the ancestor is indeed an ancestor of the slot, otherwise returns 0. Also returns 0 if either the ancestor or the slot is not found in the ghost.
- **See also**: [`fd_ghost_is_ancestor`](fd_ghost.c.driver.md#fd_ghost_is_ancestor)  (Implementation)


---
### fd\_ghost\_insert<!-- {{#callable_declaration:fd_ghost_insert}} -->
Inserts a new node into the ghost tree.
- **Description**: This function is used to insert a new node into the ghost tree, keyed by the specified slot. It should be called when you want to add a new node under an existing parent node in the tree. The function assumes that the slot is not already present in the ghost, the parent slot is already present, and there is space available in the node pool. If these conditions are not met, and handholding is enabled, the function will log a warning and return NULL. This function is typically used in scenarios where the tree structure needs to be expanded with new nodes.
- **Inputs**:
    - `ghost`: A pointer to an fd_ghost_t structure representing the ghost tree. Must be a valid, initialized local join.
    - `parent_slot`: The slot number of the parent node under which the new node will be inserted. Must already exist in the ghost tree.
    - `slot`: The slot number for the new node to be inserted. Must not already exist in the ghost tree and must be greater than the root slot.
- **Output**: Returns a pointer to the newly inserted fd_ghost_node_t if successful, or NULL if the insertion fails due to precondition violations.
- **See also**: [`fd_ghost_insert`](fd_ghost.c.driver.md#fd_ghost_insert)  (Implementation)


---
### fd\_ghost\_replay\_vote<!-- {{#callable_declaration:fd_ghost_replay_vote}} -->
Updates the vote for a given slot in the GHOST protocol.
- **Description**: This function updates the vote of a voter for a specific slot in the GHOST protocol, adjusting the stake and weight of the slot and its ancestors accordingly. It should be used when a voter's decision changes, ensuring that only the latest vote is counted. The function assumes that the slot is present in the ghost structure and that the voter's previous vote, if any, is valid. It handles cases where the previous vote was pruned or the slot is less than the root slot, ensuring the integrity of the vote propagation.
- **Inputs**:
    - `ghost`: A pointer to an fd_ghost_t structure representing the GHOST protocol state. Must not be null and should be a valid, initialized ghost.
    - `voter`: A pointer to an fd_voter_t structure representing the voter. Must not be null and should contain valid voting information, including the voter's key and stake.
    - `slot`: An unsigned long representing the slot number to vote for. Must be greater than or equal to the root slot of the ghost structure.
- **Output**: None
- **See also**: [`fd_ghost_replay_vote`](fd_ghost.c.driver.md#fd_ghost_replay_vote)  (Implementation)


---
### fd\_ghost\_gossip\_vote<!-- {{#callable_declaration:fd_ghost_gossip_vote}} -->
Adds stake to the gossip_stake field of a specified slot.
- **Description**: This function is used to add a voter's stake to the gossip_stake field of a specified slot within the ghost structure. It is intended for use in scenarios where gossip votes are being recorded for optimistic confirmation purposes, rather than for fork choice. The function assumes that the specified slot is already present in the ghost structure. If the slot is not present, the function will log an error if handholding is enabled. This function does not propagate the stake to the weight field of the slot or its ancestors.
- **Inputs**:
    - `ghost`: A pointer to an fd_ghost_t structure representing the ghost. Must not be null and should be a valid local join.
    - `voter`: A pointer to an fd_voter_t structure representing the voter. The specifics of this parameter are not detailed in the header.
    - `slot`: An unsigned long integer representing the slot number to which the stake should be added. Must be present in the ghost structure.
- **Output**: None
- **See also**: [`fd_ghost_gossip_vote`](fd_ghost.c.driver.md#fd_ghost_gossip_vote)  (Implementation)


---
### fd\_ghost\_rooted\_vote<!-- {{#callable_declaration:fd_ghost_rooted_vote}} -->
Adds a voter's stake to the rooted stake of a specified slot.
- **Description**: This function is used to add the stake of a voter to the rooted stake of a specified slot within the ghost structure. It should be called when a voter's stake needs to be accounted for in the rooted stake of a slot. The function assumes that the specified slot is present in the ghost structure. If the handholding feature is enabled, the function will check that the specified root slot is not less than the current root slot of the ghost and will log an error if this condition is violated. This function is typically used in the context of maintaining the integrity of the fork choice rule by ensuring that rooted stakes are accurately tracked.
- **Inputs**:
    - `ghost`: A pointer to an fd_ghost_t structure representing the ghost context. Must be a valid, initialized local join of the ghost.
    - `voter`: A pointer to an fd_voter_t structure representing the voter whose stake is being added. Must not be null.
    - `root`: An unsigned long representing the slot to which the voter's stake should be added. Must be greater than or equal to the current root slot of the ghost if handholding is enabled.
- **Output**: None
- **See also**: [`fd_ghost_rooted_vote`](fd_ghost.c.driver.md#fd_ghost_rooted_vote)  (Implementation)


---
### fd\_ghost\_publish<!-- {{#callable_declaration:fd_ghost_publish}} -->
Publishes a specified slot as the new root of the ghost tree.
- **Description**: This function sets the specified slot as the new root of the ghost tree, effectively making the subtree starting from this slot the new ghost tree. It prunes all nodes that are not in the ancestry of the specified slot. This function should be called when you want to update the root of the ghost tree to a new slot that is already present in the ghost. It is important to ensure that the slot is valid and present in the ghost before calling this function, as it assumes the slot exists and will return the new root node on success.
- **Inputs**:
    - `ghost`: A pointer to an fd_ghost_t structure representing the ghost tree. Must be a valid, initialized local join of the ghost.
    - `slot`: An unsigned long integer representing the slot to be published as the new root. Must be present in the ghost and should be greater than the current root slot.
- **Output**: Returns a pointer to the new root node of the ghost tree if successful, or NULL if the slot is invalid or not present in the ghost.
- **See also**: [`fd_ghost_publish`](fd_ghost.c.driver.md#fd_ghost_publish)  (Implementation)


---
### fd\_ghost\_verify<!-- {{#callable_declaration:fd_ghost_verify}} -->
Verifies the integrity and consistency of a ghost structure.
- **Description**: Use this function to check if a given ghost structure is valid and maintains its internal invariants. It should be called when you need to ensure that the ghost structure is not corrupt and that the weight of each node is greater than or equal to the sum of the weights of its children. This function is useful for debugging and validation purposes, especially after modifications to the ghost structure. It returns an error if the ghost is null, misaligned, not part of a workspace, has an incorrect magic number, or if the version query indicates the ghost is uninitialized or invalid.
- **Inputs**:
    - `ghost`: A pointer to the ghost structure to be verified. It must not be null, must be properly aligned, and must be part of a workspace. The structure should have been initialized and should contain a valid magic number. If any of these conditions are not met, the function will return an error.
- **Output**: Returns 0 if the ghost structure is valid and consistent, otherwise returns -1 if any validation checks fail.
- **See also**: [`fd_ghost_verify`](fd_ghost.c.driver.md#fd_ghost_verify)  (Implementation)


---
### fd\_ghost\_print<!-- {{#callable_declaration:fd_ghost_print}} -->
Pretty-prints a formatted ghost tree starting from a specified node.
- **Description**: Use this function to output a human-readable representation of a ghost tree, starting from a specified node, which will appear as the root in the print output. This function is useful for debugging or visualizing the structure of the ghost tree. It is typically called with the root node to print the entire tree, but can also be used to print a subtree by specifying a different starting node. Ensure that the ghost and node parameters are valid and that the ghost has been properly initialized before calling this function.
- **Inputs**:
    - `ghost`: A pointer to a constant fd_ghost_t structure representing the ghost tree to be printed. Must not be null and should be a valid, initialized ghost.
    - `epoch`: A pointer to a constant fd_epoch_t structure providing context for the print operation. Must not be null.
    - `node`: A pointer to a constant fd_ghost_node_t structure representing the starting node for the print operation. Must not be null and should be a valid node within the ghost tree.
- **Output**: None
- **See also**: [`fd_ghost_print`](fd_ghost.c.driver.md#fd_ghost_print)  (Implementation)


