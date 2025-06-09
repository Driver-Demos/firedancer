# Purpose
The provided C source code file implements a set of functions for managing a data structure referred to as "ghost," which appears to be a specialized tree or graph structure used for tracking nodes and their relationships in a shared memory context. The code is designed to handle operations such as creating, joining, leaving, deleting, and verifying the integrity of these ghost structures. It also includes functions for inserting nodes, replaying votes, publishing nodes, and determining relationships between nodes, such as finding the greatest common ancestor or checking if one node is an ancestor of another.

The file defines a public API for interacting with ghost structures, with functions like [`fd_ghost_new`](#fd_ghost_new), [`fd_ghost_join`](#fd_ghost_join), [`fd_ghost_insert`](#fd_ghost_insert), and [`fd_ghost_publish`](#fd_ghost_publish). These functions are designed to be used in a shared memory environment, as indicated by the frequent checks for memory alignment and workspace containment. The code also includes mechanisms for handling errors and logging warnings, ensuring robustness in various scenarios. Additionally, the file contains a static function for incrementing version numbers and a macro for managing version increments, which suggests a focus on maintaining consistency and version control within the ghost structures. Overall, the code provides a comprehensive set of tools for managing and interacting with ghost structures in a concurrent or distributed system.
# Imports and Dependencies

---
- `fd_ghost.h`
- `stdio.h`


# Functions

---
### ver\_inc<!-- {{#callable:ver_inc}} -->
The `ver_inc` function increments the version number pointed to by a given pointer to a pointer to an unsigned long integer.
- **Inputs**:
    - `ver`: A pointer to a pointer to an unsigned long integer, representing the version number to be incremented.
- **Control Flow**:
    - The function calls `fd_fseq_query` with the dereferenced `ver` to get the current version number.
    - It increments the retrieved version number by 1.
    - It then calls `fd_fseq_update` with the dereferenced `ver` and the incremented version number to update the version.
- **Output**: The function does not return a value; it updates the version number in place.


---
### fd\_ghost\_new<!-- {{#callable:fd_ghost_new}} -->
The `fd_ghost_new` function initializes a new ghost data structure in shared memory, setting up its components and returning the memory address if successful.
- **Inputs**:
    - `shmem`: A pointer to the shared memory where the ghost structure will be initialized.
    - `seed`: An unsigned long integer used as a seed for initializing the node map.
    - `node_max`: An unsigned long integer specifying the maximum number of nodes the ghost structure can handle.
- **Control Flow**:
    - Check if the `shmem` pointer is NULL and log a warning if so, returning NULL.
    - Verify if `shmem` is properly aligned according to `fd_ghost_align()` and log a warning if not, returning NULL.
    - Calculate the memory footprint required for the ghost structure using `fd_ghost_footprint(node_max)` and log a warning if it is zero, returning NULL.
    - Determine the workspace containing `shmem` using `fd_wksp_containing(shmem)` and log a warning if it is not part of a workspace, returning NULL.
    - Clear the memory at `shmem` for the calculated footprint size using `fd_memset`.
    - Initialize scratch allocation with `FD_SCRATCH_ALLOC_INIT` and allocate memory for the ghost structure and its components using `FD_SCRATCH_ALLOC_APPEND`.
    - Verify that the scratch allocation finalization matches the expected memory layout using `FD_SCRATCH_ALLOC_FINI`.
    - Set up the ghost structure's global addresses for version, node pool, and node map using `fd_wksp_gaddr_fast`.
    - Initialize the ghost structure's fields such as `seed`, `root_idx`, and `magic`.
    - Return the `shmem` pointer after successful initialization.
- **Output**: Returns the `shmem` pointer if the ghost structure is successfully initialized, or NULL if any error occurs during the process.
- **Functions called**:
    - [`fd_ghost_align`](fd_ghost.h.driver.md#fd_ghost_align)
    - [`fd_ghost_footprint`](fd_ghost.h.driver.md#fd_ghost_footprint)


---
### fd\_ghost\_join<!-- {{#callable:fd_ghost_join}} -->
The `fd_ghost_join` function validates and returns a pointer to a `fd_ghost_t` structure if it meets certain alignment, workspace, and magic number criteria.
- **Inputs**:
    - `shghost`: A void pointer to a shared memory region that is expected to be a `fd_ghost_t` structure.
- **Control Flow**:
    - Cast the input `shghost` to a `fd_ghost_t` pointer named `ghost`.
    - Check if `ghost` is NULL; if so, log a warning and return NULL.
    - Check if `ghost` is aligned according to [`fd_ghost_align`](fd_ghost.h.driver.md#fd_ghost_align); if not, log a warning and return NULL.
    - Retrieve the workspace containing `ghost` using `fd_wksp_containing`; if it is NULL, log a warning and return NULL.
    - Check if the `magic` field of `ghost` matches `FD_GHOST_MAGIC`; if not, log a warning and return NULL.
    - If all checks pass, return the `ghost` pointer.
- **Output**: Returns a pointer to the `fd_ghost_t` structure if all checks pass, otherwise returns NULL.
- **Functions called**:
    - [`fd_ghost_align`](fd_ghost.h.driver.md#fd_ghost_align)


---
### fd\_ghost\_leave<!-- {{#callable:fd_ghost_leave}} -->
The `fd_ghost_leave` function checks if a given `fd_ghost_t` pointer is non-null and returns it cast to a `void*`, or logs a warning and returns `NULL` if it is null.
- **Inputs**:
    - `ghost`: A constant pointer to an `fd_ghost_t` structure, representing the ghost object to be left.
- **Control Flow**:
    - Check if the `ghost` pointer is null using `FD_UNLIKELY` macro.
    - If `ghost` is null, log a warning message 'NULL ghost' and return `NULL`.
    - If `ghost` is not null, return the `ghost` pointer cast to a `void*`.
- **Output**: Returns a `void*` pointing to the `ghost` if it is non-null, otherwise returns `NULL`.


---
### fd\_ghost\_delete<!-- {{#callable:fd_ghost_delete}} -->
The `fd_ghost_delete` function checks if a given ghost pointer is valid and aligned, and returns it if so, otherwise logs a warning and returns NULL.
- **Inputs**:
    - `ghost`: A pointer to the ghost object that is to be deleted.
- **Control Flow**:
    - Check if the `ghost` pointer is NULL; if so, log a warning and return NULL.
    - Check if the `ghost` pointer is aligned according to [`fd_ghost_align`](fd_ghost.h.driver.md#fd_ghost_align); if not, log a warning and return NULL.
    - Return the `ghost` pointer.
- **Output**: Returns the `ghost` pointer if it is valid and aligned, otherwise returns NULL.
- **Functions called**:
    - [`fd_ghost_align`](fd_ghost.h.driver.md#fd_ghost_align)


---
### fd\_ghost\_init<!-- {{#callable:fd_ghost_init}} -->
The `fd_ghost_init` function initializes a ghost data structure with a specified root node.
- **Inputs**:
    - `ghost`: A pointer to an `fd_ghost_t` structure that represents the ghost data structure to be initialized.
    - `root`: An unsigned long integer representing the root node's slot value to initialize the ghost with.
- **Control Flow**:
    - Check if the `ghost` pointer is NULL and log a warning if it is, then return.
    - Check if the `root` is equal to `FD_SLOT_NULL` and log a warning if it is, then return.
    - Check if the ghost is already initialized by querying its version and log a warning if it is, then return.
    - Retrieve the node pool and node map associated with the ghost.
    - Check if the ghost's root index is not equal to the null index of the node pool and log a warning if it is already initialized, then return.
    - Acquire a new node from the node pool, initialize it as the root node with the given slot, and set its indices to null.
    - Insert the root node into the node map and update the ghost's root index with the index of the newly inserted root node.
    - Perform sanity checks to ensure the root node is correctly initialized and linked.
    - Update the ghost's version to indicate successful initialization.
- **Output**: The function does not return a value; it initializes the ghost data structure in place.
- **Functions called**:
    - [`fd_ghost_ver`](fd_ghost.h.driver.md#fd_ghost_ver)
    - [`fd_ghost_root`](fd_ghost.h.driver.md#fd_ghost_root)
    - [`fd_ghost_query`](fd_ghost.h.driver.md#fd_ghost_query)


---
### fd\_ghost\_verify<!-- {{#callable:fd_ghost_verify}} -->
The `fd_ghost_verify` function checks the validity and integrity of a `fd_ghost_t` structure by performing a series of validation checks on its alignment, workspace membership, magic number, initialization state, and node relationships.
- **Inputs**:
    - `ghost`: A pointer to a constant `fd_ghost_t` structure that represents the ghost object to be verified.
- **Control Flow**:
    - Check if the `ghost` pointer is NULL and log a warning if it is, returning -1.
    - Verify that the `ghost` pointer is properly aligned according to `fd_ghost_align()` and log a warning if it is not, returning -1.
    - Determine if the `ghost` is part of a workspace using `fd_wksp_containing()` and log a warning if it is not, returning -1.
    - Check if the `magic` field of `ghost` matches `FD_GHOST_MAGIC` and log a warning if it does not, returning -1.
    - Query the version of the `ghost` using `fd_fseq_query()` and log a warning if it is uninitialized or invalid (equal to `ULONG_MAX`), returning -1.
    - Retrieve the node pool and node map associated with the `ghost`.
    - Verify that every element in the node pool exists in the node map using `fd_ghost_node_map_verify()` and return -1 if verification fails.
    - Iterate over each node starting from the root, checking that each node's weight is greater than or equal to the sum of its children's weights, logging a warning if this condition is violated (only if `FD_GHOST_USE_HANDHOLDING` is defined).
    - Return 0 if all checks pass, indicating the `ghost` is valid.
- **Output**: Returns 0 if the `ghost` is valid, otherwise returns -1 if any validation check fails.
- **Functions called**:
    - [`fd_ghost_align`](fd_ghost.h.driver.md#fd_ghost_align)
    - [`fd_ghost_ver`](fd_ghost.h.driver.md#fd_ghost_ver)
    - [`fd_ghost_node_pool_const`](fd_ghost.h.driver.md#fd_ghost_node_pool_const)
    - [`fd_ghost_node_map_const`](fd_ghost.h.driver.md#fd_ghost_node_map_const)
    - [`fd_ghost_root`](fd_ghost.h.driver.md#fd_ghost_root)


---
### fd\_ghost\_insert<!-- {{#callable:fd_ghost_insert}} -->
The `fd_ghost_insert` function inserts a new node into a ghost data structure, linking it to a specified parent node and updating the node map for efficient access.
- **Inputs**:
    - `ghost`: A pointer to the `fd_ghost_t` structure representing the ghost data structure where the node will be inserted.
    - `parent_slot`: An unsigned long integer representing the slot of the parent node to which the new node will be linked.
    - `slot`: An unsigned long integer representing the slot of the new node to be inserted.
- **Control Flow**:
    - Increment the version counter using `VER_INC` macro.
    - Log the insertion attempt with the slot and parent slot values.
    - Retrieve the node map and node pool from the ghost structure.
    - Check if the slot is already in the ghost, if the parent slot exists, if there is space in the node pool, and if the slot is greater than the root slot (only if handholding is enabled).
    - Acquire a new node element from the node pool and initialize it with the given slot and default values for other fields.
    - Insert the new node into the node map for O(1) access.
    - Link the new node to its parent by setting the parent index.
    - If the parent has no children, set the new node as the left-most child; otherwise, find the right-most sibling and link the new node as its sibling.
    - Return the newly created node.
- **Output**: Returns a pointer to the newly created `fd_ghost_node_t` node if successful, or `NULL` if the insertion fails due to various conditions checked during handholding.
- **Functions called**:
    - [`fd_ghost_root`](fd_ghost.h.driver.md#fd_ghost_root)
    - [`fd_ghost_query`](fd_ghost.h.driver.md#fd_ghost_query)


---
### fd\_ghost\_head<!-- {{#callable:fd_ghost_head}} -->
The `fd_ghost_head` function traverses a tree of ghost nodes starting from a given root node to find the heaviest valid head node.
- **Inputs**:
    - `ghost`: A pointer to a constant `fd_ghost_t` structure representing the ghost context.
    - `root`: A pointer to a constant `fd_ghost_node_t` structure representing the root node of the tree to be traversed.
- **Control Flow**:
    - If handholding is enabled, the function checks the magic number of the ghost and the validity of the root node.
    - If the root node is not valid, the function returns NULL immediately.
    - The function retrieves the node pool from the ghost context and initializes the head to the root node.
    - It enters a loop to traverse the tree, checking if the current head node has a valid child index.
    - Within the loop, it iterates over the children of the current head node, looking for the heaviest valid child node.
    - If a valid child is found, it updates the head to this child node, using weight and slot number to determine the heaviest child.
    - If no valid children are found, the loop breaks, ending the traversal.
    - The function returns the final head node, which is the heaviest valid node found.
- **Output**: A pointer to the heaviest valid `fd_ghost_node_t` node found, or NULL if no valid head exists.
- **Functions called**:
    - [`fd_ghost_node_pool_const`](fd_ghost.h.driver.md#fd_ghost_node_pool_const)


---
### fd\_ghost\_replay\_vote<!-- {{#callable:fd_ghost_replay_vote}} -->
The `fd_ghost_replay_vote` function updates the voting state of a voter in a ghost protocol by adjusting their stake in the current and previous vote slots.
- **Inputs**:
    - `ghost`: A pointer to an `fd_ghost_t` structure representing the ghost protocol state.
    - `voter`: A pointer to an `fd_voter_t` structure representing the voter whose vote is being replayed.
    - `slot`: An unsigned long integer representing the slot number for the current vote.
- **Control Flow**:
    - Increment the version counter using the `VER_INC` macro.
    - Log the debug information about the current vote slot, voter's public key, and stake.
    - Retrieve the node map and node pool from the ghost structure.
    - Check if the current vote slot is less than the root slot and log an error if so (only if handholding is enabled).
    - If the voter's previous vote is null, break out of the loop as it's the first vote from this pubkey.
    - If the current slot is less than or equal to the voter's last vote, return early as votes must be monotonically increasing.
    - If the previous vote slot is less than the root slot, break as it was pruned.
    - Query the node map for the previous vote slot; if not found, log a warning and break.
    - Subtract the voter's stake from the previous vote node and its ancestors, checking for underflow if handholding is enabled.
    - Query the node map for the current slot and add the voter's stake to the node and its ancestors, checking for overflow if handholding is enabled.
    - Update the voter's replay vote to the current slot.
- **Output**: The function does not return a value; it updates the state of the ghost protocol and the voter in place.
- **Functions called**:
    - [`fd_ghost_root`](fd_ghost.h.driver.md#fd_ghost_root)


---
### fd\_ghost\_gossip\_vote<!-- {{#callable:fd_ghost_gossip_vote}} -->
The `fd_ghost_gossip_vote` function is a placeholder for a function intended to handle gossip voting in a ghost protocol, but it is currently unimplemented.
- **Inputs**:
    - `ghost`: A pointer to an `fd_ghost_t` structure, representing the ghost protocol state.
    - `voter`: A pointer to an `fd_voter_t` structure, representing the voter information.
    - `slot`: An unsigned long integer representing the slot number for the vote.
- **Control Flow**:
    - The function is defined but not implemented, as indicated by the `FD_LOG_ERR(( "unimplemented" ));` statement.
    - When called, it logs an error message indicating that the function is unimplemented.
- **Output**: The function does not return any value or output, as it is a void function and currently unimplemented.


---
### fd\_ghost\_rooted\_vote<!-- {{#callable:fd_ghost_rooted_vote}} -->
The `fd_ghost_rooted_vote` function updates the rooted stake of a node in a ghost DAG structure based on a voter's stake and a specified root slot.
- **Inputs**:
    - `ghost`: A pointer to an `fd_ghost_t` structure representing the ghost DAG.
    - `voter`: A pointer to an `fd_voter_t` structure representing the voter whose stake is being added.
    - `root`: An unsigned long integer representing the root slot for which the vote is being cast.
- **Control Flow**:
    - Increment the version counter using the `VER_INC` macro.
    - Log the debug information including the function name, root, voter's public key, and stake.
    - Retrieve the node map and node pool from the ghost structure.
    - Retrieve the current root node from the ghost structure.
    - If handholding is enabled, check if the provided root is less than the current root node's slot and log an error if so.
    - Query the node map for the node corresponding to the provided root slot.
    - If handholding is enabled, check if the node is NULL and log an error if so.
    - Add the voter's stake to the `rooted_stake` of the node.
- **Output**: The function does not return a value; it modifies the `rooted_stake` of a node in the ghost DAG in place.
- **Functions called**:
    - [`fd_ghost_root`](fd_ghost.h.driver.md#fd_ghost_root)


---
### fd\_ghost\_publish<!-- {{#callable:fd_ghost_publish}} -->
The `fd_ghost_publish` function updates the root of a ghost tree to a new slot, pruning the old root and its descendants except for the new root.
- **Inputs**:
    - `ghost`: A pointer to the `fd_ghost_t` structure representing the ghost tree.
    - `slot`: An unsigned long integer representing the slot number to be published as the new root.
- **Control Flow**:
    - Log the function call with the slot number.
    - Increment the version counter using `VER_INC`.
    - Retrieve the node map, node pool, and current root node from the ghost structure.
    - Check if the slot is older or the same as the current root's slot, logging a warning and returning NULL if so (only if handholding is enabled).
    - Query the node map for the new root node corresponding to the given slot.
    - If the new root node is not found, log an error and return NULL (only if handholding is enabled).
    - Remove the current root node from the node map and add it to the prune list.
    - Perform a breadth-first search (BFS) to traverse and prune the tree, excluding the new root node.
    - For each node in the BFS, remove it from the node map and add it to the prune list, ensuring not to prune the new root.
    - Release the memory of each pruned node.
    - Unlink the new root from its parent and update the ghost's root index to the new root's index.
    - Return the new root node.
- **Output**: A pointer to the `fd_ghost_node_t` structure representing the new root node, or NULL if an error occurs.
- **Functions called**:
    - [`fd_ghost_root`](fd_ghost.h.driver.md#fd_ghost_root)


---
### fd\_ghost\_gca<!-- {{#callable:fd_ghost_gca}} -->
The `fd_ghost_gca` function finds the greatest common ancestor (GCA) of two nodes identified by their slots in a ghost data structure.
- **Inputs**:
    - `ghost`: A pointer to a constant `fd_ghost_t` structure representing the ghost data structure.
    - `slot1`: An unsigned long integer representing the slot of the first node.
    - `slot2`: An unsigned long integer representing the slot of the second node.
- **Control Flow**:
    - Retrieve the constant node pool from the ghost structure.
    - Query the ghost structure to get the nodes corresponding to `slot1` and `slot2`.
    - If handholding is enabled, check if either node is missing and log a warning if so, returning NULL.
    - Iterate through the nodes' ancestry until a common ancestor is found or one of the nodes becomes NULL.
    - If a common ancestor is found (nodes have the same slot), return that node.
    - If no common ancestor is found, log an error indicating the ghost might be invalid.
- **Output**: Returns a pointer to the `fd_ghost_node_t` structure representing the greatest common ancestor of the two nodes, or NULL if no common ancestor is found or if an error occurs.
- **Functions called**:
    - [`fd_ghost_node_pool_const`](fd_ghost.h.driver.md#fd_ghost_node_pool_const)
    - [`fd_ghost_query`](fd_ghost.h.driver.md#fd_ghost_query)


---
### fd\_ghost\_is\_ancestor<!-- {{#callable:fd_ghost_is_ancestor}} -->
The `fd_ghost_is_ancestor` function checks if a given ancestor node is part of the ancestry of a specified node in a ghost data structure.
- **Inputs**:
    - `ghost`: A pointer to a constant `fd_ghost_t` structure representing the ghost data structure.
    - `ancestor`: An unsigned long integer representing the slot number of the potential ancestor node.
    - `slot`: An unsigned long integer representing the slot number of the node whose ancestry is being checked.
- **Control Flow**:
    - Retrieve the root node of the ghost data structure using [`fd_ghost_root`](fd_ghost.h.driver.md#fd_ghost_root) and the current node using [`fd_ghost_query`](fd_ghost.h.driver.md#fd_ghost_query) for the given slot.
    - If handholding is enabled, check if the ancestor slot is older than the root slot and log a warning if true, returning 0.
    - If handholding is enabled, check if the current node is NULL and log a warning if true, returning 0.
    - Iterate through the ancestry of the current node while the current node exists and its slot is greater than or equal to the ancestor slot.
    - If the current node's slot matches the ancestor slot, return 1 indicating the ancestor is found.
    - Move to the parent node of the current node using `fd_ghost_node_pool_ele_const`.
    - If the loop completes without finding the ancestor, return 0 indicating the ancestor is not found.
- **Output**: Returns an integer: 1 if the ancestor is found in the ancestry of the node, 0 otherwise.
- **Functions called**:
    - [`fd_ghost_root`](fd_ghost.h.driver.md#fd_ghost_root)
    - [`fd_ghost_query`](fd_ghost.h.driver.md#fd_ghost_query)
    - [`fd_ghost_node_pool_const`](fd_ghost.h.driver.md#fd_ghost_node_pool_const)


---
### print<!-- {{#callable:print}} -->
The `print` function recursively prints a tree structure of nodes with their weights and percentages, formatted with prefixes to indicate tree branches.
- **Inputs**:
    - `ghost`: A pointer to a constant `fd_ghost_t` structure representing the ghost context.
    - `node`: A pointer to a constant `fd_ghost_node_t` structure representing the current node to print.
    - `space`: An integer representing the number of spaces to indent the current node's output.
    - `prefix`: A constant character pointer used as a prefix for the current node's output, indicating tree structure.
    - `total`: An unsigned long integer representing the total weight of the tree, used to calculate percentage weights of nodes.
- **Control Flow**:
    - Check if the `node` is NULL and return if true.
    - Print a newline if `space` is greater than 0, then print `space` number of spaces.
    - Check if `node->weight` is greater than 100, but no action is taken in this case.
    - If `total` is 0, print the node's slot and weight with the prefix.
    - Otherwise, calculate the percentage of the node's weight relative to `total` and print it with the prefix, slot, and weight.
    - Retrieve the first child of the current node from the node pool.
    - Iterate over each child node, determining if it has siblings to set the appropriate prefix ('├── ' for more siblings, '└── ' for the last sibling).
    - Recursively call `print` for each child node with updated space and prefix values.
- **Output**: The function does not return a value; it outputs formatted text to the standard output.
- **Functions called**:
    - [`fd_ghost_node_pool_const`](fd_ghost.h.driver.md#fd_ghost_node_pool_const)


---
### fd\_ghost\_print<!-- {{#callable:fd_ghost_print}} -->
The `fd_ghost_print` function logs and prints a visual representation of a ghost node tree structure, starting from a specified node, with percentage weights relative to the total stake of an epoch.
- **Inputs**:
    - `ghost`: A pointer to a constant `fd_ghost_t` structure representing the ghost data structure to be printed.
    - `epoch`: A pointer to a constant `fd_epoch_t` structure containing the total stake information for the epoch.
    - `node`: A pointer to a constant `fd_ghost_node_t` structure representing the starting node of the ghost tree to be printed.
- **Control Flow**:
    - Logs the start of the ghost print with a notice message.
    - Calls the [`print`](#print) function to recursively print the ghost node tree starting from the specified node, using the total stake from the epoch to calculate percentage weights.
    - Prints a newline after the tree representation.
- **Output**: This function does not return any value; it performs logging and printing operations.
- **Functions called**:
    - [`print`](#print)


