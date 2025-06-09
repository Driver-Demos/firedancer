# Purpose
This C source code file is part of a larger system that manages a workspace's memory allocation using a data structure known as a treap, which is a combination of a binary search tree and a heap. The file provides three main functions: [`fd_wksp_private_used_treap_query`](#fd_wksp_private_used_treap_query), [`fd_wksp_private_used_treap_insert`](#fd_wksp_private_used_treap_insert), and [`fd_wksp_private_used_treap_remove`](#fd_wksp_private_used_treap_remove). These functions are responsible for querying, inserting, and removing nodes in the treap, respectively. The treap is used to manage partitions of memory within a workspace, ensuring that memory allocations are efficiently tracked and managed. The code includes mechanisms to handle edge cases such as cycles in the treap and invalid memory ranges, ensuring robustness in memory management operations.

The file is not a standalone executable but rather a component of a larger library or system, as indicated by the inclusion of a private header file (`fd_wksp_private.h`) and the use of macros and functions that are likely defined elsewhere in the system. The functions defined in this file are likely intended for internal use within the system, as suggested by the use of the "private" naming convention. The code is highly specialized, focusing on the manipulation of the treap data structure to maintain the integrity and efficiency of memory management within the workspace. The use of macros like `TEST`, `TEST_AND_MARK`, and `TEST_PARENT` indicates a focus on ensuring the correctness of operations, particularly in maintaining the structural properties of the treap during insertions and deletions.
# Imports and Dependencies

---
- `fd_wksp_private.h`


# Functions

---
### fd\_wksp\_private\_used\_treap\_query<!-- {{#callable:fd_wksp_private_used_treap_query}} -->
The function `fd_wksp_private_used_treap_query` searches for a given global address within a workspace's used partition treap and returns the index of the partition containing the address, or a null index if not found or if an error occurs.
- **Inputs**:
    - `gaddr`: The global address to be queried within the workspace's used partition treap.
    - `wksp`: A pointer to the `fd_wksp_t` structure representing the workspace containing the treap.
    - `pinfo`: A pointer to an array of `fd_wksp_private_pinfo_t` structures, which hold information about each partition in the treap.
- **Control Flow**:
    - Check if the given global address `gaddr` is within the valid range defined by `wksp->gaddr_lo` and `wksp->gaddr_hi`; if not, return a null index.
    - Initialize `part_max` with the maximum number of partitions and increment the `cycle_tag` to mark the current search cycle.
    - Start from the root of the treap using `wksp->part_used_cidx` and iterate through the treap nodes.
    - For each node, check if the index is valid and if the node has already been visited in the current cycle; if any check fails, return a null index.
    - Mark the current node as visited by setting its `cycle_tag`.
    - Compare `gaddr` with the current node's address range (`gaddr_lo` and `gaddr_hi`); if `gaddr` is less, move to the left child; if greater or equal, move to the right child.
    - If `gaddr` falls within the current node's range, break the loop and return the current index.
- **Output**: Returns the index of the partition containing the given global address, or `FD_WKSP_PRIVATE_PINFO_IDX_NULL` if the address is not found or an error occurs.
- **Functions called**:
    - [`fd_wksp_private_pinfo_idx`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_idx)
    - [`fd_wksp_private_pinfo_idx_is_null`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_idx_is_null)


---
### fd\_wksp\_private\_used\_treap\_insert<!-- {{#callable:fd_wksp_private_used_treap_insert}} -->
The function `fd_wksp_private_used_treap_insert` inserts a node into a treap data structure within a workspace, ensuring the treap properties are maintained.
- **Inputs**:
    - `n`: The index of the node to be inserted into the treap.
    - `wksp`: A pointer to the workspace structure (`fd_wksp_t`) that contains the treap and related metadata.
    - `pinfo`: An array of `fd_wksp_private_pinfo_t` structures that hold information about each node in the treap.
- **Control Flow**:
    - Check if the index `n` is valid and within the bounds of `part_max` and mark it with the current `cycle_tag`.
    - Retrieve the global address range (`gaddr_lo` and `gaddr_hi`) for the node `n` and validate it against the workspace's address range.
    - If the treap is empty, set `n` as the root node and return success.
    - Traverse the treap to find the appropriate leaf node where `n` can be inserted, checking left or right based on address comparisons.
    - If an overlap is detected with an existing node, return an error indicating corruption.
    - Insert `n` as a child of the found node, potentially breaking the heap property temporarily.
    - Bubble up `n` to restore the heap property by comparing priorities and adjusting parent-child relationships as needed.
    - Return success after the node is correctly inserted and the treap properties are maintained.
- **Output**: Returns `FD_WKSP_SUCCESS` on successful insertion or `FD_WKSP_ERR_CORRUPT` if an overlap or corruption is detected.
- **Functions called**:
    - [`fd_wksp_private_pinfo_idx`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_idx)
    - [`fd_wksp_private_pinfo_idx_is_null`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_idx_is_null)
    - [`fd_wksp_private_pinfo_cidx`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_cidx)


---
### fd\_wksp\_private\_used\_treap\_remove<!-- {{#callable:fd_wksp_private_used_treap_remove}} -->
The function `fd_wksp_private_used_treap_remove` removes a node from a used treap data structure, ensuring the treap properties are maintained.
- **Inputs**:
    - `d`: The index of the node to be removed from the treap.
    - `wksp`: A pointer to the workspace structure containing the treap.
    - `pinfo`: An array of private partition information structures, representing the nodes of the treap.
- **Control Flow**:
    - Initialize `part_max` and increment `cycle_tag` from the workspace.
    - Validate that `d` is within bounds and mark it with the current `cycle_tag`.
    - Ensure `d` is not part of a 'same' list and has no overlapping partitions.
    - Load and validate the left, right, and parent indices of `d`, marking them with `cycle_tag`.
    - Determine the pointer to the child index of the parent or the root if `d` is the root.
    - Enter a loop to fill the hole left by `d` in the treap.
    - If the left subtree is null, replace the hole with the right subtree and exit the loop.
    - If the right subtree is null, replace the hole with the left subtree and exit the loop.
    - If both subtrees exist, decide whether to promote the left or right subtree based on heap priorities, and adjust pointers accordingly.
    - Repeat the loop until the hole is filled.
    - Clear the links and 'in_same' status of `d` to finalize its removal.
- **Output**: Returns `FD_WKSP_SUCCESS` upon successful removal of the node from the treap.
- **Functions called**:
    - [`fd_wksp_private_pinfo_idx_is_null`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_idx_is_null)
    - [`fd_wksp_private_pinfo_idx`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_idx)
    - [`fd_wksp_private_pinfo_cidx`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_cidx)


