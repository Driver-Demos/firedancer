# Purpose
This C source code file is part of a larger system that manages a workspace, specifically focusing on the management of free memory partitions using a data structure known as a treap. The file defines three primary functions: [`fd_wksp_private_free_treap_query`](#fd_wksp_private_free_treap_query), [`fd_wksp_private_free_treap_insert`](#fd_wksp_private_free_treap_insert), and [`fd_wksp_private_free_treap_remove`](#fd_wksp_private_free_treap_remove). These functions are responsible for querying, inserting, and removing partitions within the treap, respectively. The treap is a combination of a binary search tree and a heap, which allows for efficient searching, insertion, and deletion operations. The code is designed to handle memory partitions, ensuring that operations maintain the integrity of the treap structure by checking for cycles, validating indices, and preserving the heap property during insertions and deletions.

The file is not a standalone executable but rather a component of a larger library or system, as indicated by the inclusion of a private header file (`fd_wksp_private.h`) and the use of specific data types and macros that are likely defined elsewhere in the project. The functions defined in this file are likely intended for internal use within the workspace management system, as suggested by the use of the "private" naming convention. The code includes several macros for testing conditions and maintaining the treap's structure, which are crucial for ensuring the correctness and robustness of the operations performed on the treap. Overall, this file provides specialized functionality for managing memory partitions within a workspace, leveraging the properties of a treap to achieve efficient memory management.
# Imports and Dependencies

---
- `fd_wksp_private.h`


# Functions

---
### fd\_wksp\_private\_free\_treap\_query<!-- {{#callable:fd_wksp_private_free_treap_query}} -->
The function `fd_wksp_private_free_treap_query` searches for a free partition in a workspace treap that can accommodate a given size and returns its index.
- **Inputs**:
    - `sz`: The size of the partition being queried.
    - `wksp`: A pointer to the workspace structure containing the treap.
    - `pinfo`: A pointer to an array of partition information structures.
- **Control Flow**:
    - Check if the size `sz` is zero; if so, return a null index.
    - Initialize the result index `f` to null and retrieve the maximum partition index `part_max` and the current cycle tag from the workspace.
    - Start iterating from the root of the free partition treap using the index from `wksp->part_free_cidx`.
    - In each iteration, check if the current index `i` is valid and not part of a cycle; if invalid or part of a cycle, return a null index.
    - Mark the current index `i` as visited by setting its cycle tag.
    - Retrieve the size of the current partition and compare it with `sz`.
    - If `sz` is greater than the current partition size, move to the right child; otherwise, update `f` to the current index and move to the left child if `sz` is not an exact match.
    - If an exact match is found, break the loop.
    - Return the index `f` of the suitable partition.
- **Output**: The function returns the index of a free partition that can accommodate the requested size, or a null index if no suitable partition is found.
- **Functions called**:
    - [`fd_wksp_private_pinfo_idx`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_idx)
    - [`fd_wksp_private_pinfo_idx_is_null`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_idx_is_null)
    - [`fd_wksp_private_pinfo_sz`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_sz)


---
### fd\_wksp\_private\_free\_treap\_insert<!-- {{#callable:fd_wksp_private_free_treap_insert}} -->
The function `fd_wksp_private_free_treap_insert` inserts a partition into a free treap data structure, maintaining the heap property and handling cases where partitions have the same size.
- **Inputs**:
    - `n`: The index of the partition to be inserted into the treap.
    - `wksp`: A pointer to the workspace structure containing the treap and related metadata.
    - `pinfo`: An array of partition information structures, where each element corresponds to a partition in the workspace.
- **Control Flow**:
    - Validate that the index `n` is within the valid range and mark it with the current cycle tag.
    - Calculate the size of the partition to be inserted and validate its address range within the workspace.
    - If the treap is empty, set the partition as the root and return success.
    - Traverse the treap to find the appropriate leaf node for insertion, comparing partition sizes to decide traversal direction.
    - If a partition of the same size is found, insert the new partition into the 'same' list of that node.
    - If no same-sized partition is found, insert the partition as a child of the identified node, potentially breaking the heap property.
    - Bubble up the newly inserted partition to restore the heap property, swapping nodes as necessary based on heap priorities.
- **Output**: Returns `FD_WKSP_SUCCESS` on successful insertion of the partition into the treap.
- **Functions called**:
    - [`fd_wksp_private_pinfo_idx`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_idx)
    - [`fd_wksp_private_pinfo_idx_is_null`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_idx_is_null)
    - [`fd_wksp_private_pinfo_cidx`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_cidx)
    - [`fd_wksp_private_pinfo_sz`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_sz)


---
### fd\_wksp\_private\_free\_treap\_remove<!-- {{#callable:fd_wksp_private_free_treap_remove}} -->
The function `fd_wksp_private_free_treap_remove` removes a partition from a treap data structure, maintaining the heap property and adjusting the tree structure accordingly.
- **Inputs**:
    - `d`: The index of the partition to be removed from the treap.
    - `wksp`: A pointer to the workspace structure containing the treap.
    - `pinfo`: An array of partition information structures, representing the nodes of the treap.
- **Control Flow**:
    - Initialize `part_max` and increment `cycle_tag` from the workspace.
    - Mark the partition `d` with the current `cycle_tag`.
    - Check if `d` is part of a 'same' list and remove it if so, updating parent and sibling links.
    - If `d` is not in a 'same' list, load and validate its left, right, and parent indices.
    - Determine the location of the link from the parent to `d` or the root of the tree if `d` is the root.
    - If `d` has a non-empty 'same' list, replace `d` with the first partition in its 'same' list and swap heap priorities.
    - If `d` is the only partition of its size, fill the hole by promoting subtrees based on heap priorities, preserving the heap property.
    - Update the parent and child links to remove `d` from the treap.
    - Reset the partition `d`'s indices to null values.
- **Output**: Returns `FD_WKSP_SUCCESS` to indicate successful removal of the partition from the treap.
- **Functions called**:
    - [`fd_wksp_private_pinfo_idx`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_idx)
    - [`fd_wksp_private_pinfo_idx_is_null`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_idx_is_null)
    - [`fd_wksp_private_pinfo_cidx`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_cidx)


