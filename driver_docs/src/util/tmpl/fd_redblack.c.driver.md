# Purpose
This C source code file implements a high-performance, single-threaded, fixed-capacity red-black tree. A red-black tree is a self-balancing binary search tree that maintains sorted order of nodes, allowing for efficient O(log n) operations for queries, insertions, and deletions. The code is designed to be included as a template, requiring the user to define the node type (`REDBLK_T`) and the tree name (`REDBLK_NAME`) before including the file. This approach allows for flexibility in defining the specific data structure and operations tailored to the user's needs. The file provides a comprehensive set of functions for managing red-black trees, including node acquisition and release, tree insertion and removal, and various tree traversal and search operations.

The code is structured to support multiple trees within a shared memory pool, facilitating efficient node management without the need for copying keys or values between trees. This is achieved through a pool-based memory allocation strategy, where nodes are pre-allocated and managed within a fixed-size pool. The file defines a public API for creating, managing, and manipulating red-black trees, with functions for initializing and joining pools, inserting and removing nodes, and verifying the integrity of the tree structure. The implementation also includes mechanisms for ensuring tree invariants are maintained during insertions and deletions, such as rotations and color adjustments. Additionally, the code provides detailed logging and validation checks to aid in debugging and ensure the correctness of operations.
# Imports and Dependencies

---
- `../log/fd_log.h`
- `fd_pool.c`


# Global Variables

---
### REDBLK\_
- **Type**: `function pointer`
- **Description**: `REDBLK_(nearby)` is a function pointer that represents a function for searching a key in a red-black tree. If the exact key is not found, it returns a nearby approximation, which is either the greatest node less than the key or the least node greater than the key.
- **Use**: This function is used to find a node in a red-black tree that is closest to a given key when an exact match is not found.


# Functions

---
### REDBLK\_<!-- {{#callable:REDBLK_}} -->
The `REDBLK_(verify)` function checks the integrity of a red-black tree structure within a given pool, ensuring it adheres to red-black tree properties.
- **Inputs**:
    - `pool`: A pointer to the pool of red-black tree nodes, which includes the sentinel node at index REDBLK_NIL.
    - `root`: A pointer to the root node of the red-black tree to be verified.
- **Control Flow**:
    - Check that the sentinel node (REDBLK_NIL) has no children and is black.
    - If the root is null or points to the sentinel node, return 0 as the tree is trivially correct.
    - Ensure the root node is black.
    - Calculate the size of the tree and verify it matches the number of used nodes in the pool minus one for the sentinel.
    - Compute the number of black nodes on a path from the root to a leaf by traversing the leftmost path.
    - Call the recursive function `REDBLK_(verify_private)` to verify each node's properties, including parent-child relationships, color properties, and key ordering.
- **Output**: Returns 0 if the tree is valid, or a non-zero value if an error is detected in the tree's structure.
- **Functions called**:
    - [`REDBLK_`](#REDBLK_)


