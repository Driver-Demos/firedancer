# Purpose
This C code file is a template for generating high-performance, zero-copy heap data structures, which are particularly useful in scenarios where heap elements are not stored sequentially in memory. The code is designed to be highly flexible and efficient, supporting operations such as persistence, concurrent usage, inter-process communication, and memory relocation. It provides a set of macros and functions that allow users to define custom heap types by specifying the element type, comparison function, and other parameters. The code is structured to be included in a compilation unit, allowing for the creation of different heap types within the same program.

The file defines a comprehensive API for managing heaps, including functions for creating, joining, and deleting heaps, as well as inserting and removing elements. It also includes utility functions for checking heap integrity and accessing heap elements. The code is designed to be used as a header-only library or as part of a larger library, with options for different implementation styles. The use of macros allows for the customization of heap behavior, such as element comparison and index types, making the code adaptable to various application needs. The implementation emphasizes efficiency, with operations optimized for cache and memory bandwidth, and provides mechanisms for handling large data sets and ensuring data integrity.
# Imports and Dependencies

---
- `../log/fd_log.h`


# Global Variables

---
### HEAP\_
- **Type**: `HEAP_(t) *`
- **Description**: The `HEAP_` variable is a macro that expands to a pointer to a structure representing a heap. This structure is used to manage a collection of elements in a non-sequential memory layout, allowing for operations such as insertion, removal, and peeking of elements based on a defined order.
- **Use**: This variable is used to perform heap operations like inserting and removing elements, while maintaining the heap property, in a memory-efficient manner.


# Functions

---
### HEAP\_<!-- {{#callable:HEAP_}} -->
The `HEAP_(verify)` function checks the integrity of a heap data structure by ensuring that it adheres to the heap properties and is not corrupted.
- **Inputs**:
    - `heap`: A pointer to a constant heap structure (`HEAP_(t) const *`) that represents the heap to be verified.
    - `pool`: A pointer to a constant array of heap elements (`HEAP_T const *`) that represents the storage pool for the heap elements.
- **Control Flow**:
    - Define a macro `HEAP_TEST` to log a warning and return -1 if a condition fails.
    - Validate the `heap` pointer to ensure it is not NULL.
    - Retrieve `ele_max` and `ele_cnt` from the heap and validate them against `HEAP_IDX_NULL` and each other.
    - If `ele_max` is non-zero, validate the `pool` pointer to ensure it is not NULL.
    - Initialize a stack to keep track of nodes to visit, with a maximum size of 512.
    - Initialize `visit_cnt` to track the number of visited nodes.
    - If the heap's root is not NULL, push it onto the stack after validating its index and ensuring no stack overflow.
    - While there are nodes to visit (i.e., `stack_cnt` is non-zero), pop a node from the stack and validate it against cycles.
    - For each node, check its right child: validate the heap property, ensure the index is in bounds, and push it onto the stack if valid.
    - Similarly, check the left child of each node with the same validations and push it onto the stack if valid.
    - Increment `visit_cnt` for each visited node.
    - After visiting all nodes, ensure that `visit_cnt` matches `ele_cnt` to confirm all nodes were visited.
    - Return 0 if all checks pass, indicating the heap is not obviously corrupt.
- **Output**: Returns 0 if the heap is valid and not obviously corrupt, or -1 if any validation fails, logging a warning message.
- **Functions called**:
    - [`HEAP_`](#HEAP_)


