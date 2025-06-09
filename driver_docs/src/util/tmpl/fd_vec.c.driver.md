# Purpose
This C source code file is a template for creating vectors with a bounded maximum size, designed for use in persistent and inter-process communication (IPC) contexts. The code is structured to be included in other C files, allowing developers to define custom vector types by specifying the vector name and type through preprocessor directives (`VEC_NAME` and `VEC_T`). The template provides a set of static inline functions that operate as a header-only library, offering a range of operations on these vectors. These operations include creating and managing the memory footprint of vectors, joining and leaving vector contexts, and manipulating vector elements through expansion, contraction, and removal operations. The design assumes that the vector elements are Plain Old Data (POD) types with trivial copy semantics, making it suitable for high-performance computing (HPC) applications where efficiency and memory alignment are critical.

The code defines a series of functions that manage the lifecycle and operations of the vectors, such as `new`, `join`, `leave`, and `delete`, which handle the initialization and cleanup of vector memory. It also includes functions for querying vector properties like maximum capacity, current count, and available space, as well as functions for modifying the vector's contents, such as `expand`, `contract`, `remove`, and `remove_compact`. The template is designed to be flexible, allowing multiple vector types to be defined within a single compilation unit, and it emphasizes performance by using inline functions and assuming the caller's knowledge of the vector's state. The code also hints at potential future enhancements, such as additional APIs for operations like shuffling, indicating its extensibility.
# Functions

---
### VEC\_<!-- {{#callable:VEC_}} -->
The `VEC_(remove_compact_idx)` function removes an element from a vector at a specified index by shifting subsequent elements to fill the gap, effectively compacting the vector.
- **Inputs**:
    - `join`: A pointer to the vector from which an element is to be removed.
    - `idx`: The index of the element to be removed from the vector.
- **Control Flow**:
    - Retrieve the private vector structure associated with the given vector pointer.
    - Calculate the new count of elements by decrementing the current count by one.
    - Iterate over the vector starting from the specified index to the second last element, shifting each element one position to the left to fill the gap left by the removed element.
    - Update the vector's element count to reflect the removal.
    - Return the modified vector pointer.
- **Output**: The function returns a pointer to the modified vector after the specified element has been removed and the vector has been compacted.
- **Functions called**:
    - [`VEC_`](#VEC_)


