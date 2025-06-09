# Purpose
This C source code file provides a template for implementing a high-performance, single-threaded, fixed-capacity queue. The code is designed to be included in other C files, where it can be customized by defining the `QUEUE_NAME` and `QUEUE_T` macros to specify the queue's name and the type of elements it will store, respectively. The file defines a comprehensive API for queue operations, including functions for creating, joining, and deleting queues, as well as for accessing and manipulating queue elements. The API includes both simple operations, such as `push` and `pop`, and advanced zero-copy operations, such as `peek_insert` and `peek_remove`, which allow for efficient element access without unnecessary data copying.

The code is structured to prioritize performance, with no built-in error checking, and relies on the caller to ensure correct usage, such as maintaining the queue's capacity constraints. The queue's internal structure is encapsulated within a private struct, which manages the queue's state, including its maximum capacity, current element count, and indices for the next elements to be pushed or popped. The file uses inline functions and macros to facilitate efficient queue operations, and it provides both mutable and const versions of certain functions to accommodate different usage scenarios. Overall, this file serves as a flexible and efficient template for implementing fixed-capacity queues in performance-critical applications.
# Imports and Dependencies

---
- `../bits/fd_bits.h`
- `stddef.h`


# Functions

---
### QUEUE\_<!-- {{#callable:QUEUE_}} -->
The `QUEUE_(remove_all)` function resets a queue to an empty state by setting its element count and indices to zero.
- **Inputs**:
    - `queue`: A pointer to the queue from which all elements are to be removed.
- **Control Flow**:
    - Retrieve the private header of the queue using `QUEUE_(private_hdr_from_queue)` function.
    - Set the `cnt` (element count) of the queue header to 0, indicating the queue is empty.
    - Set the `start` index of the queue header to 0, resetting the position for the next element to be popped.
    - Set the `end` index of the queue header to 0, resetting the position for the next element to be pushed.
    - Return the original queue pointer.
- **Output**: The function returns the original queue pointer, now reset to an empty state.
- **Functions called**:
    - [`QUEUE_`](#QUEUE_)


