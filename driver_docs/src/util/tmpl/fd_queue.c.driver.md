# Purpose
This C source code file provides a template for implementing a high-performance, single-threaded, fixed-capacity queue. The queue is designed to be used in contexts where performance is critical, and it operates without any error checking to maximize speed. The file is intended to be included in other C files, where the user defines the queue's name, element type, and maximum capacity through preprocessor directives. This approach allows for the creation of multiple queue instances with different configurations within the same application.

The code defines a comprehensive API for queue operations, including basic functions for creating, joining, and deleting queues, as well as accessor functions to check the queue's status (e.g., whether it is full or empty). It also provides a simple API for pushing and popping elements and an advanced API for zero-copy operations, which allows for direct manipulation of queue elements to further enhance performance. The implementation uses a circular buffer technique, with internal management of start and end indices to track the queue's state. The design ensures that overflow and underflow are practically impossible, even under extreme usage scenarios, by initializing indices to large values. This file is a utility for developers needing efficient queue operations in performance-sensitive applications.
# Imports and Dependencies

---
- `../bits/fd_bits.h`
- `stddef.h`


# Functions

---
### QUEUE\_<!-- {{#callable:QUEUE_}} -->
The `QUEUE_(remove_all)` function resets the queue to an empty state by setting the start and end indices to a large value, effectively removing all elements.
- **Inputs**:
    - `queue`: A pointer to the queue from which all elements are to be removed.
- **Control Flow**:
    - Retrieve the private header of the queue using `QUEUE_(private_hdr_from_queue)` function.
    - Set the `start` and `end` indices of the queue header to `1UL << 63`, effectively marking the queue as empty.
- **Output**: Returns the original queue pointer, now reset to an empty state.
- **Functions called**:
    - [`QUEUE_`](#QUEUE_)


