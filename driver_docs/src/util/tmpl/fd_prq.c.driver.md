# Purpose
This C source code file is a template for creating ultra-high-performance priority queues with bounded runtime size. The code is designed to be included in other C files, allowing developers to define custom priority queues by specifying the data type and name of the queue. The template provides a set of static inline functions that implement the priority queue operations, such as inserting events, removing the minimum event, and managing the queue's memory. The priority queue is implemented as a binary heap, which ensures efficient operations with logarithmic time complexity for insertion and removal.

The code is highly customizable, allowing users to define the data type of the queue elements, the field used for timeouts, and the comparison function for ordering elements. It also includes options for low-level optimizations, such as using vector registers for performance improvements. The template does not perform input argument checking to maintain high performance, placing the responsibility on the user to ensure correct usage. This file is intended for use in performance-critical applications where the overhead of additional checks would be detrimental. The template's flexibility and efficiency make it suitable for a wide range of applications requiring priority queue functionality.
# Imports and Dependencies

---
- `../bits/fd_bits.h`
- `stddef.h`
- `../log/fd_log.h`


# Functions

---
### PRQ\_<!-- {{#callable:PRQ_}} -->
The `PRQ_(remove_all)` function removes all events from a priority queue heap by resetting the event count to zero.
- **Inputs**:
    - `heap`: A pointer to the priority queue heap from which all events are to be removed.
- **Control Flow**:
    - Retrieve the private structure associated with the heap using `PRQ_(private_from_heap)` function.
    - Set the `cnt` field of the private structure to 0, effectively removing all events from the heap.
    - Return the original heap pointer.
- **Output**: Returns the original pointer to the heap, now with all events removed.
- **Functions called**:
    - [`PRQ_`](#PRQ_)


