# Purpose
This C source code file provides a template for implementing a single-threaded, compile-time fixed-capacity double-ended queue (deque) using a circular buffer. The code is designed for high-performance contexts where operations on the deque need to be efficient and fast. The implementation allows for pushing and popping elements from both ends of the deque, and it is optimized for scenarios where the maximum capacity (`DEQUE_MAX`) is a power of two, although this is not strictly required. The file is intended to be included in other C files, where the user defines the specific type of elements (`DEQUE_T`) and the name of the deque (`DEQUE_NAME`) to create a customized deque API for their specific use case.

The file defines a comprehensive API for managing the deque, including constructors, accessors, and both simple and advanced manipulation functions. The constructors handle the creation, joining, and deletion of the deque, while the accessors provide information about the deque's state, such as its capacity and whether it is full or empty. The simple API includes functions for pushing and popping elements, with additional "wrap" functions that handle overflow by discarding elements from the opposite end. The advanced API offers zero-copy operations for more efficient data handling, as well as iteration functions for traversing the deque in both forward and reverse order. The code emphasizes performance by avoiding error checking within the functions, relying on the caller to ensure valid operations.
# Imports and Dependencies

---
- `../bits/fd_bits.h`
- `stddef.h`
- `../log/fd_log.h`


# Functions

---
### DEQUE\_<!-- {{#callable:DEQUE_}} -->
The `DEQUE_(iter_ele_const)` function retrieves a constant pointer to an element in a deque at a specified iterator position, ensuring the iterator is within valid bounds if handholding is enabled.
- **Inputs**:
    - `deque`: A constant pointer to the deque from which an element is to be retrieved.
    - `iter`: An iterator of type `DEQUE_(iter_t)` indicating the position of the element to be accessed.
- **Control Flow**:
    - Retrieve the constant header of the deque using `DEQUE_(private_const_hdr_from_deque)` function.
    - If handholding is enabled, check if the iterator is out of bounds (less than `hdr->start` or greater than `hdr->end`) and log a critical error if it is.
    - Return a constant pointer to the element in the deque at the position determined by the iterator, using the `DEQUE_(private_slot)` function to map the iterator to the correct slot.
- **Output**: A constant pointer to the element in the deque at the specified iterator position.
- **Functions called**:
    - [`DEQUE_`](#DEQUE_)


