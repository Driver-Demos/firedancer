# Purpose
This C source code file provides a template for implementing a high-performance, single-threaded, fixed-capacity stack. The stack is designed to be highly efficient, with no error checking to ensure maximum performance. The code is intended to be included in other C files by defining the `STACK_NAME` and `STACK_T` macros, which specify the stack's name and the type of elements it will store, respectively. This approach allows for the creation of multiple stack instances with different configurations within the same program. The file defines a comprehensive API for stack operations, including basic operations like push and pop, as well as advanced operations for zero-copy usage, such as peek and insert.

The stack implementation is encapsulated within a private structure that maintains the stack's maximum capacity and current element count. The API provides functions to create, join, leave, and delete stack instances, as well as accessors to query the stack's state, such as its maximum capacity, current count, and availability. The stack operations are implemented as inline functions to minimize overhead, and the code uses macros to generate stack-specific function names based on the defined `STACK_NAME`. This file is not a standalone executable but rather a library intended to be included and used in other C programs, providing a flexible and efficient stack implementation tailored to specific use cases.
# Imports and Dependencies

---
- `../bits/fd_bits.h`
- `stddef.h`


# Functions

---
### STACK\_<!-- {{#callable:STACK_}} -->
The `STACK_(remove_all)` function resets the stack's element count to zero, effectively clearing all elements from the stack.
- **Inputs**:
    - `stack`: A pointer to the stack from which all elements are to be removed.
- **Control Flow**:
    - The function retrieves the private header of the stack using `STACK_(private_hdr_from_stack)` to access the stack's metadata.
    - It sets the `cnt` field of the stack's private header to `0UL`, indicating that the stack is now empty.
    - The function returns the original stack pointer.
- **Output**: The function returns the same stack pointer that was passed as input, now with its element count set to zero.
- **Functions called**:
    - [`STACK_`](#STACK_)


