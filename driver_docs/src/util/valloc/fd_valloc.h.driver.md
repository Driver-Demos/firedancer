# Purpose
This C header file defines an abstraction layer for memory allocation, providing a flexible interface for different memory allocator implementations. It introduces a virtual table (`fd_valloc_vtable_t`) containing function pointers for `malloc` and `free` operations, allowing for custom allocator behavior. The `fd_valloc_t` structure encapsulates a pointer to the allocator's state and its corresponding virtual table, enabling polymorphic memory management. The file includes predefined allocators, such as [`fd_libc_alloc_virtual`](#fd_valloc_tfd_libc_alloc_virtual) for standard library allocations and [`fd_null_alloc_virtual`](#fd_valloc_tfd_null_alloc_virtual) for a no-operation allocator. Additionally, it offers a debugging tool, [`fd_backtracing_alloc_virtual`](#fd_valloc_tfd_backtracing_alloc_virtual), for tracking memory leaks when hosted, which can be used with external tools for leak detection. The header ensures that memory allocation can be customized and extended while maintaining a consistent interface.
# Imports and Dependencies

---
- `../fd_util_base.h`


# Global Variables

---
### fd\_backtracing\_vtable
- **Type**: `const fd_valloc_vtable_t`
- **Description**: `fd_backtracing_vtable` is a constant variable of type `fd_valloc_vtable_t`, which is a structure containing function pointers for memory allocation and deallocation. It is used in the context of debugging to track memory leaks in applications that utilize virtual allocators.
- **Use**: This variable is used to provide a vtable for backtracing memory allocations, aiding in debugging and leak detection when `FD_HAS_HOSTED` is defined.


# Data Structures

---
### fd\_valloc\_vtable
- **Type**: `struct`
- **Members**:
    - `malloc`: A function pointer to a memory allocation function.
    - `free`: A function pointer to a memory deallocation function.
- **Description**: The `fd_valloc_vtable` structure is a virtual table that abstracts memory allocation and deallocation functions. It contains two function pointers, `malloc` and `free`, which are used to allocate and free memory, respectively. This structure allows for flexible memory management by enabling different implementations of memory allocation and deallocation to be used interchangeably.


---
### fd\_valloc\_vtable\_t
- **Type**: `struct`
- **Members**:
    - `malloc`: A function pointer to a memory allocation function that takes an allocator, alignment, and size as parameters.
    - `free`: A function pointer to a memory deallocation function that takes an allocator and a pointer as parameters.
- **Description**: The `fd_valloc_vtable_t` structure is a virtual table for memory allocation operations, containing function pointers for allocating and freeing memory. It abstracts the memory allocation mechanism, allowing different implementations to be used interchangeably by providing specific `malloc` and `free` functions.


---
### fd\_valloc
- **Type**: `struct`
- **Members**:
    - `self`: A pointer to the allocator instance or context.
    - `vt`: A pointer to a constant virtual table structure containing function pointers for memory allocation and deallocation.
- **Description**: The `fd_valloc` structure is designed to abstract memory allocation operations by encapsulating a pointer to an allocator instance (`self`) and a virtual table (`vt`) that provides function pointers for allocation (`malloc`) and deallocation (`free`) operations. This allows for flexible and interchangeable memory management strategies, as different virtual tables can be used to implement various allocation behaviors.


---
### fd\_valloc\_t
- **Type**: `struct`
- **Members**:
    - `self`: A pointer to the allocator instance or context.
    - `vt`: A pointer to a constant virtual table structure containing function pointers for memory allocation and deallocation.
- **Description**: The `fd_valloc_t` structure is a custom memory allocator abstraction that encapsulates a pointer to an allocator instance and a virtual table of function pointers for allocation and deallocation operations. This design allows for flexible memory management strategies by enabling different implementations of the allocator functions, which can be swapped in and out as needed. The structure is used in conjunction with the `fd_valloc_vtable_t` to provide a consistent interface for memory operations, supporting both standard and custom allocation strategies, including debugging tools for memory leak detection.


# Functions

---
### fd\_libc\_alloc\_virtual<!-- {{#callable:fd_valloc_t::fd_libc_alloc_virtual}} -->
The `fd_libc_alloc_virtual` function initializes and returns a `fd_valloc_t` structure with a NULL self-pointer and a pointer to the `fd_libc_vtable`.
- **Inputs**: None
- **Control Flow**:
    - Declare a variable `valloc` of type `fd_valloc_t` and initialize it with `self` set to `NULL` and `vt` set to the address of `fd_libc_vtable`.
    - Return the initialized `valloc` variable.
- **Output**: The function returns a `fd_valloc_t` structure initialized with a NULL self-pointer and a pointer to the `fd_libc_vtable`.
- **See also**: [`fd_valloc_t`](#fd_valloc_t)  (Data Structure)


---
### fd\_null\_alloc\_virtual<!-- {{#callable:fd_valloc_t::fd_null_alloc_virtual}} -->
The `fd_null_alloc_virtual` function initializes and returns a `fd_valloc_t` structure with both its `self` and `vt` members set to `NULL`, representing a null memory allocator.
- **Inputs**: None
- **Control Flow**:
    - Declare a variable `valloc` of type `fd_valloc_t` and initialize its `self` and `vt` members to `NULL`.
    - Return the `valloc` variable.
- **Output**: The function returns a `fd_valloc_t` structure with both `self` and `vt` members set to `NULL`.
- **See also**: [`fd_valloc_t`](#fd_valloc_t)  (Data Structure)


---
### fd\_is\_null\_alloc\_virtual<!-- {{#callable:fd_is_null_alloc_virtual}} -->
The function `fd_is_null_alloc_virtual` checks if a given virtual allocator is a null allocator by verifying if its virtual table pointer is NULL.
- **Inputs**:
    - `valloc`: A `fd_valloc_t` structure representing a virtual allocator, which contains a pointer to a virtual table (`vt`) and a self-reference pointer (`self`).
- **Control Flow**:
    - The function takes a `fd_valloc_t` structure as input.
    - It checks if the `vt` (virtual table pointer) of the `fd_valloc_t` structure is NULL.
    - The result of this check is cast to an integer and returned.
- **Output**: An integer value, 1 if the virtual table pointer (`vt`) of the input `fd_valloc_t` is NULL, indicating a null allocator, and 0 otherwise.


---
### fd\_backtracing\_alloc\_virtual<!-- {{#callable:fd_valloc_t::fd_backtracing_alloc_virtual}} -->
The `fd_backtracing_alloc_virtual` function creates a virtual allocator for debugging purposes by wrapping an existing allocator with a backtracing vtable.
- **Inputs**:
    - `inner_valloc`: A pointer to an existing `fd_valloc_t` structure that represents the inner allocator to be wrapped with backtracing capabilities.
- **Control Flow**:
    - The function initializes a `fd_valloc_t` structure named `valloc` with `inner_valloc` as its `self` field and `fd_backtracing_vtable` as its `vt` field.
    - The function returns the initialized `valloc` structure.
- **Output**: The function returns a `fd_valloc_t` structure that wraps the provided `inner_valloc` with a backtracing vtable for debugging memory allocations.
- **See also**: [`fd_valloc_t`](#fd_valloc_t)  (Data Structure)


---
### fd\_valloc\_malloc<!-- {{#callable:fd_valloc_malloc}} -->
The `fd_valloc_malloc` function allocates memory with a specified alignment and size using a virtual allocator's malloc method.
- **Inputs**:
    - `valloc`: A `fd_valloc_t` structure that contains a pointer to the allocator's state (`self`) and a pointer to a virtual table (`vt`) with function pointers for memory operations.
    - `align`: An `ulong` specifying the alignment requirement for the memory allocation.
    - `sz`: An `ulong` specifying the size of the memory to allocate.
- **Control Flow**:
    - The function accesses the `malloc` function pointer from the `vt` (virtual table) within the `valloc` structure.
    - It calls this `malloc` function, passing the `self` pointer, `align`, and `sz` as arguments.
    - The result of this call, which is a pointer to the allocated memory, is returned.
- **Output**: A pointer to the allocated memory block, or `NULL` if the allocation fails.


---
### fd\_valloc\_free<!-- {{#callable:fd_valloc_free}} -->
The `fd_valloc_free` function deallocates memory previously allocated by a virtual allocator using the specified virtual table's free function.
- **Inputs**:
    - `valloc`: A `fd_valloc_t` structure representing the virtual allocator, which contains a pointer to the allocator's state (`self`) and a pointer to a virtual table (`vt`) with function pointers for memory operations.
    - `ptr`: A pointer to the memory block that needs to be deallocated.
- **Control Flow**:
    - The function accesses the `free` function from the virtual table (`vt`) within the `valloc` structure.
    - It calls this `free` function, passing the allocator's state (`self`) and the pointer to the memory block (`ptr`) to be deallocated.
- **Output**: The function does not return any value; it performs the deallocation operation as a side effect.


