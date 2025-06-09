# Purpose
This C source code file provides specialized memory allocation and deallocation functions, with a focus on virtual memory management and optional backtracing capabilities. The file defines two sets of functions: one for standard aligned memory allocation using `aligned_alloc` and `free`, and another for enhanced memory operations that include backtracing, which is useful for debugging memory usage and tracking allocation and deallocation calls. The backtracing functionality is conditionally compiled with the `FD_HAS_HOSTED` macro, indicating that it is intended for environments where hosted execution is supported.

The code defines two virtual tables (`fd_libc_vtable` and `fd_backtracing_vtable`) that encapsulate the function pointers for the respective memory operations. These vtables provide a structured way to access the memory management functions, allowing for flexible integration into larger systems that require custom memory handling strategies. The backtracing functions utilize atomic operations and spin locks to ensure thread safety during memory operations, and they log detailed information about memory allocations and deallocations to standard output, which can be invaluable for diagnosing memory-related issues in complex applications.
# Imports and Dependencies

---
- `fd_valloc.h`
- `../bits/fd_bits.h`
- `../log/fd_log.h`
- `stdlib.h`
- `stdio.h`
- `execinfo.h`
- `unistd.h`


# Global Variables

---
### backtracing\_lock
- **Type**: `volatile ushort`
- **Description**: The `backtracing_lock` is a static volatile unsigned short variable used as a lock mechanism to ensure thread-safe operations during memory allocation and deallocation with backtracing. It is set to 0 initially, indicating that the lock is not held.
- **Use**: This variable is used to control access to the backtracing memory allocation and deallocation functions, ensuring that only one thread can perform these operations at a time.


---
### fd\_libc\_vtable
- **Type**: `fd_valloc_vtable_t`
- **Description**: The `fd_libc_vtable` is a constant instance of the `fd_valloc_vtable_t` structure, which is used to define a virtual table for memory allocation and deallocation functions. It specifically assigns the `fd_libc_malloc_virtual` function for memory allocation and the `fd_libc_free_virtual` function for memory deallocation.
- **Use**: This variable is used to provide a standard interface for memory operations using the C standard library's allocation and deallocation functions.


---
### fd\_backtracing\_vtable
- **Type**: `const fd_valloc_vtable_t`
- **Description**: The `fd_backtracing_vtable` is a constant instance of the `fd_valloc_vtable_t` structure, which is used to define a virtual table for memory allocation and deallocation functions with backtracing capabilities. It contains function pointers to `fd_backtracing_malloc_virtual` and `fd_backtracing_free_virtual`, which are responsible for allocating and freeing memory while also capturing and logging backtrace information for debugging purposes.
- **Use**: This variable is used to provide a virtual table for memory operations that include backtracing, allowing for enhanced debugging by logging allocation and deallocation call stacks.


# Functions

---
### fd\_libc\_malloc\_virtual<!-- {{#callable:fd_libc_malloc_virtual}} -->
The `fd_libc_malloc_virtual` function allocates memory with a specified alignment and size using the `aligned_alloc` function.
- **Inputs**:
    - `_self`: A void pointer, marked as unused, which is typically used for object-oriented-like function calls in C.
    - `align`: An unsigned long integer specifying the alignment requirement for the memory allocation.
    - `sz`: An unsigned long integer specifying the size of the memory block to allocate.
- **Control Flow**:
    - The function calls `fd_ulong_align_up` to adjust the size `sz` to be a multiple of the alignment `align` if necessary.
    - It then calls `aligned_alloc` with the alignment and the adjusted size to allocate the memory.
- **Output**: A pointer to the allocated memory block, or NULL if the allocation fails.


---
### fd\_libc\_free\_virtual<!-- {{#callable:fd_libc_free_virtual}} -->
The `fd_libc_free_virtual` function deallocates memory previously allocated by a corresponding allocation function.
- **Inputs**:
    - `_self`: A void pointer, marked as unused with `FD_PARAM_UNUSED`, which is typically used for passing context or state information but is not used in this function.
    - `_addr`: A void pointer to the memory block that needs to be deallocated.
- **Control Flow**:
    - The function calls the standard C library function `free` with `_addr` as the argument to deallocate the memory block pointed to by `_addr`.
- **Output**: The function does not return any value.


---
### fd\_backtracing\_malloc\_virtual<!-- {{#callable:fd_backtracing_malloc_virtual}} -->
The `fd_backtracing_malloc_virtual` function allocates memory with specified alignment and size, logs the allocation with a backtrace, and ensures thread safety using a lock mechanism.
- **Inputs**:
    - `self`: A pointer to a memory allocator context, specifically cast to `fd_valloc_t *`.
    - `align`: The alignment requirement for the memory allocation.
    - `sz`: The size of the memory to allocate.
- **Control Flow**:
    - Enter an infinite loop to acquire a lock for thread safety.
    - Check if `backtracing_lock` is not set; if so, attempt to set it using an atomic compare-and-swap operation.
    - If the lock is acquired, break out of the loop; otherwise, pause and retry.
    - Perform a memory fence to ensure memory operations are completed before proceeding.
    - Allocate memory using [`fd_valloc_malloc`](fd_valloc.h.driver.md#fd_valloc_malloc) with the given alignment and size.
    - Capture a backtrace of up to 128 frames into the `btrace` array.
    - Format a log message with the backtrace count, allocated address, alignment, and size, and write it to standard output.
    - Write the backtrace symbols to standard output.
    - Write a termination marker to standard output.
    - Perform another memory fence to ensure all operations are completed before releasing the lock.
    - Release the lock by setting `backtracing_lock` to 0.
    - Return the allocated memory address.
- **Output**: A pointer to the allocated memory block, or `NULL` if the allocation fails.
- **Functions called**:
    - [`fd_valloc_malloc`](fd_valloc.h.driver.md#fd_valloc_malloc)


---
### fd\_backtracing\_free\_virtual<!-- {{#callable:fd_backtracing_free_virtual}} -->
The `fd_backtracing_free_virtual` function releases a memory block and logs a backtrace of the operation to standard output.
- **Inputs**:
    - `self`: A pointer to a memory allocator context, specifically of type `fd_valloc_t`.
    - `addr`: A pointer to the memory block that needs to be freed.
- **Control Flow**:
    - The function enters a loop to acquire a lock by checking if `backtracing_lock` is not set and attempts to set it using an atomic compare-and-swap operation.
    - If the lock is successfully acquired, the loop breaks; otherwise, it pauses briefly and retries.
    - A memory fence is used to ensure memory operations are completed before proceeding.
    - The function calls [`fd_valloc_free`](fd_valloc.h.driver.md#fd_valloc_free) to free the memory block pointed to by `addr`.
    - A backtrace is captured using the `backtrace` function, storing up to 128 addresses in the `btrace` array.
    - A formatted string is created to log the free operation, including the backtrace count and the address being freed.
    - The log message is written to standard output, and if the write fails, an error is logged.
    - The backtrace symbols are also written to standard output using `backtrace_symbols_fd`.
    - Another log message indicating the end of the log is written to standard output.
    - A memory fence is used again to ensure all operations are completed before releasing the lock.
    - The lock is released by setting `backtracing_lock` to 0.
- **Output**: The function does not return a value; it performs memory deallocation and logging as side effects.
- **Functions called**:
    - [`fd_valloc_free`](fd_valloc.h.driver.md#fd_valloc_free)


