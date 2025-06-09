# Purpose
The provided C header file defines an API for managing high-performance, persistent, inter-process shared scratch pad memories, referred to as "spads." These spads function similarly to a thread's stack, allowing for fast O(1) allocation and deallocation of memory in a nested frame structure. The API supports operations such as pushing and popping frames, trimming allocations, and sharing memory across different threads and processes when backed by a shared memory region. This makes it particularly suitable for real-time streaming applications and scenarios requiring custom allocation alignments and large dynamic ranges of allocation sizes.

The file includes definitions for the alignment and footprint of the spad structure, ensuring compatibility with various hardware architectures and memory interfaces. It provides a set of inline functions for creating, joining, and managing spad memory, including operations for allocation, frame management, and memory usage tracking. The API also includes debugging and sanitization variants to facilitate error checking and memory safety. The header is designed to be included in other C files, providing a robust and efficient mechanism for memory management in performance-critical applications.
# Imports and Dependencies

---
- `../bits/fd_bits.h`
- `../valloc/fd_valloc.h`


# Global Variables

---
### fd\_spad\_delete
- **Type**: `function pointer`
- **Description**: `fd_spad_delete` is a static inline function that unformats a memory region used as a scratch pad (spad). It takes a pointer to the first byte of the region containing the spad and returns the same pointer on success or NULL on failure.
- **Use**: This function is used to delete or unformat a spad, ensuring that the memory region is no longer recognized as a spad.


---
### fd\_spad\_frame\_lo
- **Type**: `function pointer`
- **Description**: `fd_spad_frame_lo` is a function that returns a pointer to the start of the memory range allocated for the current frame in a scratch pad memory (`spad`). It is a pure function, meaning it has no side effects and its return value is determined only by its input parameters.
- **Use**: This function is used to access the starting address of the memory allocated for the current frame in a scratch pad memory.


---
### fd\_spad\_frame\_hi
- **Type**: `function`
- **Description**: The `fd_spad_frame_hi` function is a static inline function that returns a pointer to the high boundary of the current frame in a scratch pad memory (`spad`). It calculates this by adding the current memory used (`mem_used`) to the base address of the scratch pad's memory region.
- **Use**: This function is used to determine the upper limit of the memory allocated in the current frame of a scratch pad.


---
### fd\_spad\_alloc
- **Type**: `function pointer`
- **Description**: `fd_spad_alloc` is a static inline function that allocates a specified size of memory with a given alignment from a scratch pad memory (`fd_spad_t`). It returns a pointer to the allocated memory region.
- **Use**: This function is used to allocate memory from a scratch pad, ensuring the memory is aligned as specified and updating the scratch pad's used memory state.


---
### fd\_spad\_prepare
- **Type**: `static inline void *`
- **Description**: The `fd_spad_prepare` function is a static inline function that prepares a scratch pad allocation with a specified alignment and maximum size. It returns a pointer to the initial byte of the allocation, ensuring the alignment is respected.
- **Use**: This function is used to initiate an allocation in a scratch pad memory, allowing for efficient memory management in high-performance applications.


---
### fd\_spad\_delete\_debug
- **Type**: `void *`
- **Description**: `fd_spad_delete_debug` is a function pointer that takes a single argument, a void pointer `shspad`, and returns a void pointer. It is a debugging variant of the `fd_spad_delete` function, which is used to unformat a memory region used as a scratch pad (spad).
- **Use**: This variable is used to provide a debugging version of the `fd_spad_delete` function, which includes additional checks and logging for debugging purposes.


---
### fd\_spad\_frame\_lo\_debug
- **Type**: `function pointer`
- **Description**: `fd_spad_frame_lo_debug` is a function pointer that returns a pointer to the lower boundary of the current frame in a scratch pad memory (`spad`). It is part of a debugging variant of the `fd_spad_frame_lo` function, which provides additional checks and logging for debugging purposes.
- **Use**: This function is used to obtain the starting address of the current frame in a scratch pad memory for debugging purposes.


---
### fd\_spad\_frame\_hi\_debug
- **Type**: `void *`
- **Description**: The `fd_spad_frame_hi_debug` is a function that returns a pointer to the high boundary of the current frame in a shared scratch pad memory (spad). It is part of a debugging variant of the spad API, which includes additional checks and logging for debugging purposes.
- **Use**: This function is used to obtain the upper limit of the current frame in a spad for debugging, ensuring that the spad's memory operations are within valid bounds.


---
### fd\_spad\_alloc\_check
- **Type**: `function pointer`
- **Description**: `fd_spad_alloc_check` is a function pointer that points to a function used for allocating memory from a shared scratch pad (spad) with specified alignment and size. It is defined as a global variable and is also used as a debugging variant under the alias `fd_spad_alloc_debug`. This function is part of a high-performance API for managing shared memory regions that behave like a thread's stack, allowing for fast memory allocation and deallocation.
- **Use**: This variable is used to allocate memory from a shared scratch pad with specific alignment and size requirements, and it is also used for debugging purposes.


---
### fd\_spad\_prepare\_debug
- **Type**: `void *`
- **Description**: `fd_spad_prepare_debug` is a function pointer that returns a void pointer. It is part of a debugging variant of the API for managing high-performance persistent inter-process shared scratch pad memories. This function is used to start preparing a scratch pad allocation with a specified alignment and maximum size, providing additional checks and logging for debugging purposes.
- **Use**: This variable is used to initiate a debug-mode preparation of a memory allocation in a shared scratch pad, ensuring alignment and size constraints are met.


---
### fd\_spad\_delete\_sanitizer\_impl
- **Type**: `void *`
- **Description**: `fd_spad_delete_sanitizer_impl` is a function pointer that takes a single argument, a void pointer to a shared memory region (`shspad`), and returns a void pointer. This function is part of a set of sanitizer implementations for managing shared scratch pad memory (spad) in a high-performance, inter-process context.
- **Use**: This function is used to unformat a memory region used as a spad, ensuring proper memory sanitization in ASAN/DEEPASAN and MSAN builds.


---
### fd\_spad\_frame\_lo\_sanitizer\_impl
- **Type**: `function pointer`
- **Description**: `fd_spad_frame_lo_sanitizer_impl` is a function pointer that points to a function designed to return the lower bound of the memory range covered by the current frame in a scratch pad memory (spad) with additional logic for memory poisoning control in ASAN/DEEPASAN and MSAN builds.
- **Use**: This function is used to obtain the starting address of the current frame's memory range in a spad, with sanitization features enabled.


---
### fd\_spad\_frame\_hi\_sanitizer\_impl
- **Type**: `void *`
- **Description**: The `fd_spad_frame_hi_sanitizer_impl` is a function pointer that returns a pointer to the high boundary of the current frame in a scratch pad memory (`spad`). It is part of a set of functions that include additional logic for memory sanitization, specifically for ASAN/DEEPASAN and MSAN builds.
- **Use**: This function is used to obtain the upper limit of the current frame in a scratch pad memory, with additional sanitization logic for debugging purposes.


---
### fd\_spad\_alloc\_sanitizer\_impl
- **Type**: `function pointer`
- **Description**: `fd_spad_alloc_sanitizer_impl` is a function pointer that points to a function responsible for allocating memory from a shared scratch pad memory (`spad`) with specified alignment and size. This function is part of a set of sanitizer implementations that provide additional memory safety checks, such as memory poisoning, in ASAN/DEEPASAN and MSAN builds.
- **Use**: This function is used to allocate memory from a scratch pad with additional sanitization checks for debugging purposes.


---
### fd\_spad\_prepare\_sanitizer\_impl
- **Type**: `function pointer`
- **Description**: `fd_spad_prepare_sanitizer_impl` is a function pointer that points to a function designed to prepare a scratch pad allocation with a specified alignment and maximum size. This function is part of a set of sanitizer implementations that include additional logic for memory poisoning control in ASAN/DEEPASAN and MSAN builds.
- **Use**: This function is used to prepare a memory allocation in a scratch pad with sanitization features enabled, ensuring memory safety during allocation.


---
### fd\_spad\_vtable
- **Type**: `const fd_valloc_vtable_t`
- **Description**: `fd_spad_vtable` is a constant variable of type `fd_valloc_vtable_t`, which is a virtual function table for the spad (scratch pad) memory management system. This table provides the necessary function pointers to manage memory allocations within the spad framework.
- **Use**: This variable is used to provide a set of function pointers for managing memory allocations in the spad system, allowing for operations like allocation, deallocation, and memory management to be performed efficiently.


# Data Structures

---
### fd\_spad\_t
- **Type**: `struct`
- **Members**:
    - `magic`: A unique identifier for the spad, set to FD_SPAD_MAGIC.
    - `off`: An array of byte offsets indicating where allocations start for each frame.
    - `frame_free`: The number of frames that are free, ranging from 0 to FD_SPAD_FRAME_MAX.
    - `mem_max`: The maximum byte size of the spad memory region.
    - `mem_used`: The number of bytes currently used in the spad memory.
    - `mem_wmark`: Tracks the watermark of memory usage if FD_SPAD_TRACK_USAGE is enabled.
- **Description**: The `fd_spad_t` structure is a high-performance, persistent, inter-process shared scratch pad memory designed to behave like a thread's stack, with fast O(1) operations for allocations and frame management. It supports nested frames, automatic memory freeing upon frame popping, and can be shared across threads and processes if backed by shared memory. The structure includes metadata for managing memory offsets, frame availability, and memory usage, with additional support for debugging and sanitization.


---
### fd\_spad\_private
- **Type**: `struct`
- **Members**:
    - `magic`: A magic number used to validate the integrity of the spad structure.
    - `off`: An array of offsets indicating where allocations start for each frame in the spad memory.
    - `frame_free`: The number of frames that are currently free and available for use.
    - `mem_max`: The maximum byte size of the spad memory region.
    - `mem_used`: The number of bytes currently used in the spad memory.
    - `mem_wmark`: Tracks the watermark of memory usage if FD_SPAD_TRACK_USAGE is enabled.
- **Description**: The `fd_spad_private` structure is a custom data structure designed to manage a high-performance, persistent, inter-process shared scratch pad memory, similar to a thread's stack. It supports fast O(1) allocation and deallocation of memory grouped into nested frames, with automatic freeing of allocations when a frame is popped. The structure includes metadata for managing memory usage and frame allocation, ensuring that memory operations do not corrupt the metadata or allocated memory. It is aligned to `FD_SPAD_ALIGN` for optimal performance and can be used in multi-threaded and multi-process environments.


# Functions

---
### fd\_spad\_private\_mem<!-- {{#callable:fd_spad_private_mem}} -->
The `fd_spad_private_mem` function returns a pointer to the first byte of the memory region of a scratch pad (spad) in the caller's local address space.
- **Inputs**:
    - `spad`: A pointer to an `fd_spad_t` structure, representing a scratch pad memory region.
- **Control Flow**:
    - The function takes a pointer to an `fd_spad_t` structure as input.
    - It calculates the address of the first byte of the spad's memory region by incrementing the spad pointer by one unit of `fd_spad_t`.
    - The function returns this calculated address cast to a `uchar *`.
- **Output**: A pointer of type `uchar *` to the first byte of the spad's memory region in the caller's local address space.


---
### fd\_spad\_mem\_max\_max<!-- {{#callable:fd_spad_mem_max_max}} -->
The `fd_spad_mem_max_max` function calculates the maximum possible memory size (`mem_max`) for a scratch pad that can fit within a given footprint, ensuring alignment and size constraints are met.
- **Inputs**:
    - `footprint`: The total number of bytes available for the scratch pad, which must be aligned to `FD_SPAD_ALIGN`.
- **Control Flow**:
    - Align the `footprint` down to the nearest multiple of `FD_SPAD_ALIGN` using `fd_ulong_align_dn`.
    - Calculate `mem_max` as the maximum of the aligned footprint and the size of `fd_spad_t`, then subtract the size of `fd_spad_t`.
    - Check if `mem_max` is less than or equal to `2^63`; if true, return `mem_max`, otherwise return 0.
- **Output**: Returns the largest possible `mem_max` that fits within the aligned footprint, or 0 if the constraints cannot be satisfied.


---
### fd\_spad\_align<!-- {{#callable:fd_spad_align}} -->
The `fd_spad_align` function returns the alignment requirement for a scratch pad memory, which is defined as a constant value.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, indicating it is intended for use within the same translation unit and should be inlined by the compiler for performance.
    - It returns a constant value, `FD_SPAD_ALIGN`, which is defined as 128, representing the alignment requirement for the scratch pad memory.
- **Output**: The function returns an unsigned long integer representing the alignment requirement for a scratch pad memory, specifically the value of `FD_SPAD_ALIGN`.


---
### fd\_spad\_footprint<!-- {{#callable:fd_spad_footprint}} -->
The `fd_spad_footprint` function calculates the memory footprint required for a scratch pad memory (spad) given a maximum memory size, ensuring it does not exceed a 64-bit unsigned long limit.
- **Inputs**:
    - `mem_max`: The maximum memory size in bytes that the spad can support, specified as an unsigned long integer.
- **Control Flow**:
    - The function checks if `mem_max` is less than or equal to 2^63.
    - If true, it calculates the footprint using the `FD_SPAD_FOOTPRINT` macro with `mem_max` as the argument.
    - If false, it returns 0UL, indicating failure due to an excessively large `mem_max`.
- **Output**: The function returns the calculated memory footprint as an unsigned long integer, or 0UL if `mem_max` is too large.


---
### fd\_spad\_new<!-- {{#callable:fd_spad_new}} -->
The `fd_spad_new` function initializes a memory region as a scratch pad (spad) with specified alignment and footprint, returning a pointer to the spad on success or NULL on failure.
- **Inputs**:
    - `shmem`: A pointer to the start of the memory region to be formatted as a spad.
    - `mem_max`: The maximum number of bytes that the spad memory region can hold.
- **Control Flow**:
    - Cast the `shmem` pointer to a `fd_spad_t` pointer named `spad`.
    - Check if `spad` is NULL, if so, return NULL.
    - Check if `spad` is aligned to `FD_SPAD_ALIGN`, if not, return NULL.
    - Check if the footprint for `mem_max` is valid using [`fd_spad_footprint`](#fd_spad_footprint), if not, return NULL.
    - Set `spad->mem_max` to `mem_max`.
    - Call [`fd_spad_reset`](#fd_spad_reset) to reset the spad's state.
    - If `FD_SPAD_TRACK_USAGE` is defined, initialize `spad->mem_wmark` to 0.
    - Use memory fences (`FD_COMPILER_MFENCE`) to ensure memory operations are completed before setting `spad->magic` to `FD_SPAD_MAGIC`.
    - Return the `spad` pointer.
- **Output**: Returns a pointer to the initialized `fd_spad_t` structure on success, or NULL on failure.
- **Functions called**:
    - [`fd_spad_footprint`](#fd_spad_footprint)
    - [`fd_spad_reset`](#fd_spad_reset)


---
### fd\_spad\_join<!-- {{#callable:fd_spad_join}} -->
The `fd_spad_join` function attempts to join a shared scratch pad memory (spad) by validating its pointer, alignment, and magic number, returning a local handle if successful or NULL if any validation fails.
- **Inputs**:
    - `shspad`: A pointer to the shared memory region containing the spad, in the caller's address space.
- **Control Flow**:
    - Cast the input `shspad` to a `fd_spad_t *` type and store it in `spad`.
    - Check if `spad` is NULL; if so, return NULL.
    - Check if `spad` is aligned to `FD_SPAD_ALIGN`; if not, return NULL.
    - Check if `spad->magic` equals `FD_SPAD_MAGIC`; if not, return NULL.
    - If all checks pass, return `spad`.
- **Output**: Returns a pointer to the `fd_spad_t` structure if the join is successful, or NULL if any validation fails.


---
### fd\_spad\_leave<!-- {{#callable:fd_spad_leave}} -->
The `fd_spad_leave` function returns a pointer to the `fd_spad_t` structure, effectively leaving the current join of a scratch pad memory.
- **Inputs**:
    - `spad`: A pointer to an `fd_spad_t` structure representing the scratch pad memory to leave.
- **Control Flow**:
    - The function takes a single argument, `spad`, which is a pointer to an `fd_spad_t` structure.
    - It casts the `spad` pointer to a `void *` and returns it.
- **Output**: A `void *` pointer to the `fd_spad_t` structure, representing the memory region containing the scratch pad.


---
### fd\_spad\_frame\_max<!-- {{#callable:fd_spad_frame_max}} -->
The `fd_spad_frame_max` function returns the maximum number of frames that can be used in a scratch pad memory (spad).
- **Inputs**:
    - `spad`: A pointer to a constant `fd_spad_t` structure representing the scratch pad memory.
- **Control Flow**:
    - The function takes a single argument, `spad`, which is a pointer to a constant `fd_spad_t` structure.
    - The function does not use the `spad` argument in its logic, as indicated by the `(void)spad;` statement, which is used to suppress unused parameter warnings.
    - The function returns the constant `FD_SPAD_FRAME_MAX`, which is defined as 128UL, representing the maximum number of frames.
- **Output**: The function returns an `ulong` value representing the maximum number of frames, which is always `FD_SPAD_FRAME_MAX` (128UL).


---
### fd\_spad\_frame\_used<!-- {{#callable:fd_spad_frame_used}} -->
The `fd_spad_frame_used` function calculates the number of frames currently in use in a scratch pad memory structure.
- **Inputs**:
    - `spad`: A pointer to a constant `fd_spad_t` structure representing the scratch pad memory.
- **Control Flow**:
    - The function accesses the `frame_free` member of the `fd_spad_t` structure pointed to by `spad`.
    - It subtracts the value of `frame_free` from the constant `FD_SPAD_FRAME_MAX` to determine the number of frames in use.
- **Output**: The function returns an `ulong` representing the number of frames currently in use in the scratch pad.


---
### fd\_spad\_frame\_free<!-- {{#callable:fd_spad_frame_free}} -->
The `fd_spad_frame_free` function returns the number of free frames available in a scratch pad memory structure.
- **Inputs**:
    - `spad`: A pointer to a constant `fd_spad_t` structure, representing the scratch pad memory from which the number of free frames is to be retrieved.
- **Control Flow**:
    - The function accesses the `frame_free` member of the `fd_spad_t` structure pointed to by `spad`.
    - It returns the value of `frame_free`, which indicates the number of free frames in the scratch pad.
- **Output**: The function returns an `ulong` representing the number of free frames in the scratch pad memory.


---
### fd\_spad\_mem\_max<!-- {{#callable:fd_spad_mem_max}} -->
The `fd_spad_mem_max` function returns the maximum memory size allocated for a scratch pad memory (`spad`).
- **Inputs**:
    - `spad`: A pointer to a constant `fd_spad_t` structure representing the scratch pad memory.
- **Control Flow**:
    - The function directly accesses the `mem_max` field of the `spad` structure.
    - It returns the value of `mem_max`, which represents the maximum memory size allocated for the scratch pad.
- **Output**: The function returns an `ulong` representing the maximum memory size (`mem_max`) of the scratch pad.


---
### fd\_spad\_mem\_used<!-- {{#callable:fd_spad_mem_used}} -->
The `fd_spad_mem_used` function returns the number of bytes currently used in a scratch pad memory (`spad`).
- **Inputs**:
    - `spad`: A pointer to a constant `fd_spad_t` structure representing the scratch pad memory.
- **Control Flow**:
    - The function directly accesses the `mem_used` field of the `fd_spad_t` structure pointed to by `spad`.
    - It returns the value of `mem_used`, which indicates the number of bytes currently allocated in the scratch pad memory.
- **Output**: The function returns an `ulong` representing the number of bytes currently used in the scratch pad memory.


---
### fd\_spad\_mem\_free<!-- {{#callable:fd_spad_mem_free}} -->
The `fd_spad_mem_free` function calculates the amount of free memory available in a scratch pad memory structure.
- **Inputs**:
    - `spad`: A pointer to a constant `fd_spad_t` structure representing the scratch pad memory.
- **Control Flow**:
    - The function accesses the `mem_max` and `mem_used` fields of the `fd_spad_t` structure pointed to by `spad`.
    - It calculates the difference between `mem_max` and `mem_used` to determine the free memory.
- **Output**: The function returns an `ulong` representing the number of free bytes available in the scratch pad memory.


---
### fd\_spad\_mem\_wmark<!-- {{#callable:fd_spad_mem_wmark}} -->
The `fd_spad_mem_wmark` function retrieves the memory watermark of a scratch pad memory (`spad`).
- **Inputs**:
    - `spad`: A constant pointer to an `fd_spad_t` structure representing the scratch pad memory from which the memory watermark is to be retrieved.
- **Control Flow**:
    - The function directly accesses the `mem_wmark` field of the `spad` structure and returns its value.
- **Output**: The function returns an `ulong` representing the memory watermark of the scratch pad memory.


---
### fd\_spad\_in\_frame<!-- {{#callable:fd_spad_in_frame}} -->
The `fd_spad_in_frame` function checks if a scratch pad memory (spad) is currently within a frame.
- **Inputs**:
    - `spad`: A pointer to a constant `fd_spad_t` structure representing the scratch pad memory.
- **Control Flow**:
    - The function accesses the `frame_free` member of the `spad` structure.
    - It compares `frame_free` with the constant `FD_SPAD_FRAME_MAX`.
    - If `frame_free` is less than `FD_SPAD_FRAME_MAX`, it returns 1, indicating the spad is in a frame.
    - Otherwise, it returns 0, indicating the spad is not in a frame.
- **Output**: An integer value, 1 if the spad is in a frame, and 0 otherwise.


---
### fd\_spad\_private\_frame\_end<!-- {{#callable:fd_spad_private_frame_end}} -->
The `fd_spad_private_frame_end` function pops the current frame from a scratch pad memory, effectively freeing all allocations made in that frame.
- **Inputs**:
    - `_spad`: A pointer to a pointer of type `fd_spad_t`, representing the scratch pad memory from which the current frame will be popped.
- **Control Flow**:
    - The function calls [`fd_spad_pop`](#fd_spad_pop) with the dereferenced `_spad` pointer, which pops the current frame from the scratch pad memory.
- **Output**: This function does not return any value; it performs an operation on the scratch pad memory to free the current frame.
- **Functions called**:
    - [`fd_spad_pop`](#fd_spad_pop)


---
### fd\_spad\_virtual<!-- {{#callable:fd_valloc_t::fd_spad_virtual}} -->
The `fd_spad_virtual` function creates and returns a virtual allocation handle for a given scratch pad memory (`fd_spad_t`).
- **Inputs**:
    - `spad`: A pointer to an `fd_spad_t` structure representing the scratch pad memory for which a virtual allocation handle is to be created.
- **Control Flow**:
    - Initialize a `fd_valloc_t` structure named `valloc` with the `spad` pointer and a reference to `fd_spad_vtable`.
    - Return the initialized `valloc` structure.
- **Output**: The function returns an `fd_valloc_t` structure, which is a handle to the virtual allocation associated with the provided scratch pad memory.
- **See also**: [`fd_valloc_t`](../valloc/fd_valloc.h.driver.md#fd_valloc_t)  (Data Structure)


---
### fd\_spad\_reset\_impl<!-- {{#callable:fd_spad_reset_impl}} -->
The `fd_spad_reset_impl` function resets a scratch pad memory structure by setting its frame count to the maximum and its used memory to zero.
- **Inputs**:
    - `spad`: A pointer to an `fd_spad_t` structure representing the scratch pad memory to be reset.
- **Control Flow**:
    - The function sets the `frame_free` member of the `spad` structure to `FD_SPAD_FRAME_MAX`, indicating that all frames are free.
    - The function sets the `mem_used` member of the `spad` structure to `0UL`, indicating that no memory is currently used.
- **Output**: The function does not return a value; it modifies the `spad` structure in place.


---
### fd\_spad\_delete\_impl<!-- {{#callable:fd_spad_delete_impl}} -->
The `fd_spad_delete_impl` function unformats a memory region used as a scratch pad (spad) by verifying its integrity and resetting its magic number to zero.
- **Inputs**:
    - `shspad`: A pointer to the shared memory region containing the scratch pad to be deleted.
- **Control Flow**:
    - Cast the input `shspad` to a `fd_spad_t` pointer named `spad`.
    - Check if `spad` is NULL; if so, return NULL.
    - Check if `spad` is aligned to `FD_SPAD_ALIGN`; if not, return NULL.
    - Check if `spad->magic` equals `FD_SPAD_MAGIC`; if not, return NULL.
    - Use `FD_COMPILER_MFENCE()` to ensure memory ordering before and after setting `spad->magic` to 0.
    - Set `spad->magic` to 0 using `FD_VOLATILE`.
    - Return the `spad` pointer.
- **Output**: Returns the pointer to the `fd_spad_t` structure if successful, or NULL if any validation checks fail.


---
### fd\_spad\_alloc\_max\_impl<!-- {{#callable:fd_spad_alloc_max_impl}} -->
The `fd_spad_alloc_max_impl` function calculates the maximum number of bytes that can be allocated from a scratch pad memory with a specified alignment.
- **Inputs**:
    - `spad`: A pointer to a constant `fd_spad_t` structure representing the scratch pad memory.
    - `align`: An unsigned long integer specifying the desired alignment for the allocation, which must be a power of 2 or 0 to use the default alignment.
- **Control Flow**:
    - The function first checks if the provided alignment is greater than 0; if not, it defaults to `FD_SPAD_ALLOC_ALIGN_DEFAULT`.
    - It calculates the offset by aligning the current memory used (`spad->mem_used`) to the specified alignment.
    - It then computes the maximum of the total memory available (`spad->mem_max`) and the calculated offset.
    - Finally, it returns the difference between this maximum value and the offset, representing the maximum allocatable memory.
- **Output**: The function returns an unsigned long integer representing the maximum number of bytes that can be allocated with the specified alignment.


---
### fd\_spad\_frame\_lo\_impl<!-- {{#callable:fd_spad_frame_lo_impl}} -->
The `fd_spad_frame_lo_impl` function returns a pointer to the start of the current frame's memory allocation within a scratch pad memory structure.
- **Inputs**:
    - `spad`: A pointer to an `fd_spad_t` structure representing the scratch pad memory.
- **Control Flow**:
    - The function calls [`fd_spad_private_mem`](#fd_spad_private_mem) with the `spad` pointer to get the base address of the scratch pad's memory region.
    - It then accesses the `off` array within the `spad` structure using the index `spad->frame_free` to get the offset for the current frame.
    - The function returns the sum of the base address and the offset, which points to the start of the current frame's memory allocation.
- **Output**: A pointer to the start of the current frame's memory allocation within the scratch pad.
- **Functions called**:
    - [`fd_spad_private_mem`](#fd_spad_private_mem)


---
### fd\_spad\_frame\_hi\_impl<!-- {{#callable:fd_spad_frame_hi_impl}} -->
The `fd_spad_frame_hi_impl` function returns a pointer to the end of the currently used memory in a scratch pad memory structure.
- **Inputs**:
    - `spad`: A pointer to an `fd_spad_t` structure representing the scratch pad memory.
- **Control Flow**:
    - Call [`fd_spad_private_mem`](#fd_spad_private_mem) with `spad` to get the base address of the scratch pad memory.
    - Add `spad->mem_used` to the base address to get the address of the end of the used memory.
- **Output**: A pointer to the end of the currently used memory in the scratch pad.
- **Functions called**:
    - [`fd_spad_private_mem`](#fd_spad_private_mem)


---
### fd\_spad\_push\_impl<!-- {{#callable:fd_spad_push_impl}} -->
The `fd_spad_push_impl` function updates the scratch pad's frame management by decrementing the frame_free counter and storing the current memory usage at the new frame's offset.
- **Inputs**:
    - `spad`: A pointer to an `fd_spad_t` structure representing the scratch pad memory to be manipulated.
- **Control Flow**:
    - Decrement the `frame_free` counter of the `spad` structure to indicate a new frame is being used.
    - Store the current `mem_used` value at the offset corresponding to the new frame in the `off` array of the `spad` structure.
- **Output**: This function does not return a value; it modifies the `spad` structure in place.


---
### fd\_spad\_pop\_impl<!-- {{#callable:fd_spad_pop_impl}} -->
The `fd_spad_pop_impl` function updates the memory usage of a scratch pad by setting it to the offset of the next free frame and increments the frame free counter.
- **Inputs**:
    - `spad`: A pointer to an `fd_spad_t` structure representing the scratch pad memory.
- **Control Flow**:
    - Access the `off` array of the `spad` structure using the current `frame_free` index.
    - Set `mem_used` to the value at the current `frame_free` index in the `off` array.
    - Increment the `frame_free` index to indicate that a frame has been freed.
- **Output**: The function does not return a value; it modifies the `spad` structure in place.


---
### fd\_spad\_alloc\_impl<!-- {{#callable:fd_spad_alloc_impl}} -->
The `fd_spad_alloc_impl` function allocates a memory block from a scratch pad memory (`spad`) with a specified alignment and size, updating the memory usage accordingly.
- **Inputs**:
    - `spad`: A pointer to an `fd_spad_t` structure representing the scratch pad memory from which memory is to be allocated.
    - `align`: An unsigned long specifying the desired alignment for the allocation; if zero, a default alignment (`FD_SPAD_ALLOC_ALIGN_DEFAULT`) is used.
    - `sz`: An unsigned long specifying the size of the memory block to allocate.
- **Control Flow**:
    - The function first checks if the provided alignment is greater than zero; if not, it uses the default alignment (`FD_SPAD_ALLOC_ALIGN_DEFAULT`).
    - It calculates the offset (`off`) by aligning the current memory usage (`spad->mem_used`) to the specified alignment.
    - A pointer (`buf`) to the allocated memory is obtained by adding the offset to the base address of the scratch pad's memory region.
    - The memory usage (`spad->mem_used`) is updated to reflect the new allocation by adding the size (`sz`) to the offset.
    - If `FD_SPAD_TRACK_USAGE` is enabled, the function updates the memory watermark (`spad->mem_wmark`) if the new memory usage exceeds the previous watermark.
    - Finally, the function returns the pointer to the allocated memory block (`buf`).
- **Output**: A pointer to the allocated memory block within the scratch pad, aligned as specified.
- **Functions called**:
    - [`fd_spad_private_mem`](#fd_spad_private_mem)


---
### fd\_spad\_trim\_impl<!-- {{#callable:fd_spad_trim_impl}} -->
The `fd_spad_trim_impl` function adjusts the memory usage of a scratch pad by setting the used memory to the difference between a given high memory address and the base memory address of the scratch pad.
- **Inputs**:
    - `spad`: A pointer to an `fd_spad_t` structure representing the scratch pad memory.
    - `hi`: A pointer to a memory location representing the new high boundary of the scratch pad's used memory.
- **Control Flow**:
    - Calculate the difference between the provided high memory address (`hi`) and the base memory address of the scratch pad (`fd_spad_private_mem(spad)`).
    - Assign this difference to the `mem_used` field of the `fd_spad_t` structure, effectively updating the amount of memory used by the scratch pad.
- **Output**: The function does not return a value; it modifies the `mem_used` field of the `fd_spad_t` structure in place.
- **Functions called**:
    - [`fd_spad_private_mem`](#fd_spad_private_mem)


---
### fd\_spad\_prepare\_impl<!-- {{#callable:fd_spad_prepare_impl}} -->
The `fd_spad_prepare_impl` function prepares a memory allocation in a scratch pad with a specified alignment, returning a pointer to the aligned memory location.
- **Inputs**:
    - `spad`: A pointer to an `fd_spad_t` structure representing the scratch pad memory.
    - `align`: An unsigned long specifying the desired alignment for the memory allocation; if zero, a default alignment is used.
    - `max`: An unsigned long representing the maximum size of the allocation, though it is not used in this function.
- **Control Flow**:
    - The function first ignores the `max` parameter as it is not used in the implementation.
    - It checks if the `align` parameter is greater than zero; if not, it defaults to `FD_SPAD_ALLOC_ALIGN_DEFAULT`.
    - The function calculates the offset `off` by aligning `spad->mem_used` to the specified `align`.
    - It then calculates the buffer pointer `buf` by adding the offset `off` to the base address of the scratch pad's private memory.
    - The `mem_used` field of the `spad` structure is updated to the new offset `off`.
    - Finally, the function returns the pointer `buf` to the aligned memory location.
- **Output**: A pointer to the aligned memory location within the scratch pad's memory.
- **Functions called**:
    - [`fd_spad_private_mem`](#fd_spad_private_mem)


---
### fd\_spad\_cancel\_impl<!-- {{#callable:fd_spad_cancel_impl}} -->
The `fd_spad_cancel_impl` function is a no-operation function that takes a pointer to a `fd_spad_t` structure and does nothing with it.
- **Inputs**:
    - `spad`: A pointer to a `fd_spad_t` structure, representing a scratch pad memory, which is not used in the function.
- **Control Flow**:
    - The function takes a single argument, `spad`, which is a pointer to a `fd_spad_t` structure.
    - The function explicitly casts the `spad` argument to void to indicate that it is intentionally unused.
    - No operations are performed within the function body.
- **Output**: The function does not produce any output or modify any state.


---
### fd\_spad\_publish\_impl<!-- {{#callable:fd_spad_publish_impl}} -->
The `fd_spad_publish_impl` function updates the memory usage of a scratch pad by adding a specified size to the current memory used.
- **Inputs**:
    - `spad`: A pointer to an `fd_spad_t` structure representing the scratch pad memory.
    - `sz`: An unsigned long integer representing the size of memory to be added to the current usage.
- **Control Flow**:
    - The function takes a pointer to a scratch pad (`fd_spad_t`) and a size (`sz`).
    - It increments the `mem_used` field of the `fd_spad_t` structure by the value of `sz`.
- **Output**: The function does not return any value; it modifies the `mem_used` field of the `fd_spad_t` structure in place.


---
### fd\_spad\_reset<!-- {{#callable:fd_spad_reset}} -->
The `fd_spad_reset` function resets a scratch pad memory (spad) by popping all frames in use, effectively clearing all allocations.
- **Inputs**:
    - `spad`: A pointer to an `fd_spad_t` structure representing the scratch pad memory to be reset.
- **Control Flow**:
    - The function calls `SELECT_IMPL(fd_spad_reset)` with the `spad` argument, which selects the appropriate implementation of the reset operation based on compile-time conditions.
    - The selected implementation function is then executed, which resets the spad by popping all frames and clearing memory usage.
- **Output**: The function does not return a value; it modifies the state of the `spad` in place.


---
### fd\_spad\_delete<!-- {{#callable:fd_spad_delete}} -->
The `fd_spad_delete` function unformats a memory region used as a scratch pad (spad) and returns the pointer to the start of the region on success or NULL on failure.
- **Inputs**:
    - `shspad`: A pointer to the first byte of the memory region containing the spad, in the caller's address space.
- **Control Flow**:
    - The function calls `SELECT_IMPL(fd_spad_delete)` with `shspad` as the argument.
    - `SELECT_IMPL` is a macro that selects the appropriate implementation of `fd_spad_delete` based on compile-time conditions.
    - The selected implementation checks if `shspad` is non-NULL, properly aligned, and contains a valid spad by verifying its magic number.
    - If any of these checks fail, the function returns NULL.
    - If all checks pass, the function sets the spad's magic number to 0, effectively unformatting it, and returns the pointer to the spad.
- **Output**: The function returns the pointer `shspad` on success, or NULL if the spad is invalid or the input is misaligned or NULL.


---
### fd\_spad\_alloc\_max<!-- {{#callable:fd_spad_alloc_max}} -->
The `fd_spad_alloc_max` function returns the maximum number of bytes that can be allocated with a specified alignment from a shared scratch pad memory (spad).
- **Inputs**:
    - `spad`: A pointer to a constant `fd_spad_t` structure representing the shared scratch pad memory from which the allocation is to be made.
    - `align`: An unsigned long integer specifying the alignment requirement for the allocation, which must be a power of 2 within the range [1, FD_SPAD_ALIGN] or 0 to use the default alignment.
- **Control Flow**:
    - The function calls `SELECT_IMPL(fd_spad_alloc_max)` with the provided `spad` and `align` arguments.
    - `SELECT_IMPL` is a macro that selects the appropriate implementation of `fd_spad_alloc_max` based on compile-time conditions, such as debugging or sanitization requirements.
    - The selected implementation calculates the maximum allocatable bytes considering the alignment and current memory usage of the spad.
- **Output**: The function returns an unsigned long integer representing the maximum number of bytes that can be allocated with the specified alignment from the spad.


---
### fd\_spad\_frame\_lo<!-- {{#callable:fd_spad_frame_lo}} -->
The `fd_spad_frame_lo` function returns a pointer to the start of the memory region allocated for the current frame in a scratch pad memory.
- **Inputs**:
    - `spad`: A pointer to an `fd_spad_t` structure representing the scratch pad memory.
- **Control Flow**:
    - The function calls `SELECT_IMPL(fd_spad_frame_lo)` with the `spad` argument.
    - The `SELECT_IMPL` macro determines which implementation of `fd_spad_frame_lo` to use based on compile-time conditions, such as debugging or sanitization settings.
    - The selected implementation function returns a pointer to the start of the current frame's memory region.
- **Output**: A pointer to the start of the memory region for the current frame in the scratch pad memory.


---
### fd\_spad\_frame\_hi<!-- {{#callable:fd_spad_frame_hi}} -->
The `fd_spad_frame_hi` function returns a pointer to the end of the current frame in a shared scratch pad memory.
- **Inputs**:
    - `spad`: A pointer to an `fd_spad_t` structure representing the shared scratch pad memory.
- **Control Flow**:
    - The function calls `SELECT_IMPL(fd_spad_frame_hi)` with the `spad` argument.
    - The `SELECT_IMPL` macro determines which implementation of `fd_spad_frame_hi` to use based on compile-time conditions.
    - The selected implementation returns a pointer to the end of the current frame in the scratch pad memory.
- **Output**: A pointer to the end of the current frame in the shared scratch pad memory.


---
### fd\_spad\_push<!-- {{#callable:fd_spad_push}} -->
The `fd_spad_push` function creates a new frame in a scratch pad memory and makes it the current frame.
- **Inputs**:
    - `spad`: A pointer to an `fd_spad_t` structure representing the scratch pad memory.
- **Control Flow**:
    - The function calls `SELECT_IMPL(fd_spad_push)` with the `spad` argument.
    - The `SELECT_IMPL` macro determines which implementation of `fd_spad_push` to use based on compile-time conditions, such as debugging or sanitization options.
    - The selected implementation function (`fd_spad_push_impl`, `fd_spad_push_debug`, or `fd_spad_push_sanitizer_impl`) is executed, which decrements the `frame_free` counter and sets the current frame's offset to the current `mem_used` value.
- **Output**: The function does not return a value; it modifies the state of the `fd_spad_t` structure pointed to by `spad`.


---
### fd\_spad\_pop<!-- {{#callable:fd_spad_pop}} -->
The `fd_spad_pop` function removes the current frame from a scratch pad memory, freeing all allocations within that frame and reverting to the previous frame if one exists.
- **Inputs**:
    - `spad`: A pointer to an `fd_spad_t` structure representing the scratch pad memory from which the current frame will be popped.
- **Control Flow**:
    - The function calls `SELECT_IMPL(fd_spad_pop)` with the `spad` argument, which selects the appropriate implementation of the `fd_spad_pop` function based on compile-time conditions.
    - The selected implementation function (`fd_spad_pop_impl`, `fd_spad_pop_debug`, or `fd_spad_pop_sanitizer_impl`) is executed, which updates the `mem_used` field of the `spad` structure to the offset of the previous frame, effectively removing the current frame.
- **Output**: The function does not return a value; it modifies the `spad` structure in place to reflect the removal of the current frame.


---
### fd\_spad\_alloc<!-- {{#callable:fd_spad_alloc}} -->
The `fd_spad_alloc` function allocates a specified size of memory with a given alignment from a scratch pad memory structure.
- **Inputs**:
    - `spad`: A pointer to an `fd_spad_t` structure, representing the scratch pad memory from which memory is to be allocated.
    - `align`: An unsigned long integer specifying the alignment for the memory allocation; it must be a power of 2 within the range [1, FD_SPAD_ALIGN] or 0 to use the default alignment.
    - `sz`: An unsigned long integer specifying the size of the memory to allocate.
- **Control Flow**:
    - The function calls `SELECT_IMPL(fd_spad_alloc)` with the provided `spad`, `align`, and `sz` arguments.
    - `SELECT_IMPL` is a macro that selects the appropriate implementation of `fd_spad_alloc` based on compile-time conditions, such as debugging or sanitization needs.
    - The selected implementation function performs the memory allocation from the scratch pad.
- **Output**: A pointer to the allocated memory region within the scratch pad, aligned as specified, or NULL if the allocation fails.


---
### fd\_spad\_trim<!-- {{#callable:fd_spad_trim}} -->
The `fd_spad_trim` function adjusts the current frame's high memory boundary in a scratch pad memory to a specified address.
- **Inputs**:
    - `spad`: A pointer to the `fd_spad_t` structure representing the scratch pad memory.
    - `hi`: A pointer to the new high boundary address within the current frame of the scratch pad memory.
- **Control Flow**:
    - The function calls `SELECT_IMPL(fd_spad_trim)` with the provided `spad` and `hi` arguments.
    - The `SELECT_IMPL` macro determines which implementation of `fd_spad_trim` to use based on compile-time conditions, such as debugging or sanitization needs.
- **Output**: The function does not return a value; it modifies the `mem_used` field of the `spad` structure to reflect the new high boundary.


---
### fd\_spad\_prepare<!-- {{#callable:fd_spad_prepare}} -->
The `fd_spad_prepare` function initiates the preparation of a memory allocation in a scratch pad with specified alignment and maximum size.
- **Inputs**:
    - `spad`: A pointer to an `fd_spad_t` structure representing the scratch pad memory.
    - `align`: An unsigned long specifying the alignment for the allocation, which must be a power of 2 within the range [1, FD_SPAD_ALIGN] or 0 to use the default alignment.
    - `max`: An unsigned long indicating the maximum number of bytes to allocate.
- **Control Flow**:
    - The function calls `SELECT_IMPL(fd_spad_prepare)` with the provided arguments `spad`, `align`, and `max`.
    - The `SELECT_IMPL` macro determines which implementation of `fd_spad_prepare` to use based on compile-time conditions, such as debugging or sanitization requirements.
    - The selected implementation of `fd_spad_prepare` prepares the scratch pad for an allocation by aligning the current memory usage and returning a pointer to the start of the prepared memory region.
- **Output**: A pointer to the start of the prepared memory region in the caller's address space, aligned as specified.


---
### fd\_spad\_cancel<!-- {{#callable:fd_spad_cancel}} -->
The `fd_spad_cancel` function cancels the most recent prepare operation on a shared scratch pad memory (spad), ensuring the spad is in a frame and not in a prepare state.
- **Inputs**:
    - `spad`: A pointer to an `fd_spad_t` structure representing the shared scratch pad memory to operate on.
- **Control Flow**:
    - The function calls `SELECT_IMPL(fd_spad_cancel)` with the `spad` argument.
    - The `SELECT_IMPL` macro determines which implementation of `fd_spad_cancel` to use based on compile-time conditions, such as debugging or sanitization needs.
    - The selected implementation of `fd_spad_cancel` is executed, which currently does nothing with the `spad` argument.
- **Output**: The function does not return any value; it operates directly on the `spad` structure.


---
### fd\_spad\_publish<!-- {{#callable:fd_spad_publish}} -->
The `fd_spad_publish` function finalizes a memory allocation in a scratch pad memory by updating the used memory size with the specified allocation size.
- **Inputs**:
    - `spad`: A pointer to an `fd_spad_t` structure representing the scratch pad memory.
    - `sz`: The size in bytes of the memory allocation to finalize.
- **Control Flow**:
    - The function calls a selected implementation of `fd_spad_publish` using the `SELECT_IMPL` macro, which chooses between different implementations based on compile-time conditions.
    - The selected implementation updates the `mem_used` field of the `fd_spad_t` structure by adding the specified size `sz` to it, finalizing the allocation.
- **Output**: The function does not return a value; it modifies the state of the `fd_spad_t` structure to reflect the finalized allocation.


# Function Declarations (Public API)

---
### fd\_spad\_reset<!-- {{#callable_declaration:fd_spad_reset}} -->
Resets the scratch pad memory to its initial state.
- **Description**: Use this function to reset a scratch pad memory (spad) to its initial state by popping all frames in use. This function should be called when you want to clear all current allocations and frames, effectively starting fresh with the spad. It is assumed that the spad is a current local join when this function is called. After execution, the spad will not be in any frame, and all memory previously allocated will be freed. This operation is fast, with O(1) complexity.
- **Inputs**:
    - `spad`: A pointer to the fd_spad_t structure representing the scratch pad memory. It must not be null and should be a current local join. The caller retains ownership of the spad.
- **Output**: None
- **See also**: [`fd_spad_reset`](#fd_spad_reset)  (Implementation)


---
### fd\_spad\_delete<!-- {{#callable_declaration:fd_spad_delete}} -->
Unformats a memory region used as a shared scratch pad.
- **Description**: Use this function to unformat a memory region that was previously formatted as a shared scratch pad (spad). It should be called when the spad is no longer needed and there are no active joins to it. This function returns the original memory pointer on success, allowing for potential reuse of the memory region. It silently returns NULL if the provided pointer is invalid, misaligned, or does not point to a valid spad.
- **Inputs**:
    - `shspad`: A pointer to the first byte of the memory region containing the spad. It must be aligned to FD_SPAD_ALIGN and must not be NULL. The function will return NULL if these conditions are not met or if the memory does not contain a valid spad.
- **Output**: Returns the original pointer to the memory region on success, or NULL on failure.
- **See also**: [`fd_spad_delete`](#fd_spad_delete)  (Implementation)


---
### fd\_spad\_alloc\_max<!-- {{#callable_declaration:fd_spad_alloc_max}} -->
Returns the maximum allocatable bytes with specified alignment in a spad.
- **Description**: This function determines the maximum number of bytes that can be allocated from a scratch pad memory (spad) with a specified alignment. It should be called when the spad is currently joined locally and is within a frame. The alignment must be a power of two within the range [1, FD_SPAD_ALIGN] or zero, where zero indicates the use of the default alignment FD_SPAD_ALLOC_ALIGN_DEFAULT. This function is useful for querying the available space for allocations with specific alignment requirements.
- **Inputs**:
    - `spad`: A pointer to a constant fd_spad_t, representing the scratch pad memory. It must be a valid, currently joined spad and not null.
    - `align`: An unsigned long specifying the alignment for the allocation. It must be a power of two within [1, FD_SPAD_ALIGN] or zero to use the default alignment. Invalid values are not handled explicitly, so ensure the alignment is valid.
- **Output**: Returns an unsigned long representing the maximum number of bytes that can be allocated with the specified alignment.
- **See also**: [`fd_spad_alloc_max`](#fd_spad_alloc_max)  (Implementation)


---
### fd\_spad\_frame\_lo<!-- {{#callable_declaration:fd_spad_frame_lo}} -->
Returns the starting address of the current frame in the scratch pad memory.
- **Description**: Use this function to obtain a pointer to the beginning of the current frame in a scratch pad memory. This is useful when you need to access or manipulate data within the current frame. The function assumes that the scratch pad is a current local join and is in a frame. It is important to ensure that the scratch pad is properly initialized and joined before calling this function.
- **Inputs**:
    - `spad`: A pointer to an fd_spad_t structure representing the scratch pad memory. It must not be null and should be a current local join in a frame.
- **Output**: A pointer to the first byte of the current frame in the scratch pad memory.
- **See also**: [`fd_spad_frame_lo`](#fd_spad_frame_lo)  (Implementation)


---
### fd\_spad\_frame\_hi<!-- {{#callable_declaration:fd_spad_frame_hi}} -->
Returns the end address of the current frame in the scratch pad memory.
- **Description**: Use this function to obtain a pointer to the end of the current frame in a scratch pad memory. This is useful for determining the boundary of the current frame's allocations. The function must be called when the scratch pad is in a frame, and the caller must have a current local join to the scratch pad. The returned pointer is valid as long as the frame remains unchanged.
- **Inputs**:
    - `spad`: A pointer to a scratch pad memory (fd_spad_t). Must not be null and must be a current local join. The scratch pad must be in a frame when this function is called.
- **Output**: Returns a pointer to the end of the current frame in the scratch pad memory.
- **See also**: [`fd_spad_frame_hi`](#fd_spad_frame_hi)  (Implementation)


---
### fd\_spad\_push<!-- {{#callable_declaration:fd_spad_push}} -->
Creates a new frame in the scratch pad memory.
- **Description**: Use this function to create a new frame in the scratch pad memory, which allows for efficient memory allocation and deallocation within that frame. This function should be called when you need to start a new set of allocations that can be bulk freed later. It must be called when the scratch pad is a current local join and there is at least one frame available. After calling this function, the scratch pad will be in a frame and not in a prepare state.
- **Inputs**:
    - `spad`: A pointer to a fd_spad_t structure representing the scratch pad memory. It must not be null and should be a current local join with at least one frame free. The caller retains ownership.
- **Output**: None
- **See also**: [`fd_spad_push`](#fd_spad_push)  (Implementation)


---
### fd\_spad\_pop<!-- {{#callable_declaration:fd_spad_pop}} -->
Destroys the current frame in a scratch pad memory.
- **Description**: Use this function to destroy the current frame in a scratch pad memory, which will free all allocations made within that frame and cancel any in-progress preparations. It should be called when the spad is a current local join and is in a frame. After execution, if there was a previous frame, it will become the current frame; otherwise, the spad will not be in a frame. This operation is fast and has a time complexity of O(1).
- **Inputs**:
    - `spad`: A pointer to a fd_spad_t structure representing the scratch pad memory. It must be a current local join and in a frame. The caller retains ownership and must ensure the pointer is valid.
- **Output**: None
- **See also**: [`fd_spad_pop`](#fd_spad_pop)  (Implementation)


---
### fd\_spad\_alloc<!-- {{#callable_declaration:fd_spad_alloc}} -->
Allocates memory from a shared scratch pad with specified alignment and size.
- **Description**: Use this function to allocate a block of memory from a shared scratch pad memory (spad) with a specified alignment and size. This function should be called when the spad is a current local join and is within a frame. The alignment must be a power of 2 within the range [1, FD_SPAD_ALIGN] or 0, which defaults to FD_SPAD_ALLOC_ALIGN_DEFAULT. The size must be within the allowable allocation size for the spad. The function returns a pointer to the allocated memory, which remains valid until the next frame pop or spad deletion. This operation is fast and efficient, suitable for high-performance applications.
- **Inputs**:
    - `spad`: A pointer to the fd_spad_t structure representing the shared scratch pad memory. Must be a current local join and in a frame. The caller retains ownership.
    - `align`: Specifies the alignment of the allocation. Must be a power of 2 within [1, FD_SPAD_ALIGN] or 0 to use FD_SPAD_ALLOC_ALIGN_DEFAULT. Invalid values are not allowed.
    - `sz`: The size of the memory block to allocate. Must be within the maximum allowable allocation size for the spad. Invalid sizes are not allowed.
- **Output**: Returns a pointer to the allocated memory block with the specified alignment. The pointer is valid until the next frame pop or spad deletion.
- **See also**: [`fd_spad_alloc`](#fd_spad_alloc)  (Implementation)


---
### fd\_spad\_trim<!-- {{#callable_declaration:fd_spad_trim}} -->
Trim the current frame's high memory boundary to a specified address.
- **Description**: Use this function to adjust the high boundary of the current frame in a scratch pad memory to a specified address, effectively reducing the size of the most recent allocation. This function should be called when the scratch pad is in a frame, and the specified address must be within the current frame's memory range. It is useful for optimizing memory usage by releasing unused memory back to the scratch pad. Ensure that the scratch pad is a current local join and that the specified address is valid within the current frame's limits.
- **Inputs**:
    - `spad`: A pointer to the fd_spad_t structure representing the scratch pad memory. Must not be null and should be a current local join.
    - `hi`: A pointer to the new high boundary address within the current frame. Must be within the range [frame_lo, frame_hi] of the current frame.
- **Output**: None
- **See also**: [`fd_spad_trim`](#fd_spad_trim)  (Implementation)


---
### fd\_spad\_prepare<!-- {{#callable_declaration:fd_spad_prepare}} -->
Prepares a scratch pad allocation with specified alignment and maximum size.
- **Description**: Use this function to start preparing an allocation in a shared scratch pad memory with a specified alignment and maximum size. It should be called when the exact size of the allocation is not known upfront, allowing for dynamic allocation adjustments. The function must be called when the scratch pad is in a current local join and within a frame. It implicitly cancels any in-progress prepare operation. The returned pointer is valid until the next prepare, cancel, alloc, trim, push, pop, leave, or delete operation. This function is useful for optimizing allocations in real-time streaming or when the final size of the data is determined after some processing.
- **Inputs**:
    - `spad`: A pointer to the fd_spad_t structure representing the scratch pad. Must be a current local join and in a frame. The caller retains ownership.
    - `align`: Specifies the alignment for the allocation. Must be an integer power of 2 within [1, FD_SPAD_ALIGN] or 0 to use FD_SPAD_ALLOC_ALIGN_DEFAULT. Invalid values will default to FD_SPAD_ALLOC_ALIGN_DEFAULT.
    - `max`: The maximum number of bytes to allocate. Must be within [0, alloc_max]. Invalid values may result in undefined behavior.
- **Output**: Returns a pointer to the start of the prepared allocation with the specified alignment. The pointer is valid until the next prepare, cancel, alloc, trim, push, pop, leave, or delete operation.
- **See also**: [`fd_spad_prepare`](#fd_spad_prepare)  (Implementation)


---
### fd\_spad\_cancel<!-- {{#callable_declaration:fd_spad_cancel}} -->
Cancels the most recent prepare operation on a scratch pad.
- **Description**: Use this function to cancel the most recent prepare operation on a scratch pad memory (spad). It should be called when a prepare operation is in progress and needs to be aborted. After calling this function, the spad will be in a frame and not in a prepare state. This function is fast and operates in O(1) time complexity. It is important to note that any alignment padding done during the prepare will still be allocated after cancellation.
- **Inputs**:
    - `spad`: A pointer to a fd_spad_t structure representing the scratch pad memory. It must not be null and should be a current local join in a prepare state. The caller retains ownership of the spad.
- **Output**: None
- **See also**: [`fd_spad_cancel`](#fd_spad_cancel)  (Implementation)


---
### fd\_spad\_publish<!-- {{#callable_declaration:fd_spad_publish}} -->
Completes the allocation started by the most recent prepare call.
- **Description**: Use this function to finalize an allocation that was previously started with a prepare call. It should be called when you have determined the final size of the allocation, which must be within the maximum size specified during the prepare. This function assumes that the scratch pad is currently joined and in a prepare state. After calling this function, the scratch pad will be in a frame and not in a prepare state. It is a fast operation with O(1) complexity.
- **Inputs**:
    - `spad`: A pointer to a fd_spad_t structure representing the scratch pad memory. It must be a valid, currently joined scratch pad and not null.
    - `sz`: The size in bytes of the allocation to finalize. It must be within the range [0, prepare's max] as specified during the prepare call.
- **Output**: None
- **See also**: [`fd_spad_publish`](#fd_spad_publish)  (Implementation)


---
### fd\_spad\_verify<!-- {{#callable_declaration:fd_spad_verify}} -->
Verifies the integrity of a scratch pad memory structure.
- **Description**: Use this function to check if a given scratch pad memory (spad) is valid and not corrupt. It should be called when you need to ensure that the spad is a current local join and that its metadata is consistent. This function is useful for debugging and validation purposes, especially in environments where logging services are available. It returns an error code if the spad is corrupt, logging details of the failure, or zero if the spad is valid.
- **Inputs**:
    - `spad`: A pointer to a constant fd_spad_t structure representing the scratch pad memory to be verified. It must not be null, and the spad must be a current local join. If the spad is null or its magic number is incorrect, the function will return an error code.
- **Output**: Returns 0 if the spad is valid, or a negative integer error code if the spad is corrupt, with details logged.
- **See also**: [`fd_spad_verify`](fd_spad.c.driver.md#fd_spad_verify)  (Implementation)


---
### fd\_spad\_reset\_debug<!-- {{#callable_declaration:fd_spad_reset_debug}} -->
Resets the debug state of a shared scratch pad memory.
- **Description**: Use this function to reset the state of a shared scratch pad memory (spad) in a debug context. It should be called when you need to clear all frames and allocations in the spad, effectively returning it to an initial state. This function is intended for use in debugging scenarios and assumes that the spad is a current local join. It is important to ensure that the spad is in a valid state before calling this function to avoid undefined behavior.
- **Inputs**:
    - `spad`: A pointer to a fd_spad_t structure representing the shared scratch pad memory. Must not be null and should be a current local join. The caller retains ownership.
- **Output**: None
- **See also**: [`fd_spad_reset_debug`](fd_spad.c.driver.md#fd_spad_reset_debug)  (Implementation)


---
### fd\_spad\_delete\_debug<!-- {{#callable_declaration:fd_spad_delete_debug}} -->
Deletes a shared scratch pad memory region with debugging checks.
- **Description**: Use this function to delete a shared scratch pad memory region that was previously formatted for use as a scratch pad. This function performs additional debugging checks to ensure the integrity of the operation. It should be called when the scratch pad is no longer needed and there are no active joins to it. The function will return the pointer to the memory region on success, or NULL if the operation fails due to invalid input or if the memory region does not contain a valid scratch pad.
- **Inputs**:
    - `shspad`: A pointer to the first byte of the memory region containing the scratch pad. It must be aligned according to FD_SPAD_ALIGN and must not be NULL. The memory region should not have any active joins when this function is called. If the pointer is invalid or the region does not contain a valid scratch pad, the function will return NULL.
- **Output**: Returns the pointer to the memory region on success, or NULL on failure.
- **See also**: [`fd_spad_delete_debug`](fd_spad.c.driver.md#fd_spad_delete_debug)  (Implementation)


---
### fd\_spad\_alloc\_max\_debug<!-- {{#callable_declaration:fd_spad_alloc_max_debug}} -->
Returns the maximum number of bytes that can be allocated with a specified alignment.
- **Description**: This function determines the maximum number of bytes that can be allocated from a scratch pad memory with a specified alignment. It should be called when the scratch pad is in a frame, and the alignment must be a power of two or zero, where zero indicates the use of the default alignment. The function will log a critical error if the scratch pad is not in a frame or if the alignment is invalid. This function is useful for debugging purposes to ensure that allocations can be made with the desired alignment.
- **Inputs**:
    - `spad`: A pointer to a constant fd_spad_t structure representing the scratch pad memory. It must not be null and must be in a valid frame.
    - `align`: An unsigned long representing the desired alignment for the allocation. It must be a power of two or zero, where zero uses the default alignment. Invalid alignments will trigger a critical error log.
- **Output**: Returns the maximum number of bytes that can be allocated with the specified alignment.
- **See also**: [`fd_spad_alloc_max_debug`](fd_spad.c.driver.md#fd_spad_alloc_max_debug)  (Implementation)


---
### fd\_spad\_frame\_lo\_debug<!-- {{#callable_declaration:fd_spad_frame_lo_debug}} -->
Returns the starting address of the current frame in a scratch pad memory with debugging checks.
- **Description**: Use this function to obtain the starting address of the current frame in a scratch pad memory when debugging is enabled. It is essential to ensure that the scratch pad is currently in a frame before calling this function, as it will log a critical error and terminate the program if the scratch pad is not in a frame. This function is useful for debugging purposes to verify the integrity and state of the scratch pad memory.
- **Inputs**:
    - `spad`: A pointer to a fd_spad_t structure representing the scratch pad memory. The pointer must not be null, and the scratch pad must be in a valid frame state. The caller retains ownership of the memory.
- **Output**: Returns a pointer to the starting address of the current frame in the scratch pad memory.
- **See also**: [`fd_spad_frame_lo_debug`](fd_spad.c.driver.md#fd_spad_frame_lo_debug)  (Implementation)


---
### fd\_spad\_frame\_hi\_debug<!-- {{#callable_declaration:fd_spad_frame_hi_debug}} -->
Returns the high memory address of the current frame in a scratch pad.
- **Description**: Use this function to obtain the high memory address of the current frame in a scratch pad memory. This function should be called only when the scratch pad is in a frame, as it will log a critical error if the scratch pad is not currently in a frame. This is useful for debugging purposes to verify the current memory usage within a frame.
- **Inputs**:
    - `spad`: A pointer to a `fd_spad_t` structure representing the scratch pad. It must not be null and must be a current local join. The function will log a critical error if the scratch pad is not in a frame.
- **Output**: Returns a pointer to the high memory address of the current frame in the scratch pad.
- **See also**: [`fd_spad_frame_hi_debug`](fd_spad.c.driver.md#fd_spad_frame_hi_debug)  (Implementation)


---
### fd\_spad\_push\_debug<!-- {{#callable_declaration:fd_spad_push_debug}} -->
Pushes a new frame onto the scratch pad memory stack with debugging checks.
- **Description**: Use this function to add a new frame to the scratch pad memory stack when debugging is enabled. It ensures that there is space available for a new frame before proceeding. If the maximum number of frames is already reached, it logs a critical error and halts execution. This function should be called when the scratch pad is in a valid state and has at least one frame available for allocation.
- **Inputs**:
    - `spad`: A pointer to a `fd_spad_t` structure representing the scratch pad memory. It must not be null and should be a valid, currently joined scratch pad with at least one free frame available.
- **Output**: None
- **See also**: [`fd_spad_push_debug`](fd_spad.c.driver.md#fd_spad_push_debug)  (Implementation)


---
### fd\_spad\_pop\_debug<!-- {{#callable_declaration:fd_spad_pop_debug}} -->
Pops the current frame from the scratch pad memory.
- **Description**: Use this function to remove the current frame from the scratch pad memory, effectively freeing all allocations made within that frame. It must be called when the scratch pad is in a frame, which is a precondition for this operation. If the scratch pad is not in a frame, the function will log a critical error and terminate the program. This function is useful for managing memory in high-performance applications where frames are used to group allocations that can be freed together.
- **Inputs**:
    - `spad`: A pointer to a fd_spad_t structure representing the scratch pad memory. It must not be null and must be a valid, joined scratch pad that is currently in a frame. The caller retains ownership of the memory.
- **Output**: None
- **See also**: [`fd_spad_pop_debug`](fd_spad.c.driver.md#fd_spad_pop_debug)  (Implementation)


---
### fd\_spad\_alloc\_check<!-- {{#callable_declaration:fd_spad_alloc_check}} -->
Allocates memory from a shared scratch pad with specified alignment and size.
- **Description**: Use this function to allocate a block of memory from a shared scratch pad (spad) with a specified alignment and size. It must be called when the spad is in a frame, and the alignment must be a power of two or zero (indicating default alignment). The requested size must not exceed the maximum allocatable size for the given alignment. If any of these conditions are not met, the function will log a critical error and terminate the program. This function is suitable for high-performance scenarios where fast memory allocation is required.
- **Inputs**:
    - `spad`: A pointer to the fd_spad_t structure representing the shared scratch pad. Must not be null and must be in a valid frame.
    - `align`: The desired alignment for the allocation. Must be a power of two or zero (to use the default alignment). If not a power of two, a critical error is logged.
    - `sz`: The size of the memory block to allocate. Must be less than or equal to the maximum allocatable size for the given alignment. If not, a critical error is logged.
- **Output**: Returns a pointer to the allocated memory block with the specified alignment. The pointer is valid until the frame is popped or the spad is deleted.
- **See also**: [`fd_spad_alloc_check`](fd_spad.c.driver.md#fd_spad_alloc_check)  (Implementation)


---
### fd\_spad\_trim\_debug<!-- {{#callable_declaration:fd_spad_trim_debug}} -->
Performs a debug check and trims the current frame of a scratch pad memory.
- **Description**: This function is used to trim the current frame of a scratch pad memory to a specified high address, with additional debug checks to ensure the operation is valid. It should be called when the scratch pad is in a frame, and the specified high address is within the current frame's bounds. If any preconditions are violated, the function will log a critical error and terminate the program. This function is useful for debugging purposes to ensure that the trimming operation is performed correctly.
- **Inputs**:
    - `spad`: A pointer to a fd_spad_t structure representing the scratch pad memory. Must not be null and must be a current local join.
    - `hi`: A pointer representing the high address to which the current frame should be trimmed. Must be within the range of the current frame's low and high addresses.
- **Output**: None
- **See also**: [`fd_spad_trim_debug`](fd_spad.c.driver.md#fd_spad_trim_debug)  (Implementation)


---
### fd\_spad\_prepare\_debug<!-- {{#callable_declaration:fd_spad_prepare_debug}} -->
Prepares a debug allocation in a shared scratch pad memory.
- **Description**: Use this function to prepare a memory allocation in a shared scratch pad (spad) for debugging purposes. It must be called when the spad is in a frame, and the alignment must be a power of two or zero, which defaults to a predefined alignment. The maximum size of the allocation must not exceed the maximum allocatable size for the given alignment. This function will log a critical error if these conditions are not met, ensuring that the spad is in a valid state for allocation.
- **Inputs**:
    - `spad`: A pointer to a fd_spad_t structure representing the shared scratch pad memory. It must be a valid, joined spad that is currently in a frame.
    - `align`: An unsigned long specifying the alignment for the allocation. It must be a power of two or zero, which defaults to FD_SPAD_ALLOC_ALIGN_DEFAULT.
    - `max`: An unsigned long specifying the maximum number of bytes to allocate. It must not exceed the maximum allocatable size for the given alignment.
- **Output**: Returns a pointer to the prepared memory region in the caller's address space, aligned as specified.
- **See also**: [`fd_spad_prepare_debug`](fd_spad.c.driver.md#fd_spad_prepare_debug)  (Implementation)


---
### fd\_spad\_cancel\_debug<!-- {{#callable_declaration:fd_spad_cancel_debug}} -->
Cancels the most recent prepare operation on a scratch pad.
- **Description**: Use this function to cancel the most recent prepare operation on a scratch pad memory (spad). It should be called when a prepare operation is in progress and needs to be aborted. This function assumes that the spad is a current local join and is in a prepare state. After calling this function, the spad will be in a frame and not in a prepare state. It is important to note that any alignment padding done during the prepare will still be allocated after cancellation.
- **Inputs**:
    - `spad`: A pointer to a fd_spad_t structure representing the scratch pad memory. It must not be null and should be a current local join in a prepare state. If the spad is not in a prepare state, the function will log a critical error.
- **Output**: None
- **See also**: [`fd_spad_cancel_debug`](fd_spad.c.driver.md#fd_spad_cancel_debug)  (Implementation)


---
### fd\_spad\_publish\_debug<!-- {{#callable_declaration:fd_spad_publish_debug}} -->
Publishes a prepared allocation in a shared scratch pad memory.
- **Description**: Use this function to finalize and publish a prepared allocation in a shared scratch pad memory (spad). It must be called after a successful call to `fd_spad_prepare` and before any other allocation or frame operation. The function ensures that the spad is in a valid state and that the specified size does not exceed the maximum size prepared. If the spad is not in a frame or the size is invalid, the function will log a critical error and terminate the program.
- **Inputs**:
    - `spad`: A pointer to a `fd_spad_t` structure representing the shared scratch pad memory. Must not be null and must be a valid, current local join in a frame.
    - `sz`: The size in bytes of the allocation to publish. Must be within the range [0, max] where max is the size specified in the preceding `fd_spad_prepare` call.
- **Output**: None
- **See also**: [`fd_spad_publish_debug`](fd_spad.c.driver.md#fd_spad_publish_debug)  (Implementation)


---
### fd\_spad\_reset\_sanitizer\_impl<!-- {{#callable_declaration:fd_spad_reset_sanitizer_impl}} -->
Resets and sanitizes a shared scratch pad memory.
- **Description**: Use this function to reset a shared scratch pad memory (spad) and apply memory sanitization. It should be called when you want to clear all frames and allocations in the spad, ensuring that the memory is poisoned for debugging purposes. This function is particularly useful in environments where memory safety tools like ASAN and MSAN are used to detect memory errors. Ensure that the spad is a valid and current local join before calling this function.
- **Inputs**:
    - `spad`: A pointer to a fd_spad_t structure representing the shared scratch pad memory. It must not be null and should be a valid, current local join. Invalid or null pointers may lead to undefined behavior.
- **Output**: None
- **See also**: [`fd_spad_reset_sanitizer_impl`](fd_spad.c.driver.md#fd_spad_reset_sanitizer_impl)  (Implementation)


---
### fd\_spad\_delete\_sanitizer\_impl<!-- {{#callable_declaration:fd_spad_delete_sanitizer_impl}} -->
Deletes a shared scratch pad memory region with sanitization.
- **Description**: Use this function to delete a shared scratch pad memory region while ensuring that the memory is properly sanitized for debugging purposes. This function should be called when the shared scratch pad is no longer needed and there are no active joins to it. It returns a pointer to the deleted memory region if successful, or NULL if the deletion fails due to invalid input. The function also unpoisons the memory region to aid in debugging with sanitizers.
- **Inputs**:
    - `shspad`: A pointer to the shared scratch pad memory region to be deleted. Must be aligned according to FD_SPAD_ALIGN and not be NULL. The caller retains ownership of the memory.
- **Output**: Returns a pointer to the deleted shared scratch pad memory region on success, or NULL if the input was invalid or the deletion failed.
- **See also**: [`fd_spad_delete_sanitizer_impl`](fd_spad.c.driver.md#fd_spad_delete_sanitizer_impl)  (Implementation)


---
### fd\_spad\_alloc\_max\_sanitizer\_impl<!-- {{#callable_declaration:fd_spad_alloc_max_sanitizer_impl}} -->
Returns the maximum allocatable bytes with specified alignment in a scratch pad.
- **Description**: This function determines the maximum number of bytes that can be allocated from a scratch pad memory with a specified alignment. It should be used when you need to know the largest possible allocation size that can be made with a given alignment constraint. The function must be called with a valid scratch pad handle that is currently joined and in a frame. The alignment parameter can be zero, which defaults to a predefined alignment value. The function ensures that the alignment is at least as large as required by any active sanitizers, such as ASAN or MSAN, if they are enabled.
- **Inputs**:
    - `spad`: A pointer to a constant fd_spad_t, representing the scratch pad memory. It must be a valid, joined scratch pad and not null.
    - `align`: An unsigned long specifying the desired alignment for the allocation. It must be a power of 2 within the range [1, FD_SPAD_ALIGN] or zero, which defaults to FD_SPAD_ALLOC_ALIGN_DEFAULT. If invalid, the function defaults to the predefined alignment.
- **Output**: Returns the maximum number of bytes that can be allocated with the specified alignment. The return value is an unsigned long.
- **See also**: [`fd_spad_alloc_max_sanitizer_impl`](fd_spad.c.driver.md#fd_spad_alloc_max_sanitizer_impl)  (Implementation)


---
### fd\_spad\_frame\_lo\_sanitizer\_impl<!-- {{#callable_declaration:fd_spad_frame_lo_sanitizer_impl}} -->
Returns the starting address of the current frame in a scratch pad memory.
- **Description**: This function provides the starting address of the current frame within a scratch pad memory, which is useful for managing memory allocations in high-performance, persistent, inter-process shared environments. It should be called when the scratch pad is in a valid state and the caller is joined to the scratch pad. The function assumes that the scratch pad is currently in a frame, and it is typically used in contexts where memory management operations are performance-critical.
- **Inputs**:
    - `spad`: A pointer to a `fd_spad_t` structure representing the scratch pad memory. The pointer must not be null, and the scratch pad must be in a valid state with a current frame.
- **Output**: Returns a pointer to the first byte of the current frame in the scratch pad memory.
- **See also**: [`fd_spad_frame_lo_sanitizer_impl`](fd_spad.c.driver.md#fd_spad_frame_lo_sanitizer_impl)  (Implementation)


---
### fd\_spad\_frame\_hi\_sanitizer\_impl<!-- {{#callable_declaration:fd_spad_frame_hi_sanitizer_impl}} -->
Returns the high memory address of the current frame in a scratch pad.
- **Description**: Use this function to obtain the high memory address of the current frame in a scratch pad memory. This is useful for determining the end of the current frame's allocated memory region. The function should be called when the scratch pad is in a valid state and the caller has a current local join to the scratch pad. It is important to ensure that the scratch pad is in a frame before calling this function.
- **Inputs**:
    - `spad`: A pointer to a `fd_spad_t` structure representing the scratch pad. The pointer must not be null, and the scratch pad must be a current local join.
- **Output**: Returns a pointer to the high memory address of the current frame in the scratch pad.
- **See also**: [`fd_spad_frame_hi_sanitizer_impl`](fd_spad.c.driver.md#fd_spad_frame_hi_sanitizer_impl)  (Implementation)


---
### fd\_spad\_push\_sanitizer\_impl<!-- {{#callable_declaration:fd_spad_push_sanitizer_impl}} -->
Pushes a new frame onto the scratch pad and sanitizes unused memory.
- **Description**: This function is used to create a new frame in the scratch pad memory, which is a high-performance, persistent, inter-process shared memory structure. It should be called when a new frame is needed, and the scratch pad must be a current local join with at least one frame free. After pushing the frame, it sanitizes the remaining free memory to prevent any in-progress preparations from being completed, ensuring memory safety and integrity.
- **Inputs**:
    - `spad`: A pointer to an fd_spad_t structure representing the scratch pad. It must not be null and should be a current local join with at least one frame free. The caller retains ownership.
- **Output**: None
- **See also**: [`fd_spad_push_sanitizer_impl`](fd_spad.c.driver.md#fd_spad_push_sanitizer_impl)  (Implementation)


---
### fd\_spad\_pop\_sanitizer\_impl<!-- {{#callable_declaration:fd_spad_pop_sanitizer_impl}} -->
Pops the current frame from the scratch pad and sanitizes unused memory.
- **Description**: This function is used to pop the current frame from a scratch pad memory, effectively freeing all allocations made within that frame. It should be called when the current frame is no longer needed, and the memory can be released. After popping the frame, the function sanitizes the unused memory region by marking it as poisoned, which is useful for detecting invalid memory accesses in debugging and testing environments. This function assumes that the scratch pad is a current local join and is in a frame.
- **Inputs**:
    - `spad`: A pointer to the scratch pad memory (fd_spad_t). It must not be null and should be a valid, currently joined scratch pad. The caller retains ownership.
- **Output**: None
- **See also**: [`fd_spad_pop_sanitizer_impl`](fd_spad.c.driver.md#fd_spad_pop_sanitizer_impl)  (Implementation)


---
### fd\_spad\_alloc\_sanitizer\_impl<!-- {{#callable_declaration:fd_spad_alloc_sanitizer_impl}} -->
Allocates memory from a scratch pad with sanitizer support.
- **Description**: This function allocates a specified amount of memory from a scratch pad, ensuring that the memory is properly aligned and sanitized for use with AddressSanitizer (ASAN) or MemorySanitizer (MSAN) if enabled. It should be used when memory needs to be allocated from a shared scratch pad that supports high-performance, inter-process communication. The function ensures that the allocated memory is unpoisoned and ready for use, while the remaining memory is poisoned to prevent accidental access. It is important to ensure that the scratch pad is properly initialized and joined before calling this function.
- **Inputs**:
    - `spad`: A pointer to an fd_spad_t structure representing the scratch pad from which memory is to be allocated. Must not be null and should be a valid, joined scratch pad.
    - `align`: The desired alignment for the allocated memory. Must be a power of 2 and can be 0 to use the default alignment. If ASAN or MSAN is enabled, the alignment will be adjusted to meet their requirements.
    - `sz`: The size in bytes of the memory to allocate. Must be within the available memory of the scratch pad.
- **Output**: Returns a pointer to the allocated memory region, which is unpoisoned and aligned as specified. The pointer will be non-null if the allocation is successful.
- **See also**: [`fd_spad_alloc_sanitizer_impl`](fd_spad.c.driver.md#fd_spad_alloc_sanitizer_impl)  (Implementation)


---
### fd\_spad\_trim\_sanitizer\_impl<!-- {{#callable_declaration:fd_spad_trim_sanitizer_impl}} -->
Sanitizes memory regions in a scratch pad after trimming.
- **Description**: This function is used to sanitize memory regions in a scratch pad after a trim operation, ensuring that memory from the new high watermark to the maximum memory is appropriately poisoned for debugging purposes. It should be called when memory sanitization is required, such as in builds with DEEPASAN or MSAN enabled. The function assumes that the scratch pad is a current local join and that the high pointer is within the valid range of the current frame.
- **Inputs**:
    - `spad`: A pointer to the scratch pad memory structure. Must not be null and should be a current local join.
    - `hi`: A pointer indicating the new high watermark for the scratch pad memory. Must be within the range of the current frame's memory.
- **Output**: None
- **See also**: [`fd_spad_trim_sanitizer_impl`](fd_spad.c.driver.md#fd_spad_trim_sanitizer_impl)  (Implementation)


---
### fd\_spad\_prepare\_sanitizer\_impl<!-- {{#callable_declaration:fd_spad_prepare_sanitizer_impl}} -->
Prepares a memory allocation in a scratch pad with optional sanitization.
- **Description**: This function is used to prepare a memory allocation within a scratch pad memory region, ensuring that the memory is properly aligned and unpoisoned for use with AddressSanitizer (ASAN) or MemorySanitizer (MSAN) if applicable. It should be called when a new allocation is needed, and the caller must ensure that the scratch pad is currently joined and in a frame. The function adjusts the alignment based on the sanitization requirements and returns a pointer to the prepared memory region. This function is particularly useful in environments where memory sanitization is required for debugging or security purposes.
- **Inputs**:
    - `spad`: A pointer to the fd_spad_t structure representing the scratch pad. Must not be null and should be a current local join.
    - `align`: The desired alignment for the allocation. Must be a power of 2 or 0, where 0 indicates the use of FD_SPAD_ALLOC_ALIGN_DEFAULT. If sanitization is enabled, the alignment will be adjusted to meet the minimum requirements of ASAN or MSAN.
    - `max`: The maximum number of bytes to allocate. Must be within the limits of the available memory in the scratch pad.
- **Output**: Returns a pointer to the prepared memory region, which is aligned and unpoisoned. The pointer is guaranteed to be non-null and 8-byte aligned.
- **See also**: [`fd_spad_prepare_sanitizer_impl`](fd_spad.c.driver.md#fd_spad_prepare_sanitizer_impl)  (Implementation)


---
### fd\_spad\_cancel\_sanitizer\_impl<!-- {{#callable_declaration:fd_spad_cancel_sanitizer_impl}} -->
Cancels any in-progress memory preparation in a scratch pad and sanitizes the memory region.
- **Description**: Use this function to cancel any ongoing memory preparation in a scratch pad memory region and to sanitize the memory by marking it as poisoned. This is useful in debugging and sanitization builds to ensure that any memory from the used region to the maximum region is marked as inaccessible, preventing accidental use of uninitialized or freed memory. This function should be called when a memory preparation needs to be aborted, and it assumes that the scratch pad is currently joined and in a valid state.
- **Inputs**:
    - `spad`: A pointer to a `fd_spad_t` structure representing the scratch pad memory. It must not be null and should be a valid, currently joined scratch pad. The caller retains ownership of the memory.
- **Output**: None
- **See also**: [`fd_spad_cancel_sanitizer_impl`](fd_spad.c.driver.md#fd_spad_cancel_sanitizer_impl)  (Implementation)


---
### fd\_spad\_publish\_sanitizer\_impl<!-- {{#callable_declaration:fd_spad_publish_sanitizer_impl}} -->
Sanitizes and publishes a prepared allocation in a scratch pad memory.
- **Description**: This function is used to finalize and publish a prepared allocation in a scratch pad memory, ensuring that the memory region is properly sanitized for use with AddressSanitizer (ASAN) and MemorySanitizer (MSAN). It should be called after a successful preparation of an allocation to make the allocated memory available for use. The function assumes that the scratch pad is a current local join and that a prepare operation has been completed. It handles memory poisoning and unpoisoning to ensure that the memory is safe for use in environments with sanitization enabled.
- **Inputs**:
    - `spad`: A pointer to the scratch pad memory (fd_spad_t). Must not be null and should be a current local join.
    - `sz`: The size of the allocation to publish, in bytes. Must be within the range of the prepared allocation size.
- **Output**: None
- **See also**: [`fd_spad_publish_sanitizer_impl`](fd_spad.c.driver.md#fd_spad_publish_sanitizer_impl)  (Implementation)


