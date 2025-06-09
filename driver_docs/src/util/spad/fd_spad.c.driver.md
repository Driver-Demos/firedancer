# Purpose
This C source code file is designed to manage and verify a specialized memory allocation structure referred to as `fd_spad_t`. The file provides a set of functions that perform various operations on this structure, such as verifying its integrity, resetting, deleting, allocating, and managing memory frames. The code includes both standard and debug implementations, with the latter incorporating additional checks and logging for debugging purposes. The debug functions are conditionally compiled based on the presence of sanitizers like AddressSanitizer (ASAN) and MemorySanitizer (MSAN), which help detect memory errors. These functions ensure that memory operations are performed safely and that any misuse of the memory structure is logged and handled appropriately.

The file also defines a virtual function table (`fd_spad_vtable`) for memory allocation operations, which allows for a flexible interface to allocate and free memory using the `fd_spad_t` structure. This setup suggests that the code is part of a larger system where memory management is abstracted and modularized. The use of macros and conditional compilation indicates a focus on performance and safety, with the ability to switch between different implementations based on the build configuration. Overall, the file provides a robust framework for managing memory in a controlled and verifiable manner, with a strong emphasis on debugging and error detection.
# Imports and Dependencies

---
- `fd_spad.h`
- `../log/fd_log.h`


# Global Variables

---
### fd\_spad\_vtable
- **Type**: `const fd_valloc_vtable_t`
- **Description**: The `fd_spad_vtable` is a constant instance of the `fd_valloc_vtable_t` structure, which serves as a virtual function table for memory allocation operations specific to the SPAD (Scratchpad) memory management system. It contains function pointers for `malloc` and `free` operations, which are set to `fd_spad_valloc_malloc` and `fd_spad_valloc_free` respectively.
- **Use**: This variable is used to provide a standardized interface for memory allocation and deallocation functions within the SPAD system.


# Functions

---
### fd\_spad\_verify<!-- {{#callable:fd_spad_verify}} -->
The `fd_spad_verify` function checks the integrity and validity of a shared memory structure (`fd_spad_t`) by verifying its metadata and ensuring proper memory usage and frame ordering.
- **Inputs**:
    - `spad`: A pointer to a constant `fd_spad_t` structure representing the shared memory area to be verified.
- **Control Flow**:
    - Define a macro `TEST` to log a warning and return -1 if a condition is not met.
    - Check if the `spad` pointer is not NULL and if its `magic` field matches `FD_SPAD_MAGIC`.
    - Extract `frame_free` and `mem_used` from the `spad` structure and verify they are within their respective limits.
    - If `frame_free` equals `FD_SPAD_FRAME_MAX`, ensure `mem_used` is zero; otherwise, verify `mem_used` is greater than or equal to the offset at `frame_free`.
    - Iterate over the offsets from `frame_free` to `FD_SPAD_FRAME_MAX-1` to ensure they are in non-increasing order.
    - Ensure the last offset (`spad->off[FD_SPAD_FRAME_MAX-1]`) is zero.
    - Return 0 if all checks pass.
- **Output**: Returns 0 if all integrity checks pass, otherwise returns -1 if any check fails.


---
### fd\_spad\_reset\_debug<!-- {{#callable:fd_spad_reset_debug}} -->
The `fd_spad_reset_debug` function resets a shared memory space (spad) using a debug implementation that may vary based on the presence of sanitizers.
- **Inputs**:
    - `spad`: A pointer to an `fd_spad_t` structure representing the shared memory space to be reset.
- **Control Flow**:
    - The function uses a macro `SELECT_DEBUG_IMPL` to choose between different implementations of `fd_spad_reset` based on whether certain sanitizers (e.g., ASAN or MSAN) are active.
    - It calls the selected implementation of `fd_spad_reset` with the provided `spad` argument.
- **Output**: The function does not return a value; it performs an operation on the `spad` input.


---
### fd\_spad\_delete\_debug<!-- {{#callable:fd_spad_delete_debug}} -->
The `fd_spad_delete_debug` function deletes a shared memory space (spad) using a debug implementation, which may vary based on the presence of sanitizers.
- **Inputs**:
    - `shspad`: A pointer to the shared memory space (spad) that is to be deleted.
- **Control Flow**:
    - The function uses a macro `SELECT_DEBUG_IMPL` to choose between different implementations of the `fd_spad_delete` function based on whether certain sanitizers (e.g., ASAN, MSAN) are enabled.
    - If sanitizers are enabled, it selects the `fd_spad_delete_sanitizer_impl` function; otherwise, it selects the `fd_spad_delete_impl` function.
    - The selected implementation is then called with `shspad` as the argument.
- **Output**: Returns a pointer to the deleted shared memory space, which is the result of the selected `fd_spad_delete` implementation.


---
### fd\_spad\_alloc\_max\_debug<!-- {{#callable:fd_spad_alloc_max_debug}} -->
The `fd_spad_alloc_max_debug` function checks the validity of a shared memory allocation frame and alignment, then returns the maximum allocatable memory size using a debug implementation.
- **Inputs**:
    - `spad`: A pointer to a constant `fd_spad_t` structure representing the shared memory allocation frame.
    - `align`: An unsigned long integer specifying the desired memory alignment for the allocation.
- **Control Flow**:
    - Check if the shared memory allocation frame is currently in use with `fd_spad_frame_used(spad)`; if not, log a critical error and terminate.
    - Verify that the alignment is a power of two using `fd_ulong_is_pow2(align)`; if not, log a critical error and terminate.
    - Call the appropriate debug implementation of `fd_spad_alloc_max` based on the presence of sanitizers, passing `spad` and `align` as arguments.
- **Output**: Returns an unsigned long integer representing the maximum size of memory that can be allocated with the specified alignment.
- **Functions called**:
    - [`fd_spad_frame_used`](fd_spad.h.driver.md#fd_spad_frame_used)


---
### fd\_spad\_frame\_lo\_debug<!-- {{#callable:fd_spad_frame_lo_debug}} -->
The `fd_spad_frame_lo_debug` function checks if a frame is currently in use in the given `fd_spad_t` structure and returns the lower bound of the frame using a debug implementation.
- **Inputs**:
    - `spad`: A pointer to an `fd_spad_t` structure representing the shared memory space.
- **Control Flow**:
    - Check if the current frame is in use by calling `fd_spad_frame_used(spad)`; if not, log a critical error and terminate the program.
    - Return the result of the `SELECT_DEBUG_IMPL(fd_spad_frame_lo)(spad)` function call, which selects the appropriate implementation based on the presence of sanitizers.
- **Output**: Returns a pointer to the lower bound of the current frame in the shared memory space.
- **Functions called**:
    - [`fd_spad_frame_used`](fd_spad.h.driver.md#fd_spad_frame_used)


---
### fd\_spad\_frame\_hi\_debug<!-- {{#callable:fd_spad_frame_hi_debug}} -->
The `fd_spad_frame_hi_debug` function checks if a frame is currently in use in the given `fd_spad_t` structure and then returns the high address of the current frame using a debug implementation.
- **Inputs**:
    - `spad`: A pointer to an `fd_spad_t` structure representing the shared memory area being managed.
- **Control Flow**:
    - Check if the current frame in the `spad` is used by calling `fd_spad_frame_used(spad)`; if not, log a critical error message 'not in a frame' and terminate.
    - Call the appropriate debug implementation of `fd_spad_frame_hi` using the `SELECT_DEBUG_IMPL` macro, passing `spad` as an argument.
    - Return the result of the debug implementation call.
- **Output**: A pointer to the high address of the current frame in the `spad` structure.
- **Functions called**:
    - [`fd_spad_frame_used`](fd_spad.h.driver.md#fd_spad_frame_used)


---
### fd\_spad\_push\_debug<!-- {{#callable:fd_spad_push_debug}} -->
The `fd_spad_push_debug` function checks if there is a free frame in the shared memory allocator and logs a critical error if not, then calls the appropriate implementation of `fd_spad_push` based on the build configuration.
- **Inputs**:
    - `spad`: A pointer to an `fd_spad_t` structure representing the shared memory allocator.
- **Control Flow**:
    - Check if there is a free frame in the shared memory allocator using `fd_spad_frame_free(spad)`.
    - If there are no free frames, log a critical error message 'too many frames' using `FD_LOG_CRIT`.
    - Call the appropriate implementation of `fd_spad_push` using the `SELECT_DEBUG_IMPL` macro, which chooses between `fd_spad_push_impl` and `fd_spad_push_sanitizer_impl` based on the build configuration.
- **Output**: This function does not return a value; it performs operations on the `spad` structure and may log a critical error.
- **Functions called**:
    - [`fd_spad_frame_free`](fd_spad.h.driver.md#fd_spad_frame_free)


---
### fd\_spad\_pop\_debug<!-- {{#callable:fd_spad_pop_debug}} -->
The `fd_spad_pop_debug` function checks if a frame is currently in use in the shared memory allocator and then calls the appropriate implementation of the `fd_spad_pop` function based on the debugging configuration.
- **Inputs**:
    - `spad`: A pointer to an `fd_spad_t` structure representing the shared memory allocator state.
- **Control Flow**:
    - Check if the current frame in the shared memory allocator is used by calling `fd_spad_frame_used(spad)`.
    - If the frame is not used, log a critical error message 'not in a frame' using `FD_LOG_CRIT`.
    - Call the appropriate implementation of `fd_spad_pop` (either `fd_spad_pop_impl` or `fd_spad_pop_sanitizer_impl`) based on the debugging configuration using the `SELECT_DEBUG_IMPL` macro.
- **Output**: This function does not return a value; it performs an operation on the shared memory allocator state.
- **Functions called**:
    - [`fd_spad_frame_used`](fd_spad.h.driver.md#fd_spad_frame_used)


---
### fd\_spad\_alloc\_check<!-- {{#callable:fd_spad_alloc_check}} -->
The `fd_spad_alloc_check` function checks if a memory allocation can be performed within a specified frame and alignment constraints, and then performs the allocation if possible.
- **Inputs**:
    - `spad`: A pointer to an `fd_spad_t` structure representing the shared memory space where the allocation is to be performed.
    - `align`: An unsigned long integer specifying the alignment requirement for the memory allocation.
    - `sz`: An unsigned long integer specifying the size of the memory to be allocated.
- **Control Flow**:
    - Check if the `spad` is currently in a frame using [`fd_spad_frame_used`](fd_spad.h.driver.md#fd_spad_frame_used); if not, log a critical error and terminate.
    - Verify that the `align` parameter is a power of two; if not, log a critical error and terminate.
    - Calculate the maximum allocatable memory size with the given alignment using [`fd_spad_alloc_max`](fd_spad.h.driver.md#fd_spad_alloc_max).
    - Check if the requested size `sz` is less than or equal to the maximum allocatable size; if not, log a critical error indicating an out-of-memory condition and terminate.
    - Perform the memory allocation using the appropriate implementation of `fd_spad_alloc` based on the debug settings.
- **Output**: A pointer to the allocated memory block within the shared memory space, or the function will terminate with a critical error if any checks fail.
- **Functions called**:
    - [`fd_spad_frame_used`](fd_spad.h.driver.md#fd_spad_frame_used)
    - [`fd_spad_alloc_max`](fd_spad.h.driver.md#fd_spad_alloc_max)


---
### fd\_spad\_trim\_debug<!-- {{#callable:fd_spad_trim_debug}} -->
The `fd_spad_trim_debug` function checks the validity of a memory frame in a shared memory allocator and then calls a debug implementation of the trim operation.
- **Inputs**:
    - `spad`: A pointer to an `fd_spad_t` structure representing the shared memory allocator.
    - `hi`: A pointer to a memory location that is used to set the high boundary of the memory frame.
- **Control Flow**:
    - Check if the current frame in the shared memory allocator is used; if not, log a critical error and terminate.
    - Verify that the `hi` pointer is not below the low boundary of the current frame; if it is, log a critical error and terminate.
    - Verify that the `hi` pointer is not above the high boundary of the current frame; if it is, log a critical error and terminate.
    - Call the appropriate debug implementation of the `fd_spad_trim` function based on the build configuration.
- **Output**: This function does not return a value; it performs validation and calls a debug implementation of a trim operation.
- **Functions called**:
    - [`fd_spad_frame_used`](fd_spad.h.driver.md#fd_spad_frame_used)
    - [`fd_spad_frame_lo`](fd_spad.h.driver.md#fd_spad_frame_lo)
    - [`fd_spad_frame_hi`](fd_spad.h.driver.md#fd_spad_frame_hi)


---
### fd\_spad\_prepare\_debug<!-- {{#callable:fd_spad_prepare_debug}} -->
The `fd_spad_prepare_debug` function prepares a shared memory allocation with specified alignment and maximum size, ensuring the current frame is valid and constraints are met before delegating to a debug-specific implementation.
- **Inputs**:
    - `spad`: A pointer to an `fd_spad_t` structure representing the shared memory allocator.
    - `align`: An unsigned long specifying the alignment requirement for the memory allocation.
    - `max`: An unsigned long specifying the maximum size of the memory allocation.
- **Control Flow**:
    - Check if the current frame in the shared memory allocator is valid using [`fd_spad_frame_used`](fd_spad.h.driver.md#fd_spad_frame_used); if not, log a critical error and terminate.
    - Verify that the alignment is either zero or a power of two using `fd_ulong_is_pow2`; if not, log a critical error and terminate.
    - Ensure that the maximum allocatable size with the given alignment is at least `max` using [`fd_spad_alloc_max`](fd_spad.h.driver.md#fd_spad_alloc_max); if not, log a critical error and terminate.
    - Call the appropriate debug implementation of `fd_spad_prepare` based on the presence of sanitizers, passing the `spad`, `align`, and `max` parameters.
- **Output**: Returns a pointer to the prepared memory region, or logs a critical error and terminates if any preconditions are not met.
- **Functions called**:
    - [`fd_spad_frame_used`](fd_spad.h.driver.md#fd_spad_frame_used)
    - [`fd_spad_alloc_max`](fd_spad.h.driver.md#fd_spad_alloc_max)


---
### fd\_spad\_cancel\_debug<!-- {{#callable:fd_spad_cancel_debug}} -->
The `fd_spad_cancel_debug` function checks if a frame is in use and then calls the appropriate implementation of `fd_spad_cancel` based on the debugging configuration.
- **Inputs**:
    - `spad`: A pointer to an `fd_spad_t` structure representing the shared memory space to be operated on.
- **Control Flow**:
    - Check if the `spad` is currently in use by calling `fd_spad_frame_used(spad)`; if not, log a critical error message 'not in a frame'.
    - Call the appropriate implementation of `fd_spad_cancel` using the `SELECT_DEBUG_IMPL` macro, which selects the implementation based on whether debugging or sanitization is enabled.
- **Output**: This function does not return a value; it performs an operation on the `spad` structure.
- **Functions called**:
    - [`fd_spad_frame_used`](fd_spad.h.driver.md#fd_spad_frame_used)


---
### fd\_spad\_publish\_debug<!-- {{#callable:fd_spad_publish_debug}} -->
The `fd_spad_publish_debug` function checks the validity of a shared memory allocation frame and publishes a specified size of memory if valid.
- **Inputs**:
    - `spad`: A pointer to an `fd_spad_t` structure representing the shared memory allocation descriptor.
    - `sz`: An unsigned long integer representing the size of memory to be published.
- **Control Flow**:
    - Check if the current frame in the shared memory allocation is used using `fd_spad_frame_used(spad)`; if not, log a critical error and exit.
    - Check if the maximum allocatable memory in the current frame is less than the specified size `sz` using `fd_spad_alloc_max(spad, 1UL)`; if so, log a critical error and exit.
    - Call the appropriate implementation of `fd_spad_publish` based on the debug configuration to publish the specified size of memory.
- **Output**: The function does not return a value; it performs operations on the shared memory allocation and logs errors if conditions are not met.
- **Functions called**:
    - [`fd_spad_frame_used`](fd_spad.h.driver.md#fd_spad_frame_used)
    - [`fd_spad_alloc_max`](fd_spad.h.driver.md#fd_spad_alloc_max)


---
### fd\_spad\_reset\_sanitizer\_impl<!-- {{#callable:fd_spad_reset_sanitizer_impl}} -->
The `fd_spad_reset_sanitizer_impl` function resets a shared memory region and poisons it for AddressSanitizer (ASAN) and MemorySanitizer (MSAN) checks.
- **Inputs**:
    - `spad`: A pointer to an `fd_spad_t` structure representing the shared memory region to be reset and poisoned.
- **Control Flow**:
    - Call [`fd_spad_reset_impl`](fd_spad.h.driver.md#fd_spad_reset_impl) to reset the shared memory region pointed to by `spad`.
    - Align the private memory of `spad` to `FD_ASAN_ALIGN` and poison the memory region from this aligned address to `spad->mem_max` using `fd_asan_poison`.
    - Align the private memory of `spad` to `FD_MSAN_ALIGN` and poison the memory region from this aligned address to `spad->mem_max` using `fd_msan_poison`.
- **Output**: This function does not return a value; it performs operations directly on the memory region pointed to by `spad`.
- **Functions called**:
    - [`fd_spad_reset_impl`](fd_spad.h.driver.md#fd_spad_reset_impl)
    - [`fd_spad_private_mem`](fd_spad.h.driver.md#fd_spad_private_mem)


---
### fd\_spad\_delete\_sanitizer\_impl<!-- {{#callable:fd_spad_delete_sanitizer_impl}} -->
The `fd_spad_delete_sanitizer_impl` function deletes a shared memory region and unpoisons it using AddressSanitizer (ASAN) and MemorySanitizer (MSAN) tools if the deletion is successful.
- **Inputs**:
    - `shspad`: A pointer to the shared memory region to be deleted.
- **Control Flow**:
    - Call [`fd_spad_delete_impl`](fd_spad.h.driver.md#fd_spad_delete_impl) with `shspad` to attempt deletion of the shared memory region and store the result in `deleted_shspad`.
    - Check if `deleted_shspad` is not NULL, indicating successful deletion.
    - If successful, cast `shspad` to `fd_spad_t *` and store it in `spad`.
    - Unpoison the memory region using `fd_asan_unpoison` and `fd_msan_unpoison` functions, aligning the start address and using `spad->mem_max` as the size.
- **Output**: Returns a pointer to the deleted shared memory region if successful, otherwise NULL.
- **Functions called**:
    - [`fd_spad_delete_impl`](fd_spad.h.driver.md#fd_spad_delete_impl)
    - [`fd_spad_private_mem`](fd_spad.h.driver.md#fd_spad_private_mem)


---
### fd\_spad\_alloc\_max\_sanitizer\_impl<!-- {{#callable:fd_spad_alloc_max_sanitizer_impl}} -->
The `fd_spad_alloc_max_sanitizer_impl` function determines the maximum allocatable memory size in a shared memory region with alignment considerations, specifically for environments using AddressSanitizer (ASAN) or MemorySanitizer (MSAN).
- **Inputs**:
    - `spad`: A pointer to a constant `fd_spad_t` structure representing the shared memory region.
    - `align`: An unsigned long integer specifying the desired memory alignment.
- **Control Flow**:
    - Check if the `FD_HAS_DEEPASAN` preprocessor directive is defined.
    - If `FD_HAS_DEEPASAN` is defined, set `align` to the maximum of the current `align` and `FD_ASAN_ALIGN`, or `FD_SPAD_ALLOC_ALIGN_DEFAULT` if `align` is zero.
    - If `FD_HAS_MSAN` is defined and `FD_HAS_DEEPASAN` is not, set `align` to the maximum of the current `align` and `FD_MSAN_ALIGN`, or `FD_SPAD_ALLOC_ALIGN_DEFAULT` if `align` is zero.
    - Call [`fd_spad_alloc_max_impl`](fd_spad.h.driver.md#fd_spad_alloc_max_impl) with the `spad` and the possibly modified `align` to get the maximum allocatable size.
- **Output**: Returns an unsigned long integer representing the maximum size of memory that can be allocated in the shared memory region with the specified alignment.
- **Functions called**:
    - [`fd_spad_alloc_max_impl`](fd_spad.h.driver.md#fd_spad_alloc_max_impl)


---
### fd\_spad\_frame\_lo\_sanitizer\_impl<!-- {{#callable:fd_spad_frame_lo_sanitizer_impl}} -->
The `fd_spad_frame_lo_sanitizer_impl` function returns the low frame pointer of a shared memory region, specifically for use with sanitizers like ASAN or MSAN.
- **Inputs**:
    - `spad`: A pointer to an `fd_spad_t` structure representing the shared memory region.
- **Control Flow**:
    - The function directly calls [`fd_spad_frame_lo_impl`](fd_spad.h.driver.md#fd_spad_frame_lo_impl) with the provided `spad` argument.
    - It returns the result of the [`fd_spad_frame_lo_impl`](fd_spad.h.driver.md#fd_spad_frame_lo_impl) function call.
- **Output**: A pointer to the low frame of the shared memory region associated with the `spad`.
- **Functions called**:
    - [`fd_spad_frame_lo_impl`](fd_spad.h.driver.md#fd_spad_frame_lo_impl)


---
### fd\_spad\_frame\_hi\_sanitizer\_impl<!-- {{#callable:fd_spad_frame_hi_sanitizer_impl}} -->
The `fd_spad_frame_hi_sanitizer_impl` function returns the high frame pointer of a shared memory region, specifically for use with sanitizers like ASAN or MSAN.
- **Inputs**:
    - `spad`: A pointer to an `fd_spad_t` structure representing the shared memory region.
- **Control Flow**:
    - The function directly calls [`fd_spad_frame_hi_impl`](fd_spad.h.driver.md#fd_spad_frame_hi_impl) with the provided `spad` argument.
    - It returns the result of the [`fd_spad_frame_hi_impl`](fd_spad.h.driver.md#fd_spad_frame_hi_impl) function call.
- **Output**: A pointer to the high frame of the shared memory region.
- **Functions called**:
    - [`fd_spad_frame_hi_impl`](fd_spad.h.driver.md#fd_spad_frame_hi_impl)


---
### fd\_spad\_push\_sanitizer\_impl<!-- {{#callable:fd_spad_push_sanitizer_impl}} -->
The `fd_spad_push_sanitizer_impl` function pushes a new frame onto the stack and poisons the remaining free memory to prevent any in-progress memory preparations.
- **Inputs**:
    - `spad`: A pointer to an `fd_spad_t` structure representing the shared memory stack.
- **Control Flow**:
    - Call [`fd_spad_push_impl`](fd_spad.h.driver.md#fd_spad_push_impl) with `spad` to push a new frame onto the stack.
    - Calculate the starting address for poisoning by aligning the current memory usage to `FD_ASAN_ALIGN`.
    - Call `fd_asan_poison` to poison the memory from the calculated starting address to the end of the available memory.
- **Output**: This function does not return any value; it modifies the state of the memory pointed to by `spad`.
- **Functions called**:
    - [`fd_spad_push_impl`](fd_spad.h.driver.md#fd_spad_push_impl)
    - [`fd_spad_private_mem`](fd_spad.h.driver.md#fd_spad_private_mem)


---
### fd\_spad\_pop\_sanitizer\_impl<!-- {{#callable:fd_spad_pop_sanitizer_impl}} -->
The `fd_spad_pop_sanitizer_impl` function pops a frame from the stack and poisons the memory region from `mem_used` to `mem_max` for AddressSanitizer (ASAN) and MemorySanitizer (MSAN) purposes.
- **Inputs**:
    - `spad`: A pointer to an `fd_spad_t` structure representing the stack and memory region to be manipulated.
- **Control Flow**:
    - Call [`fd_spad_pop_impl`](fd_spad.h.driver.md#fd_spad_pop_impl) to pop a frame from the stack associated with `spad`.
    - Calculate the starting address for poisoning by aligning the address of the memory region starting at `spad->mem_used` to the required ASAN and MSAN alignment.
    - Poison the memory region from the aligned starting address to `spad->mem_max` using `fd_asan_poison` for ASAN.
    - Poison the same memory region using `fd_msan_poison` for MSAN.
- **Output**: This function does not return a value; it performs operations on the memory region associated with the `spad` pointer.
- **Functions called**:
    - [`fd_spad_pop_impl`](fd_spad.h.driver.md#fd_spad_pop_impl)
    - [`fd_spad_private_mem`](fd_spad.h.driver.md#fd_spad_private_mem)


---
### fd\_spad\_alloc\_sanitizer\_impl<!-- {{#callable:fd_spad_alloc_sanitizer_impl}} -->
The `fd_spad_alloc_sanitizer_impl` function allocates memory from a shared memory region with specific alignment requirements and applies memory sanitization techniques to ensure memory safety.
- **Inputs**:
    - `spad`: A pointer to an `fd_spad_t` structure representing the shared memory region from which memory is to be allocated.
    - `align`: An unsigned long specifying the desired alignment for the memory allocation.
    - `sz`: An unsigned long specifying the size of the memory to be allocated.
- **Control Flow**:
    - Check if the code is compiled with AddressSanitizer (ASAN) or MemorySanitizer (MSAN) and adjust the alignment to ensure it meets the minimum requirements for the active sanitizer.
    - Call [`fd_spad_alloc_impl`](fd_spad.h.driver.md#fd_spad_alloc_impl) to allocate memory from the shared memory region with the specified alignment and size.
    - Calculate the remaining memory from the allocated buffer to the maximum memory limit of the shared memory region.
    - Poison the memory from the allocated buffer to the maximum memory limit to cancel any in-progress memory preparations.
    - Unpoison the allocated memory region to mark it as safe for use.
    - Return the pointer to the allocated memory buffer.
- **Output**: A pointer to the allocated memory buffer, which is aligned and sanitized according to the specified requirements.
- **Functions called**:
    - [`fd_spad_alloc_impl`](fd_spad.h.driver.md#fd_spad_alloc_impl)
    - [`fd_spad_private_mem`](fd_spad.h.driver.md#fd_spad_private_mem)


---
### fd\_spad\_trim\_sanitizer\_impl<!-- {{#callable:fd_spad_trim_sanitizer_impl}} -->
The `fd_spad_trim_sanitizer_impl` function adjusts the memory usage of a shared memory region and applies memory poisoning for debugging purposes.
- **Inputs**:
    - `spad`: A pointer to an `fd_spad_t` structure representing the shared memory region.
    - `hi`: A pointer indicating the new high watermark for memory usage within the shared memory region.
- **Control Flow**:
    - Call [`fd_spad_trim_impl`](fd_spad.h.driver.md#fd_spad_trim_impl) to adjust the memory usage to the new high watermark `hi`.
    - If `FD_HAS_DEEPASAN` is defined, align `hi` down to the nearest `FD_ASAN_ALIGN` boundary and check if it falls within a valid allocation.
    - Poison the memory from the aligned `hi` to `mem_max` using AddressSanitizer (ASAN) if `FD_HAS_DEEPASAN` is defined.
    - If the aligned `hi` was within a valid allocation, unpoison the memory from the aligned `hi` to `hi` to correct the poisoning.
    - Poison the memory from the next 4-byte aligned address after `hi` to `mem_max` using MemorySanitizer (MSAN).
- **Output**: This function does not return a value; it modifies the memory state of the `spad` structure for debugging purposes.
- **Functions called**:
    - [`fd_spad_trim_impl`](fd_spad.h.driver.md#fd_spad_trim_impl)
    - [`fd_spad_private_mem`](fd_spad.h.driver.md#fd_spad_private_mem)


---
### fd\_spad\_prepare\_sanitizer\_impl<!-- {{#callable:fd_spad_prepare_sanitizer_impl}} -->
The `fd_spad_prepare_sanitizer_impl` function prepares a memory buffer with specified alignment and size, ensuring memory safety by unpoisoning the allocated region when AddressSanitizer (ASAN) or MemorySanitizer (MSAN) is active.
- **Inputs**:
    - `spad`: A pointer to an `fd_spad_t` structure representing the shared memory area to be prepared.
    - `align`: An unsigned long specifying the desired alignment for the memory buffer.
    - `max`: An unsigned long specifying the maximum size of the memory buffer to be prepared.
- **Control Flow**:
    - Check if AddressSanitizer (ASAN) or MemorySanitizer (MSAN) is active using preprocessor directives.
    - If ASAN is active, enforce a minimum alignment of `FD_ASAN_ALIGN` using `fd_ulong_if` and `fd_ulong_max` functions.
    - If MSAN is active, enforce a minimum alignment of `FD_MSAN_ALIGN` using `fd_ulong_if` and `fd_ulong_max` functions.
    - Call [`fd_spad_prepare_impl`](fd_spad.h.driver.md#fd_spad_prepare_impl) with the `spad`, `align`, and `max` parameters to prepare the memory buffer.
    - Unpoison the memory starting at the buffer address using `fd_asan_unpoison`, ensuring the memory is safe for use.
    - Return the pointer to the prepared memory buffer.
- **Output**: A pointer to the prepared memory buffer, which is guaranteed to be 8-byte aligned and unpoisoned for safe use.
- **Functions called**:
    - [`fd_spad_prepare_impl`](fd_spad.h.driver.md#fd_spad_prepare_impl)


---
### fd\_spad\_cancel\_sanitizer\_impl<!-- {{#callable:fd_spad_cancel_sanitizer_impl}} -->
The `fd_spad_cancel_sanitizer_impl` function cancels any in-progress memory preparations by poisoning the memory region from `mem_used` to `mem_max` in a shared memory allocator structure.
- **Inputs**:
    - `spad`: A pointer to an `fd_spad_t` structure representing the shared memory allocator.
- **Control Flow**:
    - Call [`fd_spad_cancel_impl`](fd_spad.h.driver.md#fd_spad_cancel_impl) with `spad` to perform the base cancellation operation.
    - Calculate the starting address for poisoning by adding `spad->mem_used` to the base address of the private memory region of `spad`.
    - Calculate the size of the region to poison as `spad->mem_max - spad->mem_used`.
    - Call `fd_asan_poison` to poison the calculated memory region, effectively canceling any in-progress memory preparations.
- **Output**: This function does not return a value; it performs operations directly on the memory associated with the `spad` structure.
- **Functions called**:
    - [`fd_spad_cancel_impl`](fd_spad.h.driver.md#fd_spad_cancel_impl)
    - [`fd_spad_private_mem`](fd_spad.h.driver.md#fd_spad_private_mem)


---
### fd\_spad\_publish\_sanitizer\_impl<!-- {{#callable:fd_spad_publish_sanitizer_impl}} -->
The `fd_spad_publish_sanitizer_impl` function manages memory sanitization by marking memory regions as poisoned or unpoisoned during the publishing process in a shared memory allocator.
- **Inputs**:
    - `spad`: A pointer to an `fd_spad_t` structure representing the shared memory allocator.
    - `sz`: An unsigned long integer representing the size of the memory region to be published and unpoisoned.
- **Control Flow**:
    - Calculate the offset `off` as the current memory used in the `spad` structure.
    - Determine the buffer `buf` by adding the offset to the private memory of `spad`.
    - Call [`fd_spad_publish_impl`](fd_spad.h.driver.md#fd_spad_publish_impl) to perform the actual publishing operation with the given size `sz`.
    - Poison the memory region from `buf` to the maximum memory limit `mem_max` to cancel any in-progress preparations.
    - Unpoison the allocated region starting from `buf` for the specified size `sz`, ensuring it is safe for use.
- **Output**: The function does not return a value; it modifies the memory state of the `spad` structure by poisoning and unpoisoning memory regions.
- **Functions called**:
    - [`fd_spad_private_mem`](fd_spad.h.driver.md#fd_spad_private_mem)
    - [`fd_spad_publish_impl`](fd_spad.h.driver.md#fd_spad_publish_impl)


---
### fd\_spad\_valloc\_malloc<!-- {{#callable:fd_spad_valloc_malloc}} -->
The `fd_spad_valloc_malloc` function allocates memory from a shared memory space with specified alignment and size.
- **Inputs**:
    - `_self`: A pointer to an `fd_spad_t` structure representing the shared memory space from which memory is to be allocated.
    - `align`: An unsigned long integer specifying the alignment requirement for the memory allocation.
    - `sz`: An unsigned long integer specifying the size of the memory to be allocated.
- **Control Flow**:
    - The function casts the `_self` pointer to an `fd_spad_t` pointer named `spad`.
    - It calls the [`fd_spad_alloc`](fd_spad.h.driver.md#fd_spad_alloc) function with `spad`, `align`, and `sz` as arguments to perform the actual memory allocation.
- **Output**: A pointer to the allocated memory block, or `NULL` if the allocation fails.
- **Functions called**:
    - [`fd_spad_alloc`](fd_spad.h.driver.md#fd_spad_alloc)


---
### fd\_spad\_valloc\_free<!-- {{#callable:fd_spad_valloc_free}} -->
The `fd_spad_valloc_free` function is a placeholder for freeing memory in a virtual allocation context, but it currently performs no operations.
- **Inputs**:
    - `_self`: A pointer to the context or object from which memory was allocated, but it is not used in this function.
    - `_addr`: A pointer to the memory address to be freed, but it is not used in this function.
- **Control Flow**:
    - The function takes two parameters, `_self` and `_addr`, but does not use them.
    - Both parameters are cast to void to explicitly indicate that they are unused, preventing compiler warnings about unused parameters.
- **Output**: The function does not return any value or perform any operations.


