# Purpose
The provided C header file, `fd_scratch.h`, defines a set of APIs for high-performance scratch pad memory allocation. This file is part of a larger system and is intended to be included in other C source files to provide functionality for temporary memory management. The primary purpose of this code is to offer two types of memory allocators: `fd_alloca`, which is an alignment-aware equivalent of the standard `alloca` function, and [`fd_scratch_alloc`](#fd_scratch_alloc), which is designed for complex and large temporary memory usage scenarios. The file includes mechanisms for managing memory alignment, allocation, and deallocation, with a focus on performance and cross-platform consistency.

The header defines several macros and inline functions to manage memory regions, including alignment and footprint calculations for scratch pad memory. It provides public APIs for attaching and detaching memory regions, resetting memory states, and managing memory frames. The file also includes safety checks and debugging features, such as runtime checks for memory operations and integration with AddressSanitizer (ASAN) and MemorySanitizer (MSAN) for detecting memory errors. Additionally, the file defines a virtual function table for integrating with a virtual allocator interface, allowing for flexible memory management strategies. Overall, this header file is a comprehensive toolkit for managing temporary memory allocations in performance-critical applications.
# Imports and Dependencies

---
- `../tile/fd_tile.h`
- `../valloc/fd_valloc.h`


# Global Variables

---
### fd\_scratch\_in\_prepare
- **Type**: `int`
- **Description**: The `fd_scratch_in_prepare` is a global integer variable used to track the state of a scratch memory allocation preparation process. It is only defined and used when the `FD_SCRATCH_USE_HANDHOLDING` macro is set to a non-zero value, which enables additional runtime checks for scratch memory operations.
- **Use**: This variable is used to indicate whether a scratch memory allocation is currently being prepared, helping to ensure that operations like publish or cancel are correctly matched with a prepare.


---
### fd\_scratch\_private\_start
- **Type**: `ulong`
- **Description**: `fd_scratch_private_start` is a global variable of type `ulong` that represents the starting address of the scratch pad memory region used for temporary memory allocations.
- **Use**: It is used to initialize and track the beginning of the scratch memory region when a thread attaches to a scratch pad.


---
### fd\_scratch\_private\_free
- **Type**: `ulong`
- **Description**: `fd_scratch_private_free` is a global variable of type `ulong` that represents the current free position in the scratch pad memory allocation system. It is used to track the next available memory location for allocation within the scratch pad memory.
- **Use**: This variable is used to manage memory allocation by indicating the current free position in the scratch pad memory, allowing for efficient allocation and deallocation of temporary memory.


---
### fd\_scratch\_private\_stop
- **Type**: `ulong`
- **Description**: `fd_scratch_private_stop` is a global variable of type `ulong` that represents the end address of the scratch pad memory region in the system. It is used to determine the boundary up to which memory allocations can be made within the scratch pad.
- **Use**: This variable is used to track the upper limit of the scratch pad memory, ensuring that memory allocations do not exceed this boundary.


---
### fd\_scratch\_private\_frame
- **Type**: `ulong*`
- **Description**: `fd_scratch_private_frame` is a global variable that serves as a pointer to an array of unsigned long integers. This array is used to manage the frames in a scratch pad memory allocation system, which is designed for high-performance temporary memory usage.
- **Use**: This variable is used to track the current frame stack in the scratch pad memory, allowing for efficient allocation and deallocation of temporary memory blocks.


---
### fd\_scratch\_private\_frame\_cnt
- **Type**: `ulong`
- **Description**: `fd_scratch_private_frame_cnt` is a global variable of type `ulong` that keeps track of the number of scratch frames currently in use in the scratch pad memory system. It is part of a set of variables used to manage memory allocation in a high-performance scratch pad memory system.
- **Use**: This variable is used to count the number of active scratch frames, which helps in managing memory allocation and deallocation within the scratch pad memory system.


---
### fd\_scratch\_private\_frame\_max
- **Type**: `ulong`
- **Description**: `fd_scratch_private_frame_max` is a global variable of type `ulong` that represents the maximum number of scratch frames that can be used in the scratch pad memory allocation system. It is part of the private API for managing scratch pad memory, which is used for temporary memory allocations in high-performance applications.
- **Use**: This variable is used to track the maximum allowable scratch frames, ensuring that memory allocations do not exceed the predefined limits.


---
### fd\_scratch\_vtable
- **Type**: `const fd_valloc_vtable_t`
- **Description**: `fd_scratch_vtable` is a constant variable of type `fd_valloc_vtable_t` that serves as the virtual function table for implementing the `fd_valloc` interface for the `fd_scratch` memory allocation system. This variable is declared as an external constant, indicating that its definition is provided elsewhere, likely in a source file that implements the `fd_scratch` functionality.
- **Use**: This variable is used to provide the necessary function pointers for the `fd_scratch` allocator to operate within the `fd_valloc` framework.


---
### fd\_alloca\_check\_private\_sz
- **Type**: `ulong`
- **Description**: `fd_alloca_check_private_sz` is a global variable of type `ulong` used in the context of stack allocation checks. It is specifically used to store the size of a memory allocation request when using the `fd_alloca_check` macro, which is a safer variant of `fd_alloca` that includes stack overflow checks.
- **Use**: This variable is used to temporarily hold the size of an allocation request to ensure it does not cause a stack overflow when using `fd_alloca_check`.


# Functions

---
### fd\_scratch\_private\_align\_is\_valid<!-- {{#callable:fd_scratch_private_align_is_valid}} -->
The function `fd_scratch_private_align_is_valid` checks if a given alignment value is a power of two or zero.
- **Inputs**:
    - `align`: An unsigned long integer representing the alignment value to be checked.
- **Control Flow**:
    - The function takes an unsigned long integer `align` as input.
    - It performs a bitwise AND operation between `align` and `align-1UL`.
    - The result of the bitwise operation is negated and returned as an integer.
- **Output**: The function returns an integer, which is non-zero (true) if the input `align` is a power of two or zero, and zero (false) otherwise.


---
### fd\_scratch\_private\_true\_align<!-- {{#callable:fd_scratch_private_true_align}} -->
The `fd_scratch_private_true_align` function returns the alignment value, defaulting to `FD_SCRATCH_ALIGN_DEFAULT` if the provided alignment is zero.
- **Inputs**:
    - `align`: An unsigned long integer representing the desired alignment value, which can be zero.
- **Control Flow**:
    - The function checks if the input `align` is zero.
    - If `align` is zero, it returns `FD_SCRATCH_ALIGN_DEFAULT`.
    - If `align` is not zero, it returns the input `align` value.
- **Output**: The function returns an unsigned long integer representing the alignment value to be used, which is either the input `align` or `FD_SCRATCH_ALIGN_DEFAULT` if `align` is zero.


---
### fd\_scratch\_smem\_align<!-- {{#callable:fd_scratch_smem_align}} -->
The `fd_scratch_smem_align` function returns the alignment requirement for scratch pad memory regions.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended for use within the same translation unit and suggests that the function is small and frequently called.
    - It is marked with `FD_FN_CONST`, indicating that it does not read or write any global memory and its return value depends only on its parameters (of which there are none).
    - The function simply returns the value of the macro `FD_SCRATCH_SMEM_ALIGN`.
- **Output**: The function returns an `ulong` representing the alignment requirement for scratch pad memory, which is defined by the macro `FD_SCRATCH_SMEM_ALIGN`.


---
### fd\_scratch\_smem\_footprint<!-- {{#callable:fd_scratch_smem_footprint}} -->
The `fd_scratch_smem_footprint` function calculates the aligned memory footprint required for a scratch pad memory region that can hold up to a specified number of bytes.
- **Inputs**:
    - `smax`: The maximum number of bytes the scratch pad memory region should be able to hold.
- **Control Flow**:
    - The function takes a single input, `smax`, which represents the maximum size in bytes for the scratch pad memory.
    - It calls the `fd_ulong_align_up` function with `smax` and `FD_SCRATCH_SMEM_ALIGN` as arguments to compute the aligned size.
    - The aligned size is returned as the result of the function.
- **Output**: The function returns an unsigned long integer representing the aligned memory footprint required for the scratch pad memory.


---
### fd\_scratch\_fmem\_align<!-- {{#callable:fd_scratch_fmem_align}} -->
The `fd_scratch_fmem_align` function returns the alignment requirement for the scratch pad memory metadata, which is the size of an unsigned long integer.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended to be used within the same translation unit and suggests a preference for inlining by the compiler.
    - It uses the `FD_FN_CONST` macro, indicating that the function has no side effects and its return value depends only on its parameters (though it takes no parameters).
    - The function simply returns the size of an unsigned long integer using the `sizeof` operator.
- **Output**: The function returns an unsigned long integer representing the alignment size for scratch pad memory metadata, specifically the size of an `ulong`.


---
### fd\_scratch\_fmem\_footprint<!-- {{#callable:fd_scratch_fmem_footprint}} -->
The `fd_scratch_fmem_footprint` function calculates the memory footprint required for a scratch pad memory metadata region capable of holding a specified number of scratch frames.
- **Inputs**:
    - `depth`: The number of scratch frames the memory region should be capable of holding.
- **Control Flow**:
    - The function takes a single input parameter, `depth`, which represents the number of scratch frames.
    - It calculates the memory footprint by multiplying the `depth` by the size of an `ulong`.
    - The function returns the calculated footprint as the result.
- **Output**: The function returns an `ulong` representing the memory footprint required for the specified number of scratch frames.


---
### fd\_scratch\_attach<!-- {{#callable:fd_scratch_attach}} -->
The `fd_scratch_attach` function initializes and attaches a scratch pad memory region for the calling thread, setting up the necessary memory boundaries and frame metadata.
- **Inputs**:
    - `smem`: A pointer to the scratch memory region to be used, which must be properly aligned and non-NULL.
    - `fmem`: A pointer to the frame memory region to be used, which must be properly aligned and non-NULL.
    - `smax`: The maximum size in bytes of the scratch memory region, which must be a positive value.
    - `depth`: The maximum number of frames that can be used, which must be a positive value.
- **Control Flow**:
    - If `FD_SCRATCH_USE_HANDHOLDING` is enabled, the function checks if a scratch pad is already attached, and if any of the inputs are invalid, logging errors if so.
    - The function sets `fd_scratch_private_start`, `fd_scratch_private_free`, and `fd_scratch_private_stop` to manage the scratch memory boundaries.
    - It initializes `fd_scratch_private_frame`, `fd_scratch_private_frame_cnt`, and `fd_scratch_private_frame_max` to manage frame metadata.
    - If `FD_HAS_DEEPASAN` is enabled, it poisons the scratch memory region to detect invalid memory accesses, respecting alignment requirements.
    - If `FD_HAS_MSAN` is enabled, it marks the scratch memory region as uninitialized to detect use of uninitialized memory.
- **Output**: The function does not return a value; it sets up the scratch pad memory for use by the calling thread.


---
### fd\_scratch\_detach<!-- {{#callable:fd_scratch_detach}} -->
The `fd_scratch_detach` function detaches the calling thread from its current scratch pad memory attachment, returning the start of the scratch memory and optionally storing the frame memory pointer.
- **Inputs**:
    - `_opt_fmem`: A pointer to a memory location where the frame memory pointer will be stored if it is not NULL.
- **Control Flow**:
    - If FD_SCRATCH_USE_HANDHOLDING is enabled, check if the scratch pad is attached; if not, log an error.
    - If FD_HAS_DEEPASAN is enabled, unpoison the entire scratch space to ensure it is safe for use.
    - Store the current start of the scratch memory in `smem` and the current frame memory in `fmem`.
    - Reset all private scratch pad memory variables to indicate detachment.
    - If `_opt_fmem` is not NULL, store the frame memory pointer in `_opt_fmem[0]`.
    - Return the start of the scratch memory (`smem`).
- **Output**: The function returns a pointer to the start of the scratch memory (`smem`) that was used during the attachment.


---
### fd\_scratch\_used<!-- {{#callable:fd_scratch_used}} -->
The `fd_scratch_used` function calculates the number of bytes currently used in the scratch pad memory.
- **Inputs**: None
- **Control Flow**:
    - The function calculates the difference between `fd_scratch_private_free` and `fd_scratch_private_start`.
- **Output**: The function returns an `ulong` representing the number of bytes used in the scratch pad memory.


---
### fd\_scratch\_free<!-- {{#callable:fd_scratch_free}} -->
The `fd_scratch_free` function calculates the amount of free memory available in the scratch pad memory by subtracting the current free memory pointer from the stop pointer.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, which suggests it is intended for use within the same translation unit and optimized for performance.
    - It calculates the difference between `fd_scratch_private_stop` and `fd_scratch_private_free`, which are global variables representing the end of the scratch memory and the current free position, respectively.
    - The result of this subtraction gives the number of bytes available for allocation in the scratch pad memory.
- **Output**: The function returns an unsigned long integer (`ulong`) representing the number of free bytes available in the scratch pad memory.


---
### fd\_scratch\_frame\_used<!-- {{#callable:fd_scratch_frame_used}} -->
The `fd_scratch_frame_used` function returns the number of scratch frames currently in use by the caller.
- **Inputs**: None
- **Control Flow**:
    - The function directly returns the value of the global variable `fd_scratch_private_frame_cnt`, which tracks the number of scratch frames in use.
- **Output**: The function outputs an `ulong` representing the number of scratch frames currently in use.


---
### fd\_scratch\_frame\_free<!-- {{#callable:fd_scratch_frame_free}} -->
The `fd_scratch_frame_free` function returns the number of available scratch frames that can be used for memory allocation.
- **Inputs**: None
- **Control Flow**:
    - The function calculates the difference between `fd_scratch_private_frame_max` and `fd_scratch_private_frame_cnt`.
    - It returns this difference as the number of free frames available.
- **Output**: The function returns an `ulong` representing the number of free scratch frames available for allocation.


---
### fd\_scratch\_reset<!-- {{#callable:fd_scratch_reset}} -->
The `fd_scratch_reset` function resets the scratch pad memory to its initial state after attachment, freeing all allocations and frames, and optionally poisons the memory for debugging purposes.
- **Inputs**: None
- **Control Flow**:
    - If `FD_SCRATCH_USE_HANDHOLDING` is enabled, check if the scratch pad is attached and log an error if not.
    - Set `fd_scratch_in_prepare` to 0 to indicate no preparation is in progress.
    - Reset `fd_scratch_private_free` to `fd_scratch_private_start` to free all allocations.
    - Reset `fd_scratch_private_frame_cnt` to 0 to pop all frames.
    - If `FD_HAS_DEEPASAN` is enabled, align the start and stop addresses and poison the memory region for debugging.
    - If `FD_HAS_MSAN` is enabled, align the start and stop addresses and mark the memory region as uninitialized for debugging.
- **Output**: The function does not return any value.


---
### fd\_scratch\_push<!-- {{#callable:fd_scratch_push}} -->
The `fd_scratch_push` function creates a new scratch frame and makes it the current frame, ensuring memory safety through optional runtime checks and memory poisoning.
- **Inputs**: None
- **Control Flow**:
    - If `FD_SCRATCH_USE_HANDHOLDING` is enabled, check if the scratch pad is attached and if there is space for a new frame; log errors if not.
    - Set `fd_scratch_in_prepare` to 0 to indicate no allocation is in preparation.
    - Store the current free memory pointer in the frame stack and increment the frame count.
    - If `FD_HAS_DEEPASAN` is enabled, align the start and stop pointers and poison the memory region to prevent use-after-free errors.
    - If `FD_HAS_MSAN` is enabled, similarly align and poison the memory region for uninitialized memory detection.
- **Output**: The function does not return any value; it modifies global state related to the scratch pad memory.


---
### fd\_scratch\_pop<!-- {{#callable:fd_scratch_pop}} -->
The `fd_scratch_pop` function frees all allocations in the current scratch frame, destroys the current frame, and makes the previous frame the current one, while handling memory poisoning for debugging purposes.
- **Inputs**: None
- **Control Flow**:
    - If `FD_SCRATCH_USE_HANDHOLDING` is enabled, check if the scratch pad is attached and if there is a frame to pop; log errors if not.
    - Set `fd_scratch_in_prepare` to 0 to indicate no ongoing preparation.
    - Decrement the frame count and update `fd_scratch_private_free` to the start of the previous frame.
    - If `FD_HAS_DEEPASAN` is enabled, poison the memory from the new `fd_scratch_private_free` to the end of the scratch space for debugging purposes.
    - If `FD_HAS_MSAN` is enabled, similarly poison the memory for debugging purposes.
- **Output**: The function does not return any value.


---
### fd\_scratch\_prepare<!-- {{#callable:fd_scratch_prepare}} -->
The `fd_scratch_prepare` function prepares a memory region for allocation with a specified alignment in the current scratch frame.
- **Inputs**:
    - `align`: The desired alignment for the memory allocation, where 0 indicates the use of a default alignment.
- **Control Flow**:
    - If handholding is enabled, check if there is a current frame and if the alignment is valid; log an error if not.
    - Adjust the alignment to ensure it is at least 8 bytes if DEEPASAN is enabled.
    - Calculate the true alignment and the aligned memory address for the allocation.
    - If handholding is enabled, check for overflow or insufficient memory and log an error if detected.
    - If DEEPASAN is enabled, unpoison the memory region to allow access.
    - Update the free pointer to the aligned memory address.
    - Return the aligned memory address as a void pointer.
- **Output**: A void pointer to the aligned memory address in the scratch pad memory.
- **Functions called**:
    - [`fd_scratch_private_align_is_valid`](#fd_scratch_private_align_is_valid)
    - [`fd_scratch_private_true_align`](#fd_scratch_private_true_align)


---
### fd\_scratch\_publish<!-- {{#callable:fd_scratch_publish}} -->
The `fd_scratch_publish` function finalizes an in-progress memory allocation in a scratch pad memory system, updating the free pointer and handling memory poisoning for debugging.
- **Inputs**:
    - `_end`: A pointer to the end of the allocated memory region, indicating the first byte after the final allocation.
- **Control Flow**:
    - Convert the input pointer `_end` to an unsigned long `end`.
    - If `FD_SCRATCH_USE_HANDHOLDING` is enabled, perform checks to ensure a prepare operation is in progress, and that `end` is within valid bounds, logging errors if not.
    - Set `fd_scratch_in_prepare` to 0 to indicate the end of a prepare operation.
    - If `FD_HAS_DEEPASAN` or `FD_HAS_MSAN` is enabled, align the free, end, and stop pointers and poison/unpoison memory regions accordingly for debugging purposes.
    - Update `fd_scratch_private_free` to `end` to finalize the allocation.
- **Output**: The function does not return a value; it updates internal state and potentially logs errors.


---
### fd\_scratch\_cancel<!-- {{#callable:fd_scratch_cancel}} -->
The `fd_scratch_cancel` function cancels an in-progress memory allocation preparation in a scratch pad memory system.
- **Inputs**: None
- **Control Flow**:
    - If `FD_SCRATCH_USE_HANDHOLDING` is enabled, the function checks if there is an unmatched prepare operation by verifying `fd_scratch_in_prepare` is set.
    - If the check fails, it logs an error message 'unmatched prepare'.
    - The function then resets `fd_scratch_in_prepare` to 0, indicating no prepare operation is in progress.
- **Output**: The function does not return any value.


---
### fd\_scratch\_alloc<!-- {{#callable:fd_scratch_alloc}} -->
The `fd_scratch_alloc` function allocates a specified size of memory with a given alignment in the current scratch frame, ensuring the allocation is within bounds and publishing the allocation for use.
- **Inputs**:
    - `align`: The alignment requirement for the memory allocation, which must be 0 or a power of 2; 0 defaults to FD_SCRATCH_ALIGN_DEFAULT.
    - `sz`: The size of the memory to allocate in bytes.
- **Control Flow**:
    - Call [`fd_scratch_prepare`](#fd_scratch_prepare) with the specified alignment to get the starting memory address for the allocation.
    - Calculate the end address by adding the size `sz` to the starting address `smem`.
    - If `FD_SCRATCH_USE_HANDHOLDING` is enabled, check for overflow or out-of-bounds conditions and log an error if detected.
    - Call [`fd_scratch_publish`](#fd_scratch_publish) with the end address to finalize the allocation.
    - Return the starting address `smem` as a pointer to the allocated memory.
- **Output**: A pointer to the beginning of the allocated memory block, aligned as specified.
- **Functions called**:
    - [`fd_scratch_prepare`](#fd_scratch_prepare)
    - [`fd_scratch_publish`](#fd_scratch_publish)


---
### fd\_scratch\_trim<!-- {{#callable:fd_scratch_trim}} -->
The `fd_scratch_trim` function adjusts the size of the most recent scratch allocation in the current scratch frame by setting the free pointer to a specified end address, with optional runtime checks and memory poisoning for debugging.
- **Inputs**:
    - `_end`: A pointer to the end address up to which the scratch allocation should be trimmed.
- **Control Flow**:
    - Convert the input pointer `_end` to an unsigned long `end`.
    - If `FD_SCRATCH_USE_HANDHOLDING` is enabled, perform runtime checks to ensure there is a current frame, the end address is not before the start of the current frame, and the end address is not beyond the current free pointer.
    - If `FD_HAS_DEEPASAN` is enabled, align the end address and the stop address, and poison the memory region from the aligned end to the aligned stop.
    - If `FD_HAS_MSAN` is enabled, perform similar alignment and poisoning as with `FD_HAS_DEEPASAN`.
    - Set `fd_scratch_private_free` to the end address.
- **Output**: The function does not return a value; it modifies the internal state of the scratch memory management system by updating the free pointer.


---
### fd\_scratch\_attach\_is\_safe<!-- {{#callable:fd_scratch_attach_is_safe}} -->
The `fd_scratch_attach_is_safe` function checks if the calling thread is not currently attached to a scratch pad memory, returning true if it is safe to attach.
- **Inputs**: None
- **Control Flow**:
    - The function checks the value of `fd_scratch_private_frame_max`.
    - If `fd_scratch_private_frame_max` is zero, it indicates that the thread is not attached to any scratch pad memory.
    - The function returns the negation of `fd_scratch_private_frame_max`, which evaluates to true (1) if `fd_scratch_private_frame_max` is zero, and false (0) otherwise.
- **Output**: The function returns an integer, 1 if it is safe to attach (i.e., the thread is not currently attached), and 0 otherwise.


---
### fd\_scratch\_detach\_is\_safe<!-- {{#callable:fd_scratch_detach_is_safe}} -->
The `fd_scratch_detach_is_safe` function checks if the current thread is attached to a scratch pad memory, returning true if it is.
- **Inputs**: None
- **Control Flow**:
    - The function checks the value of `fd_scratch_private_frame_max`.
    - It returns the result of the logical negation of the negation of `fd_scratch_private_frame_max`, effectively checking if it is non-zero.
- **Output**: The function returns an integer value, 1 if the thread is attached to a scratch pad memory (i.e., `fd_scratch_private_frame_max` is non-zero), and 0 otherwise.


---
### fd\_scratch\_reset\_is\_safe<!-- {{#callable:fd_scratch_reset_is_safe}} -->
The `fd_scratch_reset_is_safe` function checks if the scratch pad memory is currently attached, indicating that a reset operation can be safely performed.
- **Inputs**: None
- **Control Flow**:
    - The function checks the value of `fd_scratch_private_frame_max`.
    - It returns a boolean value indicating whether the scratch pad memory is attached.
- **Output**: The function returns an integer value, which is 1 if the scratch pad memory is attached (indicating a reset is safe) and 0 otherwise.


---
### fd\_scratch\_push\_is\_safe<!-- {{#callable:fd_scratch_push_is_safe}} -->
The `fd_scratch_push_is_safe` function checks if there is space available to push a new frame onto the scratch pad memory stack.
- **Inputs**: None
- **Control Flow**:
    - The function compares `fd_scratch_private_frame_cnt` with `fd_scratch_private_frame_max`.
    - If `fd_scratch_private_frame_cnt` is less than `fd_scratch_private_frame_max`, it returns true (1), indicating it is safe to push a new frame.
    - Otherwise, it returns false (0), indicating it is not safe to push a new frame.
- **Output**: The function returns an integer, 1 if it is safe to push a new frame, and 0 otherwise.


---
### fd\_scratch\_pop\_is\_safe<!-- {{#callable:fd_scratch_pop_is_safe}} -->
The `fd_scratch_pop_is_safe` function checks if there is at least one frame in use in the scratch pad memory, indicating that a pop operation is safe to perform.
- **Inputs**: None
- **Control Flow**:
    - The function checks the value of `fd_scratch_private_frame_cnt`, which represents the number of frames currently in use.
    - It returns a boolean value indicating whether `fd_scratch_private_frame_cnt` is non-zero, meaning there is at least one frame in use.
- **Output**: The function returns an integer value, which is 1 if there is at least one frame in use (indicating a pop operation is safe), and 0 otherwise.


---
### fd\_scratch\_prepare\_is\_safe<!-- {{#callable:fd_scratch_prepare_is_safe}} -->
The `fd_scratch_prepare_is_safe` function checks if it is safe to start preparing an allocation with a specified alignment in the current scratch frame.
- **Inputs**:
    - `align`: The alignment requirement for the allocation, which should be a power of two or zero (indicating default alignment).
- **Control Flow**:
    - Check if there is a current frame by verifying `fd_scratch_private_frame_cnt` is non-zero; return 0 if not.
    - Validate the alignment using [`fd_scratch_private_align_is_valid`](#fd_scratch_private_align_is_valid); return 0 if invalid.
    - Calculate the true alignment using [`fd_scratch_private_true_align`](#fd_scratch_private_true_align).
    - Align the current free memory pointer `fd_scratch_private_free` to the true alignment using `fd_ulong_align_up`.
    - Check for alignment overflow by comparing the aligned memory pointer with `fd_scratch_private_free`; return 0 if overflow occurs.
    - Ensure there is enough scratch memory by comparing the aligned memory pointer with `fd_scratch_private_stop`; return 0 if insufficient.
    - Return 1 if all checks pass, indicating it is safe to prepare the allocation.
- **Output**: Returns an integer (1 or 0) indicating whether it is safe to prepare an allocation with the specified alignment.
- **Functions called**:
    - [`fd_scratch_private_align_is_valid`](#fd_scratch_private_align_is_valid)
    - [`fd_scratch_private_true_align`](#fd_scratch_private_true_align)


---
### fd\_scratch\_publish\_is\_safe<!-- {{#callable:fd_scratch_publish_is_safe}} -->
The `fd_scratch_publish_is_safe` function checks if a given memory address is a valid endpoint for completing a scratch memory allocation.
- **Inputs**:
    - `_end`: A pointer to the memory address that is being checked for validity as the endpoint of a scratch memory allocation.
- **Control Flow**:
    - Convert the input pointer `_end` to an unsigned long integer `end`.
    - If `FD_SCRATCH_USE_HANDHOLDING` is enabled, check if a prepare operation is in progress; if not, return 0 indicating it is not safe.
    - Check if `end` is less than `fd_scratch_private_free`; if true, return 0 indicating it is not safe because it would move backward in memory.
    - Check if `end` is greater than `fd_scratch_private_stop`; if true, return 0 indicating it is not safe because it is out of bounds.
    - If none of the above conditions are met, return 1 indicating it is safe.
- **Output**: Returns an integer: 1 if the memory address is a valid endpoint for a scratch memory allocation, otherwise 0.


---
### fd\_scratch\_cancel\_is\_safe<!-- {{#callable:fd_scratch_cancel_is_safe}} -->
The function `fd_scratch_cancel_is_safe` always returns 1, indicating that it is always safe to cancel a scratch allocation preparation.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function with a return type of `int`.
    - It does not take any parameters.
    - The function body consists of a single return statement that returns the integer value 1.
- **Output**: The function returns an integer value of 1, indicating that it is always safe to cancel a scratch allocation preparation.


---
### fd\_scratch\_alloc\_is\_safe<!-- {{#callable:fd_scratch_alloc_is_safe}} -->
The `fd_scratch_alloc_is_safe` function checks if it is safe to allocate a specified size of memory with a given alignment in the current scratch frame.
- **Inputs**:
    - `align`: The alignment requirement for the memory allocation, which must be a power of two or zero (treated as default alignment).
    - `sz`: The size of the memory allocation in bytes.
- **Control Flow**:
    - Check if there is a current scratch frame; if not, return 0 (unsafe).
    - Verify if the alignment is valid (a power of two or zero); if not, return 0 (unsafe).
    - Calculate the true alignment using [`fd_scratch_private_true_align`](#fd_scratch_private_true_align).
    - Align the current free memory pointer `fd_scratch_private_free` to the true alignment using `fd_ulong_align_up`.
    - Check for overflow in alignment; if overflow occurs, return 0 (unsafe).
    - Calculate the end of the allocation by adding the size to the aligned memory pointer.
    - Check for overflow in size; if overflow occurs, return 0 (unsafe).
    - Ensure the end of the allocation does not exceed the available scratch memory (`fd_scratch_private_stop`); if it does, return 0 (unsafe).
    - If all checks pass, return 1 (safe).
- **Output**: Returns 1 if the allocation is safe, otherwise returns 0.
- **Functions called**:
    - [`fd_scratch_private_align_is_valid`](#fd_scratch_private_align_is_valid)
    - [`fd_scratch_private_true_align`](#fd_scratch_private_true_align)


---
### fd\_scratch\_trim\_is\_safe<!-- {{#callable:fd_scratch_trim_is_safe}} -->
The `fd_scratch_trim_is_safe` function checks if trimming the most recent scratch allocation to a specified end address is safe.
- **Inputs**:
    - `_end`: A pointer to the end address to which the scratch allocation is intended to be trimmed.
- **Control Flow**:
    - Convert the input pointer `_end` to an unsigned long integer `end`.
    - Check if there is no current frame by evaluating `fd_scratch_private_frame_cnt`; if true, return 0 indicating it is not safe to trim.
    - Check if `end` is less than the start of the current frame (`fd_scratch_private_frame[fd_scratch_private_frame_cnt-1UL]`); if true, return 0 indicating a trim underflow.
    - Check if `end` is greater than `fd_scratch_private_free`; if true, return 0 indicating a trim overflow.
    - If none of the above conditions are met, return 1 indicating it is safe to trim.
- **Output**: Returns an integer: 1 if it is safe to trim the scratch allocation to the specified end address, or 0 if it is not safe.


---
### fd\_scratch\_virtual<!-- {{#callable:fd_valloc_t::fd_scratch_virtual}} -->
The `fd_scratch_virtual` function returns an abstract handle to the `fd_scratch` join, which is valid for the lifetime of the scratch frame.
- **Inputs**: None
- **Control Flow**:
    - A `fd_valloc_t` structure named `valloc` is initialized with `NULL` and a pointer to `fd_scratch_vtable`.
    - The function returns the `valloc` structure.
- **Output**: The function returns a `fd_valloc_t` structure initialized with a `NULL` pointer and a pointer to the `fd_scratch_vtable`.
- **See also**: [`fd_valloc_t`](../valloc/fd_valloc.h.driver.md#fd_valloc_t)  (Data Structure)


---
### fd\_scratch\_scoped\_pop\_private<!-- {{#callable:fd_scratch_scoped_pop_private}} -->
The `fd_scratch_scoped_pop_private` function is a static inline function that calls `fd_scratch_pop()` to free all allocations in the current scratch frame and destroy the current scratch frame.
- **Inputs**:
    - `_unused`: A void pointer that is not used within the function, typically used to satisfy function signature requirements.
- **Control Flow**:
    - The function takes a single argument, `_unused`, which is not utilized in the function body.
    - The function explicitly casts `_unused` to void to avoid compiler warnings about unused parameters.
    - The function calls `fd_scratch_pop()` to free all allocations in the current scratch frame and destroy the current scratch frame.
- **Output**: The function does not return any value.
- **Functions called**:
    - [`fd_scratch_pop`](#fd_scratch_pop)


