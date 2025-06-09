# Purpose
The provided C code is a comprehensive implementation of a memory allocator, specifically designed to manage memory allocation and deallocation within a workspace. This allocator is part of a larger system, as indicated by the inclusion of headers like "fd_alloc.h" and "fd_alloc_cfg.h", and it is intended to be used in environments where atomic operations may or may not be available, as suggested by the conditional compilation directives checking for `FD_HAS_ATOMIC`. The allocator supports both small and large allocations, with small allocations being managed within superblocks to optimize memory usage and performance.

Key components of this allocator include functions for determining the preferred size class for a given memory footprint, managing sets of blocks within superblocks, and handling the allocation and deallocation of memory blocks. The code also includes mechanisms for handling concurrency, such as atomic operations and compiler fences, to ensure thread safety. Additionally, the allocator provides functions for creating, joining, and deleting allocator instances, as well as for compacting memory and checking if the allocator is empty. The code is structured to allow for detailed diagnostics and debugging, with functions like [`fd_alloc_fprintf`](#fd_alloc_fprintf) providing insights into the current state of the allocator and its memory usage. Overall, this code is a robust implementation of a memory allocator tailored for use in a specific system, with a focus on efficiency and concurrency management.
# Imports and Dependencies

---
- `fd_alloc.h`
- `fd_alloc_cfg.h`
- `../sanitize/fd_asan.h`
- `../tmpl/fd_smallset.c`
- `../tmpl/fd_voff.c`
- `../wksp/fd_wksp_private.h`
- `stdio.h`


# Global Variables

---
### fd\_alloc\_vtable
- **Type**: `fd_valloc_vtable_t`
- **Description**: The `fd_alloc_vtable` is a constant instance of the `fd_valloc_vtable_t` structure, which serves as a virtual function table for memory allocation operations. It contains function pointers for `malloc` and `free` operations, specifically pointing to `fd_alloc_malloc_virtual` and `fd_alloc_free_virtual` functions, respectively.
- **Use**: This variable is used to provide a standardized interface for memory allocation and deallocation operations, allowing for polymorphic behavior in memory management.


# Data Structures

---
### fd\_alloc\_superblock
- **Type**: `struct`
- **Members**:
    - `free_blocks`: Indicates which blocks in this superblock are currently allocated.
    - `next_gaddr`: Points to the next inactive superblock in the stack or is NULL if not applicable.
- **Description**: The `fd_alloc_superblock` structure is designed to manage memory allocation within a superblock, which is a larger block of memory divided into smaller blocks for allocation. It contains a set of free blocks, represented by `free_blocks`, which tracks which blocks are currently allocated. The `next_gaddr` member is used to link superblocks in an inactive stack, allowing for efficient management of memory resources. This structure is aligned to a specific boundary to optimize cache usage and performance.


---
### fd\_alloc\_superblock\_t
- **Type**: `struct`
- **Members**:
    - `free_blocks`: Indicates which blocks in this superblock are currently allocated.
    - `next_gaddr`: Points to the next inactive superblock or is NULL if not on the inactive stack.
- **Description**: The `fd_alloc_superblock_t` structure represents a superblock in a memory allocation system, specifically designed to manage blocks of memory within a larger workspace. It contains a set of blocks, tracked by `free_blocks`, which indicates the allocation status of each block within the superblock. The `next_gaddr` member is used to link superblocks in an inactive stack, allowing for efficient management and reuse of memory blocks. This structure is aligned to 16 bytes to ensure that `free_blocks` and `next_gaddr` are on the same cache line, optimizing access speed.


---
### fd\_alloc
- **Type**: `struct`
- **Members**:
    - `magic`: A unique identifier for the memory layout of the fd_alloc structure, expected to be equal to FD_ALLOC_MAGIC.
    - `wksp_off`: The offset of the first byte of this structure from the start of the workspace.
    - `tag`: A positive tag used by this allocator.
    - `active_slot`: An array storing the global address of the active superblock for sizeclass allocations done by a member of a concurrency group, or 0 if there is no active superblock.
    - `inactive_stack`: An array representing the top of the inactive stack for each sizeclass, with a versioned offset containing a 64-bit version number and a 64-bit global address.
- **Description**: The `fd_alloc` structure is a memory allocator designed to manage memory allocation within a workspace. It uses a system of active and inactive superblocks to efficiently allocate memory for different size classes and concurrency groups. The structure is aligned to a specific boundary to optimize memory access and minimize false sharing in concurrent operations. The `magic` field ensures the integrity of the structure, while `wksp_off` and `tag` provide metadata about the allocator's position and purpose. The `active_slot` and `inactive_stack` arrays manage the allocation and deallocation of memory blocks, ensuring that memory is reused efficiently and safely across different threads and operations.


# Functions

---
### fd\_alloc\_preferred\_sizeclass<!-- {{#callable:fd_alloc_preferred_sizeclass}} -->
The `fd_alloc_preferred_sizeclass` function determines the smallest size class that can accommodate a given memory footprint.
- **Inputs**:
    - `footprint`: An unsigned long integer representing the memory footprint for which the preferred size class is to be determined.
- **Control Flow**:
    - Initialize two unsigned long variables, `l` and `h`, to 0 and `FD_ALLOC_SIZECLASS_CNT-1` respectively, representing the lower and upper bounds of the size class range.
    - Iterate a fixed number of times (7 times) to perform a binary search within the size class range.
    - In each iteration, calculate the midpoint `m` of the current range `[l, h]`.
    - Check if the size class at index `m` has a block footprint greater than or equal to the given `footprint`.
    - Use conditional move operations (`fd_ulong_if`) to adjust the bounds `l` and `h` based on the comparison result, narrowing down the range to find the smallest suitable size class.
    - After the loop, return the upper bound `h`, which represents the index of the preferred size class.
- **Output**: The function returns an unsigned long integer representing the index of the preferred size class that can accommodate the given footprint.


---
### fd\_alloc\_preferred\_sizeclass\_cgroup<!-- {{#callable:fd_alloc_preferred_sizeclass_cgroup}} -->
The function `fd_alloc_preferred_sizeclass_cgroup` returns the preferred concurrency group for a given sizeclass and concurrency group index by applying a bitwise AND operation with the sizeclass's cgroup mask.
- **Inputs**:
    - `sizeclass`: An unsigned long integer representing the sizeclass index, which should be within the range [0, FD_ALLOC_SIZECLASS_CNT).
    - `cgroup_idx`: An unsigned long integer representing the concurrency group index.
- **Control Flow**:
    - The function takes two unsigned long integer parameters: `sizeclass` and `cgroup_idx`.
    - It retrieves the `cgroup_mask` for the given `sizeclass` from the `fd_alloc_sizeclass_cfg` array.
    - It performs a bitwise AND operation between `cgroup_idx` and the `cgroup_mask` of the specified `sizeclass`.
    - The result of the bitwise AND operation is returned as the preferred concurrency group.
- **Output**: The function returns an unsigned long integer representing the preferred concurrency group for the specified sizeclass and concurrency group index.


---
### fd\_alloc\_block\_set\_add<!-- {{#callable:fd_alloc_block_set_add}} -->
The `fd_alloc_block_set_add` function adds a specified number of blocks to a block set and returns the previous value of the block set.
- **Inputs**:
    - `set`: A pointer to the `fd_alloc_block_set_t` variable representing the current set of blocks.
    - `blocks`: The `fd_alloc_block_set_t` value representing the number of blocks to be added to the set.
- **Control Flow**:
    - A memory fence is executed to ensure memory operations are completed in order.
    - The current value of the block set pointed to by `set` is read and stored in `ret`.
    - The block set is updated by adding the `blocks` value to the current value of the block set.
    - Another memory fence is executed to ensure the update is completed before proceeding.
    - The previous value of the block set (stored in `ret`) is returned.
- **Output**: The function returns the value of the block set before the addition operation.


---
### fd\_alloc\_block\_set\_sub<!-- {{#callable:fd_alloc_block_set_sub}} -->
The `fd_alloc_block_set_sub` function atomically subtracts a specified number of blocks from a block set and returns the block set's value before the subtraction.
- **Inputs**:
    - `set`: A pointer to a `fd_alloc_block_set_t` representing the block set from which blocks will be subtracted.
    - `blocks`: A `fd_alloc_block_set_t` value representing the number of blocks to subtract from the block set pointed to by `set`.
- **Control Flow**:
    - Declare a variable `ret` of type `fd_alloc_block_set_t` to store the initial value of the block set.
    - Execute a memory fence operation using `FD_COMPILER_MFENCE()` to ensure memory ordering before accessing the block set.
    - Assign the current value of the block set pointed to by `set` to `ret` using `FD_VOLATILE_CONST` to ensure the value is read as volatile.
    - Subtract the `blocks` value from the block set pointed to by `set` and store the result back into the block set using `FD_VOLATILE` to ensure the operation is treated as volatile.
    - Execute another memory fence operation using `FD_COMPILER_MFENCE()` to ensure memory ordering after the subtraction operation.
    - Return the initial value of the block set stored in `ret`.
- **Output**: The function returns the value of the block set before the subtraction operation, which is of type `fd_alloc_block_set_t`.


---
### fd\_alloc\_private\_wksp<!-- {{#callable:fd_alloc_private_wksp}} -->
The `fd_alloc_private_wksp` function calculates and returns the workspace pointer associated with a given allocator by adjusting the allocator's address using its workspace offset.
- **Inputs**:
    - `alloc`: A pointer to an `fd_alloc_t` structure, representing the allocator whose workspace is to be determined.
- **Control Flow**:
    - The function takes a single input, `alloc`, which is a pointer to an `fd_alloc_t` structure.
    - It calculates the workspace pointer by subtracting the `wksp_off` field of the `alloc` structure from the address of `alloc`.
    - The result is cast to a `fd_wksp_t *` type and returned.
- **Output**: A pointer to an `fd_wksp_t` structure, representing the workspace associated with the given allocator.


---
### fd\_alloc\_private\_active\_slot\_replace<!-- {{#callable:fd_alloc_private_active_slot_replace}} -->
The `fd_alloc_private_active_slot_replace` function replaces the value in a given active slot with a new superblock global address and returns the old superblock global address, ensuring memory consistency with compiler fences and atomic operations if available.
- **Inputs**:
    - `active_slot`: A pointer to an unsigned long representing the active slot whose value is to be replaced.
    - `new_superblock_gaddr`: An unsigned long representing the new superblock global address to be set in the active slot.
- **Control Flow**:
    - A memory fence is applied to ensure memory operations are completed before proceeding.
    - If atomic operations are supported (`FD_HAS_ATOMIC` is defined), the function uses an atomic exchange operation (`FD_ATOMIC_XCHG`) to replace the value in `active_slot` with `new_superblock_gaddr`, storing the old value in `old_superblock_gaddr`.
    - If atomic operations are not supported, the function reads the current value of `active_slot` into `old_superblock_gaddr`, then sets `active_slot` to `new_superblock_gaddr` using volatile operations to ensure memory visibility.
    - Another memory fence is applied to ensure all memory operations are completed before returning.
    - The function returns the old superblock global address stored in `old_superblock_gaddr`.
- **Output**: The function returns the old superblock global address that was previously stored in the active slot.


---
### fd\_alloc\_private\_inactive\_stack\_push<!-- {{#callable:fd_alloc_private_inactive_stack_push}} -->
The function `fd_alloc_private_inactive_stack_push` pushes a superblock onto an inactive stack in a workspace, ensuring atomicity if supported.
- **Inputs**:
    - `inactive_stack`: A pointer to the top of the inactive stack where the superblock will be pushed.
    - `wksp`: A pointer to the workspace that contains the superblock.
    - `superblock_gaddr`: The global address of the superblock to be pushed onto the inactive stack.
- **Control Flow**:
    - Convert the global address of the superblock to a local address using `fd_wksp_laddr_fast`.
    - Enter an infinite loop to attempt pushing the superblock onto the stack.
    - Read the current top of the inactive stack and store it in `old`.
    - Extract the version and global address from `old`.
    - Create a new stack top with an incremented version and the superblock's global address.
    - Set the `next_gaddr` of the superblock to the current top's global address.
    - Attempt to atomically compare and swap the stack top with the new value if atomic operations are supported, otherwise use a volatile check and set.
    - If the compare and swap is successful, break out of the loop; otherwise, pause and retry.
- **Output**: The function does not return a value; it modifies the inactive stack in place.


---
### fd\_alloc\_private\_inactive\_stack\_pop<!-- {{#callable:fd_alloc_private_inactive_stack_pop}} -->
The function `fd_alloc_private_inactive_stack_pop` attempts to pop the top element from an inactive stack of superblocks, returning the global address of the popped superblock or 0 if the stack is empty.
- **Inputs**:
    - `inactive_stack`: A pointer to the top of the inactive stack, represented as a versioned global address.
    - `wksp`: A pointer to the workspace structure, which provides context for address translation and memory operations.
- **Control Flow**:
    - Initialize `top_gaddr` to store the address of the top element of the stack.
    - Enter an infinite loop to attempt popping the top element from the stack.
    - Read the current top of the inactive stack into `old`, using memory fences to ensure proper ordering.
    - Extract the global address (`top_gaddr`) and version (`top_ver`) from `old`.
    - If `top_gaddr` is zero, break the loop as the stack is empty.
    - Translate `top_gaddr` to a local address and access the `next_gaddr` of the top superblock.
    - Create a new versioned address `new` with an incremented version and `next_gaddr` as the offset.
    - Attempt to atomically compare and swap the top of the stack from `old` to `new`.
    - If the compare and swap is successful, break the loop; otherwise, pause and retry.
    - Return `top_gaddr`, which is the address of the popped superblock.
- **Output**: Returns the global address of the superblock that was at the top of the inactive stack, or 0 if the stack was empty.


---
### fd\_alloc\_hdr\_load<!-- {{#callable:fd_alloc_hdr_t::fd_alloc_hdr_load}} -->
The `fd_alloc_hdr_load` function retrieves the allocation header for a memory block given its starting address.
- **Inputs**:
    - `laddr`: A constant pointer to the starting address of the memory block in the caller's address space.
- **Control Flow**:
    - The function calculates the address of the header by subtracting the size of `fd_alloc_hdr_t` from the given `laddr`.
    - It then uses the `FD_LOAD` macro to load the header from the calculated address.
- **Output**: The function returns the `fd_alloc_hdr_t` header associated with the memory block.


---
### fd\_alloc\_hdr\_sizeclass<!-- {{#callable:fd_alloc_hdr_sizeclass}} -->
The `fd_alloc_hdr_sizeclass` function extracts and returns the size class of an allocation from a given header.
- **Inputs**:
    - `hdr`: A `fd_alloc_hdr_t` type representing the header of an allocation, which contains metadata about the allocation including its size class.
- **Control Flow**:
    - The function takes a header `hdr` as input.
    - It performs a bitwise AND operation between `hdr` and `127U` to extract the size class from the header.
    - The result of the bitwise operation is cast to `ulong` and returned.
- **Output**: The function returns an `ulong` representing the size class of the allocation, which is a value in the range [0, FD_ALLOC_SIZECLASS_CNT) or FD_ALLOC_SIZECLASS_LARGE.


---
### fd\_alloc\_hdr\_block\_idx<!-- {{#callable:fd_alloc_hdr_block_idx}} -->
The function `fd_alloc_hdr_block_idx` extracts and returns the block index from a given allocation header.
- **Inputs**:
    - `hdr`: An `fd_alloc_hdr_t` type representing the allocation header from which the block index is to be extracted.
- **Control Flow**:
    - The function takes an allocation header `hdr` as input.
    - It performs a bitwise right shift on `hdr` by 7 bits to discard the lower 7 bits.
    - It then applies a bitwise AND operation with `63U` (which is `0x3F` in hexadecimal) to extract the 6 bits that represent the block index.
    - The result of the bitwise operations is cast to `ulong` and returned.
- **Output**: The function returns an `ulong` representing the block index extracted from the allocation header.


---
### fd\_alloc\_hdr\_is\_large<!-- {{#callable:fd_alloc_hdr_is_large}} -->
The function `fd_alloc_hdr_is_large` checks if a given allocation header indicates a large allocation.
- **Inputs**:
    - `hdr`: A `fd_alloc_hdr_t` type representing the allocation header to be checked.
- **Control Flow**:
    - The function calls `fd_uint_clear_bit` on the `hdr` with bit position 7 to clear that bit.
    - It compares the result of `fd_uint_clear_bit` with the constant `FD_ALLOC_HDR_LARGE_DIRECT`.
    - If the result matches `FD_ALLOC_HDR_LARGE_DIRECT`, the function returns 1, indicating a large allocation; otherwise, it returns 0.
- **Output**: The function returns an integer: 1 if the header indicates a large allocation, and 0 otherwise.


---
### fd\_alloc\_hdr\_large\_is\_superblock<!-- {{#callable:fd_alloc_hdr_large_is_superblock}} -->
The function `fd_alloc_hdr_large_is_superblock` checks if a given large allocation header indicates that it holds a superblock.
- **Inputs**:
    - `hdr`: A `fd_alloc_hdr_t` type representing the header of a large allocation, which contains metadata about the allocation.
- **Control Flow**:
    - The function calls `fd_uint_extract_bit` with the header and the bit position 7 as arguments.
    - It returns the result of `fd_uint_extract_bit`, which checks if the 7th bit of the header is set.
- **Output**: An integer value, 1 if the 7th bit of the header is set (indicating a superblock), or 0 if it is not.


---
### fd\_alloc\_hdr\_store<!-- {{#callable:fd_alloc_hdr_store}} -->
The `fd_alloc_hdr_store` function stores a header describing a small sizeclass allocation in the memory immediately preceding the given local address.
- **Inputs**:
    - `laddr`: A pointer to the local address where the allocation begins in the caller's address space.
    - `superblock`: A pointer to the superblock containing the allocation.
    - `block_idx`: The index of the block within the superblock that contains the allocation.
    - `sizeclass`: The sizeclass of the allocation, which determines the size and alignment of the allocation.
- **Control Flow**:
    - Calculate the offset of the local address from the superblock and shift it left by 13 bits to store in the header.
    - Shift the block index left by 7 bits and combine it with the sizeclass to form the header.
    - Store the constructed header in the memory immediately preceding the local address.
    - Return the local address.
- **Output**: Returns the local address `laddr` after storing the header.


---
### fd\_alloc\_hdr\_store\_large<!-- {{#callable:fd_alloc_hdr_store_large}} -->
The `fd_alloc_hdr_store_large` function stores a header for a large memory allocation, indicating whether it is a direct user allocation or a superblock, and returns the local address of the allocation.
- **Inputs**:
    - `laddr`: A pointer to the local address of the memory allocation where the header will be stored.
    - `is_superblock`: An integer flag (0 or 1) indicating whether the allocation is a superblock (1) or a direct user allocation (0).
- **Control Flow**:
    - The function calculates the address where the header should be stored by subtracting the size of `fd_alloc_hdr_t` from `laddr`.
    - It constructs the header value by combining `FD_ALLOC_HDR_LARGE_DIRECT` with the `is_superblock` flag shifted left by 7 bits.
    - The header is stored at the calculated address using the `FD_STORE` macro.
    - The function returns the original `laddr` pointer.
- **Output**: The function returns the original local address pointer `laddr`.


---
### fd\_alloc\_private\_join\_alloc<!-- {{#callable:fd_alloc_private_join_alloc}} -->
The function `fd_alloc_private_join_alloc` returns the local address of an allocator by masking out the concurrency group hint from a given join handle.
- **Inputs**:
    - `join`: A pointer to an `fd_alloc_t` structure representing a join handle, which includes a concurrency group hint.
- **Control Flow**:
    - The function takes a single input parameter, `join`, which is a pointer to an `fd_alloc_t` structure.
    - It performs a bitwise AND operation on the `join` pointer, using the complement of `FD_ALLOC_JOIN_CGROUP_HINT_MAX` as the mask.
    - This operation effectively clears the bits used for the concurrency group hint, isolating the base address of the allocator.
    - The result of the bitwise operation is cast back to an `fd_alloc_t` pointer and returned.
- **Output**: A pointer to an `fd_alloc_t` structure, representing the local address of the allocator without the concurrency group hint.


---
### fd\_alloc\_align<!-- {{#callable:fd_alloc_align}} -->
The `fd_alloc_align` function returns the alignment requirement of the `fd_alloc_t` structure.
- **Inputs**: None
- **Control Flow**:
    - The function simply returns the result of the `alignof` operator applied to `fd_alloc_t`.
- **Output**: The function outputs an `ulong` representing the alignment requirement of the `fd_alloc_t` structure.


---
### fd\_alloc\_footprint<!-- {{#callable:fd_alloc_footprint}} -->
The `fd_alloc_footprint` function returns the size in bytes of the `fd_alloc_t` structure.
- **Inputs**: None
- **Control Flow**:
    - The function simply returns the result of the `sizeof` operator applied to `fd_alloc_t`.
- **Output**: The function outputs an `ulong` representing the size of the `fd_alloc_t` structure in bytes.


---
### fd\_alloc\_superblock\_footprint<!-- {{#callable:fd_alloc_superblock_footprint}} -->
The function `fd_alloc_superblock_footprint` returns the size of the `fd_alloc_superblock_t` structure.
- **Inputs**: None
- **Control Flow**:
    - The function directly returns the result of the `sizeof` operator applied to `fd_alloc_superblock_t`.
- **Output**: The function outputs an `ulong` representing the size in bytes of the `fd_alloc_superblock_t` structure.


---
### fd\_alloc\_new<!-- {{#callable:fd_alloc_new}} -->
The `fd_alloc_new` function initializes a new memory allocator in a shared memory region with a specified tag, ensuring proper alignment and workspace association.
- **Inputs**:
    - `shmem`: A pointer to the shared memory region where the allocator will be initialized.
    - `tag`: An unsigned long integer representing a tag to be associated with the allocator.
- **Control Flow**:
    - Check if the `shmem` pointer is NULL; if so, log a warning and return NULL.
    - Check if `shmem` is properly aligned to the alignment requirements of `fd_alloc_t`; if not, log a warning and return NULL.
    - Determine the workspace containing `shmem` using `fd_wksp_containing`; if no workspace is found, log a warning and return NULL.
    - Check if the `tag` is non-zero; if not, log a warning and return NULL.
    - Cast `shmem` to `fd_alloc_t*` and zero out the memory for the allocator structure using `fd_memset`.
    - Calculate the offset of the allocator from the start of the workspace and store it in `alloc->wksp_off`.
    - Store the `tag` in `alloc->tag`.
    - Use memory fences to ensure memory operations are completed before setting `alloc->magic` to `FD_ALLOC_MAGIC`.
    - Return the `shmem` pointer.
- **Output**: Returns the `shmem` pointer if successful, or NULL if any checks fail.


---
### fd\_alloc\_join<!-- {{#callable:fd_alloc_join}} -->
The `fd_alloc_join` function validates and joins a shared memory allocator with a concurrency group hint, returning a pointer to the allocator if successful.
- **Inputs**:
    - `shalloc`: A pointer to the shared memory allocator to be joined.
    - `cgroup_hint`: An unsigned long integer representing a concurrency group hint for the allocator.
- **Control Flow**:
    - Assign the input `shalloc` to a local variable `alloc`.
    - Check if `alloc` is NULL; if so, log a warning and return NULL.
    - Check if `alloc` is properly aligned; if not, log a warning and return NULL.
    - Check if `alloc` has the correct magic number; if not, log a warning and return NULL.
    - Call [`fd_alloc_join_cgroup_hint_set`](fd_alloc.h.driver.md#fd_alloc_join_cgroup_hint_set) with `alloc` and `cgroup_hint` and return its result.
- **Output**: Returns a pointer to the joined allocator if successful, or NULL if any validation checks fail.
- **Functions called**:
    - [`fd_alloc_join_cgroup_hint_set`](fd_alloc.h.driver.md#fd_alloc_join_cgroup_hint_set)


---
### fd\_alloc\_leave<!-- {{#callable:fd_alloc_leave}} -->
The `fd_alloc_leave` function checks if a given `fd_alloc_t` pointer is non-null and returns the local address of the allocator for a join.
- **Inputs**:
    - `join`: A pointer to an `fd_alloc_t` structure, representing a join handle for an allocator.
- **Control Flow**:
    - Check if the `join` pointer is null using `FD_UNLIKELY`; if it is, log a warning and return `NULL`.
    - If `join` is not null, call [`fd_alloc_private_join_alloc`](#fd_alloc_private_join_alloc) with `join` and return its result.
- **Output**: Returns a pointer to the local address of the allocator if `join` is valid, otherwise returns `NULL`.
- **Functions called**:
    - [`fd_alloc_private_join_alloc`](#fd_alloc_private_join_alloc)


---
### fd\_alloc\_delete<!-- {{#callable:fd_alloc_delete}} -->
The `fd_alloc_delete` function deallocates a memory allocator object, cleaning up associated resources and ensuring proper alignment and integrity checks.
- **Inputs**:
    - `shalloc`: A pointer to the shared memory allocator object to be deleted.
- **Control Flow**:
    - Check if `shalloc` is NULL and log a warning if so, returning NULL.
    - Verify that `shalloc` is properly aligned to `fd_alloc_t` and log a warning if not, returning NULL.
    - Cast `shalloc` to `fd_alloc_t` and check if its magic number matches `FD_ALLOC_MAGIC`, logging a warning and returning NULL if it doesn't.
    - Set the magic number of the allocator to 0 to mark it as deleted, using memory fences to ensure proper ordering.
    - Retrieve the workspace associated with the allocator using [`fd_alloc_private_wksp`](#fd_alloc_private_wksp).
    - Iterate over each size class, cleaning up active and inactive superblocks by replacing active slots with 0 and freeing any superblocks found.
    - Return the original `shalloc` pointer.
- **Output**: Returns the original `shalloc` pointer if successful, or NULL if any checks fail.
- **Functions called**:
    - [`fd_alloc_private_wksp`](#fd_alloc_private_wksp)
    - [`fd_alloc_private_active_slot_replace`](#fd_alloc_private_active_slot_replace)
    - [`fd_alloc_free`](#fd_alloc_free)
    - [`fd_alloc_private_inactive_stack_pop`](#fd_alloc_private_inactive_stack_pop)


---
### fd\_alloc\_wksp<!-- {{#callable:fd_alloc_wksp}} -->
The `fd_alloc_wksp` function retrieves the workspace associated with a given allocator join handle.
- **Inputs**:
    - `join`: A pointer to an `fd_alloc_t` structure representing the allocator join handle.
- **Control Flow**:
    - The function checks if the `join` pointer is likely to be non-NULL using the `FD_LIKELY` macro.
    - If `join` is non-NULL, it calls [`fd_alloc_private_join_alloc`](#fd_alloc_private_join_alloc) to get the local address of the allocator from the join handle.
    - It then calls [`fd_alloc_private_wksp`](#fd_alloc_private_wksp) with the allocator to get the workspace backing the allocator.
    - If `join` is NULL, the function returns NULL.
- **Output**: A pointer to the `fd_wksp_t` structure representing the workspace associated with the allocator, or NULL if the join handle is NULL.
- **Functions called**:
    - [`fd_alloc_private_wksp`](#fd_alloc_private_wksp)
    - [`fd_alloc_private_join_alloc`](#fd_alloc_private_join_alloc)


---
### fd\_alloc\_tag<!-- {{#callable:fd_alloc_tag}} -->
The `fd_alloc_tag` function retrieves the tag associated with a given `fd_alloc_t` allocator instance.
- **Inputs**:
    - `join`: A pointer to an `fd_alloc_t` structure, representing the allocator instance from which the tag is to be retrieved.
- **Control Flow**:
    - The function checks if the `join` pointer is likely to be non-null using the `FD_LIKELY` macro.
    - If `join` is non-null, it calls [`fd_alloc_private_join_alloc`](#fd_alloc_private_join_alloc) to get the actual allocator structure and returns its `tag` field.
    - If `join` is null, it returns `0UL` as the default value.
- **Output**: The function returns an `ulong` representing the tag of the allocator, or `0UL` if the input is null.
- **Functions called**:
    - [`fd_alloc_private_join_alloc`](#fd_alloc_private_join_alloc)


---
### fd\_alloc\_malloc\_at\_least<!-- {{#callable:fd_alloc_malloc_at_least}} -->
The `fd_alloc_malloc_at_least` function allocates memory with a specified alignment and size, ensuring the allocation is at least the requested size, and returns the maximum possible size of the allocation.
- **Inputs**:
    - `join`: A pointer to an `fd_alloc_t` structure representing the allocator context.
    - `align`: The desired alignment for the memory allocation, which must be a power of two.
    - `sz`: The minimum size of the memory allocation requested.
    - `max`: A pointer to a `ulong` where the function will store the maximum size of the allocated memory.
- **Control Flow**:
    - Check if `max` is NULL and return NULL if true.
    - Retrieve the allocator from the `join` handle and set default alignment if `align` is zero.
    - Calculate the total footprint required for the allocation, including header and alignment padding.
    - Check for invalid conditions such as non-power-of-two alignment, zero size, or unreasonable footprint, and return NULL if any are true.
    - If the footprint is large, allocate memory directly from the workspace and return the allocated address after storing the header.
    - For small footprints, determine the preferred sizeclass and concurrency group, and attempt to allocate from an active superblock.
    - If no active superblock is available, attempt to pop from the inactive stack or allocate a new superblock.
    - Once a superblock is available, allocate a block from it, update the free block set, and return the allocated address after storing the header.
- **Output**: A pointer to the allocated memory block, or NULL if the allocation fails.
- **Functions called**:
    - [`fd_alloc_private_join_alloc`](#fd_alloc_private_join_alloc)
    - [`fd_alloc_private_wksp`](#fd_alloc_private_wksp)
    - [`fd_alloc_hdr_store_large`](#fd_alloc_hdr_store_large)
    - [`fd_alloc_preferred_sizeclass`](#fd_alloc_preferred_sizeclass)
    - [`fd_alloc_preferred_sizeclass_cgroup`](#fd_alloc_preferred_sizeclass_cgroup)
    - [`fd_alloc_join_cgroup_hint`](fd_alloc.h.driver.md#fd_alloc_join_cgroup_hint)
    - [`fd_alloc_private_active_slot_replace`](#fd_alloc_private_active_slot_replace)
    - [`fd_alloc_private_inactive_stack_pop`](#fd_alloc_private_inactive_stack_pop)
    - [`fd_alloc_malloc`](fd_alloc.h.driver.md#fd_alloc_malloc)
    - [`fd_alloc_block_set_sub`](#fd_alloc_block_set_sub)
    - [`fd_alloc_private_inactive_stack_push`](#fd_alloc_private_inactive_stack_push)
    - [`fd_alloc_hdr_store`](#fd_alloc_hdr_store)


---
### fd\_alloc\_free<!-- {{#callable:fd_alloc_free}} -->
The [`fd_alloc_free`](#fd_alloc_free) function deallocates memory previously allocated by a custom allocator, handling both large and small allocations differently.
- **Inputs**:
    - `join`: A pointer to a `fd_alloc_t` structure representing the allocator context.
    - `laddr`: A pointer to the first byte of the memory allocation to be freed.
- **Control Flow**:
    - Check if the allocator (`join`) or the memory address (`laddr`) is NULL; if so, return immediately.
    - Retrieve the actual allocator from the join handle using [`fd_alloc_private_join_alloc`](#fd_alloc_private_join_alloc).
    - Load the allocation header from `laddr` to determine the sizeclass of the allocation.
    - If the sizeclass indicates a large allocation, use `fd_wksp_free` to free the memory and return.
    - For small allocations, determine the superblock and block index from the header.
    - Add the block to the set of free blocks in the superblock.
    - If the superblock had no free blocks before this operation, put it back into circulation by making it the active superblock or pushing it onto the inactive stack.
    - If the superblock is now completely free, attempt to delete an inactive superblock to prevent accumulation of empty superblocks.
- **Output**: The function does not return a value; it performs memory deallocation as a side effect.
- **Functions called**:
    - [`fd_alloc_private_join_alloc`](#fd_alloc_private_join_alloc)
    - [`fd_alloc_hdr_t::fd_alloc_hdr_load`](#fd_alloc_hdr_tfd_alloc_hdr_load)
    - [`fd_alloc_hdr_sizeclass`](#fd_alloc_hdr_sizeclass)
    - [`fd_alloc_private_wksp`](#fd_alloc_private_wksp)
    - [`fd_alloc_hdr_block_idx`](#fd_alloc_hdr_block_idx)
    - [`fd_alloc_block_set_add`](#fd_alloc_block_set_add)
    - [`fd_alloc_preferred_sizeclass_cgroup`](#fd_alloc_preferred_sizeclass_cgroup)
    - [`fd_alloc_join_cgroup_hint`](fd_alloc.h.driver.md#fd_alloc_join_cgroup_hint)
    - [`fd_alloc_private_active_slot_replace`](#fd_alloc_private_active_slot_replace)
    - [`fd_alloc_private_inactive_stack_push`](#fd_alloc_private_inactive_stack_push)
    - [`fd_alloc_private_inactive_stack_pop`](#fd_alloc_private_inactive_stack_pop)
    - [`fd_alloc_free`](#fd_alloc_free)


---
### fd\_alloc\_compact<!-- {{#callable:fd_alloc_compact}} -->
The `fd_alloc_compact` function scans and compacts memory allocations by freeing completely empty superblocks and reorganizing partially filled ones to optimize memory usage.
- **Inputs**:
    - `join`: A pointer to an `fd_alloc_t` structure representing the memory allocator to be compacted.
- **Control Flow**:
    - Retrieve the allocator from the join handle using [`fd_alloc_private_join_alloc`](#fd_alloc_private_join_alloc) and check if it is valid.
    - Obtain the workspace associated with the allocator using [`fd_alloc_private_wksp`](#fd_alloc_private_wksp).
    - Iterate over each sizeclass, checking active superblocks for complete emptiness and freeing them if they are empty.
    - For each active superblock, if it is not empty, return it to circulation and handle any displaced superblocks by pushing them onto the inactive stack.
    - Drain the inactive stack for each sizeclass, freeing empty superblocks and temporarily storing non-empty ones on a local stack.
    - Return non-empty superblocks from the local stack back to the inactive stack to maintain circulation.
- **Output**: The function does not return any value; it performs memory compaction in-place on the provided allocator.
- **Functions called**:
    - [`fd_alloc_private_join_alloc`](#fd_alloc_private_join_alloc)
    - [`fd_alloc_private_wksp`](#fd_alloc_private_wksp)
    - [`fd_alloc_private_active_slot_replace`](#fd_alloc_private_active_slot_replace)
    - [`fd_alloc_free`](#fd_alloc_free)
    - [`fd_alloc_private_inactive_stack_push`](#fd_alloc_private_inactive_stack_push)
    - [`fd_alloc_private_inactive_stack_pop`](#fd_alloc_private_inactive_stack_pop)


---
### fd\_alloc\_is\_empty<!-- {{#callable:fd_alloc_is_empty}} -->
The `fd_alloc_is_empty` function checks if a given memory allocator is empty, meaning it has no active allocations.
- **Inputs**:
    - `join`: A pointer to an `fd_alloc_t` structure representing the memory allocator to be checked.
- **Control Flow**:
    - Retrieve the internal allocator structure using [`fd_alloc_private_join_alloc`](#fd_alloc_private_join_alloc) with the provided `join` pointer.
    - If the allocator is invalid (NULL), return 0 indicating it is not empty.
    - Call [`fd_alloc_compact`](#fd_alloc_compact) to compact the allocator, potentially freeing up unused memory blocks.
    - Retrieve the workspace associated with the allocator using [`fd_alloc_private_wksp`](#fd_alloc_private_wksp).
    - Calculate the global address range (`alloc_lo` to `alloc_hi`) and tag of the allocator.
    - Iterate over the workspace's partition information to check for any large allocations with the same tag that are not within the allocator's address range.
    - If any such allocations are found, break the loop and return 0, indicating the allocator is not empty.
    - If the loop completes without finding any such allocations, return 1, indicating the allocator is empty.
- **Output**: Returns an integer: 1 if the allocator is empty (no active allocations), or 0 if it is not empty.
- **Functions called**:
    - [`fd_alloc_private_join_alloc`](#fd_alloc_private_join_alloc)
    - [`fd_alloc_compact`](#fd_alloc_compact)
    - [`fd_alloc_private_wksp`](#fd_alloc_private_wksp)


---
### fd\_alloc\_superblock\_fprintf<!-- {{#callable:fd_alloc_superblock_fprintf}} -->
The `fd_alloc_superblock_fprintf` function prints detailed information about the state of a superblock in a workspace to a given stream, including diagnostics and block usage details.
- **Inputs**:
    - `wksp`: A pointer to a `fd_wksp_t` structure representing the workspace; it must be non-NULL.
    - `superblock_gaddr`: An unsigned long representing the global address of the superblock within the workspace; it must be valid for the given workspace.
    - `sizeclass`: An unsigned long representing the size class of the superblock; it must be valid.
    - `block_cnt`: An unsigned long representing the number of blocks in the superblock; it must match the size class configuration.
    - `block_footprint`: An unsigned long representing the footprint of each block in the superblock; it must match the size class configuration.
    - `stream`: A pointer to a `FILE` structure where the output will be printed; it must be non-NULL.
    - `ctr`: A pointer to an array of unsigned longs with at least two elements, used to accumulate diagnostic counts; it must be non-NULL.
- **Control Flow**:
    - Initialize a counter `cnt` to zero for tracking the number of characters printed.
    - Retrieve the superblock from the workspace using the global address `superblock_gaddr`.
    - Extract the set of free blocks from the superblock and check for any errors by shifting the free blocks by `block_cnt` bits; increment the first element of `ctr` if an error is detected.
    - Print the free blocks information to the stream, indicating whether the state is 'good' or 'bad'.
    - Iterate over each block index from 0 to `block_cnt - 1`.
    - For each block, calculate the global address range (`gaddr_lo` to `gaddr_hi`) for the block.
    - Check if the block is free using `fd_alloc_block_set_test`; if free, skip to the next block.
    - If the block is used, attempt to find a plausible `fd_alloc_hdr_t` header by iterating over possible alignments.
    - For each alignment, calculate the estimated global address and load the header; check if the header matches the expected size class, block index, and superblock.
    - If a matching header is found, calculate the estimated size and print the block details to the stream, incrementing the second element of `ctr`.
    - If no matching header is found after all alignments, print a 'bad' block message and increment the first element of `ctr`.
    - Return the total number of characters printed, `cnt`.
- **Output**: The function returns an integer representing the number of characters printed to the stream, or a negative error code if an error occurs during printing.
- **Functions called**:
    - [`fd_alloc_hdr_sizeclass`](#fd_alloc_hdr_sizeclass)
    - [`fd_alloc_hdr_block_idx`](#fd_alloc_hdr_block_idx)


---
### fd\_alloc\_fprintf<!-- {{#callable:fd_alloc_fprintf}} -->
The `fd_alloc_fprintf` function prints detailed information about the current state of a memory allocator to a specified output stream.
- **Inputs**:
    - `join`: A pointer to the `fd_alloc_t` structure representing the allocator to be inspected.
    - `stream`: A pointer to a `FILE` stream where the output will be printed.
- **Control Flow**:
    - Check if the `stream` is NULL and return 0 if true, as nothing can be printed.
    - Initialize a counter array `ctr` to track various statistics such as errors detected, small allocations found, workspace partitions used, etc.
    - Retrieve the allocator structure from the `join` pointer and the concurrency group hint.
    - If the allocator is NULL, print an error message to the stream and increment the error counter.
    - If the allocator is valid, print a summary header including the allocator's global address, concurrency group hint, and magic number status.
    - Iterate over each size class to print details about superblock footprints, block footprints, block counts, and concurrency group counts.
    - For each size class, print the inactive stack top and details of active and inactive superblocks, including their addresses and next pointers.
    - Scan the workspace partition table for partitions matching the allocation tag, printing details about large allocations and estimating their sizes.
    - Print summary statistics including errors detected, small allocations found, workspace partitions used, and large allocations found.
- **Output**: The function returns the total number of characters printed to the stream, or a negative error code if an error occurs during printing.
- **Functions called**:
    - [`fd_alloc_private_join_alloc`](#fd_alloc_private_join_alloc)
    - [`fd_alloc_join_cgroup_hint`](fd_alloc.h.driver.md#fd_alloc_join_cgroup_hint)
    - [`fd_alloc_private_wksp`](#fd_alloc_private_wksp)
    - [`fd_alloc_superblock_fprintf`](#fd_alloc_superblock_fprintf)
    - [`fd_alloc_hdr_is_large`](#fd_alloc_hdr_is_large)
    - [`fd_alloc_hdr_large_is_superblock`](#fd_alloc_hdr_large_is_superblock)


---
### fd\_alloc\_malloc\_virtual<!-- {{#callable:fd_alloc_malloc_virtual}} -->
The `fd_alloc_malloc_virtual` function is a virtual wrapper that calls [`fd_alloc_malloc`](fd_alloc.h.driver.md#fd_alloc_malloc) to allocate memory with specified alignment and size.
- **Inputs**:
    - `self`: A pointer to the allocator object, expected to be of type `fd_alloc_t *`, which represents the memory allocator instance.
    - `align`: An unsigned long integer specifying the alignment requirement for the memory allocation.
    - `sz`: An unsigned long integer specifying the size of the memory to allocate.
- **Control Flow**:
    - The function takes three parameters: `self`, `align`, and `sz`.
    - It casts the `self` parameter to `fd_alloc_t *` type, which is the expected type for the allocator object.
    - It calls the [`fd_alloc_malloc`](fd_alloc.h.driver.md#fd_alloc_malloc) function with the casted `self`, `align`, and `sz` as arguments.
    - The result of the [`fd_alloc_malloc`](fd_alloc.h.driver.md#fd_alloc_malloc) call is returned as the output of the function.
- **Output**: A pointer to the allocated memory block, or NULL if the allocation fails.
- **Functions called**:
    - [`fd_alloc_malloc`](fd_alloc.h.driver.md#fd_alloc_malloc)


---
### fd\_alloc\_free\_virtual<!-- {{#callable:fd_alloc_free_virtual}} -->
The `fd_alloc_free_virtual` function is a wrapper that calls [`fd_alloc_free`](#fd_alloc_free) to free a memory block using a virtual function table.
- **Inputs**:
    - `self`: A pointer to the allocator object, cast to `fd_alloc_t *`.
    - `addr`: A pointer to the memory block to be freed.
- **Control Flow**:
    - The function casts the `self` pointer to `fd_alloc_t *` type.
    - It then calls the [`fd_alloc_free`](#fd_alloc_free) function with the casted `self` and `addr` as arguments.
- **Output**: This function does not return any value.
- **Functions called**:
    - [`fd_alloc_free`](#fd_alloc_free)


