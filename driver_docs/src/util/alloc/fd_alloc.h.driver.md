# Purpose
The provided C header file defines a high-performance, lock-free memory allocator named `fd_alloc`. This allocator is designed to offer efficient O(1) allocation operations, particularly optimized for high concurrency and small, clustered allocation sizes. It is intended to be used in scenarios where traditional dynamic memory allocation methods, such as `malloc`, may introduce performance bottlenecks or reliability issues due to their underlying mechanisms, such as overcommitment and page faults. The `fd_alloc` allocator maintains its state in a workspace (`wksp`), which allows it to avoid the pitfalls of traditional memory allocation by ensuring that memory is only used from a pre-allocated pool, thus preventing unexpected stalls or failures due to memory overcommitment.

The file provides a comprehensive API for managing memory allocations, including functions for creating, joining, and deleting allocator instances, as well as for performing memory allocations and deallocations. It also includes utility functions for managing concurrency hints and optimizing memory usage through compaction. The allocator supports advanced features such as sharing allocations between processes and maintaining memory persistence across process lifetimes. The file is structured to facilitate integration into larger systems, providing constants for alignment and footprint requirements, and includes a virtual function table for use with abstract memory allocation interfaces. The detailed commentary within the file highlights the allocator's advantages over traditional methods and provides guidance on its optimal use in various scenarios.
# Imports and Dependencies

---
- `../wksp/fd_wksp.h`


# Global Variables

---
### fd\_alloc\_new
- **Type**: `function pointer`
- **Description**: `fd_alloc_new` is a function that initializes a workspace allocation with the appropriate alignment and footprint to be used as a `fd_alloc`. It returns a pointer to the shared memory (`shmem`) on success or `NULL` on failure. The function is designed to work with a high-performance lock-free allocator that is optimized for high concurrency and small allocation sizes.
- **Use**: This function is used to format an unused workspace allocation for use with the `fd_alloc` allocator, tagging allocations for diagnostics and garbage collection.


---
### fd\_alloc\_join
- **Type**: `fd_alloc_t *`
- **Description**: The `fd_alloc_join` function returns a pointer to an `fd_alloc_t` structure, which is an opaque handle representing a join to a high-performance lock-free allocator. This allocator is designed for efficient memory management in concurrent and persistent use cases, optimizing for small and clustered allocation sizes.
- **Use**: The `fd_alloc_join` function is used to join a caller to a `fd_alloc` allocator, providing an opaque handle for memory allocation operations within the allocator's context.


---
### fd\_alloc\_leave
- **Type**: `void *`
- **Description**: The `fd_alloc_leave` function is a global function that takes a pointer to an `fd_alloc_t` structure, which represents a join to a lock-free allocator, and returns a pointer to the underlying shared memory allocation (`shalloc`). This function is part of a high-performance memory allocation system designed to avoid the pitfalls of traditional `malloc` implementations, such as non-deterministic performance and overcommitment issues.
- **Use**: This function is used to leave an existing join to a `fd_alloc`, effectively ending the association with the allocator and returning the underlying shared memory pointer.


---
### fd\_alloc\_delete
- **Type**: `function pointer`
- **Description**: `fd_alloc_delete` is a function that unformats a workspace allocation used as a `fd_alloc`. It assumes that no threads are joined to the `fd_alloc` and that there are no outstanding allocations. If there are still some outstanding allocations, it attempts to clean up as many as it can find, but it is not guaranteed to find all of them. The function returns the shared memory pointer on success and NULL on failure.
- **Use**: This function is used to clean up and delete a `fd_alloc` instance, ensuring that the workspace allocation is properly unformatted and resources are freed.


---
### fd\_alloc\_wksp
- **Type**: `fd_wksp_t *`
- **Description**: The `fd_alloc_wksp` function returns a pointer to a local workspace (wksp) join of the workspace backing the `fd_alloc` with the current local join. This function is part of the `fd_alloc` allocator, which is designed for high-performance, lock-free memory allocation.
- **Use**: This variable is used to obtain a reference to the workspace associated with a given `fd_alloc` instance, allowing for operations on the underlying memory space.


---
### fd\_alloc\_malloc\_at\_least
- **Type**: `function pointer`
- **Description**: `fd_alloc_malloc_at_least` is a function that allocates memory from a workspace backing the `fd_alloc` structure. It ensures that at least a specified size of memory is allocated with a given alignment. The function also updates a pointer to indicate the actual size of the allocated memory, which may be larger than the requested size.
- **Use**: This function is used to allocate memory with specific alignment and size requirements, returning the actual size allocated through a pointer.


---
### fd\_alloc\_vtable
- **Type**: `const fd_valloc_vtable_t`
- **Description**: `fd_alloc_vtable` is a constant variable that represents the virtual function table for the `fd_valloc` interface, specifically implemented for the `fd_alloc` allocator. This table contains function pointers that define the operations available for the `fd_alloc` allocator, allowing it to be used polymorphically through the `fd_valloc` interface.
- **Use**: This variable is used to provide a set of function pointers that implement the `fd_valloc` interface for the `fd_alloc` allocator, enabling polymorphic behavior.


# Data Structures

---
### fd\_alloc\_t
- **Type**: `typedef struct fd_alloc fd_alloc_t;`
- **Description**: The `fd_alloc_t` is an opaque handle to a high-performance, lock-free allocator designed for efficient memory management in concurrent and single-threaded environments. It is optimized for small, clustered allocation sizes and ensures that memory allocations are backed by a workspace (wksp) to avoid the pitfalls of traditional malloc implementations, such as non-deterministic performance and overcommitment issues. The allocator supports advanced features like sharing allocations between processes and optimizing for thread affinity, making it suitable for high-concurrency and mission-critical applications.


# Functions

---
### fd\_alloc\_join\_cgroup\_hint<!-- {{#callable:fd_alloc_join_cgroup_hint}} -->
The `fd_alloc_join_cgroup_hint` function returns the concurrency group hint for a given `fd_alloc_t` join, ensuring it is within a specified maximum range.
- **Inputs**:
    - `join`: A pointer to an `fd_alloc_t` structure representing the current join.
- **Control Flow**:
    - The function casts the `join` pointer to an unsigned long integer.
    - It performs a bitwise AND operation between the casted `join` value and the constant `FD_ALLOC_JOIN_CGROUP_HINT_MAX`.
    - The result of the bitwise operation is returned, ensuring the hint is within the range [0, FD_ALLOC_JOIN_CGROUP_HINT_MAX].
- **Output**: The function returns an unsigned long integer representing the concurrency group hint, constrained to the range [0, FD_ALLOC_JOIN_CGROUP_HINT_MAX].


---
### fd\_alloc\_join\_cgroup\_hint\_set<!-- {{#callable:fd_alloc_join_cgroup_hint_set}} -->
The `fd_alloc_join_cgroup_hint_set` function updates the concurrency group hint of a given `fd_alloc_t` join pointer and returns the updated pointer.
- **Inputs**:
    - `join`: A pointer to an `fd_alloc_t` structure representing the current join.
    - `cgroup_hint`: An unsigned long integer representing the new concurrency group hint to be set.
- **Control Flow**:
    - The function takes the `join` pointer and casts it to an unsigned long integer.
    - It performs a bitwise AND operation with the negation of `FD_ALLOC_JOIN_CGROUP_HINT_MAX` to clear the current cgroup hint bits.
    - It performs a bitwise AND operation on `cgroup_hint` with `FD_ALLOC_JOIN_CGROUP_HINT_MAX` to ensure the hint is within the valid range.
    - It combines the results of the above operations using a bitwise OR to set the new cgroup hint in the `join` pointer.
    - The result is cast back to an `fd_alloc_t` pointer and returned.
- **Output**: The function returns a pointer to `fd_alloc_t` with the updated concurrency group hint.


---
### fd\_alloc\_malloc<!-- {{#callable:fd_alloc_malloc}} -->
The `fd_alloc_malloc` function allocates memory with a specified alignment and size using a lock-free allocator, returning a pointer to the allocated memory.
- **Inputs**:
    - `join`: A pointer to an `fd_alloc_t` structure representing the allocator context.
    - `align`: An unsigned long specifying the alignment requirement for the memory allocation, which should be a power of 2 or 0.
    - `sz`: An unsigned long specifying the size of the memory allocation in bytes.
- **Control Flow**:
    - Declare a local variable `max` as an array of one unsigned long.
    - Call the [`fd_alloc_malloc_at_least`](fd_alloc.c.driver.md#fd_alloc_malloc_at_least) function with `join`, `align`, `sz`, and `max` as arguments.
    - Return the result of the [`fd_alloc_malloc_at_least`](fd_alloc.c.driver.md#fd_alloc_malloc_at_least) function call.
- **Output**: A pointer to the allocated memory if successful, or NULL if the allocation fails.
- **Functions called**:
    - [`fd_alloc_malloc_at_least`](fd_alloc.c.driver.md#fd_alloc_malloc_at_least)


---
### fd\_alloc\_max\_expand<!-- {{#callable:fd_alloc_max_expand}} -->
The `fd_alloc_max_expand` function calculates a new maximum size for a dynamically resizable structure, ensuring it is at least as large as the needed size and handles potential overflow.
- **Inputs**:
    - `max`: The current maximum size of the structure.
    - `delta`: The minimum increment by which the size should be increased, assumed to be greater than 0.
    - `needed`: The size that is actually needed for the structure.
- **Control Flow**:
    - Calculate `t0` as `max + delta` and handle overflow by setting `t0` to `ULONG_MAX` if overflow occurs.
    - Calculate `t1` as `max + (max>>2) + (max>>4)` and handle overflow by setting `t1` to `ULONG_MAX` if overflow occurs.
    - Return the maximum value among `t0`, `t1`, and `needed` to ensure the new maximum size is sufficient.
- **Output**: The function returns an unsigned long integer representing the new maximum size, which is guaranteed to be at least as large as the needed size and greater than the current maximum if it is less than `ULONG_MAX`.


---
### fd\_alloc\_virtual<!-- {{#callable:fd_valloc_t::fd_alloc_virtual}} -->
The `fd_alloc_virtual` function creates and returns a virtual allocation handle for a given allocator.
- **Inputs**:
    - `alloc`: A pointer to an `fd_alloc_t` structure representing the allocator to be virtualized.
- **Control Flow**:
    - A `fd_valloc_t` structure named `valloc` is initialized with the `alloc` pointer and a reference to `fd_alloc_vtable`.
    - The initialized `valloc` structure is returned.
- **Output**: The function returns an `fd_valloc_t` structure, which is a virtual allocation handle for the provided allocator.
- **See also**: [`fd_valloc_t`](../valloc/fd_valloc.h.driver.md#fd_valloc_t)  (Data Structure)


# Function Declarations (Public API)

---
### fd\_alloc\_align<!-- {{#callable_declaration:fd_alloc_align}} -->
Returns the alignment requirement for fd_alloc.
- **Description**: Use this function to obtain the alignment requirement for fd_alloc, which is necessary when allocating memory for fd_alloc structures. This alignment value ensures that memory allocations are correctly aligned for optimal performance and compatibility. It is particularly useful when setting up memory regions that will be used with fd_alloc, ensuring they meet the necessary alignment constraints.
- **Inputs**: None
- **Output**: The function returns an unsigned long integer representing the alignment requirement for fd_alloc.
- **See also**: [`fd_alloc_align`](fd_alloc.c.driver.md#fd_alloc_align)  (Implementation)


---
### fd\_alloc\_footprint<!-- {{#callable_declaration:fd_alloc_footprint}} -->
Returns the memory footprint required for an fd_alloc.
- **Description**: Use this function to determine the size of memory required to store an fd_alloc structure. This is useful when allocating memory for an fd_alloc in a workspace. The function is constant and does not depend on any runtime state, making it safe to call at any time.
- **Inputs**: None
- **Output**: The function returns an unsigned long integer representing the size in bytes required for an fd_alloc structure.
- **See also**: [`fd_alloc_footprint`](fd_alloc.c.driver.md#fd_alloc_footprint)  (Implementation)


---
### fd\_alloc\_new<!-- {{#callable_declaration:fd_alloc_new}} -->
Formats a workspace allocation as a high-performance allocator.
- **Description**: This function initializes a shared memory region as a high-performance, lock-free allocator. It should be used when you have a workspace allocation that you want to format for use with the fd_alloc allocator. The function requires that the shared memory is properly aligned and part of a workspace. It also requires a non-zero tag for allocation tracking. If any of these conditions are not met, the function will log a warning and return NULL. This function is useful for setting up memory management in high-concurrency environments.
- **Inputs**:
    - `shmem`: A pointer to the shared memory region to be formatted. It must not be null, must be aligned to the alignment requirements of fd_alloc_t, and must be part of a workspace.
    - `tag`: An unsigned long integer used to tag allocations. It must be non-zero and ideally unique within the workspace to avoid conflicts.
- **Output**: Returns the pointer to the shared memory region on success, or NULL if the input conditions are not met.
- **See also**: [`fd_alloc_new`](fd_alloc.c.driver.md#fd_alloc_new)  (Implementation)


---
### fd\_alloc\_join<!-- {{#callable_declaration:fd_alloc_join}} -->
Joins a caller to a high-performance allocator.
- **Description**: This function is used to join a caller to a `fd_alloc` allocator, which is a high-performance, lock-free allocator optimized for various use cases, including high concurrency and small allocation sizes. The function requires a pointer to the memory region backing the allocator and a concurrency group hint to optimize parallel and persistent use cases. It returns an opaque handle on success, which is not a simple cast of the input pointer. The function should be called after the allocator has been properly initialized, and each successful join should be matched with a corresponding leave. The concurrency group hint helps in optimizing thread performance, especially in multi-threaded environments, but a value of 0 is suitable for single-threaded use cases.
- **Inputs**:
    - `shalloc`: A pointer to the first byte of the memory region backing the allocator in the caller's address space. Must not be null and must be properly aligned. If null or misaligned, the function logs a warning and returns null.
    - `cgroup_hint`: A concurrency hint used to optimize parallel and persistent use cases. Valid values are in the range [0, FD_ALLOC_JOIN_CGROUP_HINT_MAX]. If the value is outside this range, it will be wrapped to fit within it.
- **Output**: Returns an opaque handle to the allocator on success, or null on failure due to invalid input or internal state issues.
- **See also**: [`fd_alloc_join`](fd_alloc.c.driver.md#fd_alloc_join)  (Implementation)


---
### fd\_alloc\_leave<!-- {{#callable_declaration:fd_alloc_leave}} -->
Leaves an existing join to a fd_alloc.
- **Description**: This function is used to leave an existing join to a fd_alloc, effectively ending the association between the caller and the fd_alloc. It should be called when the caller no longer needs to interact with the fd_alloc, ensuring that resources are properly released. The function must be called with a valid join handle obtained from a successful call to fd_alloc_join. If the join parameter is NULL, the function logs a warning and returns NULL, indicating failure. Otherwise, it returns the underlying shalloc pointer associated with the join.
- **Inputs**:
    - `join`: A pointer to a fd_alloc_t representing the current join. Must not be NULL. If NULL, the function logs a warning and returns NULL.
- **Output**: Returns the underlying shalloc pointer on success, or NULL if the join is NULL.
- **See also**: [`fd_alloc_leave`](fd_alloc.c.driver.md#fd_alloc_leave)  (Implementation)


---
### fd\_alloc\_delete<!-- {{#callable_declaration:fd_alloc_delete}} -->
Unformats a workspace allocation used as a fd_alloc.
- **Description**: This function is used to unformat a workspace allocation that was previously formatted as a fd_alloc. It should be called when the fd_alloc is no longer needed, and the caller must ensure that no threads are joined to the fd_alloc and that there are no outstanding allocations. If there are still outstanding allocations, the function will attempt to clean up as many as possible, but it is not guaranteed to find all of them. This function returns the original memory pointer on success or NULL on failure, logging details of any issues encountered.
- **Inputs**:
    - `shalloc`: A pointer to the memory region backing the fd_alloc. It must not be NULL, must be properly aligned, and must have a valid magic number. If these conditions are not met, the function logs a warning and returns NULL.
- **Output**: Returns the original memory pointer (shalloc) on success, or NULL on failure if the input is invalid or if the fd_alloc is not properly formatted.
- **See also**: [`fd_alloc_delete`](fd_alloc.c.driver.md#fd_alloc_delete)  (Implementation)


---
### fd\_alloc\_wksp<!-- {{#callable_declaration:fd_alloc_wksp}} -->
Returns a pointer to the workspace backing the allocator.
- **Description**: Use this function to obtain a pointer to the workspace associated with a given allocator join. This is useful when you need to interact with the underlying workspace directly. The function should be called with a valid allocator join, and it will return NULL if the join is NULL. The returned workspace pointer should not be used with fd_alloc_leave, and its lifetime is tied to the mapping of the allocator's memory region in the caller's address space.
- **Inputs**:
    - `join`: A pointer to a valid fd_alloc_t join. Must not be NULL, as a NULL join will result in a NULL return value.
- **Output**: Returns a pointer to the fd_wksp_t representing the workspace backing the allocator, or NULL if the join is NULL.
- **See also**: [`fd_alloc_wksp`](fd_alloc.c.driver.md#fd_alloc_wksp)  (Implementation)


---
### fd\_alloc\_tag<!-- {{#callable_declaration:fd_alloc_tag}} -->
Retrieve the allocation tag for a given allocator join.
- **Description**: Use this function to obtain the tag associated with allocations from a specific fd_alloc instance. This is useful for diagnostics or tracking purposes. The function should be called with a valid join handle obtained from a successful fd_alloc_join call. If the join is NULL, the function will return 0, indicating no valid tag is associated.
- **Inputs**:
    - `join`: A pointer to an fd_alloc_t structure representing a current local join to the allocator. Must not be NULL for meaningful results; if NULL, the function returns 0.
- **Output**: Returns the tag associated with the allocator join, or 0 if the join is NULL.
- **See also**: [`fd_alloc_tag`](fd_alloc.c.driver.md#fd_alloc_tag)  (Implementation)


---
### fd\_alloc\_malloc\_at\_least<!-- {{#callable_declaration:fd_alloc_malloc_at_least}} -->
Allocates memory with specified alignment and size, returning the actual allocated size.
- **Description**: This function is used to allocate a block of memory from a workspace-backed allocator, ensuring that the allocated memory is at least the specified size and aligned to at least the specified alignment. It is suitable for high-performance, concurrent applications where memory allocation needs to be efficient and predictable. The function should be called with a valid allocator join and a non-null pointer for the maximum size output. It handles cases where the requested size is zero or the alignment is not a power of two by returning NULL and setting the maximum size to zero. The function is silent on failure, making it suitable for high-performance computing scenarios.
- **Inputs**:
    - `join`: A pointer to a valid fd_alloc_t structure representing the allocator. Must not be NULL.
    - `align`: The desired alignment for the allocation, which should be a power of two or zero. If zero, a default alignment is used.
    - `sz`: The minimum size of the memory block to allocate. If zero, the function returns NULL.
    - `max`: A pointer to a ulong where the function will store the actual size of the allocated memory. Must not be NULL.
- **Output**: Returns a pointer to the allocated memory block on success, or NULL on failure. On success, *max contains the actual size of the allocated memory, which is at least sz. On failure, *max is set to zero.
- **See also**: [`fd_alloc_malloc_at_least`](fd_alloc.c.driver.md#fd_alloc_malloc_at_least)  (Implementation)


---
### fd\_alloc\_free<!-- {{#callable_declaration:fd_alloc_free}} -->
Frees a previously allocated memory block.
- **Description**: Use this function to release memory that was previously allocated using the fd_alloc system. It should be called with a valid join handle and a pointer to the first byte of the allocated memory block. The function is designed to handle both small and large allocations efficiently, optimizing for reuse within the same concurrency group. It is silent on invalid inputs, such as a NULL join or NULL pointer, making it suitable for high-performance computing scenarios where error handling is managed externally.
- **Inputs**:
    - `join`: A pointer to an fd_alloc_t structure representing the current local join to the fd_alloc. Must be a valid join handle; if NULL, the function does nothing.
    - `laddr`: A pointer to the first byte of the memory block to be freed. Must have been allocated by the fd_alloc system. If NULL, the function does nothing.
- **Output**: None
- **See also**: [`fd_alloc_free`](fd_alloc.c.driver.md#fd_alloc_free)  (Implementation)


---
### fd\_alloc\_compact<!-- {{#callable_declaration:fd_alloc_compact}} -->
Frees unused workspace allocations in the allocator.
- **Description**: Use this function to release workspace allocations that are not required for any outstanding user allocations. It is particularly useful for minimizing workspace utilization when there is no concurrent usage of the allocator. This function is safe to call even when other operations are running concurrently, but it is best effort in such cases and does not guarantee minimization of workspace utilization. It is not an O(1) operation and should be used sparingly, such as during program teardown for leak detection or rare housekeeping tasks.
- **Inputs**:
    - `join`: A pointer to a current local join of the allocator. Must not be null. If the join is invalid, the function logs a warning and returns without performing any operations.
- **Output**: None
- **See also**: [`fd_alloc_compact`](fd_alloc.c.driver.md#fd_alloc_compact)  (Implementation)


---
### fd\_alloc\_is\_empty<!-- {{#callable_declaration:fd_alloc_is_empty}} -->
Check if the allocator has no outstanding allocations.
- **Description**: Use this function to determine if a given allocator has no outstanding memory allocations. It should be called when there is no concurrent usage of the allocator to ensure accurate results. The function is not optimized for speed and may temporarily lock the underlying workspace. It is best used for diagnostic purposes, such as leak detection during program teardown. The function will return 0 if the allocator is not empty or if the join is null.
- **Inputs**:
    - `join`: A pointer to a current local join of the allocator. Must not be null for accurate results. If null, the function will silently return 0.
- **Output**: Returns 1 if the allocator has no outstanding allocations, and 0 otherwise.
- **See also**: [`fd_alloc_is_empty`](fd_alloc.c.driver.md#fd_alloc_is_empty)  (Implementation)


