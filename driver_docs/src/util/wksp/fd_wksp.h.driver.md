# Purpose
The provided C header file defines an API for managing NUMA-aware and TLB-efficient workspaces, which are used for complex inter-thread and inter-process shared memory communication patterns. This API is part of a larger system that requires the foundational setup of shared memory regions, which can be configured to use huge or gigantic pages for optimal performance. The file includes functions for creating, joining, and managing these workspaces, allowing processes to allocate and free memory in a way that is efficient and minimizes fragmentation. The API is designed to be robust against memory corruption and supports operations like verifying and rebuilding workspace metadata to ensure integrity.

Key components of this API include functions for workspace creation ([`fd_wksp_new`](#fd_wksp_new), [`fd_wksp_new_named`](#fd_wksp_new_named), [`fd_wksp_new_anon`](#fd_wksp_new_anon)), memory allocation and deallocation ([`fd_wksp_alloc`](#fd_wksp_alloc), [`fd_wksp_free`](#fd_wksp_free)), and workspace management ([`fd_wksp_attach`](#fd_wksp_attach), [`fd_wksp_detach`](#fd_wksp_detach)). The API also provides mechanisms for handling errors and logging details of operations, which aids in debugging and maintaining the system. Additionally, the API supports checkpointing and restoring workspace states, which is useful for persistence and recovery scenarios. The file defines several constants and types that facilitate the configuration and operation of workspaces, ensuring that they can be used effectively in high-performance computing environments.
# Imports and Dependencies

---
- `../tpool/fd_tpool.h`
- `../checkpt/fd_checkpt.h`


# Global Variables

---
### fd\_wksp\_new
- **Type**: `function pointer`
- **Description**: `fd_wksp_new` is a function that formats an unused memory region into a workspace with a specified footprint and alignment. It takes parameters for shared memory, workspace name, seed for heap priorities, maximum number of partitions, and maximum data region size.
- **Use**: This function is used to initialize a new workspace in a specified memory region for shared memory communication.


---
### fd\_wksp\_join
- **Type**: `fd_wksp_t *`
- **Description**: The `fd_wksp_join` function returns a pointer to a `fd_wksp_t` structure, which represents a handle to a workspace. This workspace is used for shared memory communication patterns, allowing processes to join and allocate memory from it.
- **Use**: This variable is used to obtain a local handle to a workspace, enabling the caller to read and write memory within the joined workspace.


---
### fd\_wksp\_leave
- **Type**: `function pointer`
- **Description**: The `fd_wksp_leave` function is a global function that is used to leave a workspace in the context of shared memory management. It takes a pointer to a `fd_wksp_t` structure, which represents a workspace, and returns a void pointer. The function is responsible for detaching the caller from the workspace, ensuring that the caller no longer accesses the workspace's memory, although the workspace itself continues to exist.
- **Use**: This function is used to safely detach from a workspace, ensuring that the caller does not access the workspace's memory after leaving.


---
### fd\_wksp\_delete
- **Type**: `function pointer`
- **Description**: The `fd_wksp_delete` is a function pointer that points to a function designed to unformat a memory region used as a workspace. It takes a single argument, `shwksp`, which is a pointer to the shared memory workspace to be deleted, and returns the same pointer on success or NULL on failure.
- **Use**: This function is used to delete a workspace, ensuring that no processes are joined to it at the time of deletion.


---
### fd\_wksp\_name
- **Type**: ``char const *``
- **Description**: The `fd_wksp_name` function returns a constant character pointer to the name of a workspace. This name is a valid region name and its length is between 1 and `FD_SHMEM_NAME_MAX` characters. The returned string is constant for the lifetime of the join.
- **Use**: This variable is used to retrieve the name of a workspace, which is essential for identifying and managing shared memory regions.


---
### fd\_wksp\_strerror
- **Type**: ``FD_FN_CONST char const *``
- **Description**: The `fd_wksp_strerror` function is a global function that returns a constant character pointer. It is used to convert error codes related to workspace operations into human-readable strings. The function ensures that the returned string is always non-NULL and has an infinite lifetime.
- **Use**: This function is used to provide descriptive error messages for workspace-related error codes.


---
### fd\_wksp\_laddr
- **Type**: `function`
- **Description**: The `fd_wksp_laddr` function is used to map a workspace global address to the caller's local address space. It takes a pointer to a workspace (`fd_wksp_t const * wksp`) and a global address (`ulong gaddr`) as parameters and returns a pointer to the local address corresponding to the global address within the workspace.
- **Use**: This function is used to convert a global address within a workspace to a local address that can be accessed by the caller.


---
### fd\_wksp\_usage
- **Type**: `fd_wksp_usage_t *`
- **Description**: The `fd_wksp_usage` function returns a pointer to a `fd_wksp_usage_t` structure, which contains statistics about the usage of a workspace (`wksp`). This structure includes fields for the maximum number of partitions, the current number of partitions, and the sizes of free and used partitions.
- **Use**: This variable is used to obtain and store detailed usage statistics of a workspace, including the number of partitions and their sizes, which can be used for monitoring and managing memory allocation within the workspace.


---
### fd\_wksp\_new\_anon
- **Type**: `fd_wksp_t *`
- **Description**: The `fd_wksp_new_anon` function creates a workspace local to the calling thread group, which behaves like a shared workspace with the same name, TLB, and NUMA properties. It returns a pointer to the newly created workspace (`fd_wksp_t *`) on success or NULL on failure.
- **Use**: This variable is used to store the pointer to the newly created anonymous workspace, allowing the calling thread group to manage and interact with the workspace.


---
### fd\_wksp\_attach
- **Type**: `fd_wksp_t *`
- **Description**: The `fd_wksp_attach` function returns a pointer to a `fd_wksp_t` structure, which represents a workspace in shared memory. This function is used to attach to a workspace identified by a given name, allowing processes to access and manage shared memory resources efficiently.
- **Use**: This variable is used to hold the handle to a workspace after successfully attaching to it, enabling further operations on the shared memory.


---
### fd\_wksp\_containing
- **Type**: `fd_wksp_t *`
- **Description**: The `fd_wksp_containing` function is a global function that returns a pointer to a `fd_wksp_t` structure, which represents a workspace. It takes a constant void pointer `laddr` as an argument, which is expected to be a local address within a workspace.
- **Use**: This function is used to determine which workspace a given local address belongs to, returning a pointer to the corresponding `fd_wksp_t` if the address is part of a locally joined workspace, or NULL if it is not.


---
### fd\_wksp\_alloc\_laddr
- **Type**: `function pointer`
- **Description**: `fd_wksp_alloc_laddr` is a function that allocates memory from a workspace (`fd_wksp_t`) with a specified alignment and size, and returns a pointer to the allocated memory in the caller's local address space. It also tags the allocation with a specified tag for identification purposes.
- **Use**: This function is used to allocate memory from a workspace and obtain a local address pointer to the allocated memory.


---
### fd\_wksp\_cstr
- **Type**: `function pointer`
- **Description**: The `fd_wksp_cstr` is a function that converts a workspace global address into a C-style string representation. It takes a pointer to a workspace (`fd_wksp_t`), a global address (`ulong`), and a character buffer (`char *`) to store the resulting string.
- **Use**: This function is used to generate a string representation of a workspace global address, which includes the workspace name and the address, for logging or debugging purposes.


---
### fd\_wksp\_cstr\_laddr
- **Type**: `function`
- **Description**: The `fd_wksp_cstr_laddr` function is a utility function that converts a local address within a workspace to a C-style string representation. It takes a local address (`laddr`) and a character buffer (`cstr`) as inputs and returns a pointer to the character buffer containing the string representation of the address.
- **Use**: This function is used to generate a string representation of a local address within a workspace for logging or debugging purposes.


---
### fd\_wksp\_cstr\_alloc
- **Type**: `function pointer`
- **Description**: `fd_wksp_cstr_alloc` is a function that allocates memory from a workspace identified by a name, with specified alignment and size, and returns a C-style string representation of the allocation's global address. The function takes parameters for the workspace name, alignment, size, a tag for the allocation, and a character buffer to store the resulting string.
- **Use**: This function is used to allocate memory from a named workspace and obtain a string representation of the allocation's global address for further operations.


---
### fd\_wksp\_map
- **Type**: `function pointer`
- **Description**: `fd_wksp_map` is a function that takes a constant character pointer `cstr` as an argument and returns a void pointer. This function is part of the workspace management API, which is designed for NUMA-aware and TLB-efficient shared memory communication.
- **Use**: This function is used to map a workspace allocation specified by a string containing the workspace name and global address into the caller's local address space.


---
### fd\_wksp\_pod\_attach
- **Type**: `uchar const *`
- **Description**: The `fd_wksp_pod_attach` function returns a pointer to an unsigned character constant, which is used to attach to a workspace pod. This function is part of a set of APIs designed for managing shared memory workspaces, particularly in NUMA-aware and TLB-efficient environments.
- **Use**: This variable is used to obtain a constant pointer to a workspace pod, facilitating operations on shared memory regions.


---
### fd\_wksp\_pod\_map
- **Type**: `function pointer`
- **Description**: `fd_wksp_pod_map` is a function that maps a workspace pod to a local address space based on a given path. It is part of the workspace management API, which facilitates shared memory communication patterns.
- **Use**: This function is used to map a specific path within a workspace pod to a local address space, enabling access to shared memory resources.


# Data Structures

---
### fd\_wksp\_t
- **Type**: `typedef struct fd_wksp_private fd_wksp_t;`
- **Description**: The `fd_wksp_t` is an opaque data structure representing a workspace used for NUMA-aware and TLB-efficient shared memory communication between threads and processes. It is designed to manage memory allocations in a way that minimizes fragmentation and overhead, while providing mechanisms for robust metadata integrity and recovery from partial operations. The structure is used in conjunction with various APIs to allocate, free, and manage memory in a shared workspace environment, supporting operations like attaching, detaching, and querying memory allocations.


---
### fd\_wksp\_usage
- **Type**: `struct`
- **Members**:
    - `total_max`: The maximum number of partitions the workspace can have.
    - `total_cnt`: The current number of partitions in the workspace.
    - `total_sz`: The total size in bytes available for partitioning in the workspace.
    - `free_cnt`: The number of free partitions currently available in the workspace.
    - `free_sz`: The total size in bytes of the free partitions in the workspace.
    - `used_cnt`: The number of partitions currently in use in the workspace.
    - `used_sz`: The total size in bytes of the partitions currently in use in the workspace.
- **Description**: The `fd_wksp_usage` structure is used to track and report the usage statistics of a workspace. It provides information on the total capacity of the workspace in terms of partitions and size, as well as the current state of free and used partitions. This structure is essential for managing and optimizing memory allocation within a workspace, allowing for efficient tracking of available and utilized resources.


---
### fd\_wksp\_usage\_t
- **Type**: `struct`
- **Members**:
    - `total_max`: The maximum number of partitions the workspace can have.
    - `total_cnt`: The current number of partitions in the workspace.
    - `total_sz`: The total size in bytes available for partitioning in the workspace.
    - `free_cnt`: The number of free partitions currently available in the workspace.
    - `free_sz`: The total size in bytes of the free partitions in the workspace.
    - `used_cnt`: The number of partitions currently in use in the workspace.
    - `used_sz`: The total size in bytes of the used partitions in the workspace.
- **Description**: The `fd_wksp_usage_t` structure is designed to provide detailed statistics about the usage of a workspace, including the total capacity, current usage, and available free space. It helps in monitoring and managing the memory allocations within a workspace by keeping track of the number and size of both used and free partitions. This structure is essential for understanding the allocation dynamics and optimizing the memory usage in NUMA-aware and TLB-efficient shared memory environments.


---
### fd\_wksp\_tag\_query\_info
- **Type**: `struct`
- **Members**:
    - `gaddr_lo`: Partition covers workspace global addresses [gaddr_lo,gaddr_hi).
    - `gaddr_hi`: 0<gaddr_lo<gaddr_hi.
    - `tag`: Partition tag.
- **Description**: The `fd_wksp_tag_query_info` structure is used to store information about a specific partition within a workspace, including the range of global addresses it covers (`gaddr_lo` to `gaddr_hi`) and an associated tag (`tag`). This structure is typically used in querying operations to identify and manage partitions based on their tags within a workspace, facilitating operations like allocation tracking and memory management in shared memory environments.


---
### fd\_wksp\_tag\_query\_info\_t
- **Type**: `struct`
- **Members**:
    - `gaddr_lo`: Partition covers workspace global addresses starting from this address.
    - `gaddr_hi`: Partition covers workspace global addresses up to this address, exclusive.
    - `tag`: The tag associated with the partition.
- **Description**: The `fd_wksp_tag_query_info_t` structure is used to store information about a specific partition within a workspace, including the range of global addresses it covers and the tag associated with it. This structure is typically used in conjunction with functions that query or manipulate workspace partitions based on their tags, allowing for efficient management and retrieval of partition metadata.


---
### fd\_wksp\_preview
- **Type**: `struct`
- **Members**:
    - `style`: An integer representing the style of the workspace checkpoint.
    - `seed`: An unsigned integer used as a seed for heap priorities.
    - `part_max`: An unsigned long representing the maximum number of partitions.
    - `data_max`: An unsigned long representing the maximum size of the data region.
    - `name`: A character array holding the original workspace name as a C-style string.
- **Description**: The `fd_wksp_preview` structure is used to store metadata about a workspace checkpoint, including its style, seed, maximum partitions, maximum data size, and original name. This information is crucial for recreating or analyzing the workspace's configuration and state from a checkpoint file.


---
### fd\_wksp\_preview\_t
- **Type**: `typedef struct`
- **Members**:
    - `style`: An integer representing the checkpoint style used.
    - `seed`: An unsigned integer used as a seed for the workspace.
    - `part_max`: An unsigned long indicating the maximum number of partitions.
    - `data_max`: An unsigned long indicating the maximum size of the data region.
    - `name`: A character array holding the original workspace name.
- **Description**: The `fd_wksp_preview_t` structure is used to store metadata about a workspace checkpoint, including the style of the checkpoint, a seed value, the maximum number of partitions, the maximum data size, and the original name of the workspace. This structure is typically used to preview or recreate a workspace with the same parameters as a previously saved checkpoint.


# Functions

---
### fd\_wksp\_gaddr\_fast<!-- {{#callable:fd_wksp_gaddr_fast}} -->
The `fd_wksp_gaddr_fast` function quickly converts a local address within a workspace to its corresponding global address.
- **Inputs**:
    - `wksp`: A pointer to a `fd_wksp_t` structure representing the workspace.
    - `laddr`: A constant pointer to a local address within the workspace.
- **Control Flow**:
    - The function takes two arguments: a workspace pointer `wksp` and a local address `laddr`.
    - It calculates the global address by subtracting the base address of the workspace (`wksp`) from the local address (`laddr`).
    - The result is cast to an `ulong` and returned as the global address.
- **Output**: The function returns an `ulong` representing the global address corresponding to the given local address within the workspace.


---
### fd\_wksp\_laddr\_fast<!-- {{#callable:fd_wksp_laddr_fast}} -->
The `fd_wksp_laddr_fast` function quickly converts a global address to a local address within a workspace.
- **Inputs**:
    - `wksp`: A pointer to a constant `fd_wksp_t` structure representing the workspace.
    - `gaddr`: An unsigned long integer representing the global address to be converted.
- **Control Flow**:
    - The function takes a workspace pointer and a global address as inputs.
    - It casts the workspace pointer to an unsigned long integer and adds the global address to it.
    - The result is cast back to a void pointer, representing the local address.
- **Output**: The function returns a void pointer representing the local address corresponding to the given global address within the workspace.


---
### fd\_wksp\_alloc<!-- {{#callable:fd_wksp_alloc}} -->
The `fd_wksp_alloc` function allocates memory from a workspace with specified alignment, size, and tag, returning the global address of the allocation.
- **Inputs**:
    - `wksp`: A pointer to the `fd_wksp_t` workspace from which memory is to be allocated.
    - `align`: The alignment requirement for the allocation, which must be a non-negative power of two or zero to use the default alignment.
    - `sz`: The size of the memory to allocate in bytes.
    - `tag`: A positive value used to tag the allocation for identification purposes.
- **Control Flow**:
    - The function initializes a dummy array of two `ulong` elements to store the range of the allocated memory.
    - It calls [`fd_wksp_alloc_at_least`](fd_wksp_user.c.driver.md#fd_wksp_alloc_at_least) with the workspace, alignment, size, tag, and the dummy array to perform the actual allocation.
    - The result of [`fd_wksp_alloc_at_least`](fd_wksp_user.c.driver.md#fd_wksp_alloc_at_least), which is the global address of the allocated memory, is returned.
- **Output**: The function returns the global address of the allocated memory on success, or 0UL on failure.
- **Functions called**:
    - [`fd_wksp_alloc_at_least`](fd_wksp_user.c.driver.md#fd_wksp_alloc_at_least)


---
### fd\_wksp\_new\_anonymous<!-- {{#callable:fd_wksp_new_anonymous}} -->
The `fd_wksp_new_anonymous` function creates a new anonymous workspace with specified parameters and returns a pointer to it.
- **Inputs**:
    - `page_sz`: The size of each page in the workspace, specified as an unsigned long integer.
    - `page_cnt`: The number of pages to allocate in the workspace, specified as an unsigned long integer.
    - `cpu_idx`: The index of the CPU to associate with the workspace, specified as an unsigned long integer.
    - `name`: A constant character pointer representing the name of the workspace.
    - `opt_part_max`: An optional maximum number of partitions for the workspace, specified as an unsigned long integer.
- **Control Flow**:
    - The function calls [`fd_wksp_new_anon`](fd_wksp_helper.c.driver.md#fd_wksp_new_anon) with the provided `name`, `page_sz`, a fixed sub-count of 1, pointers to `page_cnt` and `cpu_idx`, a seed value of 0, and `opt_part_max`.
    - The result of [`fd_wksp_new_anon`](fd_wksp_helper.c.driver.md#fd_wksp_new_anon) is returned directly.
- **Output**: Returns a pointer to the newly created anonymous workspace (`fd_wksp_t *`) or NULL on failure.
- **Functions called**:
    - [`fd_wksp_new_anon`](fd_wksp_helper.c.driver.md#fd_wksp_new_anon)


---
### fd\_wksp\_delete\_anonymous<!-- {{#callable:fd_wksp_delete_anonymous}} -->
The `fd_wksp_delete_anonymous` function deletes an anonymous workspace by calling [`fd_wksp_delete_anon`](fd_wksp_helper.c.driver.md#fd_wksp_delete_anon) with the given workspace pointer.
- **Inputs**:
    - `wksp`: A pointer to the `fd_wksp_t` structure representing the anonymous workspace to be deleted.
- **Control Flow**:
    - The function is a simple inline function that directly calls [`fd_wksp_delete_anon`](fd_wksp_helper.c.driver.md#fd_wksp_delete_anon) with the provided `wksp` argument.
    - There is no additional logic or branching; it simply delegates the deletion task to [`fd_wksp_delete_anon`](fd_wksp_helper.c.driver.md#fd_wksp_delete_anon).
- **Output**: The function does not return any value; it performs the deletion operation on the provided workspace.
- **Functions called**:
    - [`fd_wksp_delete_anon`](fd_wksp_helper.c.driver.md#fd_wksp_delete_anon)


---
### fd\_wksp\_checkpt<!-- {{#callable:fd_wksp_checkpt}} -->
The `fd_wksp_checkpt` function creates a checkpoint of a workspace's state by writing it to a file.
- **Inputs**:
    - `wksp`: A pointer to the `fd_wksp_t` structure representing the workspace to be checkpointed.
    - `path`: A constant character pointer representing the file path where the checkpoint will be saved.
    - `mode`: An unsigned long integer specifying the file permissions for the checkpoint file.
    - `style`: An integer indicating the checkpoint style, which should be one of the `FD_WKSP_CHECKPT_STYLE_*` values or 0 for default.
    - `uinfo`: A constant character pointer to a user information string, which can be NULL or a string up to 16384 bytes long.
- **Control Flow**:
    - The function calls [`fd_wksp_checkpt_tpool`](fd_wksp_io.c.driver.md#fd_wksp_checkpt_tpool) with a NULL thread pool, indicating a serial checkpoint operation.
    - It passes the workspace, path, mode, style, and user information to [`fd_wksp_checkpt_tpool`](fd_wksp_io.c.driver.md#fd_wksp_checkpt_tpool).
    - The function returns the result of the [`fd_wksp_checkpt_tpool`](fd_wksp_io.c.driver.md#fd_wksp_checkpt_tpool) call, which indicates success or failure.
- **Output**: The function returns an integer indicating success (0) or failure (negative error code) of the checkpoint operation.
- **Functions called**:
    - [`fd_wksp_checkpt_tpool`](fd_wksp_io.c.driver.md#fd_wksp_checkpt_tpool)


---
### fd\_wksp\_restore<!-- {{#callable:fd_wksp_restore}} -->
The `fd_wksp_restore` function restores a workspace from a checkpoint file using a specified seed.
- **Inputs**:
    - `wksp`: A pointer to the `fd_wksp_t` structure representing the workspace to be restored.
    - `path`: A constant character pointer to the path of the checkpoint file from which the workspace will be restored.
    - `seed`: An unsigned integer used as a seed for the restoration process.
- **Control Flow**:
    - The function calls [`fd_wksp_restore_tpool`](fd_wksp_io.c.driver.md#fd_wksp_restore_tpool) with a NULL thread pool, a single thread (0UL to 1UL), and the provided workspace, path, and seed.
    - The function returns the result of the [`fd_wksp_restore_tpool`](fd_wksp_io.c.driver.md#fd_wksp_restore_tpool) call.
- **Output**: The function returns an integer indicating success (0) or an error code (negative value) if the restoration fails.
- **Functions called**:
    - [`fd_wksp_restore_tpool`](fd_wksp_io.c.driver.md#fd_wksp_restore_tpool)


# Function Declarations (Public API)

---
### fd\_wksp\_part\_max\_est<!-- {{#callable_declaration:fd_wksp_part_max_est}} -->
Estimate the maximum number of partitions for a workspace.
- **Description**: This function estimates the maximum number of partitions that can fit within a given workspace footprint, assuming typical allocation sizes. It is useful for determining how to efficiently pack a workspace into a specified memory region. The function should be called with a valid footprint and typical size, and it returns zero if the footprint is too small, the typical size is zero, or if the typical size is too large to allow for any partitions.
- **Inputs**:
    - `footprint`: The total size in bytes of the workspace memory region. Must be a positive value and aligned to FD_WKSP_ALIGN. If zero, the function returns zero.
    - `sz_typical`: The typical size of allocations within the workspace. Must be a positive value. If zero or larger than the available space for partitions, the function returns zero.
- **Output**: Returns the estimated maximum number of partitions as a positive unsigned long integer, or zero if the estimation fails due to invalid input or constraints.
- **See also**: [`fd_wksp_part_max_est`](fd_wksp_admin.c.driver.md#fd_wksp_part_max_est)  (Implementation)


---
### fd\_wksp\_data\_max\_est<!-- {{#callable_declaration:fd_wksp_data_max_est}} -->
Estimates the maximum data region size for a workspace.
- **Description**: This function calculates an estimated maximum size for the data region of a workspace given a specific footprint and a maximum number of partitions. It is useful for determining how to efficiently pack a workspace within a known footprint. The function should be called with valid footprint and part_max values, as it returns 0 if the footprint is too small, part_max is 0, or if part_max exceeds implementation limits or results in a non-positive data region size.
- **Inputs**:
    - `footprint`: The total size in bytes of the workspace footprint. It must be aligned to FD_WKSP_ALIGN and should be large enough to accommodate the workspace structure. If it is zero or too small, the function returns 0.
    - `part_max`: The maximum number of partitions the workspace can have. It must be a positive value and not exceed FD_WKSP_PRIVATE_PINFO_IDX_NULL or other internal limits. If it is zero or too large, the function returns 0.
- **Output**: Returns the estimated maximum size of the data region in bytes, or 0 if the input parameters are invalid or result in an unusable configuration.
- **See also**: [`fd_wksp_data_max_est`](fd_wksp_admin.c.driver.md#fd_wksp_data_max_est)  (Implementation)


---
### fd\_wksp\_align<!-- {{#callable_declaration:fd_wksp_align}} -->
Return the required alignment for a workspace.
- **Description**: This function provides the alignment requirement for a workspace, which is a constant value defined by the system. It is useful when setting up or configuring workspaces to ensure that memory allocations adhere to the necessary alignment constraints. This function can be called at any time and does not depend on any prior initialization or state.
- **Inputs**: None
- **Output**: Returns the alignment requirement as an unsigned long integer, which is a positive power of two.
- **See also**: [`fd_wksp_align`](fd_wksp_admin.c.driver.md#fd_wksp_align)  (Implementation)


---
### fd\_wksp\_footprint<!-- {{#callable_declaration:fd_wksp_footprint}} -->
Calculates the memory footprint required for a workspace.
- **Description**: This function computes the memory footprint needed for a workspace that can support a specified maximum number of partitions and a data region of a given size. It should be used when planning memory allocation for a workspace to ensure that the required memory does not exceed system limits. The function returns zero if the input parameters are invalid, such as when either parameter is zero or when the calculated footprint would exceed ULONG_MAX.
- **Inputs**:
    - `part_max`: The maximum number of partitions the workspace should support. Must be greater than zero and not exceed FD_WKSP_PRIVATE_PINFO_IDX_NULL. If invalid, the function returns zero.
    - `data_max`: The size of the data region in bytes. Must be greater than zero. If invalid, the function returns zero.
- **Output**: Returns the calculated memory footprint in bytes, or zero if the inputs are invalid or the footprint calculation would overflow.
- **See also**: [`fd_wksp_footprint`](fd_wksp_admin.c.driver.md#fd_wksp_footprint)  (Implementation)


---
### fd\_wksp\_new<!-- {{#callable_declaration:fd_wksp_new}} -->
Formats a memory region as a workspace with specified parameters.
- **Description**: This function initializes a memory region, pointed to by `shmem`, as a workspace with a given name, seed, and maximum partition and data sizes. It should be used when setting up a new workspace in a shared memory region. The memory region must be properly aligned and have sufficient size to accommodate the workspace's footprint. The function returns a pointer to the initialized workspace on success or NULL if any preconditions are not met, such as invalid alignment, name, or size parameters.
- **Inputs**:
    - `shmem`: A pointer to the memory region to be formatted as a workspace. Must not be null and must be aligned to FD_WKSP_ALIGN.
    - `name`: A string representing the name of the workspace. Must be a valid non-empty string.
    - `seed`: An unsigned integer used to seed the workspace's internal operations.
    - `part_max`: The maximum number of partitions the workspace can support. Must be greater than zero.
    - `data_max`: The maximum size of the data region in bytes. Must be greater than zero.
- **Output**: Returns a pointer to the initialized workspace on success, or NULL on failure.
- **See also**: [`fd_wksp_new`](fd_wksp_admin.c.driver.md#fd_wksp_new)  (Implementation)


---
### fd\_wksp\_join<!-- {{#callable_declaration:fd_wksp_join}} -->
Joins a workspace mapped into the caller's address space.
- **Description**: This function is used to join a workspace that has been mapped into the caller's address space, allowing the caller to read and write memory within the workspace. It should be called when a workspace is already mapped and the caller needs to interact with it. The function returns a local handle to the workspace on success, or NULL if the workspace is invalid, improperly aligned, or corrupted. It is important to ensure that the workspace is correctly aligned and initialized before calling this function.
- **Inputs**:
    - `shwksp`: A pointer to the location where the workspace is mapped in the caller's address space. Must not be null, must be aligned to FD_WKSP_ALIGN, and must have a valid magic number. If these conditions are not met, the function returns NULL and logs a warning.
- **Output**: Returns a pointer to the local handle of the workspace on success, or NULL on failure.
- **See also**: [`fd_wksp_join`](fd_wksp_admin.c.driver.md#fd_wksp_join)  (Implementation)


---
### fd\_wksp\_leave<!-- {{#callable_declaration:fd_wksp_leave}} -->
Leaves a workspace and returns its shared memory pointer.
- **Description**: Use this function to leave a workspace when it is no longer needed by the caller. This function should be called after all necessary operations on the workspace have been completed. It is important to note that the workspace will continue to exist, but the caller should not access it after leaving. This function returns the shared memory pointer on success, allowing the caller to manage the memory if needed. If the workspace pointer is null, the function logs a warning and returns null.
- **Inputs**:
    - `wksp`: A pointer to the workspace to leave. Must not be null. If null, the function logs a warning and returns null.
- **Output**: Returns the shared memory pointer of the workspace on success, or null if the input workspace pointer is null.
- **See also**: [`fd_wksp_leave`](fd_wksp_admin.c.driver.md#fd_wksp_leave)  (Implementation)


---
### fd\_wksp\_delete<!-- {{#callable_declaration:fd_wksp_delete}} -->
Unformats a memory region used as a workspace.
- **Description**: This function is used to delete a workspace by unformatting the memory region that was previously formatted as a workspace. It should be called when the workspace is no longer needed and there are no active joins to it. The function returns the original shared memory pointer on success, allowing for potential reuse or deallocation of the memory. If the input is invalid, such as a null pointer or a misaligned workspace, the function logs a warning and returns null.
- **Inputs**:
    - `shwksp`: A pointer to the shared memory region that was formatted as a workspace. It must not be null, must be properly aligned, and must have a valid workspace magic number. If these conditions are not met, the function logs a warning and returns null.
- **Output**: Returns the original shared memory pointer on success, or null if the input is invalid.
- **See also**: [`fd_wksp_delete`](fd_wksp_admin.c.driver.md#fd_wksp_delete)  (Implementation)


---
### fd\_wksp\_name<!-- {{#callable_declaration:fd_wksp_name}} -->
Returns the name of the workspace.
- **Description**: This function provides access to the name of a workspace, which is a constant string representing the workspace's identifier. It is useful for retrieving the workspace's name for logging, debugging, or display purposes. The function assumes that the workspace pointer provided is valid and that the workspace is currently joined. The returned string is valid for the lifetime of the join and should not be modified by the caller.
- **Inputs**:
    - `wksp`: A pointer to a constant fd_wksp_t structure representing the workspace. It must not be null and should point to a valid, currently joined workspace. If the pointer is invalid, the behavior is undefined.
- **Output**: A constant character pointer to the workspace's name string. The string is valid for the duration of the join and should not be altered.
- **See also**: [`fd_wksp_name`](fd_wksp_admin.c.driver.md#fd_wksp_name)  (Implementation)


---
### fd\_wksp\_seed<!-- {{#callable_declaration:fd_wksp_seed}} -->
Retrieve the seed value of a workspace.
- **Description**: Use this function to obtain the seed value that was used during the creation or most recent rebuild of a workspace. This function is useful when you need to verify or utilize the seed for operations that depend on the initial configuration of the workspace. It is important to ensure that the workspace is currently joined locally before calling this function.
- **Inputs**:
    - `wksp`: A pointer to a constant fd_wksp_t structure representing the workspace. The workspace must be a current local join, and the pointer must not be null.
- **Output**: Returns the seed value as an unsigned integer, which was used at the workspace's creation or most recent rebuild.
- **See also**: [`fd_wksp_seed`](fd_wksp_admin.c.driver.md#fd_wksp_seed)  (Implementation)


---
### fd\_wksp\_part\_max<!-- {{#callable_declaration:fd_wksp_part_max}} -->
Retrieve the maximum number of partitions for a workspace.
- **Description**: Use this function to obtain the maximum number of partitions that a workspace can support. This function is useful when you need to understand the partitioning capabilities of a workspace that you have joined. It is important to ensure that the workspace is a valid and current local join before calling this function.
- **Inputs**:
    - `wksp`: A pointer to a constant fd_wksp_t structure representing the workspace. This must be a valid and current local join. If the workspace is not valid, the behavior is undefined.
- **Output**: Returns the maximum number of partitions (part_max) that the workspace can support as an unsigned long integer.
- **See also**: [`fd_wksp_part_max`](fd_wksp_admin.c.driver.md#fd_wksp_part_max)  (Implementation)


---
### fd\_wksp\_data\_max<!-- {{#callable_declaration:fd_wksp_data_max}} -->
Retrieve the maximum data region size of a workspace.
- **Description**: Use this function to obtain the maximum size of the data region for a given workspace. This is useful for understanding the capacity of the workspace's data storage. The function should be called only when the workspace is properly initialized and joined. It does not modify the workspace or any of its properties.
- **Inputs**:
    - `wksp`: A pointer to a constant fd_wksp_t structure representing the workspace. It must not be null and should point to a valid, currently joined workspace.
- **Output**: Returns the maximum size of the data region in the workspace as an unsigned long integer.
- **See also**: [`fd_wksp_data_max`](fd_wksp_admin.c.driver.md#fd_wksp_data_max)  (Implementation)


---
### fd\_wksp\_owner<!-- {{#callable_declaration:fd_wksp_owner}} -->
Returns the current owner ID of a workspace operation.
- **Description**: Use this function to determine the ID of the thread group currently performing an operation on the workspace. It should be called when the workspace is in a valid local join state. The function provides a snapshot of the owner at a specific point in time, which may change immediately after the call. This is useful for debugging or monitoring purposes to check which thread group is interacting with the workspace.
- **Inputs**:
    - `wksp`: A pointer to a valid fd_wksp_t structure representing the workspace. It must not be null and should be a current local join.
- **Output**: Returns the ID of the thread group currently operating on the workspace, 0 if the workspace is being constructed, or ULONG_MAX if no operation is in progress.
- **See also**: [`fd_wksp_owner`](fd_wksp_admin.c.driver.md#fd_wksp_owner)  (Implementation)


---
### fd\_wksp\_strerror<!-- {{#callable_declaration:fd_wksp_strerror}} -->
Converts an error code to a human-readable string.
- **Description**: Use this function to obtain a human-readable description of an error code returned by other fd_wksp functions. This can be useful for logging or debugging purposes. The function will return a string corresponding to the error code if it is recognized, or "unknown" if the error code is not recognized. The returned string is a constant and should not be modified.
- **Inputs**:
    - `err`: An integer representing the error code to be converted. Valid values are FD_WKSP_SUCCESS, FD_WKSP_ERR_INVAL, FD_WKSP_ERR_FAIL, and FD_WKSP_ERR_CORRUPT. Any other value will result in the string "unknown" being returned.
- **Output**: A constant string describing the error code. The string is always non-NULL and has an infinite lifetime.
- **See also**: [`fd_wksp_strerror`](fd_wksp_admin.c.driver.md#fd_wksp_strerror)  (Implementation)


---
### fd\_wksp\_verify<!-- {{#callable_declaration:fd_wksp_verify}} -->
Verifies the integrity of a workspace.
- **Description**: Use this function to perform an extensive verification of a workspace to ensure its integrity. It checks the workspace's metadata, idle stack, partitioning, and treap structures for any inconsistencies or corruption. This function should be called when there is suspicion of corruption, such as when a process may have terminated unexpectedly during a workspace operation. It is important to ensure that no concurrent operations are being performed on the workspace while this function is executing.
- **Inputs**:
    - `wksp`: A pointer to a fd_wksp_t structure representing the workspace to verify. Must not be null and should be a current local join to a workspace. If invalid, the function will return an error code.
- **Output**: Returns FD_WKSP_SUCCESS (0) if the workspace is verified successfully without issues, or FD_WKSP_ERR_CORRUPT (-3) if corruption is detected.
- **See also**: [`fd_wksp_verify`](fd_wksp_admin.c.driver.md#fd_wksp_verify)  (Implementation)


---
### fd\_wksp\_rebuild<!-- {{#callable_declaration:fd_wksp_rebuild}} -->
Rebuilds a workspace to restore consistency after a failure.
- **Description**: Use this function to rebuild a workspace when it is detected that a previous operation left the workspace in an inconsistent state, such as when a process was terminated unexpectedly during an allocation or free operation. This function attempts to restore the workspace to a consistent state without affecting completed allocations. It should be called when no other operations are being performed on the workspace to ensure thread safety. The function returns a success code if the rebuild is successful or an error code if it fails due to corruption or overlapping allocations.
- **Inputs**:
    - `wksp`: A pointer to the workspace to be rebuilt. Must not be null. If null, the function returns an error code indicating corruption.
    - `seed`: An unsigned integer used to seed the rebuilding process. It helps in randomizing certain internal structures to prevent predictable patterns.
- **Output**: Returns FD_WKSP_SUCCESS (0) if the workspace was rebuilt successfully, or FD_WKSP_ERR_CORRUPT (-3) if the rebuild failed due to corruption or overlapping allocations.
- **See also**: [`fd_wksp_rebuild`](fd_wksp_admin.c.driver.md#fd_wksp_rebuild)  (Implementation)


---
### fd\_wksp\_laddr<!-- {{#callable_declaration:fd_wksp_laddr}} -->
Maps a workspace global address to a local address.
- **Description**: This function is used to convert a global address within a workspace to a local address in the caller's address space. It should be called when you need to access memory allocated in a workspace using a global address. The function requires that the workspace is currently joined locally. If the workspace pointer is null or the global address is invalid or zero, the function will return null and log a warning.
- **Inputs**:
    - `wksp`: A pointer to a valid fd_wksp_t workspace structure. Must not be null, as a null value will result in a null return and a warning log.
    - `gaddr`: An unsigned long representing the global address within the workspace. Must be within the valid range of global addresses for the workspace; otherwise, the function returns null and logs a warning. A value of zero will also result in a null return.
- **Output**: Returns a pointer to the local address corresponding to the given global address, or null if the input is invalid.
- **See also**: [`fd_wksp_laddr`](fd_wksp_user.c.driver.md#fd_wksp_laddr)  (Implementation)


---
### fd\_wksp\_gaddr<!-- {{#callable_declaration:fd_wksp_gaddr}} -->
Maps a workspace local address to a global address.
- **Description**: Use this function to convert a local address within a workspace to its corresponding global address, which is consistent across all joiners of the workspace. This function should be called when you need to share or store an address that can be universally understood by all processes or threads using the workspace. Ensure that the workspace is a valid current local join before calling this function. If the local address is invalid or out of the workspace's bounds, the function will return 0UL, indicating an error.
- **Inputs**:
    - `wksp`: A pointer to a valid fd_wksp_t workspace. Must not be null. If null, the function returns 0UL.
    - `laddr`: A pointer to a local address within the workspace. Can be null, in which case the function returns 0UL. If the address is invalid or out of bounds, the function also returns 0UL.
- **Output**: Returns the global address corresponding to the local address if valid, or 0UL if the input is invalid or out of bounds.
- **See also**: [`fd_wksp_gaddr`](fd_wksp_user.c.driver.md#fd_wksp_gaddr)  (Implementation)


---
### fd\_wksp\_alloc\_at\_least<!-- {{#callable_declaration:fd_wksp_alloc_at_least}} -->
Allocates at least a specified size from a workspace with alignment and tagging.
- **Description**: This function attempts to allocate at least 'sz' bytes from the specified workspace 'wksp', ensuring the allocation is aligned to 'align' bytes and tagged with 'tag'. It returns the global address of the allocated memory on success, or 0UL on failure. The function also updates the provided pointers '_lo' and '_hi' with the actual range of the allocated memory. The alignment must be a power of two or zero (indicating default alignment), and the tag must be a positive value. The workspace must be a valid, non-null pointer, and the size must be non-zero. This function is useful for applications that require specific alignment and tagging of memory allocations within a shared workspace.
- **Inputs**:
    - `wksp`: A pointer to the workspace from which to allocate memory. Must not be null.
    - `align`: The alignment for the allocation in bytes. Must be a power of two or zero (for default alignment).
    - `sz`: The minimum size of the allocation in bytes. Must be greater than zero.
    - `tag`: A positive value used to tag the allocation. Must be non-zero.
    - `_lo`: A pointer to a ulong where the lower bound of the allocated range will be stored. Must not be null.
    - `_hi`: A pointer to a ulong where the upper bound of the allocated range will be stored. Must not be null.
- **Output**: Returns the global address of the allocated memory on success, or 0UL on failure. Updates *_lo and *_hi with the allocated range.
- **See also**: [`fd_wksp_alloc_at_least`](fd_wksp_user.c.driver.md#fd_wksp_alloc_at_least)  (Implementation)


---
### fd\_wksp\_free<!-- {{#callable_declaration:fd_wksp_free}} -->
Frees a workspace allocation.
- **Description**: Use this function to free a previously allocated memory block in a workspace. It should be called with a valid workspace handle and a global address pointing to any byte within the allocated block. The function will silently return if the global address is zero, indicating no operation is needed. It is important to ensure that the workspace handle is not null before calling this function, as a null handle will result in a warning and no operation will be performed. This function can be called by any joiner of the workspace, regardless of who made the allocation.
- **Inputs**:
    - `wksp`: A pointer to the workspace from which the allocation was made. Must not be null, as a null value will result in a warning and no operation will be performed. The caller retains ownership.
    - `gaddr`: A global address pointing to any byte within the allocation to be freed. If this is zero, the function will return immediately without performing any operation.
- **Output**: None
- **See also**: [`fd_wksp_free`](fd_wksp_user.c.driver.md#fd_wksp_free)  (Implementation)


---
### fd\_wksp\_tag<!-- {{#callable_declaration:fd_wksp_tag}} -->
Returns the tag associated with a workspace allocation.
- **Description**: Use this function to retrieve the tag associated with a specific allocation in a workspace. It is useful for identifying or categorizing allocations. The function should be called with a valid workspace handle and a global address pointing to any byte within the allocation. If the workspace is null or the global address does not correspond to a valid allocation, the function will return 0, indicating no tag is associated. This function is silent and does not log errors, making it suitable for use in analysis tools.
- **Inputs**:
    - `wksp`: A pointer to a valid fd_wksp_t workspace. Must not be null, as a null value will result in a return value of 0.
    - `gaddr`: A global address within the workspace that points to any byte in the allocation. If it does not point to a valid allocation, the function will return 0.
- **Output**: Returns the tag associated with the allocation if successful, or 0 if the workspace is null or the global address is invalid.
- **See also**: [`fd_wksp_tag`](fd_wksp_user.c.driver.md#fd_wksp_tag)  (Implementation)


---
### fd\_wksp\_tag\_query<!-- {{#callable_declaration:fd_wksp_tag_query}} -->
Queries the workspace for partitions matching specified tags.
- **Description**: Use this function to find and retrieve information about workspace partitions that have specific tags. It is useful for applications that need to manage or analyze memory allocations based on their tags. The function requires a valid workspace and a non-null tag array. If no tags are provided, the function returns immediately with zero. The function can optionally populate an array with detailed information about the matching partitions, up to a specified maximum number of entries. It returns the total number of matching partitions found.
- **Inputs**:
    - `wksp`: A pointer to a valid fd_wksp_t workspace. Must not be null. If null, the function logs a warning and returns zero.
    - `tag`: A pointer to an array of tags to query. Must not be null. If null, the function logs a warning and returns zero.
    - `tag_cnt`: The number of tags in the tag array. If zero, the function returns immediately with zero.
    - `info`: A pointer to an array of fd_wksp_tag_query_info_t structures to be filled with information about matching partitions. Can be null if info_max is zero. If info_max is non-zero and info is null, the function logs a warning and returns zero.
    - `info_max`: The maximum number of entries to fill in the info array. If zero, no information is written to the info array.
- **Output**: Returns the number of partitions that match any of the specified tags. If no partitions match or if any input is invalid, returns zero.
- **See also**: [`fd_wksp_tag_query`](fd_wksp_user.c.driver.md#fd_wksp_tag_query)  (Implementation)


---
### fd\_wksp\_tag\_free<!-- {{#callable_declaration:fd_wksp_tag_free}} -->
Frees all allocations in a workspace that match specified tags.
- **Description**: Use this function to free all memory allocations in a workspace that are associated with any of the specified tags. This is useful for batch deallocation of resources tagged for specific purposes. The function should be called when you want to release multiple tagged allocations at once. It is important to ensure that the workspace (`wksp`) and the tag array (`tag`) are valid and not null before calling this function. If `tag_cnt` is zero, the function will return immediately without performing any operations. The function logs warnings if the workspace or tag array is null, or if any other issues are detected during execution.
- **Inputs**:
    - `wksp`: A pointer to the workspace from which allocations will be freed. Must not be null. If null, a warning is logged and the function returns without freeing any allocations.
    - `tag`: A pointer to an array of tags. Each tag in the array is used to identify allocations to be freed. Must not be null. If null, a warning is logged and the function returns without freeing any allocations.
    - `tag_cnt`: The number of tags in the `tag` array. If zero, the function returns immediately without freeing any allocations.
- **Output**: None
- **See also**: [`fd_wksp_tag_free`](fd_wksp_user.c.driver.md#fd_wksp_tag_free)  (Implementation)


---
### fd\_wksp\_memset<!-- {{#callable_declaration:fd_wksp_memset}} -->
Sets all bytes in a workspace allocation to a specified character.
- **Description**: This function is used to fill an entire memory allocation within a workspace with a specified character. It should be called when you need to initialize or reset the memory content of an allocation to a uniform value. The function requires a valid workspace pointer and a global address pointing to any byte within the allocation. If the workspace pointer is null or the global address does not correspond to a current allocation, the function logs a warning and returns without making any changes. This function is atomic with respect to other operations on the workspace, ensuring thread safety.
- **Inputs**:
    - `wksp`: A pointer to a valid fd_wksp_t workspace. Must not be null. If null, the function logs a warning and returns without performing any operation.
    - `gaddr`: A global address pointing to any byte within the allocation to be set. Must correspond to a current allocation in the workspace. If it does not, the function logs a warning and returns without performing any operation.
    - `c`: The character to set each byte of the allocation to. Any valid integer value is accepted, and it is cast to an unsigned char.
- **Output**: None
- **See also**: [`fd_wksp_memset`](fd_wksp_user.c.driver.md#fd_wksp_memset)  (Implementation)


---
### fd\_wksp\_reset<!-- {{#callable_declaration:fd_wksp_reset}} -->
Frees all allocations in the specified workspace.
- **Description**: Use this function to clear all allocations from a workspace, effectively resetting it to an empty state. This is useful when you want to reuse the workspace without retaining any previous allocations. Ensure that no allocations are in use before calling this function, as it will invalidate all existing allocations. The function logs a warning if the workspace is detected to be corrupt. It must be called with a valid workspace pointer, and it is the caller's responsibility to handle any potential warnings or errors logged during the operation.
- **Inputs**:
    - `wksp`: A pointer to the workspace to be reset. Must not be null. If null, a warning is logged and the function returns without performing any action.
    - `seed`: An unsigned integer used to seed the workspace's internal structures. This can be used to change the internal state of the workspace, potentially affecting allocation patterns.
- **Output**: None
- **See also**: [`fd_wksp_reset`](fd_wksp_user.c.driver.md#fd_wksp_reset)  (Implementation)


---
### fd\_wksp\_new\_named<!-- {{#callable_declaration:fd_wksp_new_named}} -->
Creates a shared memory region and formats it as a workspace.
- **Description**: This function is used to create a new shared memory region with a specified name and format it as a workspace for inter-thread and inter-process communication. It is essential to ensure that the `name` is valid and that the `page_sz` is supported. The function requires a non-zero `sub_cnt` and valid pointers for `sub_page_cnt` and `sub_cpu_idx`. The `mode` parameter specifies the permissions for the shared memory region. The function returns a success code if the operation is successful or an error code if it fails due to invalid inputs or shared memory limitations.
- **Inputs**:
    - `name`: A string representing the name of the shared memory region. It must be a valid name and not empty.
    - `page_sz`: The size of each page in the shared memory region. It must be a supported page size.
    - `sub_cnt`: The number of subregions to create. It must be greater than zero.
    - `sub_page_cnt`: A pointer to an array specifying the number of pages in each subregion. It must not be null.
    - `sub_cpu_idx`: A pointer to an array specifying the CPU indices for each subregion. It must not be null.
    - `mode`: Specifies the permissions for the shared memory region.
    - `seed`: An arbitrary value used to seed the heap priorities.
    - `part_max`: The maximum number of partitions. If zero, it will be estimated based on the footprint.
- **Output**: Returns FD_WKSP_SUCCESS (0) on success or an FD_WKSP_ERR_* (negative) on failure.
- **See also**: [`fd_wksp_new_named`](fd_wksp_helper.c.driver.md#fd_wksp_new_named)  (Implementation)


---
### fd\_wksp\_delete\_named<!-- {{#callable_declaration:fd_wksp_delete_named}} -->
Deletes a named workspace.
- **Description**: Use this function to delete a workspace that was previously created with fd_wksp_new_named. It is important to ensure that there are no active joins or attachments to the workspace when this function is called. This function will return a success code if the workspace is successfully deleted, or an error code if the operation fails. It is typically used when the workspace is no longer needed and resources should be freed.
- **Inputs**:
    - `name`: A pointer to a constant character string representing the name of the workspace to be deleted. The name must correspond to a valid, existing workspace. The caller retains ownership of the string, and it must not be null. If the name is invalid or the workspace cannot be deleted, the function will return an error code.
- **Output**: Returns FD_WKSP_SUCCESS (0) on successful deletion, or an FD_WKSP_ERR_* (negative) error code on failure.
- **See also**: [`fd_wksp_delete_named`](fd_wksp_helper.c.driver.md#fd_wksp_delete_named)  (Implementation)


---
### fd\_wksp\_new\_anon<!-- {{#callable_declaration:fd_wksp_new_anon}} -->
Creates a local anonymous workspace for shared memory operations.
- **Description**: This function is used to create a workspace that is local to the calling thread group, allowing for efficient shared memory operations with NUMA and TLB considerations. It should be used when a temporary, local workspace is needed without the need for a named shared memory region. The function requires valid input parameters and will return NULL if any parameter is invalid or if the workspace cannot be created. The workspace should be deleted using `fd_wksp_delete_anon` when no longer needed.
- **Inputs**:
    - `name`: A non-null, non-empty string representing the name of the workspace. It must be a valid shared memory name.
    - `page_sz`: The size of each memory page. Must be a supported page size.
    - `sub_cnt`: The number of subregions. Must be greater than zero.
    - `sub_page_cnt`: An array specifying the number of pages in each subregion. Must not be null.
    - `sub_cpu_idx`: An array specifying the CPU index for each subregion. Must not be null.
    - `seed`: An arbitrary value used to seed the workspace's internal structures.
    - `opt_part_max`: The maximum number of partitions. If zero, a default value is estimated based on the workspace size.
- **Output**: Returns a pointer to the newly created and joined workspace on success, or NULL on failure.
- **See also**: [`fd_wksp_new_anon`](fd_wksp_helper.c.driver.md#fd_wksp_new_anon)  (Implementation)


---
### fd\_wksp\_delete\_anon<!-- {{#callable_declaration:fd_wksp_delete_anon}} -->
Deletes an anonymous workspace.
- **Description**: Use this function to delete a workspace that was created anonymously using `fd_wksp_new_anon`. It should be called when the workspace is no longer needed and there are no other joins or attachments to it. This function ensures that the resources associated with the anonymous workspace are properly released. It is important to ensure that no other processes or threads are using the workspace when this function is called, as it will log details if any issues are detected during the deletion process.
- **Inputs**:
    - `wksp`: A pointer to the `fd_wksp_t` workspace to be deleted. This must be a valid workspace that was created using `fd_wksp_new_anon`. The caller must ensure that there are no other joins or attachments to this workspace before calling this function.
- **Output**: None
- **See also**: [`fd_wksp_delete_anon`](fd_wksp_helper.c.driver.md#fd_wksp_delete_anon)  (Implementation)


---
### fd\_wksp\_attach<!-- {{#callable_declaration:fd_wksp_attach}} -->
Attaches to a shared memory workspace by name.
- **Description**: Use this function to attach to a workspace that is held by a shared memory region identified by the given name. This is useful for accessing shared memory resources across different processes or threads. The function returns a handle to the workspace on success, which can be used for further operations. If the attachment fails, it returns NULL and logs the details of the failure. It is important to pair each successful call to this function with a corresponding call to detach from the workspace to avoid resource leaks.
- **Inputs**:
    - `name`: A non-null string representing the name of the shared memory region to attach to. The name should correspond to a valid shared memory region that has been previously created and formatted as a workspace. If the name is invalid or the workspace cannot be attached, the function will return NULL and log the error.
- **Output**: Returns a pointer to an fd_wksp_t structure representing the attached workspace on success, or NULL on failure.
- **See also**: [`fd_wksp_attach`](fd_wksp_helper.c.driver.md#fd_wksp_attach)  (Implementation)


---
### fd\_wksp\_detach<!-- {{#callable_declaration:fd_wksp_detach}} -->
Detaches from a given workspace.
- **Description**: Use this function to detach from a workspace that has been previously attached. It is important to ensure that all necessary operations on the workspace are completed before detaching, as the workspace will no longer be accessible in the caller's address space after this call. This function should be paired with a prior successful call to attach to the workspace. It logs details on failure and returns a non-zero value if the detachment is unsuccessful.
- **Inputs**:
    - `wksp`: A pointer to the fd_wksp_t workspace to detach from. Must not be null. If null, the function logs a warning and returns an error code.
- **Output**: Returns 0 on successful detachment, or a non-zero error code if the detachment fails.
- **See also**: [`fd_wksp_detach`](fd_wksp_helper.c.driver.md#fd_wksp_detach)  (Implementation)


---
### fd\_wksp\_containing<!-- {{#callable_declaration:fd_wksp_containing}} -->
Finds the workspace containing a given local address.
- **Description**: Use this function to determine which workspace a given local address belongs to. This is useful for verifying if a pointer is part of a workspace that has been joined locally. The function should be called with a valid local address that is expected to be part of a workspace. If the address is not part of any workspace, the function will return NULL. This function is silent and can be used to check if a pointer is from a workspace without logging any errors.
- **Inputs**:
    - `laddr`: A constant pointer to a local address. It must not be NULL, as passing a NULL value will result in a NULL return value. The address should be part of a workspace that has been joined locally.
- **Output**: Returns a pointer to the workspace (fd_wksp_t *) containing the given local address, or NULL if the address is not part of any locally joined workspace.
- **See also**: [`fd_wksp_containing`](fd_wksp_helper.c.driver.md#fd_wksp_containing)  (Implementation)


---
### fd\_wksp\_alloc\_laddr<!-- {{#callable_declaration:fd_wksp_alloc_laddr}} -->
Allocates memory from a workspace and returns a local address.
- **Description**: This function allocates a block of memory from the specified workspace with the given alignment and size, tagging the allocation with the provided tag. It returns a pointer to the allocated memory in the caller's local address space. If the allocation fails, it returns NULL. This function should be used when you need a local address for the allocated memory, and it assumes that the workspace is already joined and valid.
- **Inputs**:
    - `wksp`: A pointer to a valid fd_wksp_t workspace from which memory is to be allocated. The workspace must be a current local join and must not be NULL.
    - `align`: The alignment for the allocation, which must be a non-negative power of two or zero. If zero, the default alignment FD_WKSP_ALIGN_DEFAULT is used.
    - `sz`: The size of the memory block to allocate in bytes. If zero, the function will return NULL silently.
    - `tag`: A positive value used to tag the allocation for identification purposes. It is application-specific and can be used for debugging or analytics.
- **Output**: Returns a pointer to the allocated memory in the caller's local address space on success, or NULL if the allocation fails.
- **See also**: [`fd_wksp_alloc_laddr`](fd_wksp_helper.c.driver.md#fd_wksp_alloc_laddr)  (Implementation)


---
### fd\_wksp\_free\_laddr<!-- {{#callable_declaration:fd_wksp_free_laddr}} -->
Frees a workspace allocation using a local address.
- **Description**: Use this function to free a memory allocation in a workspace when you have a local address pointing to it. This function is useful when you do not have the global address of the allocation but have a pointer within the local address space of the workspace. It is important to ensure that the local address provided is valid and corresponds to an allocation within a workspace. If the local address is null or does not belong to a workspace, the function will return without performing any action.
- **Inputs**:
    - `laddr`: A pointer to the local address of the allocation to be freed. It must not be null and should point to a valid allocation within a workspace. If the address is invalid or null, the function will log a warning and return without freeing any memory.
- **Output**: None
- **See also**: [`fd_wksp_free_laddr`](fd_wksp_helper.c.driver.md#fd_wksp_free_laddr)  (Implementation)


---
### fd\_wksp\_cstr<!-- {{#callable_declaration:fd_wksp_cstr}} -->
Converts a workspace global address to a string representation.
- **Description**: Use this function to convert a global address within a workspace to a string format that includes the workspace name and the address. This is useful for logging or debugging purposes where a human-readable format is needed. The function requires a valid workspace pointer and a non-null character buffer to store the result. The global address must be within the valid range of the workspace's data region. If any of these conditions are not met, the function will return NULL and log a warning.
- **Inputs**:
    - `wksp`: A pointer to a valid fd_wksp_t workspace. Must not be null. If null, the function logs a warning and returns NULL.
    - `gaddr`: An unsigned long representing the global address within the workspace. Must be within the valid range of the workspace's data region or zero. If not, the function logs a warning and returns NULL.
    - `cstr`: A character buffer where the resulting string will be stored. Must not be null and should have space for FD_WKSP_CSTR_MAX bytes. If null, the function logs a warning and returns NULL.
- **Output**: Returns the cstr pointer on success, or NULL if any input is invalid.
- **See also**: [`fd_wksp_cstr`](fd_wksp_helper.c.driver.md#fd_wksp_cstr)  (Implementation)


---
### fd\_wksp\_cstr\_laddr<!-- {{#callable_declaration:fd_wksp_cstr_laddr}} -->
Converts a local workspace address to a string representation.
- **Description**: Use this function to obtain a string representation of a workspace global address from a local address within a workspace. This is useful for logging or debugging purposes where a human-readable format of the address is needed. The function requires a valid local address that belongs to a workspace and a non-null character buffer to store the resulting string. If the local address does not belong to a workspace or the character buffer is null, the function will return null and log a warning.
- **Inputs**:
    - `laddr`: A pointer to a local address within a workspace. It must be a valid address from a workspace; otherwise, the function will return null.
    - `cstr`: A character buffer where the resulting string representation will be stored. It must not be null, and it should have enough space to store the string. If null, the function will return null.
- **Output**: Returns the character buffer containing the string representation of the global address on success, or null if the input is invalid.
- **See also**: [`fd_wksp_cstr_laddr`](fd_wksp_helper.c.driver.md#fd_wksp_cstr_laddr)  (Implementation)


---
### fd\_wksp\_cstr\_alloc<!-- {{#callable_declaration:fd_wksp_cstr_alloc}} -->
Allocates memory from a workspace and returns a formatted string representation.
- **Description**: This function allocates a specified amount of memory from a workspace identified by its name, with a given alignment and tag, and returns a string representation of the allocation in the provided buffer. It is useful for obtaining a workspace allocation and its corresponding string identifier in one step, which can be used for later reference or deallocation. The function must be called with a non-null buffer for the string output, and the workspace name must be valid. If the allocation fails, the function returns NULL and logs the failure details.
- **Inputs**:
    - `name`: The name of the workspace from which to allocate memory. It must be a valid workspace name and cannot be null.
    - `align`: The alignment requirement for the allocation. It should be a power of two or zero, where zero indicates the default alignment.
    - `sz`: The size of the memory to allocate in bytes. If zero, the function will return NULL without logging.
    - `tag`: A tag associated with the allocation, used for tracking and management purposes. It should be a positive value.
    - `cstr`: A buffer to store the resulting string representation of the allocation. It must not be null and should have space for up to FD_WKSP_CSTR_MAX bytes.
- **Output**: Returns the cstr buffer containing the formatted string on success, or NULL on failure.
- **See also**: [`fd_wksp_cstr_alloc`](fd_wksp_helper.c.driver.md#fd_wksp_cstr_alloc)  (Implementation)


---
### fd\_wksp\_cstr\_free<!-- {{#callable_declaration:fd_wksp_cstr_free}} -->
Frees a workspace allocation specified by a cstr.
- **Description**: This function is used to free a memory allocation in a workspace that is specified by a cstr in the format '[name]:[gaddr]'. It is useful for managing memory in shared workspaces, especially when allocations are identified by a string representation. This function should be called when the memory associated with the cstr is no longer needed, to prevent memory leaks. It is efficient for single operations, but for multiple operations on the same workspace, it is recommended to attach to the workspace once, perform all operations, and then detach to improve performance.
- **Inputs**:
    - `cstr`: A constant character pointer representing the workspace and global address in the format '[name]:[gaddr]'. It must not be null, and it should correctly parse to a valid workspace name and global address. If parsing fails, the function will return without performing any operation.
- **Output**: None
- **See also**: [`fd_wksp_cstr_free`](fd_wksp_helper.c.driver.md#fd_wksp_cstr_free)  (Implementation)


---
### fd\_wksp\_cstr\_tag<!-- {{#callable_declaration:fd_wksp_cstr_tag}} -->
Retrieves the tag of a workspace allocation specified by a cstr.
- **Description**: Use this function to obtain the tag associated with a workspace allocation identified by a cstr in the format [name]:[gaddr]. This is useful for querying metadata about specific allocations within a workspace. The function should be called when you need to verify or utilize the tag information of an allocation. It is efficient to perform multiple queries on the same workspace by attaching to the workspace once, performing all queries, and then detaching.
- **Inputs**:
    - `cstr`: A non-null string in the format [name]:[gaddr] that specifies the workspace and global address of the allocation. The function will log details if the cstr is invalid or if parsing fails.
- **Output**: Returns the tag associated with the specified allocation, or 0 if the allocation is not found or if an error occurs.
- **See also**: [`fd_wksp_cstr_tag`](fd_wksp_helper.c.driver.md#fd_wksp_cstr_tag)  (Implementation)


---
### fd\_wksp\_cstr\_memset<!-- {{#callable_declaration:fd_wksp_cstr_memset}} -->
Sets all bytes in a workspace allocation to a specified character.
- **Description**: This function is used to fill an entire workspace allocation with a specified character. It should be called when you need to initialize or reset the memory of a workspace allocation to a specific value. The function requires a valid cstr that specifies the workspace and global address of the allocation. If the cstr is invalid or the workspace cannot be attached, the function will return without making any changes. It is important to ensure that the workspace is properly initialized and that the cstr is correctly formatted before calling this function.
- **Inputs**:
    - `cstr`: A constant character string specifying the workspace and global address in the format [name]:[gaddr]. It must not be null and should be correctly formatted. If invalid, the function will return without performing any operation.
    - `c`: An integer representing the character to set in the workspace allocation. This value is used to fill the entire allocation.
- **Output**: None
- **See also**: [`fd_wksp_cstr_memset`](fd_wksp_helper.c.driver.md#fd_wksp_cstr_memset)  (Implementation)


---
### fd\_wksp\_map<!-- {{#callable_declaration:fd_wksp_map}} -->
Maps a workspace allocation specified by a cstr to the caller's address space.
- **Description**: This function is used to map a workspace allocation, identified by a cstr in the format '[name]:[gaddr]', into the caller's local address space. It should be used when you need to access a specific allocation within a workspace from your process. The function returns a pointer to the mapped memory on success, or NULL if the mapping fails. It is important to ensure that the cstr is correctly formatted and that the workspace and global address specified are valid. The function is efficient and has low overhead, especially if the workspace has been previously attached.
- **Inputs**:
    - `cstr`: A string in the format '[name]:[gaddr]' where 'name' is the name of the shared memory region and 'gaddr' is the global address within that workspace. The string must be non-null and correctly formatted. Invalid or malformed strings will result in a NULL return value.
- **Output**: Returns a non-null pointer to the mapped memory on success, or NULL on failure.
- **See also**: [`fd_wksp_map`](fd_wksp_helper.c.driver.md#fd_wksp_map)  (Implementation)


---
### fd\_wksp\_unmap<!-- {{#callable_declaration:fd_wksp_unmap}} -->
Unmaps a pointer previously mapped by fd_wksp_map.
- **Description**: Use this function to unmap a pointer that was previously mapped using fd_wksp_map. This function should be called when the mapped memory is no longer needed, to release resources associated with the mapping. It is important to ensure that the pointer provided was indeed obtained from fd_wksp_map, as undefined behavior may occur otherwise. The function handles a NULL pointer silently, assuming that a NULL might not be an error case.
- **Inputs**:
    - `laddr`: A constant pointer to the local address to be unmapped. It must be a valid pointer returned by fd_wksp_map, or NULL. If NULL, the function returns silently without performing any action.
- **Output**: None
- **See also**: [`fd_wksp_unmap`](fd_wksp_helper.c.driver.md#fd_wksp_unmap)  (Implementation)


---
### fd\_wksp\_pod\_attach<!-- {{#callable_declaration:fd_wksp_pod_attach}} -->
Attaches to a workspace pod using a global address string.
- **Description**: This function is used to attach to a workspace pod by mapping a global address string into the local address space and joining the pod. It should be called when you need to access a pod in a workspace using its global address. The function expects a valid global address string and will terminate the calling thread group with an error message if the address is null or if the mapping or joining fails. Ensure that the workspace is properly initialized and accessible before calling this function.
- **Inputs**:
    - `gaddr`: A non-null string representing the global address of the workspace pod. The caller retains ownership of the string. If the string is null, the function will log an error and terminate the calling thread group.
- **Output**: Returns a pointer to the attached pod in the local address space. The pointer is valid until the pod is detached.
- **See also**: [`fd_wksp_pod_attach`](fd_wksp_helper.c.driver.md#fd_wksp_pod_attach)  (Implementation)


---
### fd\_wksp\_pod\_detach<!-- {{#callable_declaration:fd_wksp_pod_detach}} -->
Detaches a POD from a workspace.
- **Description**: Use this function to safely detach a POD from a workspace when it is no longer needed. This function should be called after you have finished using the POD to ensure that resources are properly released. It is important to pass a valid POD pointer to avoid errors. The function will log an error and terminate the program if a null pointer is provided or if the detachment process fails.
- **Inputs**:
    - `pod`: A pointer to the POD to be detached. Must not be null. If null, the function logs an error and terminates the program.
- **Output**: None
- **See also**: [`fd_wksp_pod_detach`](fd_wksp_helper.c.driver.md#fd_wksp_pod_detach)  (Implementation)


---
### fd\_wksp\_pod\_map<!-- {{#callable_declaration:fd_wksp_pod_map}} -->
Maps a workspace object from a POD using a specified path.
- **Description**: This function is used to map a workspace object from a POD (Plain Old Data) structure using a specified path. It is essential to ensure that both the POD and path parameters are non-null before calling this function, as null values will result in an error. The function retrieves a global address string from the POD using the path and then maps this address into the local address space. If the path is not found in the POD or if the mapping fails, the function will log an error and terminate the calling thread group. This function should be paired with a call to `fd_wksp_pod_unmap` when the mapped object is no longer needed.
- **Inputs**:
    - `pod`: A pointer to a constant unsigned character array representing the POD structure. Must not be null, as a null value will result in an error.
    - `path`: A pointer to a constant character string representing the path to the object within the POD. Must not be null, as a null value will result in an error.
- **Output**: Returns a pointer to the mapped object in the local address space. If any error occurs, the function logs the error and terminates the calling thread group.
- **See also**: [`fd_wksp_pod_map`](fd_wksp_helper.c.driver.md#fd_wksp_pod_map)  (Implementation)


---
### fd\_wksp\_pod\_unmap<!-- {{#callable_declaration:fd_wksp_pod_unmap}} -->
Unmaps a previously mapped workspace object.
- **Description**: Use this function to unmap a workspace object that was previously mapped using fd_wksp_pod_map. It is essential to call this function to release resources and maintain proper memory management. The function must be called with a valid non-null pointer to the object to be unmapped. If the provided pointer is null, the function will log an error and terminate the program. This function is typically used in conjunction with fd_wksp_pod_map to manage workspace memory efficiently.
- **Inputs**:
    - `obj`: A pointer to the object to be unmapped. Must not be null. If null, the function logs an error and terminates the program.
- **Output**: None
- **See also**: [`fd_wksp_pod_unmap`](fd_wksp_helper.c.driver.md#fd_wksp_pod_unmap)  (Implementation)


---
### fd\_wksp\_checkpt\_tpool<!-- {{#callable_declaration:fd_wksp_checkpt_tpool}} -->
Writes the workspace's state to a file using a thread pool.
- **Description**: This function is used to create a checkpoint of a workspace's state, writing it to a specified file using a range of threads from a thread pool. It is useful for saving the current state of a workspace for later restoration. The function requires valid input parameters, including a non-null workspace and file path, and a valid mode. The style parameter determines the format of the checkpoint, and if not specified, a default style is used. The function handles invalid inputs by returning an error code and logs warnings for issues like null pointers or unsupported styles.
- **Inputs**:
    - `tpool`: A pointer to a thread pool structure used for parallel processing. The caller retains ownership and it must be valid if threads are specified.
    - `t0`: The starting index of the thread range in the thread pool to be used. Must be less than t1.
    - `t1`: The ending index of the thread range in the thread pool to be used. Must be greater than t0.
    - `wksp`: A pointer to the workspace to be checkpointed. Must not be null, otherwise the function returns an error.
    - `path`: A constant character pointer to the file path where the checkpoint will be saved. Must not be null, otherwise the function returns an error.
    - `mode`: An unsigned long representing the file permissions for the checkpoint file. Must be a valid mode, otherwise the function returns an error.
    - `style`: An integer specifying the checkpoint style. If zero, a default style is used. Unsupported styles result in an error.
    - `uinfo`: A constant character pointer to additional user information. If null, it defaults to an empty string. The information is truncated if it exceeds 16383 characters.
- **Output**: Returns 0 on success or a negative error code on failure, indicating the type of error encountered.
- **See also**: [`fd_wksp_checkpt_tpool`](fd_wksp_io.c.driver.md#fd_wksp_checkpt_tpool)  (Implementation)


---
### fd\_wksp\_restore\_tpool<!-- {{#callable_declaration:fd_wksp_restore_tpool}} -->
Restores a workspace from a checkpoint using a thread pool.
- **Description**: This function restores the state of a workspace from a checkpoint file located at the specified path, using a range of threads from a thread pool. It is useful for recovering or initializing a workspace to a previously saved state. The function requires a valid workspace and path, and it uses the specified seed for the restoration process. It is important to ensure that the workspace can accommodate the allocations from the checkpoint. The function returns an error code if the restoration fails due to invalid inputs, I/O errors, or checkpoint corruption.
- **Inputs**:
    - `tpool`: A pointer to a thread pool (fd_tpool_t) used for parallel processing during the restore. The caller retains ownership and it must be valid.
    - `t0`: The starting index of the thread range in the thread pool to be used for the restore. Must be less than t1.
    - `t1`: The ending index of the thread range in the thread pool to be used for the restore. Must be greater than t0.
    - `wksp`: A pointer to the workspace (fd_wksp_t) to be restored. Must not be null, and it should be capable of supporting the allocations from the checkpoint.
    - `path`: A constant character pointer to the file path of the checkpoint. Must not be null and should point to a valid checkpoint file.
    - `new_seed`: An unsigned integer used as the seed for the restoration process. The value is arbitrary and can be chosen by the user.
- **Output**: Returns FD_WKSP_SUCCESS (0) on success or a negative error code (FD_WKSP_ERR_*) on failure, indicating the type of error encountered.
- **See also**: [`fd_wksp_restore_tpool`](fd_wksp_io.c.driver.md#fd_wksp_restore_tpool)  (Implementation)


---
### fd\_wksp\_printf<!-- {{#callable_declaration:fd_wksp_printf}} -->
Prints information about a workspace checkpoint to a file descriptor.
- **Description**: Use this function to output detailed information about a workspace checkpoint located at the specified path to the given file descriptor. The verbosity level controls the amount of detail included in the output, ranging from basic preview information to detailed metadata and data dumps. This function is useful for debugging or inspecting workspace checkpoints. Ensure that the file descriptor is valid and open for writing, and that the path points to a valid workspace checkpoint file.
- **Inputs**:
    - `fd`: A valid file descriptor open for writing. The function will write output to this descriptor.
    - `path`: A non-null string representing the path to the workspace checkpoint file. The path must point to a valid checkpoint file.
    - `verbose`: An integer specifying the verbosity level of the output. Levels range from less than 0 (no output) to greater than 4 (detailed hex dumps). Negative values result in no output.
- **Output**: Returns the total number of characters written to the file descriptor, or a negative error code if an error occurs.
- **See also**: [`fd_wksp_printf`](fd_wksp_io.c.driver.md#fd_wksp_printf)  (Implementation)


---
### fd\_wksp\_mprotect<!-- {{#callable_declaration:fd_wksp_mprotect}} -->
Sets the memory protection of a workspace to read-only or read-write.
- **Description**: This function is used to change the memory protection settings of a workspace, making it either read-only or read-write based on the provided flag. It should be called on a valid workspace that is properly aligned and initialized. If the workspace pointer is null, not aligned, or has an invalid magic number, the function will log a warning and return without making any changes. This function is useful for controlling access to shared memory regions, especially in multi-threaded or multi-process environments.
- **Inputs**:
    - `wksp`: A pointer to a valid fd_wksp_t workspace structure. Must not be null, must be aligned to FD_WKSP_ALIGN, and must have a valid magic number. If these conditions are not met, the function logs a warning and returns.
    - `flag`: An integer indicating the desired memory protection level. A non-zero value sets the workspace to read-only, while zero sets it to read-write.
- **Output**: None
- **See also**: [`fd_wksp_mprotect`](fd_wksp_admin.c.driver.md#fd_wksp_mprotect)  (Implementation)


