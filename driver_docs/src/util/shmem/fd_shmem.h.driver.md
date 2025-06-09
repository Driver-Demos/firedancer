# Purpose
The provided C header file, `fd_shmem.h`, defines a comprehensive API for managing interprocess shared memory with a focus on NUMA (Non-Uniform Memory Access) and page size awareness. This API is designed to facilitate the creation, manipulation, and querying of complex shared memory topologies, which are essential for high-performance computing applications that require efficient memory access patterns across multiple processors. The file includes definitions for constants, data structures, and function prototypes that enable users to create, join, leave, and query shared memory regions, as well as manage NUMA and CPU topology information.

Key components of this header file include macros for defining maximum limits and page sizes, data structures for storing shared memory region information, and function prototypes for user and administrative operations. The API supports operations such as joining and leaving shared memory regions, querying region details, and creating or unlinking shared memory regions. It also provides functions for handling NUMA and CPU configurations, ensuring that memory allocations are optimized for the underlying hardware architecture. The file is intended to be included in other C source files, providing a public API for shared memory management, and it is designed to work in conjunction with a command and control script for host configuration.
# Imports and Dependencies

---
- `../log/fd_log.h`


# Global Variables

---
### fd\_shmem\_join
- **Type**: `function pointer`
- **Description**: `fd_shmem_join` is a function that allows a thread group to join a named shared memory region. It facilitates mapping the region into the thread group's local address space and can handle multiple joins to the same region efficiently. The function can also call a user-provided function (`fd_shmem_join_func_t`) for additional address translations if needed.
- **Use**: This function is used to join a thread group to a shared memory region, potentially invoking a user-defined function for custom handling of the memory mapping.


---
### fd\_shmem\_acquire\_multi
- **Type**: `function`
- **Description**: The `fd_shmem_acquire_multi` function is designed to acquire a specified number of pages of shared memory for the private use of the caller's thread group. It allows for the creation of a memory region consisting of multiple subregions, each with a specified number of pages and associated with a specific CPU index.
- **Use**: This function is used to allocate shared memory pages across multiple subregions, facilitating NUMA-aware memory allocation for complex interprocess communication.


---
### fd\_shmem\_lg\_page\_sz\_to\_cstr
- **Type**: `function pointer`
- **Description**: The `fd_shmem_lg_page_sz_to_cstr` is a function that returns a constant character pointer to a C-style string (cstr) that represents the string equivalent of a shared memory log2 page size. If the provided `lg_page_sz` is not a valid shared memory log2 page size, the function returns the string "unknown".
- **Use**: This function is used to convert a log2 page size integer into a human-readable string representation for shared memory page sizes.


---
### fd\_shmem\_page\_sz\_to\_cstr
- **Type**: `function pointer`
- **Description**: The `fd_shmem_page_sz_to_cstr` is a function that returns a constant character pointer to a C-style string (cstr) that represents a shared memory page size. The function takes an unsigned long integer `page_sz` as an argument, which specifies the page size. If the provided `page_sz` is not a valid shared memory page size, the function returns the string "unknown".
- **Use**: This function is used to convert a shared memory page size into a human-readable string representation.


# Data Structures

---
### fd\_shmem\_private\_key
- **Type**: `struct`
- **Members**:
    - `cstr`: An array of characters with a size defined by FD_SHMEM_NAME_MAX, used to store a string.
- **Description**: The `fd_shmem_private_key` structure is designed to hold a character string (cstr) with a maximum length defined by the constant `FD_SHMEM_NAME_MAX`. This structure is primarily used for internal purposes, particularly for interoperability with templates and mappings in shared memory configurations. The character array is intended to store names of shared memory regions, ensuring they conform to the maximum length constraints.


---
### fd\_shmem\_private\_key\_t
- **Type**: `struct`
- **Members**:
    - `cstr`: A character array used to store a string, with a maximum length defined by FD_SHMEM_NAME_MAX.
- **Description**: The `fd_shmem_private_key_t` is a structure used internally for interoperability with the `tmpl/fd_map` system. It contains a single member, `cstr`, which is a character array intended to hold a string representation of a shared memory region's name. This structure is primarily used for internal operations and is not intended for public API exposure.


---
### fd\_shmem\_join\_info
- **Type**: `struct`
- **Members**:
    - `ref_cnt`: Number of joins, with -1 indicating a join/leave is in progress.
    - `join`: Local join handle, which is NULL during a join function call.
    - `shmem`: Location in the thread group's local address space, non-NULL and page size aligned.
    - `page_sz`: Page size used for the region, a non-zero integer power-of-two.
    - `page_cnt`: Number of pages in the region, non-zero and ensures no overflow with page_sz.
    - `mode`: Access mode, either FD_SHMEM_JOIN_MODE_READ_ONLY or FD_SHMEM_JOIN_MODE_READ_WRITE.
    - `hash`: Hash value computed from the region's name.
    - `name`: C-string with the region name at join time, guaranteed to be null-terminated.
    - `key`: Private key for interoperability with fd_map.h.
- **Description**: The `fd_shmem_join_info` structure is used to store detailed information about a shared memory join operation in a thread group. It includes fields for tracking the reference count of joins, the local join handle, and the shared memory location. The structure also specifies the page size and count, ensuring alignment and preventing overflow. The access mode is defined to control read and write permissions, and a hash of the region's name is stored for quick identification. Additionally, it contains a union for storing either the region's name or a private key for interoperability purposes.


---
### fd\_shmem\_join\_info\_t
- **Type**: `struct`
- **Members**:
    - `ref_cnt`: Number of joins, with -1 indicating a join/leave is in progress.
    - `join`: Local join handle, which is NULL during a join function call.
    - `shmem`: Location in the thread group's local address space, non-NULL and page size aligned.
    - `page_sz`: Page size used for the region, a supported non-zero integer power-of-two.
    - `page_cnt`: Number of pages in the region, non-zero and page_sz*page_cnt will not overflow.
    - `mode`: Access mode, either FD_SHMEM_JOIN_MODE_READ_ONLY or FD_SHMEM_JOIN_MODE_READ_WRITE.
    - `hash`: Hash value computed as (uint)fd_hash(0UL, name, FD_SHMEM_NAME_MAX).
    - `name`: C-string with the region name at join time, guaranteed to be null-terminated.
    - `key`: For easy interoperability with tmpl/fd_map.h.
- **Description**: The `fd_shmem_join_info_t` structure provides detailed information about a shared memory join operation, including reference count, local join handle, memory location, page size, page count, access mode, and a hash of the region name. It is used by various APIs to manage and query shared memory regions, ensuring proper alignment and access permissions. The structure also includes a union for storing the region name or a private key for interoperability purposes.


---
### fd\_shmem\_info
- **Type**: `struct`
- **Members**:
    - `page_sz`: Page size of the region, which is a supported non-zero integer power of two.
    - `page_cnt`: Number of pages in the region, which is positive and ensures no overflow when multiplied by page_sz.
- **Description**: The `fd_shmem_info` structure is used to provide low-level details about a shared memory region, specifically focusing on its page size and the number of pages it contains. This structure is crucial for managing shared memory in a NUMA and page size-aware manner, ensuring that the memory region is correctly sized and aligned for efficient interprocess communication.


---
### fd\_shmem\_info\_t
- **Type**: `struct`
- **Members**:
    - `page_sz`: Page size of the region, will be a supported page size (e.g. non-zero, integer power of two).
    - `page_cnt`: Number of pages in the region, will be positive, page_sz*page_cnt will not overflow.
- **Description**: The `fd_shmem_info_t` structure is used to provide low-level details about a shared memory region. It contains information about the page size and the number of pages in the region, ensuring that the page size is a supported non-zero integer power of two and that the total number of pages is positive and does not cause overflow when multiplied by the page size. This structure is essential for managing and querying shared memory regions in a NUMA and page size-aware manner.


# Functions

---
### fd\_shmem\_create<!-- {{#callable:fd_shmem_create}} -->
The `fd_shmem_create` function creates a shared memory region with a specified name, page size, page count, CPU index, and mode by wrapping the [`fd_shmem_create_multi`](fd_shmem_admin.c.driver.md#fd_shmem_create_multi) function for a single subregion.
- **Inputs**:
    - `name`: A constant character pointer representing the name of the shared memory region to be created.
    - `page_sz`: An unsigned long integer specifying the size of each page in the shared memory region.
    - `page_cnt`: An unsigned long integer indicating the number of pages in the shared memory region.
    - `cpu_idx`: An unsigned long integer representing the CPU index near which the memory should be allocated.
    - `mode`: An unsigned long integer specifying the permissions for the shared memory region, similar to file permissions.
- **Control Flow**:
    - The function calls [`fd_shmem_create_multi`](fd_shmem_admin.c.driver.md#fd_shmem_create_multi) with the provided `name`, `page_sz`, `mode`, and pointers to `page_cnt` and `cpu_idx`, setting `sub_cnt` to 1UL to indicate a single subregion.
    - The function returns the result of the [`fd_shmem_create_multi`](fd_shmem_admin.c.driver.md#fd_shmem_create_multi) call, which is an integer indicating success or failure.
- **Output**: The function returns an integer, where 0 indicates success and a non-zero value indicates an error, compatible with `strerror` for error description.
- **Functions called**:
    - [`fd_shmem_create_multi`](fd_shmem_admin.c.driver.md#fd_shmem_create_multi)


---
### fd\_shmem\_acquire<!-- {{#callable:fd_shmem_acquire}} -->
The `fd_shmem_acquire` function allocates a single subregion of shared memory with a specified page size, page count, and CPU index.
- **Inputs**:
    - `page_sz`: The size of each page in the shared memory region, which should be one of the predefined page sizes (e.g., FD_SHMEM_NORMAL_PAGE_SZ, FD_SHMEM_HUGE_PAGE_SZ, FD_SHMEM_GIGANTIC_PAGE_SZ).
    - `page_cnt`: The number of pages to allocate in the shared memory region.
    - `cpu_idx`: The index of the CPU near which the memory should be allocated, ensuring NUMA locality.
- **Control Flow**:
    - The function calls [`fd_shmem_acquire_multi`](fd_shmem_admin.c.driver.md#fd_shmem_acquire_multi) with the provided `page_sz`, a subregion count of 1, and pointers to `page_cnt` and `cpu_idx`.
- **Output**: A pointer to the allocated shared memory region on success, or NULL on failure.
- **Functions called**:
    - [`fd_shmem_acquire_multi`](fd_shmem_admin.c.driver.md#fd_shmem_acquire_multi)


---
### fd\_shmem\_is\_page\_sz<!-- {{#callable:fd_shmem_is_page_sz}} -->
The `fd_shmem_is_page_sz` function checks if a given page size is one of the predefined valid shared memory page sizes.
- **Inputs**:
    - `page_sz`: An unsigned long integer representing the page size to be checked.
- **Control Flow**:
    - The function compares the input `page_sz` with three predefined constants: `FD_SHMEM_NORMAL_PAGE_SZ`, `FD_SHMEM_HUGE_PAGE_SZ`, and `FD_SHMEM_GIGANTIC_PAGE_SZ`.
    - It uses the bitwise OR operator to combine the results of these comparisons, effectively returning a non-zero value if any of the comparisons are true.
- **Output**: The function returns an integer that is non-zero if `page_sz` matches any of the predefined valid page sizes, otherwise it returns zero.


# Function Declarations (Public API)

---
### fd\_shmem\_join<!-- {{#callable_declaration:fd_shmem_join}} -->
Joins a shared memory region by name with specified access mode.
- **Description**: This function is used to join a named shared memory region into the calling thread group's local address space, allowing for interprocess communication. It should be called when a thread group needs to access a shared memory region, either in read-only or read-write mode. The function can handle multiple joins to the same region within a thread group efficiently. A user-defined function can be provided to perform additional setup on the memory region. The function must be called after the shared memory system is initialized and should be paired with a corresponding leave operation. It returns a pointer to the joined memory region or NULL on failure, logging warnings for invalid inputs or errors.
- **Inputs**:
    - `name`: A non-null string representing the name of the shared memory region to join. The name must be valid and within the allowed length range.
    - `mode`: An integer specifying the access mode, either FD_SHMEM_JOIN_MODE_READ_ONLY or FD_SHMEM_JOIN_MODE_READ_WRITE. Invalid modes result in a NULL return.
    - `join_func`: An optional function pointer for additional setup on the memory region. If NULL, no special handling is performed.
    - `context`: A pointer to user-defined data passed to the join_func. Can be NULL if join_func is NULL or does not require context.
    - `opt_info`: An optional pointer to a fd_shmem_join_info_t structure to receive details about the join. Can be NULL if no additional information is needed.
- **Output**: Returns a pointer to the joined memory region on success, or NULL on failure. If opt_info is provided, it is populated with join details on success.
- **See also**: [`fd_shmem_join`](fd_shmem_user.c.driver.md#fd_shmem_join)  (Implementation)


---
### fd\_shmem\_leave<!-- {{#callable_declaration:fd_shmem_leave}} -->
Leaves a shared memory region.
- **Description**: Use this function to leave a shared memory region that was previously joined using `fd_shmem_join`. It should be called when the shared memory region is no longer needed by the thread group. The function decreases the reference count of the join and unmaps the memory if the reference count reaches zero. It is important to ensure that the `join` parameter is valid and currently joined; otherwise, the function will log a warning and return an error. This function can also execute a user-provided leave function if specified, allowing for additional cleanup or context-specific operations.
- **Inputs**:
    - `join`: A pointer to the join handle representing the shared memory region to leave. Must not be null and must be a valid current join; otherwise, the function logs a warning and returns an error.
    - `leave_func`: An optional user-provided function to execute additional cleanup operations. Can be null if no special handling is needed.
    - `context`: A pointer to user-defined data that will be passed to the `leave_func`. Can be null if `leave_func` does not require additional context.
- **Output**: Returns 0 on success, indicating the shared memory region was successfully left. Returns 1 on failure, such as when the join is invalid or if there are issues unmapping the memory. Logs warnings for any errors encountered.
- **See also**: [`fd_shmem_leave`](fd_shmem_user.c.driver.md#fd_shmem_leave)  (Implementation)


---
### fd\_shmem\_join\_query\_by\_name<!-- {{#callable_declaration:fd_shmem_join_query_by_name}} -->
Queries if a shared memory region is joined by name.
- **Description**: Use this function to check if a shared memory region with a specific name is currently joined by the caller's thread group. It should be called when you need to verify the existence of a join for a given name. The function must be called after the shared memory system is initialized. If the region is joined, it can optionally provide detailed information about the join. The function returns an error code if the name is invalid or if no join exists for the given name.
- **Inputs**:
    - `name`: A pointer to a null-terminated string representing the name of the shared memory region. The name must be valid and non-null, with a length between 1 and FD_SHMEM_NAME_MAX. If the name is invalid, the function returns EINVAL.
    - `opt_info`: An optional pointer to a fd_shmem_join_info_t structure where join details will be stored if the region is joined. If non-null and the region is joined, this structure is populated with join information. If null, no join details are returned.
- **Output**: Returns 0 on success if the region is joined, and a non-zero error code (EINVAL or ENOENT) on failure.
- **See also**: [`fd_shmem_join_query_by_name`](fd_shmem_user.c.driver.md#fd_shmem_join_query_by_name)  (Implementation)


---
### fd\_shmem\_join\_query\_by\_join<!-- {{#callable_declaration:fd_shmem_join_query_by_join}} -->
Queries shared memory join information by join handle.
- **Description**: This function checks if a given join handle is currently associated with a shared memory region in the caller's thread group. It should be used when you need to verify the existence of a join or retrieve its details. The function must be called with a valid join handle, and it is expected that the shared memory system is initialized and operational. If the join handle is valid and associated with a region, the function can optionally provide detailed information about the join. It is important to handle potential error codes that indicate invalid input or the absence of a join.
- **Inputs**:
    - `join`: A pointer to the join handle to be queried. Must not be null. If null, the function returns EINVAL.
    - `opt_info`: An optional pointer to a fd_shmem_join_info_t structure where join details will be stored if the query is successful. If null, no details are returned.
- **Output**: Returns 0 on success, with optional join details written to *opt_info. Returns EINVAL if join is null, or ENOENT if no join is found.
- **See also**: [`fd_shmem_join_query_by_join`](fd_shmem_user.c.driver.md#fd_shmem_join_query_by_join)  (Implementation)


---
### fd\_shmem\_join\_query\_by\_addr<!-- {{#callable_declaration:fd_shmem_join_query_by_addr}} -->
Queries if a memory address range overlaps with a shared memory region.
- **Description**: Use this function to determine if a specified memory address range overlaps with any currently joined shared memory regions. It should be called when you need to verify the presence of a shared memory region within a given address range. The function requires that the size of the range is non-zero and that the range does not wrap around the address space. If the range overlaps with multiple regions, it will return information about one of them, but it is undefined which one. This function is useful for checking shared memory mappings without generating excessive log output.
- **Inputs**:
    - `addr`: A pointer to the starting address of the memory range to query. The address is expected to be a valid pointer within the process's address space.
    - `sz`: The size of the memory range to query. Must be greater than zero and should not cause the address range to wrap around the address space. If zero, the function returns ENOENT.
    - `opt_info`: An optional pointer to a fd_shmem_join_info_t structure where details about the overlapping shared memory region will be stored if the range overlaps. If null, no additional information is provided.
- **Output**: Returns 0 on success if the range overlaps with a shared memory region, and a non-zero error code on failure. Possible error codes include ENOENT if no overlap is found or if the size is zero, and EINVAL if the address range wraps around the address space.
- **See also**: [`fd_shmem_join_query_by_addr`](fd_shmem_user.c.driver.md#fd_shmem_join_query_by_addr)  (Implementation)


---
### fd\_shmem\_join\_anonymous<!-- {{#callable_declaration:fd_shmem_join_anonymous}} -->
Joins an anonymous shared memory region to the local address space.
- **Description**: This function allows a memory region, specified by the caller, to be treated as a shared memory region within the local thread group. It is useful for integrating memory regions obtained through non-standard means into the shared memory management system. The function must be called with valid parameters, including a non-null, properly aligned memory pointer and a valid page size and count. The function will fail if the name is invalid, the join handle or memory pointer is null, the page size is unsupported, or the page count is zero. It will also fail if the memory region is already mapped or if the maximum number of concurrent joins has been reached.
- **Inputs**:
    - `name`: A string representing the name of the shared memory region. It must be a valid, non-null string that adheres to naming constraints. If the name is invalid or already in use, the function returns EINVAL.
    - `mode`: An integer specifying the access mode for the memory region. It must be either FD_SHMEM_JOIN_MODE_READ_ONLY or FD_SHMEM_JOIN_MODE_READ_WRITE. Invalid modes result in EINVAL.
    - `join`: A pointer to a join handle. It must not be null and should not already be in use. If invalid, the function returns EINVAL.
    - `mem`: A pointer to the memory region to be joined. It must be non-null, aligned to the specified page size, and not already mapped. Invalid pointers result in EINVAL.
    - `page_sz`: An unsigned long representing the page size. It must be a supported page size (e.g., FD_SHMEM_NORMAL_PAGE_SZ, FD_SHMEM_HUGE_PAGE_SZ, or FD_SHMEM_GIGANTIC_PAGE_SZ). Unsupported sizes result in EINVAL.
    - `page_cnt`: An unsigned long representing the number of pages. It must be greater than zero and the total size (page_sz * page_cnt) must not overflow. Invalid counts result in EINVAL.
- **Output**: Returns 0 on success, or a strerror-friendly error code (e.g., EINVAL) on failure.
- **See also**: [`fd_shmem_join_anonymous`](fd_shmem_user.c.driver.md#fd_shmem_join_anonymous)  (Implementation)


---
### fd\_shmem\_leave\_anonymous<!-- {{#callable_declaration:fd_shmem_leave_anonymous}} -->
Leaves an anonymous shared memory region.
- **Description**: Use this function to leave an anonymous shared memory region that was previously joined. It should be called when the region is no longer needed, ensuring that the join reference count is exactly 1. This function will log warnings and return an error if the join is invalid, not a current join, or if the reference count is not 1. If successful, and if `opt_info` is provided, it will be populated with details about the join, with the reference count set to zero.
- **Inputs**:
    - `join`: A pointer to the join handle of the anonymous shared memory region. Must not be null and must correspond to a valid current join with a reference count of 1.
    - `opt_info`: An optional pointer to a `fd_shmem_join_info_t` structure. If non-null and the function succeeds, it will be filled with details about the join, with the reference count set to zero. If null, no additional information is provided.
- **Output**: Returns 0 on success. On failure, returns EINVAL and logs a warning if the join is invalid, not a current join, or if the reference count is not 1.
- **See also**: [`fd_shmem_leave_anonymous`](fd_shmem_user.c.driver.md#fd_shmem_leave_anonymous)  (Implementation)


---
### fd\_shmem\_numa\_cnt<!-- {{#callable_declaration:fd_shmem_numa_cnt}} -->
Return the number of NUMA nodes configured in the system.
- **Description**: Use this function to determine the number of NUMA nodes available in the system, which is essential for NUMA-aware memory management. This function should be called after the system has been booted and configured, as it relies on the system's current configuration. The returned value will be within the range of 1 to FD_SHMEM_NUMA_MAX, inclusive.
- **Inputs**: None
- **Output**: The function returns an unsigned long integer representing the number of NUMA nodes configured in the system.
- **See also**: [`fd_shmem_numa_cnt`](fd_shmem_admin.c.driver.md#fd_shmem_numa_cnt)  (Implementation)


---
### fd\_shmem\_cpu\_cnt<!-- {{#callable_declaration:fd_shmem_cpu_cnt}} -->
Return the number of logical CPUs configured in the system.
- **Description**: Use this function to determine the number of logical CPUs available in the system, which is configured at the time of thread group boot. This information is useful for applications that need to optimize their operations based on the number of available CPUs. The function can be called at any time after the system has been booted, and it will return a value within the range [1, FD_SHMEM_CPU_MAX].
- **Inputs**: None
- **Output**: Returns the number of logical CPUs configured in the system as an unsigned long integer.
- **See also**: [`fd_shmem_cpu_cnt`](fd_shmem_admin.c.driver.md#fd_shmem_cpu_cnt)  (Implementation)


---
### fd\_shmem\_numa\_idx<!-- {{#callable_declaration:fd_shmem_numa_idx}} -->
Returns the closest NUMA node index for a given logical CPU index.
- **Description**: Use this function to determine the NUMA node that is closest to a specified logical CPU index. This is useful in scenarios where memory locality is important for performance optimization. The function should be called with a valid CPU index that is within the range of available logical CPUs as determined by `fd_shmem_cpu_cnt()`. If the provided CPU index is out of range, the function returns `ULONG_MAX`, indicating an invalid input.
- **Inputs**:
    - `cpu_idx`: The logical CPU index for which the closest NUMA node index is requested. It must be within the range [0, fd_shmem_cpu_cnt()). If the index is out of this range, the function returns ULONG_MAX.
- **Output**: Returns the index of the closest NUMA node if the input is valid, or ULONG_MAX if the input CPU index is out of range.
- **See also**: [`fd_shmem_numa_idx`](fd_shmem_admin.c.driver.md#fd_shmem_numa_idx)  (Implementation)


---
### fd\_shmem\_cpu\_idx<!-- {{#callable_declaration:fd_shmem_cpu_idx}} -->
Returns the smallest CPU index close to a given NUMA node index.
- **Description**: Use this function to determine the smallest logical CPU index that is close to a specified NUMA node index. This is useful in scenarios where you need to optimize resource allocation or scheduling based on NUMA topology. The function should be called with a valid NUMA node index, which must be within the range of available NUMA nodes as determined by `fd_shmem_numa_cnt()`. If the provided NUMA node index is out of range, the function returns `ULONG_MAX` to indicate an error.
- **Inputs**:
    - `numa_idx`: The index of the NUMA node for which the closest CPU index is desired. It must be within the range [0, fd_shmem_numa_cnt()). If the index is out of this range, the function returns ULONG_MAX.
- **Output**: Returns the smallest CPU index close to the specified NUMA node index, or ULONG_MAX if the NUMA node index is invalid.
- **See also**: [`fd_shmem_cpu_idx`](fd_shmem_admin.c.driver.md#fd_shmem_cpu_idx)  (Implementation)


---
### fd\_shmem\_numa\_validate<!-- {{#callable_declaration:fd_shmem_numa_validate}} -->
Validates that memory pages are on the correct NUMA node.
- **Description**: This function checks if all pages in a specified memory region are located on a NUMA node close to a given CPU index. It should be used when you need to ensure that memory is correctly allocated in a NUMA-aware manner. The function requires that the memory pointer is non-null, the page size is valid, the memory is aligned to the page size, and the page count is within a valid range. It logs warnings and returns an error code if any of these conditions are not met or if the pages are not on the expected NUMA node.
- **Inputs**:
    - `mem`: Pointer to the start of the memory region to validate. Must not be null and must be aligned to the specified page size.
    - `page_sz`: Size of each page in the memory region. Must be a valid page size as defined by the system.
    - `page_cnt`: Number of pages in the memory region. Must be at least 1 and such that the total size does not exceed system limits.
    - `cpu_idx`: Index of the CPU to which the memory should be close. Must be less than the total number of CPUs in the system.
- **Output**: Returns 0 if validation is successful, otherwise returns a non-zero error code indicating the type of failure.
- **See also**: [`fd_shmem_numa_validate`](fd_shmem_admin.c.driver.md#fd_shmem_numa_validate)  (Implementation)


---
### fd\_shmem\_create\_multi<!-- {{#callable_declaration:fd_shmem_create_multi}} -->
Creates a shared memory region with multiple subregions.
- **Description**: This function is used to create a shared memory region identified by a unique name, consisting of multiple subregions, each with a specified number of pages and associated with a specific CPU index. It is suitable for applications requiring complex shared memory topologies with NUMA and page size awareness. The function must be called with valid parameters, and the system must be booted to use this API. It returns an error code on failure, which can occur due to invalid parameters or system resource limitations.
- **Inputs**:
    - `name`: A pointer to a constant character string representing the name of the shared memory region. The name must be a valid C string and adhere to naming constraints.
    - `page_sz`: An unsigned long specifying the page size for the shared memory region. It should be one of the predefined page sizes: FD_SHMEM_NORMAL_PAGE_SZ, FD_SHMEM_HUGE_PAGE_SZ, or FD_SHMEM_GIGANTIC_PAGE_SZ.
    - `sub_cnt`: An unsigned long indicating the number of subregions to create. This value must be positive.
    - `_sub_page_cnt`: A pointer to an array of unsigned long values, each representing the number of pages in a corresponding subregion. The array must have at least 'sub_cnt' elements, and the total number of pages must not exceed ULONG_MAX when multiplied by page_sz.
    - `_sub_cpu_idx`: A pointer to an array of unsigned long values, each specifying the CPU index near which the corresponding subregion should be located. The array must have at least 'sub_cnt' elements, and each index should be within the range [0, fd_shmem_cpu_cnt()).
    - `mode`: An unsigned long representing the permissions for the shared memory region, similar to file permissions (e.g., 0660 for user read/write, group read/write, world none).
- **Output**: Returns 0 on success, or an error code on failure, which is compatible with strerror for error description.
- **See also**: [`fd_shmem_create_multi`](fd_shmem_admin.c.driver.md#fd_shmem_create_multi)  (Implementation)


---
### fd\_shmem\_update\_multi<!-- {{#callable_declaration:fd_shmem_update_multi}} -->
Updates an existing shared memory region with new parameters.
- **Description**: Use this function to modify an existing shared memory region created by `fd_shmem_create_multi` with new configuration parameters without deleting and recreating the region. This approach is efficient as it avoids zeroing the underlying memory, but it means that the previous contents of the memory will remain accessible. Ensure that the shared memory region is not in use by other processes or threads when updating to prevent data corruption or undefined behavior.
- **Inputs**:
    - `name`: A pointer to a constant character string representing the name of the shared memory region. It must be a valid name as per the shared memory naming conventions.
    - `page_sz`: An unsigned long specifying the page size for the shared memory region. It should be one of the predefined page sizes like FD_SHMEM_NORMAL_PAGE_SZ, FD_SHMEM_HUGE_PAGE_SZ, or FD_SHMEM_GIGANTIC_PAGE_SZ.
    - `sub_cnt`: An unsigned long indicating the number of subregions within the shared memory region. It must be a positive value.
    - `_sub_page_cnt`: A pointer to an array of unsigned long values, each representing the number of pages in a corresponding subregion. The array must have at least `sub_cnt` elements.
    - `_sub_cpu_idx`: A pointer to an array of unsigned long values, each specifying the CPU index near which the corresponding subregion should be located. The array must have at least `sub_cnt` elements, and each index should be within the range of available CPUs.
    - `mode`: An unsigned long representing the access mode for the shared memory region, typically using POSIX permission bits (e.g., 0660 for user read/write, group read/write, world none).
- **Output**: Returns an integer, 0 on success or a non-zero error code on failure, which is compatible with strerror for error description.
- **See also**: [`fd_shmem_update_multi`](fd_shmem_admin.c.driver.md#fd_shmem_update_multi)  (Implementation)


---
### fd\_shmem\_unlink<!-- {{#callable_declaration:fd_shmem_unlink}} -->
Unlinks a shared memory region by its name and page size.
- **Description**: Use this function to remove the association of a shared memory region with a given name and page size from the system, making it unavailable for future mappings. This function should be called when the shared memory region is no longer needed and you want to ensure that its resources are freed once no longer in use by any thread group. It is important to ensure that the name and page size are valid before calling this function, as invalid inputs will result in an error. The function logs detailed warnings if the unlink operation fails.
- **Inputs**:
    - `name`: A pointer to a null-terminated string representing the name of the shared memory region. The name must be valid, with a length between 1 and FD_SHMEM_NAME_MAX, and must not be null. Invalid names result in an EINVAL error.
    - `page_sz`: An unsigned long representing the page size of the shared memory region. It must be one of the valid page sizes: FD_SHMEM_NORMAL_PAGE_SZ, FD_SHMEM_HUGE_PAGE_SZ, or FD_SHMEM_GIGANTIC_PAGE_SZ. Invalid page sizes result in an EINVAL error.
- **Output**: Returns 0 on success. On failure, returns a strerror-compatible error code indicating the reason for failure, such as EINVAL for invalid inputs or the error code from the unlink operation if it fails.
- **See also**: [`fd_shmem_unlink`](fd_shmem_admin.c.driver.md#fd_shmem_unlink)  (Implementation)


---
### fd\_shmem\_acquire\_multi<!-- {{#callable_declaration:fd_shmem_acquire_multi}} -->
Acquires a multi-subregion shared memory area with specified page size and CPU affinity.
- **Description**: This function is used to allocate a shared memory region consisting of multiple subregions, each with a specified number of pages and CPU affinity. It is suitable for applications requiring NUMA-aware memory allocation. The function must be called with valid page size and subregion specifications. It returns a pointer to the allocated memory on success or NULL on failure, logging details of any errors encountered. The caller is responsible for ensuring that the total number of pages does not exceed system limits and that CPU indices are valid.
- **Inputs**:
    - `page_sz`: Specifies the size of each page in the memory region. Must be a valid page size such as FD_SHMEM_NORMAL_PAGE_SZ, FD_SHMEM_HUGE_PAGE_SZ, or FD_SHMEM_GIGANTIC_PAGE_SZ. Invalid values result in a NULL return.
    - `sub_cnt`: Indicates the number of subregions to allocate. Must be greater than zero. A zero value results in a NULL return.
    - `_sub_page_cnt`: Pointer to an array specifying the number of pages for each subregion. Must not be NULL, and each entry should be positive. A NULL pointer or zero pages in any subregion results in a NULL return.
    - `_sub_cpu_idx`: Pointer to an array specifying the CPU index for each subregion. Must not be NULL, and each index should be within the range [0, fd_shmem_cpu_cnt()). A NULL pointer or invalid CPU index results in a NULL return.
- **Output**: Returns a pointer to the allocated memory region on success, or NULL on failure.
- **See also**: [`fd_shmem_acquire_multi`](fd_shmem_admin.c.driver.md#fd_shmem_acquire_multi)  (Implementation)


---
### fd\_shmem\_release<!-- {{#callable_declaration:fd_shmem_release}} -->
Releases a specified number of memory pages back to the system.
- **Description**: Use this function to release a previously acquired memory region back to the system. It is important to ensure that the memory region was allocated using a compatible mechanism and that the parameters provided are consistent with the original allocation. The function checks for valid input parameters and logs warnings if any issues are detected, such as a null memory pointer, invalid page size, misaligned memory, or an invalid page count. It returns an error code if the release operation fails.
- **Inputs**:
    - `mem`: Pointer to the start of the memory region to be released. Must not be null and should be aligned to the specified page size.
    - `page_sz`: Size of each memory page in bytes. Must be a valid page size as defined by the system.
    - `page_cnt`: Number of pages to release. Must be a positive number and the total size (page_sz * page_cnt) must not exceed system limits.
- **Output**: Returns 0 on success, or -1 if an error occurs during the release process.
- **See also**: [`fd_shmem_release`](fd_shmem_admin.c.driver.md#fd_shmem_release)  (Implementation)


---
### fd\_shmem\_name\_len<!-- {{#callable_declaration:fd_shmem_name_len}} -->
Returns the length of a valid shared memory region name.
- **Description**: Use this function to determine the length of a valid shared memory region name. It checks if the provided name is a valid C-style string that adheres to specific naming rules, such as starting with an alphanumeric character and containing only alphanumeric characters, underscores, hyphens, or periods. The function returns zero if the name is null, too short, too long, or contains invalid characters. This function is useful for validating shared memory region names before using them in other operations.
- **Inputs**:
    - `name`: A pointer to a constant character string representing the shared memory region name. The string must not be null and should adhere to specific character constraints. If the string is null or invalid, the function returns zero.
- **Output**: Returns the length of the valid name as an unsigned long integer, or zero if the name is invalid.
- **See also**: [`fd_shmem_name_len`](fd_shmem_admin.c.driver.md#fd_shmem_name_len)  (Implementation)


---
### fd\_cstr\_to\_shmem\_lg\_page\_sz<!-- {{#callable_declaration:fd_cstr_to_shmem_lg_page_sz}} -->
Converts a string to a shared memory log2 page size identifier.
- **Description**: This function is used to convert a string representation of a page size into its corresponding log2 page size identifier for shared memory operations. It supports case-insensitive string inputs such as "normal", "huge", and "gigantic", as well as numeric strings that directly correspond to the log2 page size values. If the input string does not match any known page size or is null, the function returns a special identifier indicating an unknown page size. This function is useful when interpreting user input or configuration files that specify page sizes in a human-readable format.
- **Inputs**:
    - `cstr`: A pointer to a null-terminated string representing the page size. Valid inputs include "normal", "huge", "gigantic", or numeric strings corresponding to log2 page sizes. The string comparison is case-insensitive. If the input is null or does not match any known page size, the function returns an unknown page size identifier.
- **Output**: Returns an integer representing the log2 page size identifier, which will be one of FD_SHMEM_NORMAL_LG_PAGE_SZ, FD_SHMEM_HUGE_LG_PAGE_SZ, FD_SHMEM_GIGANTIC_LG_PAGE_SZ, or FD_SHMEM_UNKNOWN_LG_PAGE_SZ if the input is invalid or unrecognized.
- **See also**: [`fd_cstr_to_shmem_lg_page_sz`](fd_shmem_admin.c.driver.md#fd_cstr_to_shmem_lg_page_sz)  (Implementation)


---
### fd\_shmem\_lg\_page\_sz\_to\_cstr<!-- {{#callable_declaration:fd_shmem_lg_page_sz_to_cstr}} -->
Convert a log2 page size to a corresponding string representation.
- **Description**: Use this function to obtain a human-readable string representation of a shared memory log2 page size. It is useful for logging or displaying page size information in a user-friendly format. The function returns a string corresponding to the given log2 page size, such as "normal", "huge", or "gigantic". If the input does not match any known log2 page size, the function returns "unknown". This function is guaranteed to return a non-NULL string with an infinite lifetime.
- **Inputs**:
    - `lg_page_sz`: An integer representing the log2 page size. Valid values are FD_SHMEM_NORMAL_LG_PAGE_SZ, FD_SHMEM_HUGE_LG_PAGE_SZ, and FD_SHMEM_GIGANTIC_LG_PAGE_SZ. If the value does not match any of these, the function returns "unknown".
- **Output**: A pointer to a constant string representing the log2 page size. The string will be "normal", "huge", "gigantic", or "unknown".
- **See also**: [`fd_shmem_lg_page_sz_to_cstr`](fd_shmem_admin.c.driver.md#fd_shmem_lg_page_sz_to_cstr)  (Implementation)


---
### fd\_cstr\_to\_shmem\_page\_sz<!-- {{#callable_declaration:fd_cstr_to_shmem_page_sz}} -->
Converts a string to a shared memory page size.
- **Description**: Use this function to convert a string representation of a shared memory page size to its corresponding numeric value. It supports case-insensitive string inputs such as "normal", "huge", and "gigantic", as well as numeric strings that match predefined page sizes. If the input string is null or does not match any known page size, the function returns a value indicating an unknown page size. This function is useful for interpreting configuration strings into actionable memory sizes in shared memory operations.
- **Inputs**:
    - `cstr`: A pointer to a null-terminated string representing the desired page size. Valid inputs include "normal", "huge", "gigantic", or numeric strings corresponding to these sizes. The string comparison is case-insensitive. If the input is null or does not match any known page size, the function returns a value indicating an unknown page size.
- **Output**: Returns the numeric value of the page size corresponding to the input string. If the input is invalid or unrecognized, it returns FD_SHMEM_UNKNOWN_PAGE_SZ.
- **See also**: [`fd_cstr_to_shmem_page_sz`](fd_shmem_admin.c.driver.md#fd_cstr_to_shmem_page_sz)  (Implementation)


---
### fd\_shmem\_page\_sz\_to\_cstr<!-- {{#callable_declaration:fd_shmem_page_sz_to_cstr}} -->
Convert a shared memory page size to a string representation.
- **Description**: Use this function to obtain a human-readable string that represents a given shared memory page size. It is useful for logging or displaying page size information in a user-friendly format. The function accepts a page size and returns a corresponding string such as "normal", "huge", or "gigantic". If the provided page size does not match any known sizes, the function returns "unknown". This function is safe to call with any unsigned long value.
- **Inputs**:
    - `page_sz`: The page size to convert, which should be one of the predefined constants: FD_SHMEM_NORMAL_PAGE_SZ, FD_SHMEM_HUGE_PAGE_SZ, or FD_SHMEM_GIGANTIC_PAGE_SZ. If the value does not match any of these, the function will return "unknown".
- **Output**: A constant string representing the page size, or "unknown" if the page size is not recognized.
- **See also**: [`fd_shmem_page_sz_to_cstr`](fd_shmem_admin.c.driver.md#fd_shmem_page_sz_to_cstr)  (Implementation)


