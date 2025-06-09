# Purpose
This C source code file provides a comprehensive set of functions for managing shared memory workspaces, which are used to facilitate memory allocation and management in a multi-process environment. The file includes functions for creating, deleting, attaching, and detaching named and anonymous workspaces, as well as functions for allocating and freeing memory within these workspaces. The code is structured around the concept of shared memory (shmem) and workspaces (wksp), with a focus on ensuring that memory operations are safe and efficient. The file also includes helper functions for handling C-style strings (cstr) that represent workspace names and global addresses, as well as functions for interacting with a "pod" structure, which appears to be a higher-level abstraction for managing collections of data within a workspace.

The code is designed to be used as part of a larger system, likely a library, that provides shared memory management capabilities. It includes both private and public functions, with the private functions being used internally to manage the lifecycle of workspaces and the public functions providing an API for external use. The file makes extensive use of logging to provide detailed information about the operations being performed, which is useful for debugging and monitoring. The code also includes error handling to ensure that invalid operations are caught and reported. Overall, this file is a critical component of a shared memory management system, providing the necessary functionality to create and manage workspaces in a multi-process environment.
# Imports and Dependencies

---
- `fd_wksp_private.h`
- `../pod/fd_pod.h`


# Functions

---
### fd\_wksp\_private\_join\_func<!-- {{#callable:fd_wksp_private_join_func}} -->
The `fd_wksp_private_join_func` function joins a shared memory workspace using the provided join information.
- **Inputs**:
    - `context`: A void pointer to context data, which is not used in this function.
    - `info`: A pointer to a constant `fd_shmem_join_info_t` structure containing information needed to join the shared memory.
- **Control Flow**:
    - The function explicitly ignores the `context` parameter by casting it to void.
    - It calls the [`fd_wksp_join`](fd_wksp_admin.c.driver.md#fd_wksp_join) function with the `shmem` field from the `info` structure to join the shared memory workspace.
    - The function returns the result of the [`fd_wksp_join`](fd_wksp_admin.c.driver.md#fd_wksp_join) call.
- **Output**: A pointer to the joined shared memory workspace, as returned by [`fd_wksp_join`](fd_wksp_admin.c.driver.md#fd_wksp_join).
- **Functions called**:
    - [`fd_wksp_join`](fd_wksp_admin.c.driver.md#fd_wksp_join)


---
### fd\_wksp\_private\_leave\_func<!-- {{#callable:fd_wksp_private_leave_func}} -->
The `fd_wksp_private_leave_func` function facilitates the detachment from a shared memory workspace by invoking the [`fd_wksp_leave`](fd_wksp_admin.c.driver.md#fd_wksp_leave) function with the join information provided.
- **Inputs**:
    - `context`: A void pointer to any context data, which is not used in this function.
    - `info`: A constant pointer to a `fd_shmem_join_info_t` structure containing join information, specifically the join handle needed for detachment.
- **Control Flow**:
    - The function begins by explicitly ignoring the `context` parameter, indicating it is unused.
    - It then calls the [`fd_wksp_leave`](fd_wksp_admin.c.driver.md#fd_wksp_leave) function, passing `info->join` as the argument, which handles the actual detachment process and logs details.
- **Output**: The function returns the result of the [`fd_wksp_leave`](fd_wksp_admin.c.driver.md#fd_wksp_leave) function, which is a pointer indicating the status or result of the leave operation.
- **Functions called**:
    - [`fd_wksp_leave`](fd_wksp_admin.c.driver.md#fd_wksp_leave)


---
### fd\_wksp\_private\_cstr<!-- {{#callable:fd_wksp_private_cstr}} -->
The `fd_wksp_private_cstr` function constructs a string in the format '[name]:[gaddr]' and stores it in the provided buffer `cstr`.
- **Inputs**:
    - `name`: A constant character pointer representing the name of the workspace, assumed to be a valid shared memory name.
    - `gaddr`: An unsigned long integer representing a global address.
    - `cstr`: A character pointer to a buffer where the resulting string will be stored, assumed to be at least FD_WKSP_CSTR_MAX bytes in size.
- **Control Flow**:
    - Initialize the `cstr` buffer using `fd_cstr_init`.
    - Append the `name` to the `cstr` using `fd_cstr_append_cstr`.
    - Append a colon ':' character to the `cstr` using `fd_cstr_append_char`.
    - Append the `gaddr` as a text to the `cstr` using `fd_cstr_append_ulong_as_text`, with the number of digits determined by `fd_ulong_base10_dig_cnt`.
    - Finalize the `cstr` using `fd_cstr_fini`.
- **Output**: Returns the pointer to the `cstr` buffer containing the formatted string.


---
### fd\_wksp\_private\_cstr\_parse<!-- {{#callable:fd_wksp_private_cstr_parse}} -->
The `fd_wksp_private_cstr_parse` function parses a string in the format '[name]:[gaddr]' to extract the name and gaddr, storing them in provided buffers.
- **Inputs**:
    - `cstr`: A constant character pointer to the string to be parsed, expected to be in the format '[name]:[gaddr]'.
    - `name`: A character pointer with space for FD_SHMEM_NAME_MAX bytes, where the extracted name will be stored on success.
    - `gaddr`: A pointer to an unsigned long where the extracted gaddr will be stored on success.
- **Control Flow**:
    - Check if the input string `cstr` is NULL and log a warning if so, returning NULL.
    - Initialize `len` to 0 and `name_len` to ULONG_MAX, then iterate over `cstr` to find the length of the name and the position of the ':' character.
    - Calculate `gaddr_len` as the difference between the total length and `name_len`, minus one.
    - Check for various error conditions such as missing name, missing ':', missing gaddr, or name length exceeding FD_SHMEM_NAME_MAX, logging warnings and returning NULL if any are true.
    - Copy the name portion of `cstr` into `name`, null-terminate it, and convert the gaddr portion to an unsigned long, storing it in `gaddr`.
    - Return the `name` pointer on successful parsing.
- **Output**: Returns the `name` pointer on success, or NULL on failure, logging details of the failure.


---
### fd\_ulong\_sum\_sat<!-- {{#callable:fd_ulong_sum_sat}} -->
The `fd_ulong_sum_sat` function calculates the sum of an array of unsigned long integers, saturating at `ULONG_MAX` if an overflow occurs.
- **Inputs**:
    - `cnt`: The number of elements in the array `x` to be summed.
    - `x`: A pointer to an array of unsigned long integers to be summed.
- **Control Flow**:
    - Initialize `sum` to 0 and `ovfl` (overflow flag) to 0.
    - Iterate over each element in the array `x` up to `cnt`.
    - For each element, calculate the temporary sum `tmp` by adding the current element to `sum`.
    - Check if an overflow occurred by comparing `tmp` with `sum`; if `tmp` is less than `sum`, set the overflow flag `ovfl`.
    - Update `sum` to `tmp`.
    - After the loop, return `ULONG_MAX` if an overflow was detected (`ovfl` is true), otherwise return the calculated `sum`.
- **Output**: The function returns the sum of the array elements, or `ULONG_MAX` if an overflow occurred during the summation.


---
### fd\_wksp\_new\_named<!-- {{#callable:fd_wksp_new_named}} -->
The `fd_wksp_new_named` function creates and initializes a new named shared memory workspace with specified parameters.
- **Inputs**:
    - `name`: A constant character pointer representing the name of the shared memory region.
    - `page_sz`: An unsigned long representing the size of each page in the shared memory region.
    - `sub_cnt`: An unsigned long representing the number of sub-regions within the shared memory region.
    - `sub_page_cnt`: A constant pointer to an array of unsigned longs, each representing the number of pages in a sub-region.
    - `sub_cpu_idx`: A constant pointer to an array of unsigned longs, each representing the CPU index for a sub-region.
    - `mode`: An unsigned long representing the mode for creating the shared memory region.
    - `seed`: An unsigned integer used as a seed for initializing the workspace.
    - `part_max`: An unsigned long representing the maximum number of partitions; if zero, it will be estimated.
- **Control Flow**:
    - Check if the input arguments are valid, logging warnings and returning an error code if any are invalid.
    - Calculate the total number of pages (`page_cnt`) by summing the pages in each sub-region, checking for overflow and returning an error if detected.
    - Calculate the total memory footprint (`footprint`) by multiplying `page_cnt` by `page_sz`.
    - Estimate `part_max` if it is zero, logging a warning and returning an error if estimation fails.
    - Estimate `data_max` based on `footprint` and `part_max`, logging a warning and returning an error if estimation fails.
    - Create the shared memory region using `fd_shmem_create_multi`, logging details and returning an error if creation fails.
    - Join the created shared memory region using `fd_shmem_join`, logging details and returning an error if joining fails.
    - Format the joined memory region as a workspace using [`fd_wksp_new`](fd_wksp_admin.c.driver.md#fd_wksp_new), logging details and returning an error if formatting fails.
    - Leave the shared memory region using `fd_shmem_leave`, logging details.
- **Output**: Returns `FD_WKSP_SUCCESS` on successful creation and initialization of the workspace, or an error code (`FD_WKSP_ERR_INVAL` or `FD_WKSP_ERR_FAIL`) if any step fails.
- **Functions called**:
    - [`fd_ulong_sum_sat`](#fd_ulong_sum_sat)
    - [`fd_wksp_part_max_est`](fd_wksp_admin.c.driver.md#fd_wksp_part_max_est)
    - [`fd_wksp_data_max_est`](fd_wksp_admin.c.driver.md#fd_wksp_data_max_est)
    - [`fd_wksp_new`](fd_wksp_admin.c.driver.md#fd_wksp_new)


---
### fd\_wksp\_delete\_named<!-- {{#callable:fd_wksp_delete_named}} -->
The `fd_wksp_delete_named` function deletes a named shared memory workspace by joining it, deleting the workspace, unlinking the shared memory, and then leaving the workspace.
- **Inputs**:
    - `name`: A constant character pointer representing the name of the shared memory workspace to be deleted.
- **Control Flow**:
    - The function attempts to join the shared memory region with the given name in read-write mode, logging details and storing join information in `info`.
    - If the join fails, the function returns `FD_WKSP_ERR_FAIL`.
    - The page size of the joined region is retrieved from `info->page_sz`.
    - The function attempts to delete the workspace using [`fd_wksp_delete`](fd_wksp_admin.c.driver.md#fd_wksp_delete).
    - If the deletion fails, it leaves the shared memory region and returns `FD_WKSP_ERR_FAIL`.
    - The function attempts to unlink the shared memory using `fd_shmem_unlink` with the name and page size.
    - If the unlinking fails, it leaves the shared memory region and returns `FD_WKSP_ERR_FAIL`.
    - Finally, the function leaves the shared memory region and returns `FD_WKSP_SUCCESS`.
- **Output**: The function returns `FD_WKSP_SUCCESS` on successful deletion and unlinking of the workspace, or `FD_WKSP_ERR_FAIL` if any step fails.
- **Functions called**:
    - [`fd_wksp_delete`](fd_wksp_admin.c.driver.md#fd_wksp_delete)


---
### fd\_wksp\_new\_anon<!-- {{#callable:fd_wksp_new_anon}} -->
The `fd_wksp_new_anon` function creates a new anonymous workspace in shared memory with specified parameters and returns a pointer to it.
- **Inputs**:
    - `name`: A constant character pointer representing the name of the workspace.
    - `page_sz`: An unsigned long representing the size of each page in the workspace.
    - `sub_cnt`: An unsigned long representing the number of subregions in the workspace.
    - `sub_page_cnt`: A constant unsigned long pointer representing the number of pages in each subregion.
    - `sub_cpu_idx`: A constant unsigned long pointer representing the CPU indices for each subregion.
    - `seed`: An unsigned integer used as a seed for randomization or initialization purposes.
    - `part_max`: An unsigned long representing the maximum number of partitions; if zero, it will be estimated.
- **Control Flow**:
    - Check if the input arguments are valid, logging warnings and returning NULL if any are invalid.
    - Calculate the total number of pages using [`fd_ulong_sum_sat`](#fd_ulong_sum_sat) and check for overflow or zero pages, logging warnings and returning NULL if issues are found.
    - Calculate the workspace footprint and estimate `part_max` if it is zero, logging warnings and returning NULL if estimation fails.
    - Estimate `data_max` and log a warning and return NULL if it is zero.
    - Acquire shared memory pages using `fd_shmem_acquire_multi`, logging details and returning NULL if acquisition fails.
    - Format the acquired memory as a workspace using [`fd_wksp_new`](fd_wksp_admin.c.driver.md#fd_wksp_new), logging details and releasing memory if formatting fails.
    - Join the workspace using [`fd_wksp_join`](fd_wksp_admin.c.driver.md#fd_wksp_join), logging details and releasing memory if joining fails.
    - Register the join with `fd_shmem_join_anonymous`, logging details and releasing memory if registration fails.
    - Return the pointer to the joined workspace.
- **Output**: A pointer to the newly created and joined `fd_wksp_t` workspace, or NULL if any step fails.
- **Functions called**:
    - [`fd_ulong_sum_sat`](#fd_ulong_sum_sat)
    - [`fd_wksp_part_max_est`](fd_wksp_admin.c.driver.md#fd_wksp_part_max_est)
    - [`fd_wksp_data_max_est`](fd_wksp_admin.c.driver.md#fd_wksp_data_max_est)
    - [`fd_wksp_new`](fd_wksp_admin.c.driver.md#fd_wksp_new)
    - [`fd_wksp_join`](fd_wksp_admin.c.driver.md#fd_wksp_join)
    - [`fd_wksp_delete`](fd_wksp_admin.c.driver.md#fd_wksp_delete)
    - [`fd_wksp_leave`](fd_wksp_admin.c.driver.md#fd_wksp_leave)


---
### fd\_wksp\_delete\_anon<!-- {{#callable:fd_wksp_delete_anon}} -->
The `fd_wksp_delete_anon` function deletes an anonymous workspace by leaving it and releasing its associated shared memory resources.
- **Inputs**:
    - `wksp`: A pointer to the anonymous workspace (`fd_wksp_t`) to be deleted.
- **Control Flow**:
    - Declare a `fd_shmem_join_info_t` array `info` to store join information.
    - Call `fd_shmem_leave_anonymous` with `wksp` and `info` to leave the anonymous workspace; if this call fails, return immediately.
    - Call [`fd_wksp_leave`](fd_wksp_admin.c.driver.md#fd_wksp_leave) to leave the workspace and pass its result to [`fd_wksp_delete`](fd_wksp_admin.c.driver.md#fd_wksp_delete) to delete the workspace.
    - Call `fd_shmem_release` with the result of [`fd_wksp_delete`](fd_wksp_admin.c.driver.md#fd_wksp_delete), `info->page_sz`, and `info->page_cnt` to release the shared memory resources.
- **Output**: The function does not return a value; it performs its operations for side effects, specifically deleting the workspace and releasing resources.
- **Functions called**:
    - [`fd_wksp_delete`](fd_wksp_admin.c.driver.md#fd_wksp_delete)
    - [`fd_wksp_leave`](fd_wksp_admin.c.driver.md#fd_wksp_leave)


---
### fd\_wksp\_attach<!-- {{#callable:fd_wksp_attach}} -->
The `fd_wksp_attach` function attaches to a shared memory workspace identified by a given name, allowing read and write access.
- **Inputs**:
    - `name`: A constant character pointer representing the name of the shared memory workspace to attach to.
- **Control Flow**:
    - The function calls `fd_shmem_join` with the provided name, specifying read-write mode and using `fd_wksp_private_join_func` as the join function.
    - The `fd_shmem_join` function handles the actual joining process and logs details of the operation.
- **Output**: Returns a pointer to `fd_wksp_t`, which represents the attached workspace, or NULL if the attachment fails.


---
### fd\_wksp\_detach<!-- {{#callable:fd_wksp_detach}} -->
The `fd_wksp_detach` function detaches a workspace by leaving the shared memory region associated with it.
- **Inputs**:
    - `wksp`: A pointer to the `fd_wksp_t` structure representing the workspace to be detached.
- **Control Flow**:
    - Check if the `wksp` pointer is NULL; if so, log a warning and return 1.
    - Call `fd_shmem_leave` with the `wksp`, `fd_wksp_private_leave_func`, and NULL as arguments to leave the shared memory region and log details.
- **Output**: Returns 1 if the `wksp` is NULL, otherwise returns the result of `fd_shmem_leave`, which typically indicates success or failure of the detach operation.


---
### fd\_wksp\_containing<!-- {{#callable:fd_wksp_containing}} -->
The `fd_wksp_containing` function determines the workspace containing a given local address.
- **Inputs**:
    - `laddr`: A constant pointer to a local address that is being queried to find its containing workspace.
- **Control Flow**:
    - Check if the input `laddr` is NULL; if so, return NULL.
    - Declare an array `info` of type `fd_shmem_join_info_t` to store join information.
    - Call `fd_shmem_join_query_by_addr` with `laddr`, `1UL`, and `info` to query the join information; if it fails, return NULL.
    - Cast `info->join` to `fd_wksp_t *` and assign it to `wksp`; if `wksp` is NULL, return NULL.
    - Check if `wksp->magic` is equal to `FD_WKSP_MAGIC`; if not, return NULL.
    - Return the `wksp` pointer.
- **Output**: Returns a pointer to the `fd_wksp_t` structure representing the workspace containing the given local address, or NULL if no such workspace is found or if any checks fail.


---
### fd\_wksp\_alloc\_laddr<!-- {{#callable:fd_wksp_alloc_laddr}} -->
The `fd_wksp_alloc_laddr` function allocates memory in a workspace with specified alignment, size, and tag, and returns the local address of the allocated memory.
- **Inputs**:
    - `wksp`: A pointer to the workspace (`fd_wksp_t`) where memory is to be allocated.
    - `align`: The alignment requirement for the memory allocation.
    - `sz`: The size of the memory to be allocated.
    - `tag`: A tag associated with the memory allocation for identification or categorization purposes.
- **Control Flow**:
    - Call [`fd_wksp_alloc`](fd_wksp.h.driver.md#fd_wksp_alloc) with the provided workspace, alignment, size, and tag to allocate memory and get a global address (`gaddr`).
    - Check if `gaddr` is zero (indicating allocation failure); if so, return `NULL`.
    - If allocation is successful, convert the global address to a local address using [`fd_wksp_laddr_fast`](fd_wksp.h.driver.md#fd_wksp_laddr_fast) and return it.
- **Output**: Returns a pointer to the local address of the allocated memory, or `NULL` if the allocation fails.
- **Functions called**:
    - [`fd_wksp_alloc`](fd_wksp.h.driver.md#fd_wksp_alloc)
    - [`fd_wksp_laddr_fast`](fd_wksp.h.driver.md#fd_wksp_laddr_fast)


---
### fd\_wksp\_free\_laddr<!-- {{#callable:fd_wksp_free_laddr}} -->
The `fd_wksp_free_laddr` function frees a local address from a workspace if it is valid and belongs to the workspace.
- **Inputs**:
    - `laddr`: A pointer to the local address that needs to be freed from the workspace.
- **Control Flow**:
    - Check if the `laddr` is NULL; if so, return immediately.
    - Determine the workspace containing `laddr` using [`fd_wksp_containing`](#fd_wksp_containing); if no workspace is found, log a warning and return.
    - Calculate the global address `gaddr` corresponding to `laddr` using [`fd_wksp_gaddr_fast`](fd_wksp.h.driver.md#fd_wksp_gaddr_fast).
    - Verify if `gaddr` is within the valid range of the workspace's global addresses; if not, log a warning and return.
    - Call [`fd_wksp_free`](fd_wksp_user.c.driver.md#fd_wksp_free) to free the address from the workspace.
- **Output**: The function does not return any value; it performs the operation of freeing the address if valid.
- **Functions called**:
    - [`fd_wksp_containing`](#fd_wksp_containing)
    - [`fd_wksp_gaddr_fast`](fd_wksp.h.driver.md#fd_wksp_gaddr_fast)
    - [`fd_wksp_free`](fd_wksp_user.c.driver.md#fd_wksp_free)


---
### fd\_wksp\_cstr<!-- {{#callable:fd_wksp_cstr}} -->
The `fd_wksp_cstr` function generates a string representation of a workspace's name and a global address, ensuring the inputs are valid and within bounds before delegating to a helper function.
- **Inputs**:
    - `wksp`: A pointer to a constant `fd_wksp_t` structure representing the workspace.
    - `gaddr`: An unsigned long integer representing the global address within the workspace.
    - `cstr`: A pointer to a character array where the resulting string will be stored.
- **Control Flow**:
    - Check if `cstr` is NULL; if so, log a warning and return NULL.
    - Check if `wksp` is NULL; if so, log a warning and return NULL.
    - Verify that `gaddr` is either zero or within the bounds of `wksp->gaddr_lo` and `wksp->gaddr_hi`; if not, log a warning and return NULL.
    - Call [`fd_wksp_private_cstr`](#fd_wksp_private_cstr) with `wksp->name`, `gaddr`, and `cstr` to populate `cstr` with the formatted string and return it.
- **Output**: Returns a pointer to the `cstr` containing the formatted string, or NULL if any validation fails.
- **Functions called**:
    - [`fd_wksp_private_cstr`](#fd_wksp_private_cstr)


---
### fd\_wksp\_cstr\_laddr<!-- {{#callable:fd_wksp_cstr_laddr}} -->
The `fd_wksp_cstr_laddr` function converts a local address to a workspace-specific string representation, ensuring the address is valid within the workspace.
- **Inputs**:
    - `laddr`: A constant pointer to the local address that needs to be converted to a string representation.
    - `cstr`: A pointer to a character array where the resulting string representation will be stored.
- **Control Flow**:
    - Check if the `cstr` pointer is NULL and log a warning if it is, returning NULL.
    - Determine the workspace containing the given local address using [`fd_wksp_containing`](#fd_wksp_containing).
    - If the workspace is not found, log a warning and return NULL.
    - Calculate the global address corresponding to the local address using [`fd_wksp_gaddr_fast`](fd_wksp.h.driver.md#fd_wksp_gaddr_fast).
    - Verify that the global address is within the valid range of the workspace's global addresses.
    - If the global address is not valid, log a warning and return 0UL.
    - Call [`fd_wksp_private_cstr`](#fd_wksp_private_cstr) to populate `cstr` with the workspace name and global address, and return `cstr`.
- **Output**: Returns the `cstr` containing the workspace name and global address if successful, or NULL/0UL if an error occurs.
- **Functions called**:
    - [`fd_wksp_containing`](#fd_wksp_containing)
    - [`fd_wksp_gaddr_fast`](fd_wksp.h.driver.md#fd_wksp_gaddr_fast)
    - [`fd_wksp_private_cstr`](#fd_wksp_private_cstr)


---
### fd\_wksp\_cstr\_alloc<!-- {{#callable:fd_wksp_cstr_alloc}} -->
The `fd_wksp_cstr_alloc` function allocates memory in a workspace and returns a string representation of the allocation in the format '[name]:[gaddr]'.
- **Inputs**:
    - `name`: A constant character pointer representing the name of the workspace to attach to.
    - `align`: An unsigned long specifying the alignment requirement for the allocation.
    - `sz`: An unsigned long specifying the size of the memory to allocate.
    - `tag`: An unsigned long used as a tag for the allocation.
    - `cstr`: A character pointer where the resulting string representation of the allocation will be stored.
- **Control Flow**:
    - Check if the `cstr` pointer is NULL and log a warning if it is, returning NULL.
    - Attach to the workspace specified by `name` using [`fd_wksp_attach`](#fd_wksp_attach). If this fails, return NULL.
    - Allocate memory in the workspace with the specified `align`, `sz`, and `tag` using [`fd_wksp_alloc`](fd_wksp.h.driver.md#fd_wksp_alloc). If allocation fails and `sz` is non-zero, detach from the workspace and return NULL.
    - Detach from the workspace after allocation.
    - Use [`fd_wksp_private_cstr`](#fd_wksp_private_cstr) to populate `cstr` with the string representation of the allocation and return `cstr`.
- **Output**: Returns a character pointer to `cstr` containing the string representation '[name]:[gaddr]' of the allocated memory, or NULL if an error occurs.
- **Functions called**:
    - [`fd_wksp_attach`](#fd_wksp_attach)
    - [`fd_wksp_alloc`](fd_wksp.h.driver.md#fd_wksp_alloc)
    - [`fd_wksp_detach`](#fd_wksp_detach)
    - [`fd_wksp_private_cstr`](#fd_wksp_private_cstr)


---
### fd\_wksp\_cstr\_free<!-- {{#callable:fd_wksp_cstr_free}} -->
The `fd_wksp_cstr_free` function frees a workspace allocation specified by a string containing the workspace name and global address.
- **Inputs**:
    - `cstr`: A constant character pointer representing a string in the format '[name]:[gaddr]', where 'name' is the workspace name and 'gaddr' is the global address of the allocation to be freed.
- **Control Flow**:
    - Parse the input string `cstr` to extract the workspace name and global address using [`fd_wksp_private_cstr_parse`](#fd_wksp_private_cstr_parse).
    - If parsing fails, the function returns immediately without performing any operations.
    - Attach to the workspace using the extracted name with [`fd_wksp_attach`](#fd_wksp_attach).
    - If attaching fails, the function returns immediately without performing any operations.
    - Free the allocation at the specified global address within the workspace using [`fd_wksp_free`](fd_wksp_user.c.driver.md#fd_wksp_free).
    - Detach from the workspace using [`fd_wksp_detach`](#fd_wksp_detach).
- **Output**: The function does not return any value; it performs operations to free a workspace allocation and logs details of the operations.
- **Functions called**:
    - [`fd_wksp_private_cstr_parse`](#fd_wksp_private_cstr_parse)
    - [`fd_wksp_attach`](#fd_wksp_attach)
    - [`fd_wksp_free`](fd_wksp_user.c.driver.md#fd_wksp_free)
    - [`fd_wksp_detach`](#fd_wksp_detach)


---
### fd\_wksp\_cstr\_tag<!-- {{#callable:fd_wksp_cstr_tag}} -->
The `fd_wksp_cstr_tag` function retrieves the tag associated with a global address (gaddr) in a workspace identified by a given string representation (cstr).
- **Inputs**:
    - `cstr`: A constant character pointer representing a string in the format '[name]:[gaddr]', where 'name' is the workspace name and 'gaddr' is the global address.
- **Control Flow**:
    - Parse the input string `cstr` to extract the workspace name and global address using [`fd_wksp_private_cstr_parse`](#fd_wksp_private_cstr_parse).
    - If parsing fails, return 0UL indicating an error.
    - Attach to the workspace using the extracted name with [`fd_wksp_attach`](#fd_wksp_attach).
    - If attachment fails, return 0UL indicating an error.
    - Retrieve the tag associated with the global address in the workspace using [`fd_wksp_tag`](fd_wksp_user.c.driver.md#fd_wksp_tag).
    - Detach from the workspace using [`fd_wksp_detach`](#fd_wksp_detach).
    - Return the retrieved tag.
- **Output**: Returns an unsigned long integer representing the tag associated with the specified global address in the workspace, or 0UL if an error occurs during parsing or workspace attachment.
- **Functions called**:
    - [`fd_wksp_private_cstr_parse`](#fd_wksp_private_cstr_parse)
    - [`fd_wksp_attach`](#fd_wksp_attach)
    - [`fd_wksp_tag`](fd_wksp_user.c.driver.md#fd_wksp_tag)
    - [`fd_wksp_detach`](#fd_wksp_detach)


---
### fd\_wksp\_cstr\_memset<!-- {{#callable:fd_wksp_cstr_memset}} -->
The `fd_wksp_cstr_memset` function sets a memory region in a workspace to a specified value, using a string representation of the workspace and address.
- **Inputs**:
    - `cstr`: A constant character pointer representing the workspace and global address in the format '[name]:[gaddr]'.
    - `c`: An integer value to set in the specified memory region.
- **Control Flow**:
    - Parse the input string `cstr` to extract the workspace name and global address using [`fd_wksp_private_cstr_parse`](#fd_wksp_private_cstr_parse).
    - If parsing fails, the function returns immediately.
    - Attach to the workspace using [`fd_wksp_attach`](#fd_wksp_attach) with the extracted name.
    - If attachment fails, the function returns immediately.
    - Call [`fd_wksp_memset`](fd_wksp_user.c.driver.md#fd_wksp_memset) to set the memory at the specified global address to the value `c`.
    - Detach from the workspace using [`fd_wksp_detach`](#fd_wksp_detach).
- **Output**: The function does not return any value; it performs operations on the workspace memory and logs details of the operations.
- **Functions called**:
    - [`fd_wksp_private_cstr_parse`](#fd_wksp_private_cstr_parse)
    - [`fd_wksp_attach`](#fd_wksp_attach)
    - [`fd_wksp_memset`](fd_wksp_user.c.driver.md#fd_wksp_memset)
    - [`fd_wksp_detach`](#fd_wksp_detach)


---
### fd\_wksp\_map<!-- {{#callable:fd_wksp_map}} -->
The `fd_wksp_map` function maps a global address from a workspace, specified by a string, to a local address in the process's address space.
- **Inputs**:
    - `cstr`: A constant character string representing the workspace name and global address in the format '[name]:[gaddr]'.
- **Control Flow**:
    - Parse the input string `cstr` to extract the workspace name and global address using [`fd_wksp_private_cstr_parse`](#fd_wksp_private_cstr_parse).
    - If parsing fails, return `NULL`.
    - Attach to the workspace using [`fd_wksp_attach`](#fd_wksp_attach) with the extracted name.
    - If attachment fails, return `NULL`.
    - Convert the global address to a local address using [`fd_wksp_laddr`](fd_wksp_user.c.driver.md#fd_wksp_laddr).
    - If conversion fails, detach from the workspace using [`fd_wksp_detach`](#fd_wksp_detach) and return `NULL`.
    - Return the local address.
- **Output**: Returns a pointer to the local address corresponding to the global address in the workspace, or `NULL` if any step fails.
- **Functions called**:
    - [`fd_wksp_private_cstr_parse`](#fd_wksp_private_cstr_parse)
    - [`fd_wksp_attach`](#fd_wksp_attach)
    - [`fd_wksp_laddr`](fd_wksp_user.c.driver.md#fd_wksp_laddr)
    - [`fd_wksp_detach`](#fd_wksp_detach)


---
### fd\_wksp\_unmap<!-- {{#callable:fd_wksp_unmap}} -->
The `fd_wksp_unmap` function unmaps a local address from a workspace, ensuring it was previously mapped and logging warnings if any issues are detected.
- **Inputs**:
    - `laddr`: A constant pointer to the local address that needs to be unmapped from the workspace.
- **Control Flow**:
    - Check if `laddr` is NULL; if so, return immediately as NULL might not be an error case.
    - Query the shared memory join information for the given `laddr` using `fd_shmem_join_query_by_addr`.
    - If the query fails, log a warning that `laddr` does not seem to be from `fd_wksp_map` and return.
    - Retrieve the workspace pointer from the join information.
    - If the workspace pointer is NULL, log a warning indicating a potential misuse of the function and return.
    - Call [`fd_wksp_detach`](#fd_wksp_detach) to detach the workspace, which logs details of the operation.
- **Output**: The function does not return any value; it performs operations and logs warnings if necessary.
- **Functions called**:
    - [`fd_wksp_detach`](#fd_wksp_detach)


---
### fd\_wksp\_pod\_attach<!-- {{#callable:fd_wksp_pod_attach}} -->
The `fd_wksp_pod_attach` function maps a global address to a local address space and joins it to a pod, returning a pointer to the pod.
- **Inputs**:
    - `gaddr`: A constant character pointer representing the global address of the pod to be attached.
- **Control Flow**:
    - Check if the input `gaddr` is NULL and log an error if it is.
    - Call [`fd_wksp_map`](#fd_wksp_map) with `gaddr` to map the global address to a local address space, storing the result in `obj`.
    - Check if `obj` is NULL and log an error if it is.
    - Call `fd_pod_join` with `obj` to join the mapped object to a pod, storing the result in `pod`.
    - Check if `pod` is NULL and log an error if it is.
    - Return the `pod` pointer.
- **Output**: A constant unsigned character pointer to the joined pod.
- **Functions called**:
    - [`fd_wksp_map`](#fd_wksp_map)


---
### fd\_wksp\_pod\_detach<!-- {{#callable:fd_wksp_pod_detach}} -->
The `fd_wksp_pod_detach` function detaches a POD (Plain Old Data) from a workspace by leaving the POD and unmapping the associated object.
- **Inputs**:
    - `pod`: A constant pointer to an unsigned character array representing the POD to be detached.
- **Control Flow**:
    - Check if the input `pod` is NULL and log an error if it is.
    - Call `fd_pod_leave` with the `pod` to leave the POD and obtain the associated object.
    - Check if the object returned by `fd_pod_leave` is NULL and log an error if it is.
    - Call [`fd_wksp_unmap`](#fd_wksp_unmap) with the object to unmap it from the workspace.
- **Output**: This function does not return a value; it performs operations to detach and unmap a POD.
- **Functions called**:
    - [`fd_wksp_unmap`](#fd_wksp_unmap)


---
### fd\_wksp\_pod\_map<!-- {{#callable:fd_wksp_pod_map}} -->
The `fd_wksp_pod_map` function maps a specified path within a pod to a local address space and returns the mapped object.
- **Inputs**:
    - `pod`: A pointer to the pod from which the path will be queried.
    - `path`: A string representing the path within the pod to be mapped.
- **Control Flow**:
    - Check if the `pod` pointer is NULL and log an error if it is.
    - Check if the `path` string is NULL and log an error if it is.
    - Query the pod using `fd_pod_query_cstr` to get the global address (`gaddr`) associated with the given path.
    - If the `gaddr` is NULL, log an error indicating the path was not found in the pod.
    - Map the `gaddr` to a local address space using [`fd_wksp_map`](#fd_wksp_map).
    - If the mapping fails, log an error indicating the failure to map the path into the local address space.
    - Return the mapped object.
- **Output**: A pointer to the mapped object in the local address space.
- **Functions called**:
    - [`fd_wksp_map`](#fd_wksp_map)


---
### fd\_wksp\_pod\_unmap<!-- {{#callable:fd_wksp_pod_unmap}} -->
The `fd_wksp_pod_unmap` function unmaps a previously mapped object from the workspace.
- **Inputs**:
    - `obj`: A pointer to the object to be unmapped from the workspace.
- **Control Flow**:
    - Check if the input `obj` is NULL and log an error if it is.
    - Call [`fd_wksp_unmap`](#fd_wksp_unmap) with `obj` to unmap the object from the workspace, which also logs details of the operation.
- **Output**: The function does not return any value.
- **Functions called**:
    - [`fd_wksp_unmap`](#fd_wksp_unmap)


