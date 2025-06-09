# Purpose
This C source code file is part of a shared memory management system, providing a comprehensive set of APIs for handling shared memory regions, particularly in a NUMA (Non-Uniform Memory Access) environment. The file includes functions for converting between string representations and size constants of memory pages, managing NUMA topology, creating and destroying shared memory regions, and handling raw page allocations. It also includes boot and halt functions to initialize and clean up the shared memory environment, respectively. The code is designed to be portable and includes conditional compilation directives to handle different environments, such as threaded or non-threaded systems.

The file defines several public APIs that facilitate the creation, management, and validation of shared memory regions. These include functions for creating and updating shared memory regions with specific NUMA bindings, acquiring and releasing memory pages, and validating memory alignment and NUMA node allocation. The code also includes error handling and logging mechanisms to ensure robust operation and provide diagnostic information. The use of mutexes and memory policies indicates a focus on thread safety and efficient memory management in multi-threaded and multi-core systems. Overall, this file is a critical component of a larger system that manages shared memory resources in a high-performance computing environment.
# Imports and Dependencies

---
- `fd_shmem_private.h`
- `ctype.h`
- `errno.h`
- `unistd.h`
- `fcntl.h`
- `linux/mempolicy.h`
- `sys/mman.h`
- `sys/stat.h`
- `linux/mman.h`


# Global Variables

---
### fd\_shmem\_private\_lock
- **Type**: `pthread_mutex_t`
- **Description**: `fd_shmem_private_lock` is a global mutex array of size 1, used for thread synchronization in a multi-threaded environment. It is defined only if the `FD_HAS_THREADS` macro is set, indicating that the code is compiled with threading support.
- **Use**: This mutex is used to ensure safe access to shared memory resources in a multi-threaded context.


---
### fd\_shmem\_private\_base
- **Type**: `char array`
- **Description**: `fd_shmem_private_base` is a global character array with a size defined by `FD_SHMEM_PRIVATE_BASE_MAX`. It is initialized to an empty string at the start of a thread group and is set up during the boot process.
- **Use**: This variable is used to store the base path for shared memory operations within the application.


---
### fd\_shmem\_private\_base\_len
- **Type**: `ulong`
- **Description**: The `fd_shmem_private_base_len` is a global variable of type `ulong` that represents the length of the shared memory base path string used in the application. It is initialized at boot time and is set to 0UL initially.
- **Use**: This variable is used to store the length of the shared memory base path, which is crucial for managing shared memory operations within the application.


---
### fd\_shmem\_private\_numa\_cnt
- **Type**: `ulong`
- **Description**: `fd_shmem_private_numa_cnt` is a static global variable of type `ulong` that represents the count of NUMA (Non-Uniform Memory Access) nodes available in the system. It is initialized at boot time and is set to 0 at the start of a thread group.
- **Use**: This variable is used to store and provide the number of NUMA nodes for memory allocation and management purposes in the shared memory system.


---
### fd\_shmem\_private\_cpu\_cnt
- **Type**: `ulong`
- **Description**: The `fd_shmem_private_cpu_cnt` is a static global variable of type `ulong` that represents the count of CPUs available in the system. It is initialized at boot time and is used to manage shared memory operations in a NUMA (Non-Uniform Memory Access) environment.
- **Use**: This variable is used to store the total number of CPUs detected during the initialization of the shared memory subsystem, facilitating CPU-related operations.


---
### fd\_shmem\_private\_numa\_idx
- **Type**: `ushort array`
- **Description**: The `fd_shmem_private_numa_idx` is a static array of unsigned short integers with a size defined by `FD_SHMEM_CPU_MAX`. It is used to map CPU indices to their corresponding NUMA node indices.
- **Use**: This array is used to quickly retrieve the NUMA node index for a given CPU index, facilitating memory allocation and management in NUMA architectures.


---
### fd\_shmem\_private\_cpu\_idx
- **Type**: `ushort array`
- **Description**: The `fd_shmem_private_cpu_idx` is a static array of unsigned short integers with a size defined by `FD_SHMEM_NUMA_MAX`. It is used to map NUMA node indices to CPU indices, facilitating the management of shared memory in a NUMA architecture.
- **Use**: This array is used to retrieve the CPU index corresponding to a given NUMA node index.


# Functions

---
### fd\_cstr\_to\_shmem\_lg\_page\_sz<!-- {{#callable:fd_cstr_to_shmem_lg_page_sz}} -->
The function `fd_cstr_to_shmem_lg_page_sz` converts a string representation of a shared memory page size to its corresponding integer constant.
- **Inputs**:
    - `cstr`: A constant character pointer representing the string input that specifies the page size, such as "normal", "huge", or "gigantic".
- **Control Flow**:
    - Check if the input string `cstr` is NULL; if so, return `FD_SHMEM_UNKNOWN_LG_PAGE_SZ`.
    - Compare the input string `cstr` case-insensitively with "normal", "huge", and "gigantic"; return the corresponding page size constant if a match is found.
    - Convert the input string `cstr` to an integer using `fd_cstr_to_int`.
    - Check if the converted integer matches any of the known page size constants (`FD_SHMEM_NORMAL_LG_PAGE_SZ`, `FD_SHMEM_HUGE_LG_PAGE_SZ`, `FD_SHMEM_GIGANTIC_LG_PAGE_SZ`); return the matching constant if found.
    - If no matches are found, return `FD_SHMEM_UNKNOWN_LG_PAGE_SZ`.
- **Output**: An integer representing the large page size constant corresponding to the input string, or `FD_SHMEM_UNKNOWN_LG_PAGE_SZ` if the input is invalid or unrecognized.


---
### fd\_shmem\_lg\_page\_sz\_to\_cstr<!-- {{#callable:fd_shmem_lg_page_sz_to_cstr}} -->
The function `fd_shmem_lg_page_sz_to_cstr` converts a given large page size identifier to its corresponding string representation.
- **Inputs**:
    - `lg_page_sz`: An integer representing the large page size identifier, which can be one of the predefined constants: FD_SHMEM_NORMAL_LG_PAGE_SZ, FD_SHMEM_HUGE_LG_PAGE_SZ, or FD_SHMEM_GIGANTIC_LG_PAGE_SZ.
- **Control Flow**:
    - The function uses a switch statement to check the value of `lg_page_sz`.
    - If `lg_page_sz` matches `FD_SHMEM_NORMAL_LG_PAGE_SZ`, the function returns the string "normal".
    - If `lg_page_sz` matches `FD_SHMEM_HUGE_LG_PAGE_SZ`, the function returns the string "huge".
    - If `lg_page_sz` matches `FD_SHMEM_GIGANTIC_LG_PAGE_SZ`, the function returns the string "gigantic".
    - If `lg_page_sz` does not match any of the predefined constants, the function returns the string "unknown".
- **Output**: A constant character pointer to a string representing the large page size, which can be "normal", "huge", "gigantic", or "unknown".


---
### fd\_cstr\_to\_shmem\_page\_sz<!-- {{#callable:fd_cstr_to_shmem_page_sz}} -->
The function `fd_cstr_to_shmem_page_sz` converts a string representation of a shared memory page size to its corresponding numeric value.
- **Inputs**:
    - `cstr`: A constant character pointer representing the string input that specifies the shared memory page size, such as "normal", "huge", or "gigantic".
- **Control Flow**:
    - Check if the input string `cstr` is NULL; if so, return `FD_SHMEM_UNKNOWN_PAGE_SZ`.
    - Compare the input string `cstr` with "normal", "huge", and "gigantic" using a case-insensitive comparison function `fd_cstr_casecmp`; return the corresponding page size constant if a match is found.
    - Convert the input string `cstr` to an unsigned long using `fd_cstr_to_ulong`.
    - Check if the converted unsigned long matches any of the predefined page size constants (`FD_SHMEM_NORMAL_PAGE_SZ`, `FD_SHMEM_HUGE_PAGE_SZ`, `FD_SHMEM_GIGANTIC_PAGE_SZ`); return the matching constant if found.
    - If no match is found, return `FD_SHMEM_UNKNOWN_PAGE_SZ`.
- **Output**: The function returns an unsigned long representing the numeric value of the shared memory page size, or `FD_SHMEM_UNKNOWN_PAGE_SZ` if the input string does not match any known page size.


---
### fd\_shmem\_page\_sz\_to\_cstr<!-- {{#callable:fd_shmem_page_sz_to_cstr}} -->
The `fd_shmem_page_sz_to_cstr` function converts a shared memory page size constant to its corresponding string representation.
- **Inputs**:
    - `page_sz`: An unsigned long integer representing the page size constant to be converted to a string.
- **Control Flow**:
    - The function uses a switch statement to check the value of `page_sz`.
    - If `page_sz` matches `FD_SHMEM_NORMAL_PAGE_SZ`, it returns the string "normal".
    - If `page_sz` matches `FD_SHMEM_HUGE_PAGE_SZ`, it returns the string "huge".
    - If `page_sz` matches `FD_SHMEM_GIGANTIC_PAGE_SZ`, it returns the string "gigantic".
    - If `page_sz` does not match any of the predefined constants, it returns the string "unknown".
- **Output**: A constant character pointer to a string representing the page size, which can be "normal", "huge", "gigantic", or "unknown".


---
### fd\_shmem\_numa\_cnt<!-- {{#callable:fd_shmem_numa_cnt}} -->
The `fd_shmem_numa_cnt` function returns the number of NUMA nodes available in the system.
- **Inputs**: None
- **Control Flow**:
    - The function directly returns the value of the static variable `fd_shmem_private_numa_cnt`.
- **Output**: The function outputs an `ulong` representing the count of NUMA nodes.


---
### fd\_shmem\_cpu\_cnt<!-- {{#callable:fd_shmem_cpu_cnt}} -->
The `fd_shmem_cpu_cnt` function returns the number of CPUs available for shared memory operations.
- **Inputs**: None
- **Control Flow**:
    - The function directly returns the value of the global variable `fd_shmem_private_cpu_cnt`.
- **Output**: The function outputs an unsigned long integer representing the number of CPUs.


---
### fd\_shmem\_numa\_idx<!-- {{#callable:fd_shmem_numa_idx}} -->
The `fd_shmem_numa_idx` function retrieves the NUMA node index associated with a given CPU index.
- **Inputs**:
    - `cpu_idx`: An unsigned long integer representing the index of the CPU for which the NUMA node index is to be retrieved.
- **Control Flow**:
    - Check if the input `cpu_idx` is greater than or equal to `fd_shmem_private_cpu_cnt` using the `FD_UNLIKELY` macro.
    - If the condition is true, return `ULONG_MAX` to indicate an invalid CPU index.
    - Otherwise, return the NUMA node index from the `fd_shmem_private_numa_idx` array corresponding to the given `cpu_idx`.
- **Output**: Returns the NUMA node index as an unsigned long integer if the CPU index is valid, otherwise returns `ULONG_MAX`.


---
### fd\_shmem\_cpu\_idx<!-- {{#callable:fd_shmem_cpu_idx}} -->
The `fd_shmem_cpu_idx` function retrieves the CPU index associated with a given NUMA index, returning `ULONG_MAX` if the NUMA index is out of bounds.
- **Inputs**:
    - `numa_idx`: An unsigned long integer representing the NUMA index for which the corresponding CPU index is requested.
- **Control Flow**:
    - Check if the provided `numa_idx` is greater than or equal to `fd_shmem_private_numa_cnt` using `FD_UNLIKELY` macro for unlikely conditions.
    - If the condition is true, return `ULONG_MAX` indicating an invalid or out-of-bounds NUMA index.
    - If the condition is false, return the CPU index corresponding to the given `numa_idx` from the `fd_shmem_private_cpu_idx` array.
- **Output**: Returns the CPU index as an unsigned long integer corresponding to the given NUMA index, or `ULONG_MAX` if the NUMA index is invalid.


---
### fd\_shmem\_numa\_validate<!-- {{#callable:fd_shmem_numa_validate}} -->
The `fd_shmem_numa_validate` function checks if a given memory region is correctly aligned, sized, and allocated on the expected NUMA node for a specified CPU index.
- **Inputs**:
    - `mem`: A pointer to the memory region to be validated.
    - `page_sz`: The size of each memory page in the region.
    - `page_cnt`: The number of pages in the memory region.
    - `cpu_idx`: The index of the CPU whose NUMA node should be checked against the memory allocation.
- **Control Flow**:
    - Check if the memory pointer `mem` is NULL and return `EINVAL` if true.
    - Validate if `page_sz` is a valid page size using [`fd_shmem_is_page_sz`](fd_shmem.h.driver.md#fd_shmem_is_page_sz) and return `EINVAL` if not.
    - Check if `mem` is aligned to `page_sz` using `fd_ulong_is_aligned` and return `EINVAL` if not.
    - Ensure `page_cnt` is within valid bounds and return `EINVAL` if not.
    - Verify `cpu_idx` is less than the total CPU count using [`fd_shmem_cpu_cnt`](#fd_shmem_cpu_cnt) and return `EINVAL` if not.
    - Determine the NUMA index for the given `cpu_idx` using [`fd_shmem_numa_idx`](#fd_shmem_numa_idx).
    - Iterate over the memory pages, batching them into groups of up to 512 pages.
    - For each batch, use `fd_numa_move_pages` to query the NUMA node allocation status of the pages.
    - Check the status of each page in the batch; if any page has a negative status, log an error and return the error code.
    - If any page is not allocated to the expected NUMA node, log an error and return `EFAULT`.
    - Continue until all pages are validated.
- **Output**: Returns 0 if the memory region is valid and correctly allocated, or an error code if any validation step fails.
- **Functions called**:
    - [`fd_shmem_is_page_sz`](fd_shmem.h.driver.md#fd_shmem_is_page_sz)
    - [`fd_shmem_cpu_cnt`](#fd_shmem_cpu_cnt)
    - [`fd_shmem_numa_idx`](#fd_shmem_numa_idx)


---
### fd\_shmem\_create\_multi\_flags<!-- {{#callable:fd_shmem_create_multi_flags}} -->
The `fd_shmem_create_multi_flags` function creates a shared memory region with specified parameters, handling NUMA node memory policies and ensuring proper memory alignment and allocation.
- **Inputs**:
    - `name`: A string representing the name of the shared memory region to be created.
    - `page_sz`: An unsigned long representing the size of each page in the shared memory region.
    - `sub_cnt`: An unsigned long representing the number of subregions within the shared memory region.
    - `_sub_page_cnt`: A pointer to an array of unsigned longs, each representing the number of pages in a corresponding subregion.
    - `_sub_cpu_idx`: A pointer to an array of unsigned longs, each representing the CPU index for the corresponding subregion.
    - `mode`: An unsigned long representing the file mode for the shared memory region.
    - `open_flags`: An integer representing the flags used when opening the shared memory region.
- **Control Flow**:
    - Validate input arguments, including name, page size, subregion count, and pointers to subregion page counts and CPU indices.
    - Calculate the total number of pages required and validate against overflow and CPU index limits.
    - Lock shared memory operations to ensure thread safety.
    - Save the current NUMA node memory policy and create the shared memory region using the specified name, page size, and open flags.
    - Set the size of the shared memory region using `ftruncate` and map it into the process's address space using `mmap`.
    - Validate the memory mapping alignment and iterate over each subregion to set memory policies and lock memory pages to ensure they are backed by physical memory.
    - For each subregion, bind the memory to the appropriate NUMA node and validate the NUMA binding.
    - Handle errors by unmapping, closing, and unlinking the shared memory region as necessary, and restore the original NUMA memory policy.
    - Unlock shared memory operations and return the error code, if any.
- **Output**: Returns an integer error code, with 0 indicating success and non-zero indicating an error occurred during the creation of the shared memory region.
- **Functions called**:
    - [`fd_shmem_name_len`](#fd_shmem_name_len)
    - [`fd_shmem_is_page_sz`](fd_shmem.h.driver.md#fd_shmem_is_page_sz)
    - [`fd_shmem_cpu_cnt`](#fd_shmem_cpu_cnt)
    - [`fd_shmem_private_path`](fd_shmem_private.h.driver.md#fd_shmem_private_path)
    - [`fd_shmem_numa_idx`](#fd_shmem_numa_idx)
    - [`fd_shmem_numa_validate`](#fd_shmem_numa_validate)


---
### fd\_shmem\_create\_multi<!-- {{#callable:fd_shmem_create_multi}} -->
The `fd_shmem_create_multi` function creates a shared memory region with specified parameters and flags for multiple subregions.
- **Inputs**:
    - `name`: A constant character pointer representing the name of the shared memory region to be created.
    - `page_sz`: An unsigned long integer specifying the size of each page in the shared memory region.
    - `sub_cnt`: An unsigned long integer indicating the number of subregions to be created within the shared memory region.
    - `_sub_page_cnt`: A constant pointer to an array of unsigned long integers, each representing the number of pages in a corresponding subregion.
    - `_sub_cpu_idx`: A constant pointer to an array of unsigned long integers, each representing the CPU index for the corresponding subregion.
    - `mode`: An unsigned long integer specifying the mode (permissions) for the shared memory region.
- **Control Flow**:
    - The function calls [`fd_shmem_create_multi_flags`](#fd_shmem_create_multi_flags) with the provided parameters and additional flags `O_RDWR | O_CREAT | O_EXCL`.
- **Output**: The function returns an integer which is the result of the [`fd_shmem_create_multi_flags`](#fd_shmem_create_multi_flags) function call, indicating success or failure of the shared memory creation.
- **Functions called**:
    - [`fd_shmem_create_multi_flags`](#fd_shmem_create_multi_flags)


---
### fd\_shmem\_update\_multi<!-- {{#callable:fd_shmem_update_multi}} -->
The `fd_shmem_update_multi` function updates an existing shared memory region with specified parameters by calling [`fd_shmem_create_multi_flags`](#fd_shmem_create_multi_flags) with read-write access.
- **Inputs**:
    - `name`: A constant character pointer representing the name of the shared memory region to update.
    - `page_sz`: An unsigned long integer specifying the size of each page in the shared memory region.
    - `sub_cnt`: An unsigned long integer indicating the number of subregions within the shared memory region.
    - `_sub_page_cnt`: A constant pointer to an array of unsigned long integers, each representing the number of pages in a subregion.
    - `_sub_cpu_idx`: A constant pointer to an array of unsigned long integers, each representing the CPU index associated with a subregion.
    - `mode`: An unsigned long integer specifying the mode (permissions) for the shared memory region.
- **Control Flow**:
    - The function directly calls [`fd_shmem_create_multi_flags`](#fd_shmem_create_multi_flags) with the provided parameters and the `O_RDWR` flag, indicating read-write access.
    - No additional logic or control structures are present in this function; it serves as a wrapper for [`fd_shmem_create_multi_flags`](#fd_shmem_create_multi_flags).
- **Output**: The function returns an integer status code from [`fd_shmem_create_multi_flags`](#fd_shmem_create_multi_flags), indicating success or failure of the update operation.
- **Functions called**:
    - [`fd_shmem_create_multi_flags`](#fd_shmem_create_multi_flags)


---
### fd\_shmem\_unlink<!-- {{#callable:fd_shmem_unlink}} -->
The `fd_shmem_unlink` function attempts to unlink a shared memory object specified by its name and page size.
- **Inputs**:
    - `name`: A constant character pointer representing the name of the shared memory object to be unlinked.
    - `page_sz`: An unsigned long integer representing the page size of the shared memory object.
- **Control Flow**:
    - The function begins by declaring a character array `path` to store the path of the shared memory object.
    - It checks if the `name` is valid using [`fd_shmem_name_len`](#fd_shmem_name_len); if not, it logs a warning and returns `EINVAL`.
    - It checks if `page_sz` is a valid page size using [`fd_shmem_is_page_sz`](fd_shmem.h.driver.md#fd_shmem_is_page_sz); if not, it logs a warning and returns `EINVAL`.
    - The function constructs the path of the shared memory object using [`fd_shmem_private_path`](fd_shmem_private.h.driver.md#fd_shmem_private_path) and attempts to unlink it using the `unlink` system call.
    - If the `unlink` call fails, it logs a warning with the error details and returns the error number.
    - If successful, the function returns 0.
- **Output**: The function returns 0 on success or an error code on failure, specifically `EINVAL` for invalid inputs or the error number from the `unlink` system call if it fails.
- **Functions called**:
    - [`fd_shmem_name_len`](#fd_shmem_name_len)
    - [`fd_shmem_is_page_sz`](fd_shmem.h.driver.md#fd_shmem_is_page_sz)
    - [`fd_shmem_private_path`](fd_shmem_private.h.driver.md#fd_shmem_private_path)


---
### fd\_shmem\_info<!-- {{#callable:fd_shmem_info}} -->
The [`fd_shmem_info`](fd_shmem.h.driver.md#fd_shmem_info) function retrieves information about a shared memory region specified by its name and page size, and optionally stores this information in a provided structure.
- **Inputs**:
    - `name`: A constant character pointer representing the name of the shared memory region.
    - `page_sz`: An unsigned long integer representing the size of the memory pages; if zero, the function will attempt to find the region with different predefined page sizes.
    - `opt_info`: A pointer to an `fd_shmem_info_t` structure where the function can store the retrieved shared memory information, if not NULL.
- **Control Flow**:
    - Check if the provided name is valid using [`fd_shmem_name_len`](#fd_shmem_name_len); if not, log a warning and return `EINVAL`.
    - If `page_sz` is zero, recursively call [`fd_shmem_info`](fd_shmem.h.driver.md#fd_shmem_info) with different predefined page sizes (gigantic, huge, normal) until one succeeds or return `ENOENT` if none do.
    - Validate the `page_sz` using [`fd_shmem_is_page_sz`](fd_shmem.h.driver.md#fd_shmem_is_page_sz); if invalid, log a warning and return `EINVAL`.
    - Construct the file path for the shared memory region using [`fd_shmem_private_path`](fd_shmem_private.h.driver.md#fd_shmem_private_path) and attempt to open it in read-only mode.
    - If the file cannot be opened, return the error code without logging, as this might be an existence check.
    - Use `fstat` to retrieve the file status; if it fails, log a warning, close the file, and return the error code.
    - Check if the file size is aligned with the page size; if not, log a warning, close the file, and return `EFAULT`.
    - Calculate the number of pages by dividing the file size by the page size.
    - Close the file and log a warning if closing fails.
    - If `opt_info` is not NULL, store the page size and page count in the provided structure.
- **Output**: Returns 0 on success, or an error code (`EINVAL`, `ENOENT`, `EFAULT`, or other `errno` values) on failure.
- **Functions called**:
    - [`fd_shmem_name_len`](#fd_shmem_name_len)
    - [`fd_shmem_info`](fd_shmem.h.driver.md#fd_shmem_info)
    - [`fd_shmem_is_page_sz`](fd_shmem.h.driver.md#fd_shmem_is_page_sz)
    - [`fd_shmem_private_path`](fd_shmem_private.h.driver.md#fd_shmem_private_path)


---
### fd\_shmem\_acquire\_multi<!-- {{#callable:fd_shmem_acquire_multi}} -->
The `fd_shmem_acquire_multi` function allocates and configures shared memory regions across multiple NUMA nodes based on specified page sizes and CPU indices.
- **Inputs**:
    - `page_sz`: The size of each memory page to be allocated, which must be a valid page size.
    - `sub_cnt`: The number of subregions to allocate within the shared memory.
    - `_sub_page_cnt`: An array specifying the number of pages for each subregion.
    - `_sub_cpu_idx`: An array specifying the CPU index for each subregion, used to determine the NUMA node for allocation.
- **Control Flow**:
    - The function first validates the input arguments, checking for valid page size, non-zero subregion count, and non-null pointers for page counts and CPU indices.
    - It calculates the total number of pages required by summing the pages for each subregion, ensuring no overflow occurs.
    - For each subregion, it checks that the CPU index is within the valid range of available CPUs.
    - It sets memory allocation flags based on the page size, including options for huge or gigantic pages if applicable.
    - The function locks shared memory operations to ensure thread safety during allocation.
    - It retrieves the current NUMA memory policy and node mask to restore them later.
    - The function attempts to map the required memory using `mmap`, logging and returning NULL on failure.
    - For each subregion, it sets the NUMA memory policy to bind memory to the appropriate NUMA node based on the CPU index.
    - It locks the memory pages to ensure they are resident in RAM and attempts to bind them to the specified NUMA node.
    - The function validates the NUMA binding for each subregion, logging warnings if the binding fails.
    - If any errors occur during these operations, it cleans up by unmapping the memory and restoring the original NUMA policy.
    - Finally, it unlocks the shared memory and returns the allocated memory pointer or NULL if an error occurred.
- **Output**: The function returns a pointer to the allocated shared memory if successful, or NULL if an error occurs during allocation or configuration.
- **Functions called**:
    - [`fd_shmem_is_page_sz`](fd_shmem.h.driver.md#fd_shmem_is_page_sz)
    - [`fd_shmem_cpu_cnt`](#fd_shmem_cpu_cnt)
    - [`fd_shmem_numa_idx`](#fd_shmem_numa_idx)
    - [`fd_shmem_numa_validate`](#fd_shmem_numa_validate)


---
### fd\_shmem\_release<!-- {{#callable:fd_shmem_release}} -->
The `fd_shmem_release` function releases a shared memory region by unmapping it from the process's address space.
- **Inputs**:
    - `mem`: A pointer to the start of the memory region to be released.
    - `page_sz`: The size of each page in the memory region, which must be a valid page size.
    - `page_cnt`: The number of pages in the memory region, which must be a positive number and not exceed the maximum allowable size.
- **Control Flow**:
    - Check if the `mem` pointer is NULL and log a warning if it is, returning -1.
    - Verify that `page_sz` is a valid page size using [`fd_shmem_is_page_sz`](fd_shmem.h.driver.md#fd_shmem_is_page_sz) and log a warning if it is not, returning -1.
    - Ensure that `mem` is aligned to `page_sz` using `fd_ulong_is_aligned` and log a warning if it is not, returning -1.
    - Check that `page_cnt` is within the valid range and log a warning if it is not, returning -1.
    - Calculate the total size of the memory region as `page_sz * page_cnt`.
    - Attempt to unmap the memory region using `munmap` and log a warning if it fails, including the error number and description.
    - Return the result of the `munmap` operation.
- **Output**: Returns 0 on success, or -1 if any validation checks fail or if `munmap` fails.
- **Functions called**:
    - [`fd_shmem_is_page_sz`](fd_shmem.h.driver.md#fd_shmem_is_page_sz)


---
### fd\_shmem\_name\_len<!-- {{#callable:fd_shmem_name_len}} -->
The `fd_shmem_name_len` function calculates the length of a shared memory name string, ensuring it is valid and within a specified maximum length.
- **Inputs**:
    - `name`: A constant character pointer representing the shared memory name to be validated and measured.
- **Control Flow**:
    - Check if the input `name` is NULL; if so, return 0.
    - Initialize a variable `len` to 0 to track the length of the name.
    - Enter a loop that continues while `len` is less than `FD_SHMEM_NAME_MAX`.
    - In each iteration, retrieve the character at the current `len` index of `name`.
    - If the character is the null terminator, break the loop.
    - Check if the character is not alphanumeric and not one of '_', '-', or '.' (except for the first character); if so, return 0.
    - Increment `len` to move to the next character.
    - After the loop, check if `len` is 0 (indicating an empty string) or if `len` is greater than or equal to `FD_SHMEM_NAME_MAX`; if either condition is true, return 0.
    - Return `len` as the length of the valid shared memory name.
- **Output**: The function returns an unsigned long integer representing the length of the valid shared memory name, or 0 if the name is invalid or NULL.


---
### fd\_shmem\_private\_boot<!-- {{#callable:fd_shmem_private_boot}} -->
The `fd_shmem_private_boot` function initializes shared memory settings by stripping command line arguments related to shared memory paths, ensuring consistent environment parsing across platforms.
- **Inputs**:
    - `pargc`: A pointer to an integer representing the count of command line arguments.
    - `pargv`: A pointer to an array of strings representing the command line arguments.
- **Control Flow**:
    - Logs the message 'fd_shmem: booting' to indicate the start of the boot process.
    - Calls `fd_env_strip_cmdline_cstr` to strip the command line of the '--shmem-path' argument, using 'FD_SHMEM_PATH' as the environment variable and '/mnt/.fd' as the default path.
    - Logs the message 'fd_shmem: --shmem-path (ignored)' to indicate that the '--shmem-path' argument is ignored.
    - Logs the message 'fd_shmem: boot success' to indicate successful completion of the boot process.
- **Output**: The function does not return any value; it performs its operations for side effects, such as logging and modifying the command line arguments.


---
### fd\_shmem\_private\_halt<!-- {{#callable:fd_shmem_private_halt}} -->
The `fd_shmem_private_halt` function logs the start and successful completion of halting shared memory operations.
- **Inputs**: None
- **Control Flow**:
    - Logs the message 'fd_shmem: halting' to indicate the start of the halt process.
    - Logs the message 'fd_shmem: halt success' to indicate the successful completion of the halt process.
- **Output**: The function does not return any value or output.


