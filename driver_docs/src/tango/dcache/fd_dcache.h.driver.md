# Purpose
The provided C header file defines a set of macros, functions, and data structures for managing a "dcache" (data cache) system. This system is designed to handle memory regions that are used for storing data and application-specific information in a structured and efficient manner. The file specifies alignment and footprint requirements for these memory regions, ensuring that they are properly aligned to mitigate false sharing and optimize performance. The header file includes macros for calculating the required size of data regions based on parameters such as maximum transmission unit (MTU), depth, and burst size, which are critical for managing the data cache's capacity and ensuring that it can handle concurrent data production and consumption.

The file provides a comprehensive API for constructing, joining, and managing these dcache regions. It includes functions for creating new dcaches, joining and leaving them, and deleting them when they are no longer needed. Additionally, the file offers accessor functions to retrieve the sizes of the data and application regions and to obtain pointers to these regions in the local address space. The header also includes functionality to ensure that the dcache can safely store data in a compact, quasi-ring-like structure, which is essential for efficient data handling in concurrent environments. Overall, this header file is a crucial component for applications that require efficient and reliable data caching mechanisms, providing both the necessary infrastructure and the flexibility to adapt to various data handling scenarios.
# Imports and Dependencies

---
- `../fd_tango_base.h`


# Global Variables

---
### fd\_dcache\_new
- **Type**: `function`
- **Description**: The `fd_dcache_new` function is responsible for formatting an unused memory region to be used as a dcache. It takes a pointer to the shared memory region (`shmem`), the size of the data region (`data_sz`), and the size of the application region (`app_sz`) as parameters. The function returns the `shmem` pointer if successful, with the memory region formatted as a dcache, or `NULL` on failure.
- **Use**: This function is used to initialize a memory region for use as a dcache, setting up the data and application regions with specified sizes.


---
### fd\_dcache\_join
- **Type**: `uchar *`
- **Description**: The `fd_dcache_join` function is a global function that returns a pointer to the data region of a dcache in the local address space. It takes a pointer to the shared memory region backing the dcache as an argument and returns a pointer to the data region on success or NULL on failure.
- **Use**: This function is used to join a caller to a dcache, providing access to its data region for further operations.


---
### fd\_dcache\_leave
- **Type**: `function`
- **Description**: The `fd_dcache_leave` function is designed to leave a current local join to a dcache, which is a data cache structure used for managing shared memory regions. It takes a pointer to the dcache as an argument and returns a pointer to the underlying shared memory region on success, or NULL on failure.
- **Use**: This function is used to safely disconnect from a dcache, ensuring that resources are properly released and the shared memory region can be accessed or managed further.


---
### fd\_dcache\_delete
- **Type**: `function pointer`
- **Description**: The `fd_dcache_delete` function is a global function that unformats a memory region used as a dcache, assuming no one is currently joined to the region. It returns a pointer to the underlying shared memory region or NULL if there is an error, such as if the provided pointer is not a valid dcache.
- **Use**: This function is used to clean up and reclaim the memory region previously formatted as a dcache, transferring ownership back to the caller.


---
### fd\_dcache\_app\_laddr\_const
- **Type**: `function pointer`
- **Description**: `fd_dcache_app_laddr_const` is a function that returns a constant pointer to an unsigned character, representing the location in the caller's local address space of memory set aside for application-specific usage within a dcache. This function ensures that the returned pointer is const-correct, meaning it cannot be used to modify the data it points to.
- **Use**: This function is used to access the application-specific memory region of a dcache in a read-only manner.


---
### fd\_dcache\_app\_laddr
- **Type**: `function`
- **Description**: The `fd_dcache_app_laddr` function returns a pointer to the location in the caller's local address space that is reserved for application-specific usage within a dcache. This function assumes that the dcache is a current local join, meaning the caller is actively using the dcache.
- **Use**: This function is used to access the application-specific memory region within a dcache, allowing applications to store and retrieve data specific to their needs.


# Functions

---
### fd\_dcache\_compact\_chunk0<!-- {{#callable:fd_dcache_compact_chunk0}} -->
The function `fd_dcache_compact_chunk0` calculates the starting chunk index of a dcache's data region relative to a base address.
- **Inputs**:
    - `base`: A pointer to the base address from which the chunk index is calculated.
    - `dcache`: A pointer to the dcache whose starting chunk index is being calculated.
- **Control Flow**:
    - The function casts the `dcache` and `base` pointers to `ulong` for arithmetic operations.
    - It calculates the difference between the `dcache` and `base` addresses.
    - The difference is right-shifted by `FD_CHUNK_LG_SZ` to convert the byte difference into a chunk index.
- **Output**: The function returns an `ulong` representing the starting chunk index of the dcache's data region relative to the base address.


---
### fd\_dcache\_compact\_chunk1<!-- {{#callable:fd_dcache_compact_chunk1}} -->
The `fd_dcache_compact_chunk1` function calculates the upper bound of chunk indices for a data cache's data region relative to a base address.
- **Inputs**:
    - `base`: A pointer to the base address from which the chunk index calculation is relative.
    - `dcache`: A pointer to the data cache whose data region's chunk index upper bound is being calculated.
- **Control Flow**:
    - Convert the `dcache` pointer to an unsigned long integer.
    - Calculate the size of the data region in the `dcache` using [`fd_dcache_data_sz`](fd_dcache.c.driver.md#fd_dcache_data_sz).
    - Subtract the `base` pointer (converted to an unsigned long) from the sum of the `dcache` pointer and the data size.
    - Right shift the result by `FD_CHUNK_LG_SZ` to compute the chunk index.
- **Output**: The function returns an unsigned long integer representing the upper bound of chunk indices for the data region of the `dcache` relative to the `base` address.
- **Functions called**:
    - [`fd_dcache_data_sz`](fd_dcache.c.driver.md#fd_dcache_data_sz)


---
### fd\_dcache\_compact\_wmark<!-- {{#callable:fd_dcache_compact_wmark}} -->
The `fd_dcache_compact_wmark` function calculates the watermark chunk index for a dcache, which is used to determine the boundary for writing fragments compactly.
- **Inputs**:
    - `base`: A pointer to the base address used for chunk indexing, typically the start of the workspace containing the dcache.
    - `dcache`: A pointer to the dcache's data region, which should be a current local join.
    - `mtu`: The maximum transmission unit, representing the maximum size of a fragment that can be written into the dcache.
- **Control Flow**:
    - Calculate `chunk_mtu` by adjusting the `mtu` to account for chunk alignment and size, ensuring it is a multiple of two chunks.
    - Call [`fd_dcache_compact_chunk1`](#fd_dcache_compact_chunk1) to get the end chunk index of the dcache's data region relative to the base address.
    - Subtract `chunk_mtu` from the result of [`fd_dcache_compact_chunk1`](#fd_dcache_compact_chunk1) to determine the watermark chunk index.
- **Output**: The function returns an unsigned long integer representing the watermark chunk index, which is the boundary for writing fragments compactly in the dcache.
- **Functions called**:
    - [`fd_dcache_compact_chunk1`](#fd_dcache_compact_chunk1)


---
### fd\_dcache\_compact\_next<!-- {{#callable:fd_dcache_compact_next}} -->
The `fd_dcache_compact_next` function calculates the next chunk index for storing data in a compact dcache, ensuring it wraps around if it exceeds a watermark.
- **Inputs**:
    - `chunk`: The current chunk index, assumed to be within the range [chunk0, wmark].
    - `sz`: The size of the data to be stored, assumed to be within the range [0, mtu].
    - `chunk0`: The starting chunk index, obtained from fd_dcache_compact_chunk0.
    - `wmark`: The watermark chunk index, obtained from fd_dcache_compact_wmark.
- **Control Flow**:
    - Calculate the number of chunks needed to store the data by adding the size `sz` to `2*FD_CHUNK_SZ-1`, right-shifting by `1+FD_CHUNK_LG_SZ`, and then left-shifting by 1.
    - Add the calculated number of chunks to the current `chunk` index to determine the next chunk index.
    - Use `fd_ulong_if` to check if the new chunk index exceeds the `wmark`. If it does, return `chunk0` to wrap around; otherwise, return the new chunk index.
- **Output**: The function returns the next chunk index, which will be within the range [chunk0, wmark].


# Function Declarations (Public API)

---
### fd\_dcache\_req\_data\_sz<!-- {{#callable_declaration:fd_dcache_req_data_sz}} -->
Calculate the required size of a data region for a dcache.
- **Description**: This function computes the size of a data region in bytes necessary for a dcache configuration based on the maximum transmission unit (MTU), the depth of visible fragments, the burst capacity, and whether the storage is compact. It should be used when setting up a dcache to ensure that the data region is appropriately sized to handle the specified number of fragments and burst capacity. The function returns zero if any of the input parameters are invalid, such as zero values for MTU, depth, or burst, or if the calculated size would exceed ULONG_MAX.
- **Inputs**:
    - `mtu`: The maximum size in bytes of a fragment payload that the producer might write. Must be greater than zero. If zero or too large, the function returns zero.
    - `depth`: The maximum number of fragment payloads that can be visible to consumers. Must be greater than zero. If zero, the function returns zero.
    - `burst`: The maximum number of fragment payloads that can be concurrently prepared by the producer. Must be greater than zero. If zero, the function returns zero.
    - `compact`: An integer indicating whether the storage is compact. Non-zero for compact storage, zero otherwise. This affects the calculation of the total slot count.
- **Output**: Returns the size in bytes of the required data region, or zero if any input is invalid or if the size calculation overflows.
- **See also**: [`fd_dcache_req_data_sz`](fd_dcache.c.driver.md#fd_dcache_req_data_sz)  (Implementation)


---
### fd\_dcache\_align<!-- {{#callable_declaration:fd_dcache_align}} -->
Returns the required alignment for a dcache memory region.
- **Description**: Use this function to obtain the alignment requirement for a memory region intended to be used as a dcache. This alignment is crucial for ensuring efficient memory access and avoiding false sharing. The function is typically used when setting up or validating memory regions for dcache usage, ensuring they meet the necessary alignment constraints.
- **Inputs**: None
- **Output**: The function returns an unsigned long representing the alignment requirement, which is a constant value defined as FD_DCACHE_ALIGN.
- **See also**: [`fd_dcache_align`](fd_dcache.c.driver.md#fd_dcache_align)  (Implementation)


---
### fd\_dcache\_footprint<!-- {{#callable_declaration:fd_dcache_footprint}} -->
Calculates the memory footprint required for a dcache.
- **Description**: This function computes the total memory footprint needed for a dcache with specified data and application region sizes. It should be used when determining the memory allocation requirements for a dcache. The function expects valid data_sz and app_sz values, meaning they should not result in a footprint larger than ULONG_MAX. If either data_sz or app_sz is invalid, or if any internal calculation overflows, the function returns 0, indicating an error. This function is useful for validating dcache configuration parameters before allocation.
- **Inputs**:
    - `data_sz`: The size in bytes of the data region. Must be a valid size that does not cause the total footprint to exceed ULONG_MAX.
    - `app_sz`: The size in bytes of the application region. Must be a valid size that does not cause the total footprint to exceed ULONG_MAX.
- **Output**: Returns the total memory footprint in bytes required for the dcache, or 0 if the input sizes are invalid or cause an overflow.
- **See also**: [`fd_dcache_footprint`](fd_dcache.c.driver.md#fd_dcache_footprint)  (Implementation)


---
### fd\_dcache\_new<!-- {{#callable_declaration:fd_dcache_new}} -->
Formats a memory region for use as a dcache.
- **Description**: This function prepares a specified memory region to be used as a dcache, initializing its data and application regions to zero. It should be called with a valid, non-null pointer to a memory region that meets the required alignment and footprint for the specified data and application sizes. The function returns the pointer to the formatted memory region on success, or NULL if the input parameters are invalid, logging details of the failure. This function does not join the caller to the dcache.
- **Inputs**:
    - `shmem`: A non-null pointer to the memory region to be formatted as a dcache. The memory must be aligned according to fd_dcache_align() and have a sufficient footprint as determined by fd_dcache_footprint(). If the pointer is null or misaligned, the function returns NULL.
    - `data_sz`: The size in bytes of the data region within the dcache. Zero is a valid value. If the size is invalid (e.g., results in a footprint larger than ULONG_MAX), the function returns NULL.
    - `app_sz`: The size in bytes of the application region within the dcache. Zero is a valid value. If the size is invalid (e.g., results in a footprint larger than ULONG_MAX), the function returns NULL.
- **Output**: Returns the pointer to the formatted memory region on success, or NULL on failure.
- **See also**: [`fd_dcache_new`](fd_dcache.c.driver.md#fd_dcache_new)  (Implementation)


---
### fd\_dcache\_join<!-- {{#callable_declaration:fd_dcache_join}} -->
Joins the caller to a dcache and returns a pointer to its data region.
- **Description**: Use this function to join a dcache, allowing access to its data region. The function requires a valid pointer to the start of the dcache memory region, which must be properly aligned and formatted. It returns a pointer to the data region within the dcache on success, or NULL if the input is invalid or the dcache is not correctly formatted. Ensure that every successful join is matched with a corresponding leave to maintain proper resource management.
- **Inputs**:
    - `shdcache`: A pointer to the start of the dcache memory region. It must not be NULL, must be aligned according to fd_dcache_align(), and must point to a correctly formatted dcache. If these conditions are not met, the function returns NULL and logs a warning.
- **Output**: Returns a pointer to the dcache's data region on success, or NULL on failure.
- **See also**: [`fd_dcache_join`](fd_dcache.c.driver.md#fd_dcache_join)  (Implementation)


---
### fd\_dcache\_leave<!-- {{#callable_declaration:fd_dcache_leave}} -->
Leaves a current local join of a dcache.
- **Description**: This function is used to leave a current local join of a dcache, effectively ending the caller's association with the dcache. It should be called after the caller has finished using the dcache and no longer needs access to its data. This function returns a pointer to the underlying shared memory region on success, which is important for managing the memory lifecycle. It is crucial to ensure that the `dcache` parameter is not null before calling this function, as passing a null pointer will result in a logged warning and a null return value.
- **Inputs**:
    - `dcache`: A non-null pointer to the dcache that the caller is currently joined to. The caller must ensure this is a valid dcache pointer; otherwise, the function will log a warning and return null.
- **Output**: Returns a pointer to the underlying shared memory region on success, or null if the input is invalid (e.g., null dcache).
- **See also**: [`fd_dcache_leave`](fd_dcache.c.driver.md#fd_dcache_leave)  (Implementation)


---
### fd\_dcache\_delete<!-- {{#callable_declaration:fd_dcache_delete}} -->
Unformats a memory region used as a dcache.
- **Description**: Use this function to unformat a memory region that was previously formatted as a dcache, assuming no threads are currently joined to it. This function is typically called when the dcache is no longer needed, and the memory region should be reclaimed or repurposed. It is important to ensure that no active joins exist to the dcache before calling this function, as it assumes exclusive access to the memory region. The function logs a warning and returns NULL if the provided pointer is invalid or misaligned.
- **Inputs**:
    - `shdcache`: A pointer to the memory region that is currently formatted as a dcache. It must be non-null, properly aligned according to fd_dcache_align(), and must have been previously formatted with a valid dcache magic number. The caller retains ownership of the memory.
- **Output**: Returns the same pointer to the underlying shared memory region if successful, or NULL if the input is invalid (e.g., null, misaligned, or not a dcache).
- **See also**: [`fd_dcache_delete`](fd_dcache.c.driver.md#fd_dcache_delete)  (Implementation)


---
### fd\_dcache\_data\_sz<!-- {{#callable_declaration:fd_dcache_data_sz}} -->
Retrieve the size of the data region in a dcache.
- **Description**: Use this function to obtain the size of the data region within a dcache. It is essential that the dcache is a current local join before calling this function. This function is useful for understanding the capacity of the data region in the dcache, which can be critical for managing memory and ensuring that operations on the dcache do not exceed its bounds.
- **Inputs**:
    - `dcache`: A pointer to the dcache from which the data size is to be retrieved. It must not be null and should point to a valid dcache that is currently joined locally. If the dcache is not a valid current local join, the behavior is undefined.
- **Output**: The function returns the size of the data region in the dcache as an unsigned long integer.
- **See also**: [`fd_dcache_data_sz`](fd_dcache.c.driver.md#fd_dcache_data_sz)  (Implementation)


---
### fd\_dcache\_app\_sz<!-- {{#callable_declaration:fd_dcache_app_sz}} -->
Retrieve the size of the application region in a dcache.
- **Description**: Use this function to obtain the size of the application-specific region within a dcache. It is essential that the dcache is a current local join when calling this function. This function is useful for determining the amount of memory allocated for application-specific data within the dcache, which can be critical for managing memory usage and ensuring that application data does not exceed allocated space.
- **Inputs**:
    - `dcache`: A pointer to the dcache from which the application region size is to be retrieved. This pointer must not be null and must refer to a dcache that is currently joined locally. If the dcache is not a valid current local join, the behavior is undefined.
- **Output**: The function returns the size of the application region in bytes as an unsigned long integer.
- **See also**: [`fd_dcache_app_sz`](fd_dcache.c.driver.md#fd_dcache_app_sz)  (Implementation)


---
### fd\_dcache\_app\_laddr\_const<!-- {{#callable_declaration:fd_dcache_app_laddr_const}} -->
Returns the local address of the application-specific memory region in a dcache.
- **Description**: Use this function to obtain a pointer to the application-specific region of a dcache that the caller is currently joined to. This function should be called only after a successful join to the dcache, as it assumes the dcache is a current local join. The returned pointer is valid for the duration of the join and provides access to a memory region aligned to FD_DCACHE_ALIGN and sized according to fd_dcache_app_sz.
- **Inputs**:
    - `dcache`: A pointer to the dcache from which the application-specific memory region address is to be retrieved. It must not be null and should point to a valid dcache that the caller is currently joined to.
- **Output**: Returns a pointer to the application-specific memory region within the dcache, aligned to FD_DCACHE_ALIGN.
- **See also**: [`fd_dcache_app_laddr_const`](fd_dcache.c.driver.md#fd_dcache_app_laddr_const)  (Implementation)


---
### fd\_dcache\_app\_laddr<!-- {{#callable_declaration:fd_dcache_app_laddr}} -->
Returns the local address of the application-specific memory region in a dcache.
- **Description**: Use this function to obtain a pointer to the application-specific region of a dcache that the caller is currently joined to. This function should be called only after a successful join to the dcache, as it assumes the dcache is a current local join. The returned pointer is aligned to FD_DCACHE_ALIGN and the size of the region is determined by fd_dcache_app_sz. The lifetime of the returned pointer is tied to the duration of the join.
- **Inputs**:
    - `dcache`: A pointer to the dcache from which the application-specific memory region address is to be retrieved. It must not be null and should point to a dcache that the caller is currently joined to. If the dcache is not a valid join, behavior is undefined.
- **Output**: Returns a pointer to the application-specific memory region within the dcache, aligned to FD_DCACHE_ALIGN.
- **See also**: [`fd_dcache_app_laddr`](fd_dcache.c.driver.md#fd_dcache_app_laddr)  (Implementation)


---
### fd\_dcache\_compact\_is\_safe<!-- {{#callable_declaration:fd_dcache_compact_is_safe}} -->
Determine if a dcache can safely store fragments compactly.
- **Description**: Use this function to check if a given dcache can safely store fragments in a compact manner, which is useful for optimizing storage and access patterns. This function should be called after ensuring that the dcache is properly initialized and joined. It checks alignment and size constraints to ensure that the dcache can handle the specified maximum transmission unit (MTU) and depth of fragments. If any of the preconditions are not met, the function will return 0 and log a warning, indicating that the dcache is not safe for compact storage.
- **Inputs**:
    - `base`: A pointer to the base address relative to which the dcache is indexed. Must be double chunk aligned. If not aligned, the function returns 0 and logs a warning.
    - `dcache`: A pointer to the dcache. Must not be null and must be double chunk aligned. If null or not aligned, the function returns 0 and logs a warning.
    - `mtu`: The maximum size of a fragment that might be written into the dcache. Must be non-zero. If zero, the function returns 0 and logs a warning.
    - `depth`: The maximum number of fragments that might be concurrently accessed in the dcache. Must be non-zero. If zero, the function returns 0 and logs a warning.
- **Output**: Returns 1 if the dcache is safe for compact storage, otherwise returns 0 and logs a warning.
- **See also**: [`fd_dcache_compact_is_safe`](fd_dcache.c.driver.md#fd_dcache_compact_is_safe)  (Implementation)


