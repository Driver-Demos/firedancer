# Purpose
The provided C header file, `fd_mcache.h`, defines a memory cache (mcache) system for managing metadata associated with data fragments in a high-performance computing environment. This file is part of a larger framework, likely related to the `fd_tango` project, and it provides both the structure and the API for creating, managing, and accessing a memory cache that stores metadata for data fragments. The mcache is designed to be highly efficient, supporting operations such as creating a new mcache, joining and leaving an mcache, and publishing and querying metadata. The file includes detailed macros and inline functions to facilitate these operations, ensuring that they are performed with minimal overhead and maximum concurrency.

Key components of this file include definitions for alignment and footprint requirements, construction and accessor APIs, and various macros for waiting and publishing metadata. The file also provides specialized implementations for different hardware capabilities, such as SSE and AVX, to optimize performance on compatible systems. The mcache system is designed to handle sequence numbers efficiently, allowing for fast access and updates while minimizing false sharing and cache line contention. This header file is intended to be included in other C source files, providing a robust and efficient mechanism for managing metadata in high-throughput, low-latency applications.
# Imports and Dependencies

---
- `../fd_tango_base.h`


# Global Variables

---
### fd\_mcache\_new
- **Type**: `function pointer`
- **Description**: The `fd_mcache_new` function is a global function that initializes a memory region for use as a metadata cache (mcache). It takes a pointer to a shared memory region, the number of cache entries (depth), the size of an application-specific region (app_sz), and an initial sequence number (seq0) as parameters. The function returns a pointer to the formatted memory region on success or NULL on failure.
- **Use**: This function is used to format a memory region for use as a metadata cache, setting up the necessary structure and initializing it for subsequent operations.


---
### fd\_mcache\_join
- **Type**: `fd_frag_meta_t *`
- **Description**: The `fd_mcache_join` function is a global function that returns a pointer to `fd_frag_meta_t`, which represents the metadata entries of a memory cache (mcache) in the local address space. It is used to join the caller to the mcache, allowing access to its entries.
- **Use**: This function is used to map the shared memory cache into the caller's local address space, enabling the caller to interact with the mcache's metadata entries.


---
### fd\_mcache\_leave
- **Type**: `function pointer`
- **Description**: `fd_mcache_leave` is a function that facilitates leaving a current local join to a memory cache (mcache). It takes a constant pointer to `fd_frag_meta_t`, which represents the metadata of the fragments in the mcache, and returns a pointer to the underlying shared memory region.
- **Use**: This function is used to properly exit a local join to an mcache, ensuring that resources are correctly released and the shared memory region is returned.


---
### fd\_mcache\_delete
- **Type**: `function pointer`
- **Description**: The `fd_mcache_delete` is a function pointer that points to a function designed to unformat a memory region used as a memory cache (mcache). It assumes that no threads are currently joined to the mcache region. The function returns a pointer to the underlying shared memory region or NULL if there is an error, such as when the provided pointer does not point to a valid mcache.
- **Use**: This function is used to clean up and reclaim the memory region previously formatted as an mcache, transferring ownership of the memory back to the caller.


---
### fd\_mcache\_seq\_laddr\_const
- **Type**: `function`
- **Description**: The `fd_mcache_seq_laddr_const` function returns a pointer to the location in the caller's local address space of the mcache's sequence array. This array is indexed from 0 to `FD_MCACHE_SEQ_CNT` and is aligned to `FD_MCACHE_ALIGN`. The function provides a const-correct version of the sequence array location, ensuring that the returned pointer cannot be used to modify the sequence data.
- **Use**: This function is used to access the sequence array of an mcache in a read-only manner, ensuring that the sequence data is not modified.


---
### fd\_mcache\_seq\_laddr
- **Type**: `function`
- **Description**: The `fd_mcache_seq_laddr` function returns a pointer to the location in the caller's local address space of the sequence array within a memory cache (`mcache`). This sequence array is used to track the sequence numbers of fragments in the cache.
- **Use**: This function is used to access the sequence array of a memory cache, which is crucial for managing and tracking the sequence numbers of cached fragments.


---
### fd\_mcache\_app\_laddr\_const
- **Type**: `uchar const *`
- **Description**: The `fd_mcache_app_laddr_const` is a function that returns a constant pointer to an unsigned character array. This pointer represents the location in the caller's local address space of memory set aside for application-specific usage within a memory cache (mcache).
- **Use**: This function is used to access the application-specific region of an mcache in a read-only manner, ensuring that the data is not modified.


---
### fd\_mcache\_app\_laddr
- **Type**: `function`
- **Description**: The `fd_mcache_app_laddr` function returns a pointer to the location in the caller's local address space of the memory set aside for application-specific usage within a memory cache (mcache). This function assumes that the mcache is a current local join and provides access to a region with a specific alignment and size.
- **Use**: This function is used to access the application-specific memory region of an mcache for custom data storage or manipulation.


---
### \_fd\_mcache\_wait\_seq\_test
- **Type**: `ulong`
- **Description**: The variable `_fd_mcache_wait_seq_test` is a global variable of type `ulong` that is used to store the sequence number from a memory cache line during a wait operation. It is part of a macro that facilitates waiting for a specific sequence number to be produced by a producer in a memory cache system. The value is typically a fast L1 cache hit, indicating it is frequently accessed and updated.
- **Use**: This variable is used within the `FD_MCACHE_WAIT` macro to temporarily hold the sequence number from a cache line to verify consistency during a wait operation.


---
### \_fd\_mcache\_wait\_done
- **Type**: `int`
- **Description**: The variable `_fd_mcache_wait_done` is an integer used to determine the completion status of a wait operation in the FD_MCACHE_WAIT macro. It is calculated based on whether the expected sequence number has been found or if the polling limit has been reached.
- **Use**: This variable is used within a loop to decide when to exit the polling loop in the FD_MCACHE_WAIT macro.


# Functions

---
### fd\_mcache\_seq\_query<!-- {{#callable:fd_mcache_seq_query}} -->
The `fd_mcache_seq_query` function atomically reads a sequence number from a memory cache to determine the producer's current position in sequence space.
- **Inputs**:
    - `_seq`: A pointer to a constant unsigned long integer representing the sequence number to be queried.
- **Control Flow**:
    - The function begins by executing a compiler memory fence to ensure memory operations are not reordered around this point.
    - It reads the sequence number from the memory location pointed to by `_seq` using a volatile read to prevent compiler optimizations from caching the value.
    - Another compiler memory fence is executed to ensure subsequent operations are not reordered before this point.
    - The function returns the read sequence number.
- **Output**: The function returns an unsigned long integer representing the sequence number read from the memory cache.


---
### fd\_mcache\_seq\_update<!-- {{#callable:fd_mcache_seq_update}} -->
The `fd_mcache_seq_update` function updates a sequence number in a memory cache with memory fencing to ensure proper ordering of operations.
- **Inputs**:
    - `_seq`: A pointer to the sequence number in the memory cache that needs to be updated.
    - `seq`: The new sequence number value to be set in the memory cache.
- **Control Flow**:
    - A memory fence is executed to ensure that all previous memory operations are completed before updating the sequence number.
    - The sequence number pointed to by `_seq` is updated to the new value `seq` using a volatile store to prevent compiler optimizations from reordering this operation.
    - Another memory fence is executed to ensure that the update is completed before any subsequent memory operations.
- **Output**: This function does not return any value; it updates the sequence number in place.


---
### fd\_mcache\_line\_idx<!-- {{#callable:fd_mcache_line_idx}} -->
The `fd_mcache_line_idx` function calculates the index of a cache line in a memory cache for a given sequence number and depth, considering interleaving and block size constraints.
- **Inputs**:
    - `seq`: The sequence number for which the cache line index is to be calculated.
    - `depth`: The depth of the memory cache, which is assumed to be a power of 2 and at least equal to the block size.
- **Control Flow**:
    - Calculate `block_mask` as `FD_MCACHE_BLOCK - 1UL`, which is a compile-time constant.
    - Calculate `page_mask` as `(depth-1UL) & (~block_mask)`, which is typically a compile-time or loop invariant value.
    - Determine `page` by applying `page_mask` to `seq` using a bitwise AND operation.
    - Calculate `bank` by left-shifting `seq` by `FD_MCACHE_LG_INTERLEAVE` and applying `block_mask` using a bitwise AND operation.
    - Determine `idx` by applying `block_mask` to `seq` and right-shifting by `(FD_MCACHE_LG_BLOCK-FD_MCACHE_LG_INTERLEAVE)`.
    - Combine `page`, `bank`, and `idx` using bitwise OR operations to compute the final cache line index.
- **Output**: Returns an unsigned long integer representing the index of the cache line within the range [0, depth).


---
### fd\_mcache\_publish<!-- {{#callable:fd_mcache_publish}} -->
The `fd_mcache_publish` function updates a metadata cache with fragment metadata for a given sequence number, ensuring memory consistency through compiler memory fences.
- **Inputs**:
    - `mcache`: A pointer to the metadata cache (fd_frag_meta_t) where the fragment metadata will be stored.
    - `depth`: The depth of the cache, assumed to be an integer power-of-2 and at least equal to BLOCK.
    - `seq`: The sequence number of the fragment being published.
    - `sig`: The signature associated with the fragment.
    - `chunk`: The chunk identifier, assumed to be in the range [0, UINT_MAX].
    - `sz`: The size of the fragment, assumed to be in the range [0, USHORT_MAX].
    - `ctl`: Control information for the fragment, assumed to be in the range [0, USHORT_MAX].
    - `tsorig`: The original timestamp of the fragment, assumed to be in the range [0, UINT_MAX].
    - `tspub`: The publication timestamp of the fragment, assumed to be in the range [0, UINT_MAX].
- **Control Flow**:
    - Calculate the index in the cache where the metadata for the given sequence number should be stored using [`fd_mcache_line_idx`](#fd_mcache_line_idx).
    - Issue a compiler memory fence to ensure memory operations are not reordered.
    - Set the sequence number in the metadata to `seq - 1` to mark the cache line as being updated.
    - Issue another compiler memory fence.
    - Update the metadata fields (sig, chunk, sz, ctl, tsorig, tspub) with the provided values.
    - Issue another compiler memory fence.
    - Set the sequence number in the metadata to `seq` to mark the metadata as available for consumers.
    - Issue a final compiler memory fence.
- **Output**: The function does not return a value; it updates the metadata cache in place.
- **Functions called**:
    - [`fd_mcache_line_idx`](#fd_mcache_line_idx)


---
### fd\_mcache\_publish\_sse<!-- {{#callable:fd_mcache_publish_sse}} -->
The `fd_mcache_publish_sse` function publishes metadata for a fragment sequence into a memory cache using SSE instructions, ensuring memory consistency with compiler memory fences.
- **Inputs**:
    - `mcache`: A pointer to the memory cache where the metadata will be published, assumed to be a current local join.
    - `depth`: The depth of the memory cache, assumed to be an integer power-of-2 and at least equal to BLOCK.
    - `seq`: The sequence number of the fragment being published.
    - `sig`: The signature associated with the fragment.
    - `chunk`: The chunk identifier, assumed to be in the range [0, UINT_MAX].
    - `sz`: The size of the fragment, assumed to be in the range [0, USHORT_MAX].
    - `ctl`: The control flags for the fragment, assumed to be in the range [0, USHORT_MAX].
    - `tsorig`: The original timestamp of the fragment, assumed to be in the range [0, UINT_MAX].
    - `tspub`: The publication timestamp of the fragment, assumed to be in the range [0, UINT_MAX].
- **Control Flow**:
    - Calculate the index in the cache where the metadata should be stored using [`fd_mcache_line_idx`](#fd_mcache_line_idx) with the sequence number and depth.
    - Create SSE metadata vectors `meta_sse0` and `meta_sse1` using `fd_frag_meta_sse0` and `fd_frag_meta_sse1` functions, respectively.
    - Use a compiler memory fence to ensure memory operations are not reordered by the compiler.
    - Store `meta_sse0` into the cache line's `sse0` field using a volatile store to ensure atomicity.
    - Use another compiler memory fence to ensure the store operation is completed before proceeding.
    - Store `meta_sse1` into the cache line's `sse1` field using a volatile store to ensure atomicity.
    - Use another compiler memory fence to ensure the store operation is completed before proceeding.
    - Finally, update the sequence number in the cache line to `seq` and use a final compiler memory fence to ensure all previous operations are completed.
- **Output**: The function does not return a value; it modifies the memory cache in place to store the metadata for the given sequence.
- **Functions called**:
    - [`fd_mcache_line_idx`](#fd_mcache_line_idx)


---
### fd\_mcache\_publish\_avx<!-- {{#callable:fd_mcache_publish_avx}} -->
The `fd_mcache_publish_avx` function publishes metadata for a fragment sequence into a memory cache using AVX instructions, ensuring atomicity and memory consistency.
- **Inputs**:
    - `mcache`: A pointer to the memory cache where the metadata will be published, assumed to be a current local join.
    - `depth`: The depth of the cache, assumed to be an integer power-of-2 and at least equal to BLOCK.
    - `seq`: The sequence number of the fragment being published.
    - `sig`: The signature associated with the fragment.
    - `chunk`: The chunk identifier, assumed to be in the range [0, UINT_MAX].
    - `sz`: The size of the fragment, assumed to be in the range [0, USHORT_MAX].
    - `ctl`: The control flags for the fragment, assumed to be in the range [0, USHORT_MAX].
    - `tsorig`: The original timestamp of the fragment, assumed to be in the range [0, UINT_MAX].
    - `tspub`: The publication timestamp of the fragment, assumed to be in the range [0, UINT_MAX].
- **Control Flow**:
    - Calculate the index in the cache where the metadata for the given sequence number should be stored using [`fd_mcache_line_idx`](#fd_mcache_line_idx).
    - Create a 256-bit AVX register containing the metadata using `fd_frag_meta_avx`.
    - Insert a compiler memory fence to ensure memory operations are not reordered.
    - Store the 256-bit AVX metadata into the cache using a volatile store to ensure atomicity, as some compilers may split the store into non-atomic operations.
    - Insert another compiler memory fence to ensure memory consistency after the store.
- **Output**: The function does not return a value; it modifies the memory cache in place to store the metadata for the specified fragment sequence.
- **Functions called**:
    - [`fd_mcache_line_idx`](#fd_mcache_line_idx)


---
### fd\_mcache\_query<!-- {{#callable:fd_mcache_query}} -->
The `fd_mcache_query` function retrieves the sequence number from a metadata cache for a given query sequence number, considering the cache's depth.
- **Inputs**:
    - `mcache`: A pointer to the metadata cache (fd_frag_meta_t const *) from which the sequence number is to be queried.
    - `depth`: The depth of the metadata cache, which is an integer power of two and at least FD_MCACHE_BLOCK.
    - `seq_query`: The sequence number to be queried in the metadata cache.
- **Control Flow**:
    - Calculate the index in the metadata cache using [`fd_mcache_line_idx`](#fd_mcache_line_idx) with `seq_query` and `depth`.
    - Retrieve the sequence number at the calculated index using `fd_frag_meta_seq_query`.
    - Return the retrieved sequence number.
- **Output**: The function returns the sequence number from the metadata cache corresponding to the queried sequence number, which may be the same, earlier, or later than `seq_query` depending on the cache state.
- **Functions called**:
    - [`fd_mcache_line_idx`](#fd_mcache_line_idx)


# Function Declarations (Public API)

---
### fd\_mcache\_align<!-- {{#callable_declaration:fd_mcache_align}} -->
Returns the required alignment for a memory region suitable for use as an mcache.
- **Description**: Use this function to obtain the alignment requirement for a memory region intended to be used as an mcache. This alignment is necessary to ensure proper memory access and performance characteristics, such as mitigating false sharing. The function is typically used during the setup or configuration phase of an mcache to ensure that the memory region is correctly aligned before use.
- **Inputs**: None
- **Output**: Returns the alignment requirement as an unsigned long integer, which is a constant value defined by FD_MCACHE_ALIGN.
- **See also**: [`fd_mcache_align`](fd_mcache.c.driver.md#fd_mcache_align)  (Implementation)


---
### fd\_mcache\_footprint<!-- {{#callable_declaration:fd_mcache_footprint}} -->
Calculates the memory footprint required for an mcache with specified depth and application size.
- **Description**: Use this function to determine the total memory footprint needed for an mcache with a given number of entries (depth) and an application-specific region size (app_sz). This function is useful for validating mcache configuration parameters before allocation. It returns 0 if the depth is not a power of two, is less than FD_MCACHE_BLOCK, or if the calculated footprint exceeds ULONG_MAX, indicating invalid parameters.
- **Inputs**:
    - `depth`: The number of entries in the mcache, which must be a power of two and at least FD_MCACHE_BLOCK. If this condition is not met, the function returns 0.
    - `app_sz`: The size of the application-specific region in bytes. The function aligns this size to FD_MCACHE_ALIGN. If the aligned size overflows, the function returns 0.
- **Output**: Returns the total memory footprint in bytes required for the mcache, or 0 if the input parameters are invalid.
- **See also**: [`fd_mcache_footprint`](fd_mcache.c.driver.md#fd_mcache_footprint)  (Implementation)


---
### fd\_mcache\_new<!-- {{#callable_declaration:fd_mcache_new}} -->
Formats a memory region for use as a metadata cache (mcache).
- **Description**: This function initializes a given memory region to be used as a metadata cache (mcache) with a specified number of entries and an application-specific region. It should be called with a properly aligned and sized memory region. The function sets up the mcache to handle sequence numbers starting from a given initial sequence number, ensuring that consumers can correctly interpret the cache's state immediately after creation. The application region within the mcache is zero-initialized. The function returns the pointer to the formatted memory region on success or NULL if the input parameters are invalid, logging the reason for failure.
- **Inputs**:
    - `shmem`: A non-NULL pointer to the memory region to be formatted as an mcache. The memory must be aligned to FD_MCACHE_ALIGN and have a sufficient footprint as determined by fd_mcache_footprint. If the pointer is NULL or misaligned, the function returns NULL.
    - `depth`: The number of cache entries, which must be an integer power of 2 and at least FD_MCACHE_BLOCK. If the depth is invalid, the function returns NULL.
    - `app_sz`: The size of the application-specific region within the mcache. The combination of depth and app_sz must not result in a footprint larger than ULONG_MAX. If invalid, the function returns NULL.
    - `seq0`: The initial sequence number for the mcache. This is used to initialize the sequence tracking within the mcache.
- **Output**: Returns the pointer to the formatted memory region on success, or NULL on failure.
- **See also**: [`fd_mcache_new`](fd_mcache.c.driver.md#fd_mcache_new)  (Implementation)


---
### fd\_mcache\_join<!-- {{#callable_declaration:fd_mcache_join}} -->
Joins the caller to an mcache.
- **Description**: This function is used to join a caller to a memory cache (mcache) by providing a pointer to the shared memory region backing the mcache. It is essential to ensure that the provided pointer is correctly aligned and points to a valid mcache region. The function returns a pointer to the mcache's entries, which is not simply a cast of the input pointer. This function should be followed by a corresponding leave operation to properly manage the join lifecycle. It is important to handle the return value correctly, as a NULL return indicates a failure due to invalid input or misalignment.
- **Inputs**:
    - `shmcache`: A pointer to the first byte of the memory region backing the mcache in the caller's address space. It must not be null and must be aligned according to the mcache's alignment requirements. If the pointer is null or misaligned, the function logs a warning and returns NULL.
- **Output**: Returns a pointer to the mcache's entries on success, or NULL on failure if the input is invalid or misaligned.
- **See also**: [`fd_mcache_join`](fd_mcache.c.driver.md#fd_mcache_join)  (Implementation)


---
### fd\_mcache\_leave<!-- {{#callable_declaration:fd_mcache_leave}} -->
Leaves a current local join to an mcache.
- **Description**: Use this function to leave a previously joined mcache, which is necessary to properly manage resources and ensure that the shared memory region is not accessed after leaving. This function should be called after you are done using the mcache to ensure that all resources are released appropriately. It is important to match every successful join with a corresponding leave to maintain proper resource management. The function will return a pointer to the underlying shared memory region if successful, or NULL if the mcache parameter is NULL, logging a warning in such cases.
- **Inputs**:
    - `mcache`: A pointer to the mcache that the caller is currently joined to. Must not be NULL. If NULL, the function logs a warning and returns NULL.
- **Output**: Returns a pointer to the underlying shared memory region on success, or NULL if the mcache parameter is NULL.
- **See also**: [`fd_mcache_leave`](fd_mcache.c.driver.md#fd_mcache_leave)  (Implementation)


---
### fd\_mcache\_delete<!-- {{#callable_declaration:fd_mcache_delete}} -->
Unformats a memory region used as a mcache.
- **Description**: Use this function to unformat a memory region that was previously formatted as a mcache, assuming no threads are currently joined to it. This function is typically called when the mcache is no longer needed, and the memory region is to be repurposed or released. It checks for a valid mcache by verifying alignment and a magic number. If the checks fail, it logs a warning and returns NULL. On success, it returns the original pointer to the shared memory region, transferring ownership back to the caller.
- **Inputs**:
    - `shmcache`: A pointer to the memory region to be unformatted. It must not be NULL, must be properly aligned according to fd_mcache_align(), and must have a valid mcache magic number. If these conditions are not met, the function logs a warning and returns NULL.
- **Output**: Returns the original pointer to the shared memory region on success, or NULL if the input is invalid.
- **See also**: [`fd_mcache_delete`](fd_mcache.c.driver.md#fd_mcache_delete)  (Implementation)


---
### fd\_mcache\_depth<!-- {{#callable_declaration:fd_mcache_depth}} -->
Retrieve the depth of the mcache.
- **Description**: Use this function to obtain the number of entries in a memory cache (mcache) that was specified during its construction. This function should be called only when the mcache is a current local join, meaning the caller has successfully joined the mcache and is interacting with it in the local address space. It is useful for understanding the capacity of the mcache and for operations that depend on the number of entries available.
- **Inputs**:
    - `mcache`: A pointer to a constant fd_frag_meta_t structure representing the mcache. It must not be null and should point to a valid mcache that the caller has joined. If the mcache is not a current local join, the behavior is undefined.
- **Output**: Returns an unsigned long representing the depth of the mcache, which is the number of entries it can hold.
- **See also**: [`fd_mcache_depth`](fd_mcache.c.driver.md#fd_mcache_depth)  (Implementation)


---
### fd\_mcache\_app\_sz<!-- {{#callable_declaration:fd_mcache_app_sz}} -->
Retrieve the application region size of a memory cache.
- **Description**: Use this function to obtain the size of the application-specific region within a memory cache. It is essential to call this function only after successfully joining the memory cache, as it assumes the cache is a current local join. This function is useful when you need to know the allocated size for application-specific data within the cache.
- **Inputs**:
    - `mcache`: A pointer to a constant fd_frag_meta_t structure representing the memory cache. It must not be null and should point to a valid, joined memory cache. Passing an invalid or null pointer results in undefined behavior.
- **Output**: Returns an unsigned long representing the size of the application region in bytes.
- **See also**: [`fd_mcache_app_sz`](fd_mcache.c.driver.md#fd_mcache_app_sz)  (Implementation)


---
### fd\_mcache\_seq0<!-- {{#callable_declaration:fd_mcache_seq0}} -->
Retrieve the initial sequence number for a given mcache.
- **Description**: Use this function to obtain the initial sequence number (seq0) that was set during the construction of a memory cache (mcache). This function is typically called after joining an mcache to understand the starting point for sequence numbers in the cache. It is important to ensure that the mcache pointer provided is a valid and current local join to the mcache.
- **Inputs**:
    - `mcache`: A pointer to a constant fd_frag_meta_t structure representing the mcache. It must be a valid and current local join to the mcache. If the pointer is invalid, the behavior is undefined.
- **Output**: Returns the initial sequence number (seq0) as an unsigned long integer.
- **See also**: [`fd_mcache_seq0`](fd_mcache.c.driver.md#fd_mcache_seq0)  (Implementation)


---
### fd\_mcache\_seq\_laddr\_const<!-- {{#callable_declaration:fd_mcache_seq_laddr_const}} -->
Retrieve the local address of the sequence array in a memory cache.
- **Description**: Use this function to obtain a constant pointer to the sequence array of a memory cache, which is indexed from 0 to FD_MCACHE_SEQ_CNT and aligned to FD_MCACHE_ALIGN. This function should be called when you need to access the sequence numbers in a memory cache that is currently joined in the local address space. The returned pointer's validity is tied to the lifetime of the join, and it is important to ensure that the memory cache is properly joined before calling this function.
- **Inputs**:
    - `mcache`: A pointer to a constant fd_frag_meta_t structure representing the memory cache. It must not be null and should be a current local join to the memory cache.
- **Output**: A constant pointer to the sequence array within the memory cache, which can be used to access sequence numbers.
- **See also**: [`fd_mcache_seq_laddr_const`](fd_mcache.c.driver.md#fd_mcache_seq_laddr_const)  (Implementation)


---
### fd\_mcache\_seq\_laddr<!-- {{#callable_declaration:fd_mcache_seq_laddr}} -->
Returns the local address of the sequence array in the mcache.
- **Description**: Use this function to obtain a pointer to the sequence array of an mcache, which is used to track sequence numbers. This function should be called only after successfully joining the mcache, as it assumes the mcache is a current local join. The returned pointer is valid for the duration of the join and provides access to an array indexed from 0 to FD_MCACHE_SEQ_CNT, with special meaning assigned to seq[0].
- **Inputs**:
    - `mcache`: A pointer to a fd_frag_meta_t structure representing the mcache. It must not be null and should be a current local join. If the mcache is not properly joined, the behavior is undefined.
- **Output**: A pointer to the sequence array in the local address space, which is aligned to FD_MCACHE_ALIGN.
- **See also**: [`fd_mcache_seq_laddr`](fd_mcache.c.driver.md#fd_mcache_seq_laddr)  (Implementation)


---
### fd\_mcache\_app\_laddr\_const<!-- {{#callable_declaration:fd_mcache_app_laddr_const}} -->
Retrieve the local address of the application-specific region in a memory cache.
- **Description**: This function provides access to the application-specific region of a memory cache, which is intended for custom usage by the application. It should be called when the caller is already joined to the memory cache, ensuring that the memory cache is properly initialized and accessible. The returned pointer is valid for the duration of the join and provides a const-correct view of the application region, which is aligned to FD_MCACHE_ALIGN and has a size determined by fd_mcache_app_sz().
- **Inputs**:
    - `mcache`: A pointer to a constant fd_frag_meta_t structure representing the memory cache. It must not be null and should point to a valid, joined memory cache. If the pointer is invalid, the behavior is undefined.
- **Output**: A constant pointer to an unsigned char, representing the start of the application-specific region in the local address space.
- **See also**: [`fd_mcache_app_laddr_const`](fd_mcache.c.driver.md#fd_mcache_app_laddr_const)  (Implementation)


---
### fd\_mcache\_app\_laddr<!-- {{#callable_declaration:fd_mcache_app_laddr}} -->
Returns the local address of the application-specific region in the mcache.
- **Description**: Use this function to obtain a pointer to the application-specific memory region within a memory cache (mcache) that has been joined in the local address space. This function should be called only after successfully joining the mcache, as it assumes the mcache is a current local join. The returned pointer is aligned according to FD_MCACHE_ALIGN and the size of the region is determined by fd_mcache_app_sz. The lifetime of the returned pointer is tied to the mcache join.
- **Inputs**:
    - `mcache`: A pointer to a joined mcache structure. It must not be null and should be a valid mcache that the caller has joined locally. If the mcache is not properly joined, the behavior is undefined.
- **Output**: Returns a pointer to the application-specific region within the mcache, aligned to FD_MCACHE_ALIGN.
- **See also**: [`fd_mcache_app_laddr`](fd_mcache.c.driver.md#fd_mcache_app_laddr)  (Implementation)


