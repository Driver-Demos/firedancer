# Purpose
The provided C header file, `fd_tcache.h`, defines a data structure and associated functions for managing a cache of unique 64-bit tags, known as `fd_tcache_t`. This cache is designed to efficiently handle deduplication tasks by storing the most recently observed unique tags, which can be useful in scenarios such as network traffic analysis where deduplication based on packet signatures is required. The implementation is optimized for large cache sizes, potentially handling millions of tags, and is designed to perform well in environments where memory is relatively inexpensive and tag duplication is common and temporally localized.

The file includes several macros and inline functions that define the cache's alignment and memory footprint requirements, as well as operations for creating, joining, and managing the cache. Key components include the `fd_tcache_private` structure, which holds metadata about the cache, and macros like `FD_TCACHE_INSERT` and `FD_TCACHE_QUERY` that facilitate efficient tag insertion and lookup. The cache uses a ring buffer to maintain the order of tags and a sparse linear-probed map for fast tag lookup, with optimizations for random access patterns. The header file is intended to be included in other C source files, providing a public API for interacting with the tag cache, and is designed to be used in performance-critical contexts, with considerations for NUMA and TLB optimizations.
# Imports and Dependencies

---
- `../fd_tango_base.h`


# Global Variables

---
### fd\_tcache\_new
- **Type**: `function pointer`
- **Description**: `fd_tcache_new` is a function that initializes a memory region for use as a tcache, which is a cache for storing the most recently observed unique 64-bit tags. It takes a pointer to a memory region (`shmem`), the number of unique tags to store (`depth`), and the number of slots for the map (`map_cnt`).
- **Use**: This function is used to format a memory region as a tcache, returning the pointer to the formatted region on success or NULL on failure.


---
### fd\_tcache\_join
- **Type**: `fd_tcache_t *`
- **Description**: The `fd_tcache_join` function is a global function that returns a pointer to an `fd_tcache_t` structure. This function is used to join a caller to a tcache, which is a cache of the most recently observed unique 64-bit tags. The function takes a pointer to the memory region backing the tcache as its parameter.
- **Use**: This function is used to establish a connection to a tcache, allowing the caller to access and manipulate the cache's entries.


---
### fd\_tcache\_leave
- **Type**: `function pointer`
- **Description**: `fd_tcache_leave` is a function that allows a caller to leave a current local join of a tcache, which is a cache of the most recently observed unique 64-bit tags. It returns a pointer to the underlying shared memory region on success, or NULL on failure.
- **Use**: This function is used to properly exit a tcache join, ensuring that resources are released and the shared memory region is returned to the caller.


---
### fd\_tcache\_delete
- **Type**: `function pointer`
- **Description**: The `fd_tcache_delete` is a function pointer that points to a function responsible for unformatting a memory region used as a tcache. It assumes that no one is joined to the region and returns a pointer to the underlying shared memory region or NULL if used incorrectly.
- **Use**: This function is used to delete a tcache, transferring ownership of the memory region back to the caller.


---
### \_fti\_tag\_oldest
- **Type**: `ulong`
- **Description**: The variable `_fti_tag_oldest` is a temporary variable used within the `FD_TCACHE_INSERT` macro to store the value of the oldest tag in the tcache ring before it is replaced by a new tag. This variable is of type `ulong`, which is an unsigned long integer, typically used for storing large non-negative integer values.
- **Use**: It is used to hold the value of the oldest tag in the tcache ring during the insertion process, allowing for its removal from the map if necessary.


# Data Structures

---
### fd\_tcache\_private
- **Type**: `struct`
- **Members**:
    - `magic`: A magic number used to verify the integrity of the structure, expected to be FD_TCACHE_MAGIC.
    - `depth`: Indicates the number of most recent unique tags the tcache will maintain.
    - `map_cnt`: Represents the number of slots in the sparse linear probed key-only map of tags.
    - `oldest`: Index of the oldest tag in the tcache, within the range [0, depth).
- **Description**: The `fd_tcache_private` structure is designed to manage a cache of the most recently observed unique 64-bit tags, optimized for deduplication tasks. It maintains a cyclic buffer (ring) of tags up to a specified depth, allowing efficient tracking and eviction of the oldest tags as new ones are inserted. The structure also includes a sparse map for quick lookup of tags, minimizing probe collisions and ensuring predictable cache operations. This design is particularly suited for high-performance environments where memory footprint is less of a concern compared to computational efficiency.


---
### fd\_tcache\_t
- **Type**: `typedef struct fd_tcache_private fd_tcache_t;`
- **Members**:
    - `magic`: A magic number used to verify the integrity of the tcache structure.
    - `depth`: The number of unique tags the tcache can maintain in its history.
    - `map_cnt`: The number of slots in the sparse linear probed key-only map for tags.
    - `oldest`: An index indicating the oldest tag in the tcache's ring buffer.
- **Description**: The `fd_tcache_t` structure is a specialized cache designed to store and manage a history of unique 64-bit tags, primarily for deduplication purposes. It is optimized for large depths and scenarios where tag duplication is common and temporally localized. The structure includes a cyclic ring buffer to maintain the order of tags and a sparse map for efficient tag lookup. The implementation is designed to minimize memory footprint while maintaining high computational efficiency, making it suitable for performance-critical applications. The structure is aligned to mitigate false sharing and is intended to be used with large memory pages to reduce TLB thrashing.


# Functions

---
### fd\_tcache\_map\_cnt\_default<!-- {{#callable:fd_tcache_map_cnt_default}} -->
The `fd_tcache_map_cnt_default` function calculates the default number of slots (`map_cnt`) for a tag cache map based on a given depth, ensuring it does not exceed system limits.
- **Inputs**:
    - `depth`: An unsigned long integer representing the depth of the tag cache, which must be a positive value.
- **Control Flow**:
    - Check if the input depth is zero or equals ULONG_MAX, returning 0 in either case to indicate an invalid depth or potential overflow.
    - Calculate the logarithm base 2 of (depth + 1) and add a predefined sparsity constant (`FD_TCACHE_SPARSE_DEFAULT`) to determine `lg_map_cnt`.
    - Check if `lg_map_cnt` exceeds 63, returning 0 if true to prevent overflow issues.
    - Return the value of 2 raised to the power of `lg_map_cnt`, which represents the default `map_cnt`.
- **Output**: Returns an unsigned long integer representing the default `map_cnt` for the given depth, or 0 if the depth is invalid or results in an overflow.


---
### fd\_tcache\_depth<!-- {{#callable:fd_tcache_depth}} -->
The `fd_tcache_depth` function retrieves the depth of a given tcache, which represents the number of unique tags it can store.
- **Inputs**:
    - `tcache`: A pointer to a constant `fd_tcache_t` structure, representing the tcache whose depth is to be retrieved.
- **Control Flow**:
    - The function is defined as a static inline function, indicating it is intended for use within the same translation unit and optimized for performance.
    - It directly accesses the `depth` field of the `fd_tcache_t` structure pointed to by `tcache`.
    - The function returns the value of the `depth` field.
- **Output**: The function returns an `ulong` representing the depth of the tcache, which is the number of unique tags it can store.


---
### fd\_tcache\_map\_cnt<!-- {{#callable:fd_tcache_map_cnt}} -->
The `fd_tcache_map_cnt` function retrieves the number of slots in the tag map of a given tcache.
- **Inputs**:
    - `tcache`: A pointer to a constant `fd_tcache_t` structure representing the tcache from which the map count is to be retrieved.
- **Control Flow**:
    - The function is defined as a static inline function, indicating it is intended for use within the same translation unit and should be inlined for performance.
    - It is marked with `FD_FN_PURE`, suggesting that the function has no side effects and its return value depends only on its input parameters.
    - The function directly accesses the `map_cnt` field of the `fd_tcache_t` structure pointed to by `tcache` and returns its value.
- **Output**: The function returns an `ulong` representing the number of slots in the tcache's map.


---
### fd\_tcache\_oldest\_laddr<!-- {{#callable:fd_tcache_oldest_laddr}} -->
The `fd_tcache_oldest_laddr` function returns a pointer to the 'oldest' field of a given `fd_tcache_t` structure.
- **Inputs**:
    - `tcache`: A pointer to an `fd_tcache_t` structure, representing a tag cache object.
- **Control Flow**:
    - The function takes a single argument, `tcache`, which is a pointer to an `fd_tcache_t` structure.
    - It returns the address of the `oldest` field within the `fd_tcache_t` structure.
- **Output**: A pointer to the `oldest` field of the `fd_tcache_t` structure, which is of type `ulong *`.


---
### fd\_tcache\_ring\_laddr<!-- {{#callable:fd_tcache_ring_laddr}} -->
The `fd_tcache_ring_laddr` function calculates the starting address of the ring buffer within a `fd_tcache_t` structure.
- **Inputs**:
    - `tcache`: A pointer to an `fd_tcache_t` structure, representing a tag cache object.
- **Control Flow**:
    - The function takes a pointer to a `fd_tcache_t` structure as input.
    - It casts the `tcache` pointer to a `ulong` pointer.
    - It returns the address of the fifth `ulong` element in the `tcache` structure, which corresponds to the start of the ring buffer.
- **Output**: A pointer to the start of the ring buffer within the `fd_tcache_t` structure.


---
### fd\_tcache\_map\_laddr<!-- {{#callable:fd_tcache_map_laddr}} -->
The `fd_tcache_map_laddr` function calculates and returns the local address of the map section within a `fd_tcache_t` structure.
- **Inputs**:
    - `tcache`: A pointer to a `fd_tcache_t` structure, representing a tag cache object.
- **Control Flow**:
    - The function takes a pointer to a `fd_tcache_t` structure as input.
    - It calculates the address by casting the `tcache` pointer to a `ulong` pointer.
    - It adds 4 to the pointer to skip the first four `ulong` fields of the structure.
    - It then adds the `depth` value from the `tcache` structure to the pointer to reach the start of the map section.
    - Finally, it returns the calculated address as a `ulong` pointer.
- **Output**: A `ulong` pointer representing the local address of the map section within the `fd_tcache_t` structure.


---
### fd\_tcache\_tag\_is\_null<!-- {{#callable:fd_tcache_tag_is_null}} -->
The `fd_tcache_tag_is_null` function checks if a given tag is equal to the predefined null tag value `FD_TCACHE_TAG_NULL`.
- **Inputs**:
    - `tag`: An unsigned long integer representing the tag to be checked against the null tag value.
- **Control Flow**:
    - The function compares the input `tag` with the constant `FD_TCACHE_TAG_NULL`.
    - If the `tag` is equal to `FD_TCACHE_TAG_NULL`, the function returns a non-zero value (true).
    - If the `tag` is not equal to `FD_TCACHE_TAG_NULL`, the function returns zero (false).
- **Output**: The function returns an integer: non-zero if the tag is null, and zero otherwise.


---
### fd\_tcache\_reset<!-- {{#callable:fd_tcache_reset}} -->
The `fd_tcache_reset` function resets a tcache's ring and map arrays to an empty state by setting all elements to a null tag value.
- **Inputs**:
    - `ring`: A pointer to the ring array, which stores the most recent tags in the tcache.
    - `depth`: The number of elements in the ring array, representing the history depth of the tcache.
    - `map`: A pointer to the map array, which is a sparse linear probed key-only map of tags currently in the tcache.
    - `map_cnt`: The number of elements in the map array, representing the number of slots available for storing tags.
- **Control Flow**:
    - Iterate over each index in the ring array up to the specified depth, setting each element to FD_TCACHE_TAG_NULL.
    - Iterate over each index in the map array up to the specified map_cnt, setting each element to FD_TCACHE_TAG_NULL.
    - Return 0UL, which represents the index of the oldest tag in the ring array, now reset.
- **Output**: The function returns 0UL, indicating the index of the oldest tag in the ring array, which is reset to an empty state.


---
### fd\_tcache\_map\_start<!-- {{#callable:fd_tcache_map_start}} -->
The `fd_tcache_map_start` function calculates the initial index in a tcache map to start probing for a given tag, assuming the map count is a power of two.
- **Inputs**:
    - `tag`: A non-null 64-bit unsigned long integer representing the tag for which the starting index in the map is to be calculated.
    - `map_cnt`: A positive integer power of 2 representing the number of slots in the tcache map.
- **Control Flow**:
    - The function takes two parameters: `tag` and `map_cnt`.
    - It performs a bitwise AND operation between `tag` and `map_cnt-1UL`.
    - The result of the bitwise operation is returned as the starting index for probing in the map.
- **Output**: The function returns an unsigned long integer representing the starting index in the tcache map for the given tag.


---
### fd\_tcache\_map\_next<!-- {{#callable:fd_tcache_map_next}} -->
The `fd_tcache_map_next` function calculates the next index to probe in a circular map given the current index and the map size.
- **Inputs**:
    - `idx`: The current index in the map, which is a non-negative integer.
    - `map_cnt`: The total number of slots in the map, which is a positive integer power of 2.
- **Control Flow**:
    - The function takes two arguments: `idx` and `map_cnt`.
    - It increments `idx` by 1.
    - It performs a bitwise AND operation between the incremented `idx` and `map_cnt-1UL` to ensure the result wraps around if it exceeds `map_cnt`.
    - The result is returned as the next index to probe.
- **Output**: The function returns an unsigned long integer representing the next index to probe in the map, ensuring it wraps around if necessary.


---
### fd\_tcache\_remove<!-- {{#callable:fd_tcache_remove}} -->
The `fd_tcache_remove` function removes a specified tag from a cache map if it exists and is not null.
- **Inputs**:
    - `map`: A pointer to an array of unsigned long integers representing the cache map.
    - `map_cnt`: The number of slots in the cache map, which must be a positive integer power of two.
    - `tag`: The tag to be removed from the cache map, represented as an unsigned long integer.
- **Control Flow**:
    - Check if the tag is not null using [`fd_tcache_tag_is_null`](#fd_tcache_tag_is_null); if it is null, exit the function as there is nothing to remove.
    - Use the `FD_TCACHE_QUERY` macro to search for the tag in the map; if not found, exit the function as there is nothing to remove.
    - If the tag is found, set the map slot containing the tag to `FD_TCACHE_TAG_NULL` to remove it.
    - Enter a loop to handle potential rehashing of subsequent tags in the map to fill the hole left by the removed tag.
    - In the inner loop, find the next slot in the map using [`fd_tcache_map_next`](#fd_tcache_map_next) and check if it contains a null tag; if so, exit the function as the rehashing is complete.
    - If the next slot contains a non-null tag, calculate its starting position using [`fd_tcache_map_start`](#fd_tcache_map_start) and determine if it should be moved to the current hole position.
    - If the tag should be moved, break the inner loop and place the tag in the hole, then continue the outer loop to handle any further rehashing.
- **Output**: The function does not return a value; it modifies the cache map in place by removing the specified tag if it exists.
- **Functions called**:
    - [`fd_tcache_tag_is_null`](#fd_tcache_tag_is_null)
    - [`fd_tcache_map_next`](#fd_tcache_map_next)
    - [`fd_tcache_map_start`](#fd_tcache_map_start)


# Function Declarations (Public API)

---
### fd\_tcache\_align<!-- {{#callable_declaration:fd_tcache_align}} -->
Returns the required memory alignment for a tcache.
- **Description**: Use this function to determine the alignment requirement for a memory region intended to be used as a tcache. This is important for ensuring that the memory is correctly aligned to avoid performance penalties due to misalignment. The function is constant and does not depend on any input parameters, making it straightforward to use whenever you need to allocate or verify memory for a tcache.
- **Inputs**: None
- **Output**: Returns the alignment size in bytes as an unsigned long, which is the constant FD_TCACHE_ALIGN.
- **See also**: [`fd_tcache_align`](fd_tcache.c.driver.md#fd_tcache_align)  (Implementation)


---
### fd\_tcache\_footprint<!-- {{#callable_declaration:fd_tcache_footprint}} -->
Calculates the memory footprint required for a tcache with specified depth and map count.
- **Description**: This function computes the memory footprint necessary for a tcache given a specific depth and map count. It is useful for determining the memory allocation size needed before initializing a tcache. The function should be called with a positive depth and a map count that is a power of 2 and at least depth+2. If the map count is zero, a default value based on the depth will be used. The function returns zero if the input parameters are invalid or if the calculated footprint exceeds ULONG_MAX, allowing it to be used for validating tcache configuration parameters.
- **Inputs**:
    - `depth`: The number of unique tags the tcache can store. Must be a positive integer.
    - `map_cnt`: The number of slots in the tag map. Must be a power of 2 and at least depth+2. If zero, a default value is used.
- **Output**: Returns the calculated memory footprint in bytes, or 0 if the parameters are invalid or the footprint exceeds ULONG_MAX.
- **See also**: [`fd_tcache_footprint`](fd_tcache.c.driver.md#fd_tcache_footprint)  (Implementation)


---
### fd\_tcache\_new<!-- {{#callable_declaration:fd_tcache_new}} -->
Formats a memory region for use as a tcache.
- **Description**: This function initializes a memory region to be used as a tcache, which is a cache for storing the most recently observed unique 64-bit tags. It is useful for deduplication tasks. The function requires a non-null, properly aligned memory region with sufficient size to accommodate the tcache. The depth parameter specifies the number of unique tags the tcache can store, and map_cnt specifies the number of slots in the map. If map_cnt is zero, a default value is used. The function returns the initialized memory region on success or NULL if any parameter is invalid, logging the reason for failure.
- **Inputs**:
    - `shmem`: A pointer to the memory region to be formatted as a tcache. Must not be null and must be aligned according to fd_tcache_align(). The caller retains ownership.
    - `depth`: The number of unique tags the tcache can store. Must be a positive integer.
    - `map_cnt`: The number of slots in the map. If zero, a default value is used. Must be a power of 2 and at least depth+2 if not zero.
- **Output**: Returns the pointer to the formatted memory region on success, or NULL on failure.
- **See also**: [`fd_tcache_new`](fd_tcache.c.driver.md#fd_tcache_new)  (Implementation)


---
### fd\_tcache\_join<!-- {{#callable_declaration:fd_tcache_join}} -->
Joins the caller to an existing tcache.
- **Description**: Use this function to join a caller to an existing tcache, allowing access to its entries. It should be called with a valid pointer to the memory region backing the tcache. The function checks for null pointers, proper alignment, and a valid magic number to ensure the memory region is a valid tcache. If any of these checks fail, the function logs a warning and returns NULL. A successful join should be followed by a corresponding leave to properly manage resources.
- **Inputs**:
    - `_tcache`: A pointer to the first byte of the memory region backing the tcache in the caller's address space. Must not be null, must be properly aligned according to fd_tcache_align(), and must point to a valid tcache with the correct magic number. If these conditions are not met, the function returns NULL.
- **Output**: Returns a pointer to the tcache's entries on success, or NULL if the input is invalid.
- **See also**: [`fd_tcache_join`](fd_tcache.c.driver.md#fd_tcache_join)  (Implementation)


---
### fd\_tcache\_leave<!-- {{#callable_declaration:fd_tcache_leave}} -->
Leaves a current local join of a tcache.
- **Description**: This function is used to leave a current local join of a tcache, effectively ending the caller's association with the tcache. It should be called after a successful join to ensure proper resource management. The function returns a pointer to the underlying shared memory region, which can be used for further operations or cleanup. If the provided tcache pointer is NULL, the function logs a warning and returns NULL, indicating an error.
- **Inputs**:
    - `tcache`: A pointer to the fd_tcache_t structure representing the tcache to leave. Must not be NULL. If NULL, the function logs a warning and returns NULL.
- **Output**: Returns a pointer to the underlying shared memory region on success, or NULL if the tcache pointer is NULL.
- **See also**: [`fd_tcache_leave`](fd_tcache.c.driver.md#fd_tcache_leave)  (Implementation)


---
### fd\_tcache\_delete<!-- {{#callable_declaration:fd_tcache_delete}} -->
Unformats a memory region used as a tcache.
- **Description**: Use this function to unformat a memory region that was previously formatted as a tcache, effectively deleting the tcache structure. This function should be called when the tcache is no longer needed and you want to reclaim the memory for other uses. It is important to ensure that no threads are joined to the tcache when this function is called, as it assumes exclusive access to the memory region. The function will log a warning and return NULL if the provided pointer is NULL, misaligned, or does not point to a valid tcache.
- **Inputs**:
    - `_tcache`: A pointer to the memory region that is currently formatted as a tcache. The pointer must be non-NULL, properly aligned according to fd_tcache_align(), and must point to a valid tcache structure. The caller assumes ownership of the memory region after the function returns.
- **Output**: Returns a pointer to the underlying shared memory region if successful, or NULL if the input is invalid.
- **See also**: [`fd_tcache_delete`](fd_tcache.c.driver.md#fd_tcache_delete)  (Implementation)


