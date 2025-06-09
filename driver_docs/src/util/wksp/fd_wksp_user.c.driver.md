# Purpose
The provided C source code file is part of a memory management system, specifically dealing with workspace partitioning and allocation. It defines a set of private and public functions for managing memory partitions within a workspace (`fd_wksp_t`). The primary functionality includes splitting and merging memory partitions, allocating and freeing memory, and converting between local and global addresses. The file contains both internal functions (prefixed with `fd_wksp_private_`) for handling low-level partition operations and public APIs for user interaction with the workspace.

The internal functions, such as [`fd_wksp_private_split_before`](#fd_wksp_private_split_before), [`fd_wksp_private_split_after`](#fd_wksp_private_split_after), [`fd_wksp_private_merge_before`](#fd_wksp_private_merge_before), and [`fd_wksp_private_merge_after`](#fd_wksp_private_merge_after), manage the splitting and merging of partitions to optimize memory usage. These functions ensure that partitions are correctly indexed and managed within the workspace's data structures, such as idle stacks and treaps. The public APIs, including [`fd_wksp_alloc_at_least`](#fd_wksp_alloc_at_least), [`fd_wksp_free`](#fd_wksp_free), [`fd_wksp_tag`](#fd_wksp_tag), and [`fd_wksp_usage`](#fd_wksp_usage), provide users with the ability to allocate, free, and query memory within the workspace. These functions handle synchronization and error checking to maintain the integrity of the workspace. The file is designed to be part of a larger system, likely a memory allocator or a custom memory management library, providing both low-level and high-level interfaces for efficient memory management.
# Imports and Dependencies

---
- `fd_wksp_private.h`


# Functions

---
### fd\_wksp\_private\_split\_before<!-- {{#callable:fd_wksp_private_split_before}} -->
The `fd_wksp_private_split_before` function splits a given partition into two, creating a new partition immediately before the original one and returns the index of the new partition.
- **Inputs**:
    - `i2`: The index of the original partition to be split, within the range [0, part_max).
    - `s2`: The size of the new partition to be created, which must be in the range (0, size of i2).
    - `wksp`: A pointer to the current workspace structure, representing the local join.
    - `pinfo`: A pointer to the private partition information array associated with the workspace.
- **Control Flow**:
    - Calculate the new end address `g2` for the new partition by subtracting `s2` from the old end address `g3` of the original partition `i2`.
    - Determine the start address `g1` for the new partition from the original partition's start address.
    - Retrieve the index `i0` of the partition preceding `i2` and pop an index `i1` from the idle stack for the new partition.
    - Initialize the new partition `i1` with calculated addresses, zero tag, and update its linkage to the surrounding partitions.
    - Update the original partition `i2` to start at the new end address `g2` and link it to the new partition `i1`.
    - Adjust the workspace's head index or the next index of the preceding partition `i0` to point to the new partition `i1`.
    - Return the index `i1` of the newly created partition.
- **Output**: The function returns the index of the newly created partition, which is in the range [0, part_max).
- **Functions called**:
    - [`fd_wksp_private_pinfo_idx`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_idx)
    - [`fd_wksp_private_idle_stack_pop`](fd_wksp_private.h.driver.md#fd_wksp_private_idle_stack_pop)
    - [`fd_wksp_private_pinfo_cidx`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_cidx)
    - [`fd_wksp_private_pinfo_idx_is_null`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_idx_is_null)


---
### fd\_wksp\_private\_split\_after<!-- {{#callable:fd_wksp_private_split_after}} -->
The `fd_wksp_private_split_after` function splits a workspace partition into two, creating a new partition immediately after the specified partition.
- **Inputs**:
    - `i1`: The index of the original partition to be split, within the range [0, part_max).
    - `s1`: The size of the new partition to be created, which must be greater than 0 and less than the size of the original partition.
    - `wksp`: A pointer to the current workspace structure, representing the local join.
    - `pinfo`: A pointer to the private partition information array associated with the workspace.
- **Control Flow**:
    - Calculate the starting and ending global addresses for the new partition based on the original partition's addresses and the specified size `s1`.
    - Pop an index from the idle stack to use for the new partition and determine the index of the partition following the original partition.
    - Initialize the new partition's metadata, including its global address range, tag, and various index pointers.
    - Update the original partition's metadata to reflect the split, adjusting its ending address and next partition index.
    - If the original partition was the last in the list, update the workspace's tail index; otherwise, update the previous index of the partition following the original partition.
    - Return the index of the newly created partition.
- **Output**: The function returns the index of the newly created partition, which is within the range [0, part_max).
- **Functions called**:
    - [`fd_wksp_private_idle_stack_pop`](fd_wksp_private.h.driver.md#fd_wksp_private_idle_stack_pop)
    - [`fd_wksp_private_pinfo_idx`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_idx)
    - [`fd_wksp_private_pinfo_cidx`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_cidx)
    - [`fd_wksp_private_pinfo_idx_is_null`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_idx_is_null)


---
### fd\_wksp\_private\_merge\_before<!-- {{#callable:fd_wksp_private_merge_before}} -->
The `fd_wksp_private_merge_before` function merges a partition `i1` into its succeeding partition `i2` in a workspace, updating the workspace's partition information and pushing `i1` onto the idle stack for future use.
- **Inputs**:
    - `i1`: The index of the partition to be merged, which is immediately before `i2` and will be pushed onto the idle stack after merging.
    - `i2`: The index of the partition into which `i1` will be merged.
    - `wksp`: A pointer to the current workspace structure, representing the local join.
    - `pinfo`: A pointer to the partition information array associated with the workspace, used to access and modify partition details.
- **Control Flow**:
    - Retrieve the index `i0` of the partition preceding `i1` using [`fd_wksp_private_pinfo_idx`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_idx) and `pinfo[i1].prev_cidx`.
    - Update `pinfo[i2].gaddr_lo` to `pinfo[i1].gaddr_lo`, effectively merging the address range of `i1` into `i2`.
    - Set `pinfo[i2].prev_cidx` to the index of `i0`, linking `i2` to the partition before `i1`.
    - If `i0` is null, update `wksp->part_head_cidx` to point to `i2`, making `i2` the new head of the partition list; otherwise, set `pinfo[i0].next_cidx` to point to `i2`, maintaining the linked list structure.
    - Push `i1` onto the idle stack using [`fd_wksp_private_idle_stack_push`](fd_wksp_private.h.driver.md#fd_wksp_private_idle_stack_push), making its index available for future allocations.
- **Output**: The function does not return a value; it modifies the workspace and partition information in place.
- **Functions called**:
    - [`fd_wksp_private_pinfo_idx`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_idx)
    - [`fd_wksp_private_pinfo_cidx`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_cidx)
    - [`fd_wksp_private_pinfo_idx_is_null`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_idx_is_null)
    - [`fd_wksp_private_idle_stack_push`](fd_wksp_private.h.driver.md#fd_wksp_private_idle_stack_push)


---
### fd\_wksp\_private\_merge\_after<!-- {{#callable:fd_wksp_private_merge_after}} -->
The `fd_wksp_private_merge_after` function merges two adjacent partitions in a workspace, specifically merging the partition at index `i2` into the partition at index `i1`, and then pushes the index `i2` onto the idle stack for future use.
- **Inputs**:
    - `i1`: The index of the first partition in the workspace, in the range [0, part_max).
    - `i2`: The index of the second partition, which is adjacent to `i1` and will be merged into `i1`, in the range [0, part_max).
    - `wksp`: A pointer to the current local join of the workspace.
    - `pinfo`: A pointer to the private partition information array associated with the workspace.
- **Control Flow**:
    - Retrieve the index `i3` of the partition following `i2` using [`fd_wksp_private_pinfo_idx`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_idx) on `pinfo[i2].next_cidx`.
    - Update `pinfo[i1].gaddr_hi` to `pinfo[i2].gaddr_hi`, effectively extending the partition `i1` to include `i2`.
    - Set `pinfo[i1].next_cidx` to the index of `i3`, linking `i1` to the partition after `i2`.
    - If `i3` is null (indicating `i2` was the last partition), update `wksp->part_tail_cidx` to point to `i1`. Otherwise, update `pinfo[i3].prev_cidx` to point to `i1`, maintaining the linked list structure.
    - Push `i2` onto the idle stack using [`fd_wksp_private_idle_stack_push`](fd_wksp_private.h.driver.md#fd_wksp_private_idle_stack_push), making it available for future allocations.
- **Output**: The function does not return a value; it modifies the workspace and partition information in place.
- **Functions called**:
    - [`fd_wksp_private_pinfo_idx`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_idx)
    - [`fd_wksp_private_pinfo_cidx`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_cidx)
    - [`fd_wksp_private_pinfo_idx_is_null`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_idx_is_null)
    - [`fd_wksp_private_idle_stack_push`](fd_wksp_private.h.driver.md#fd_wksp_private_idle_stack_push)


---
### fd\_wksp\_private\_free<!-- {{#callable:fd_wksp_private_free}} -->
The `fd_wksp_private_free` function frees a specified partition in a workspace, updates the workspace's data structures, and merges adjacent free partitions if possible.
- **Inputs**:
    - `i`: The index of the partition to free, which should be in the range [0, part_max).
    - `wksp`: A pointer to the current local join of the workspace.
    - `pinfo`: A pointer to the private partition information array associated with the workspace.
- **Control Flow**:
    - The function begins by setting the tag of the partition at index `i` to 0, indicating it is free, and uses memory fences to ensure memory ordering.
    - It attempts to remove the partition from the used treap; if this fails, it logs a warning and exits.
    - The function checks the previous partition; if it is free, it removes it from the free treap, merges it with the current partition, and logs a warning if removal fails.
    - Similarly, it checks the next partition; if it is free, it removes it from the free treap, merges it with the current partition, and logs a warning if removal fails.
    - Finally, it attempts to insert the now-free partition into the free treap and logs a warning if this fails.
    - If the `FD_HAS_DEEPASAN` flag is set, it poisons the data region of the freed allocation to help detect memory errors.
- **Output**: The function does not return a value; it modifies the workspace and partition information in place.
- **Functions called**:
    - [`fd_wksp_private_used_treap_remove`](fd_wksp_used_treap.c.driver.md#fd_wksp_private_used_treap_remove)
    - [`fd_wksp_private_pinfo_idx`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_idx)
    - [`fd_wksp_private_free_treap_remove`](fd_wksp_free_treap.c.driver.md#fd_wksp_private_free_treap_remove)
    - [`fd_wksp_private_merge_before`](#fd_wksp_private_merge_before)
    - [`fd_wksp_private_merge_after`](#fd_wksp_private_merge_after)
    - [`fd_wksp_private_free_treap_insert`](fd_wksp_free_treap.c.driver.md#fd_wksp_private_free_treap_insert)
    - [`fd_wksp_laddr_fast`](fd_wksp.h.driver.md#fd_wksp_laddr_fast)


---
### fd\_wksp\_laddr<!-- {{#callable:fd_wksp_laddr}} -->
The `fd_wksp_laddr` function converts a global address to a local address within a workspace, ensuring the address is valid and within the workspace's bounds.
- **Inputs**:
    - `wksp`: A pointer to a constant `fd_wksp_t` structure representing the workspace.
    - `gaddr`: An unsigned long integer representing the global address to be converted to a local address.
- **Control Flow**:
    - Check if the `wksp` pointer is NULL; if so, log a warning and return NULL.
    - Check if `gaddr` is zero; if so, return NULL as it maps to a NULL address.
    - Verify that `gaddr` is within the valid range defined by `wksp->gaddr_lo` and `wksp->gaddr_hi`; if not, log a warning and return NULL.
    - If all checks pass, call [`fd_wksp_laddr_fast`](fd_wksp.h.driver.md#fd_wksp_laddr_fast) with `wksp` and `gaddr` to perform the conversion and return the result.
- **Output**: A pointer to the local address corresponding to the given global address, or NULL if the input is invalid or out of bounds.
- **Functions called**:
    - [`fd_wksp_laddr_fast`](fd_wksp.h.driver.md#fd_wksp_laddr_fast)


---
### fd\_wksp\_gaddr<!-- {{#callable:fd_wksp_gaddr}} -->
The `fd_wksp_gaddr` function converts a local address to a global address within a workspace, ensuring the address is valid within the workspace's address range.
- **Inputs**:
    - `wksp`: A pointer to a constant `fd_wksp_t` structure representing the workspace.
    - `laddr`: A constant pointer to the local address to be converted to a global address.
- **Control Flow**:
    - Check if the `wksp` pointer is NULL; if so, log a warning and return 0UL.
    - Check if the `laddr` pointer is NULL; if so, return 0UL as NULL maps to 'NULL'.
    - Call [`fd_wksp_gaddr_fast`](fd_wksp.h.driver.md#fd_wksp_gaddr_fast) to convert the local address to a global address.
    - Check if the computed global address is within the valid range of the workspace's global addresses (`gaddr_lo` to `gaddr_hi`); if not, log a warning and return 0UL.
    - Return the computed global address.
- **Output**: The function returns the global address corresponding to the given local address, or 0UL if the input is invalid or out of range.
- **Functions called**:
    - [`fd_wksp_gaddr_fast`](fd_wksp.h.driver.md#fd_wksp_gaddr_fast)


---
### fd\_wksp\_alloc\_at\_least<!-- {{#callable:fd_wksp_alloc_at_least}} -->
The `fd_wksp_alloc_at_least` function allocates a memory partition in a workspace with a specified alignment, size, and tag, ensuring the allocation is at least the requested size.
- **Inputs**:
    - `wksp`: A pointer to the workspace (`fd_wksp_t`) where the memory allocation is to be made.
    - `align`: The alignment requirement for the allocation; if zero, a default alignment is used.
    - `sz`: The size of the memory to allocate.
    - `tag`: A tag to associate with the allocated memory partition.
    - `_lo`: A pointer to store the lower bound of the allocated memory partition.
    - `_hi`: A pointer to store the upper bound of the allocated memory partition.
- **Control Flow**:
    - Set alignment to a default if not provided and calculate the footprint of the allocation.
    - Check for invalid input conditions such as zero size, null workspace, non-power-of-two alignment, or zero tag, and log warnings if any are found.
    - Adjust alignment and size for AddressSanitizer (ASan) if enabled, ensuring proper alignment and size for memory poisoning requirements.
    - Check for size overflow and log a warning if detected.
    - Lock the workspace to ensure thread safety during allocation.
    - Query the free treap for a suitable partition that can accommodate the requested footprint.
    - If no suitable partition is found, log a warning and fail the allocation.
    - If a suitable partition is found, remove it from the free treap and prepare it for allocation.
    - Align the start of the partition and calculate the end based on the requested size.
    - Check if there are enough idle partitions to complete the allocation; if not, log a warning and fail.
    - Split the partition if necessary to fit the requested size and alignment tightly.
    - Insert the partition into the used treap and update its tag to make the allocation official.
    - Unpoison the allocated memory region if ASan is enabled.
    - Unlock the workspace and return the aligned start address of the allocated memory.
- **Output**: Returns the aligned start address of the allocated memory partition, or 0 if the allocation fails. The lower and upper bounds of the allocated partition are stored in the provided `_lo` and `_hi` pointers.
- **Functions called**:
    - [`fd_wksp_private_pinfo`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo)
    - [`fd_wksp_private_lock`](fd_wksp_admin.c.driver.md#fd_wksp_private_lock)
    - [`fd_wksp_private_free_treap_query`](fd_wksp_free_treap.c.driver.md#fd_wksp_private_free_treap_query)
    - [`fd_wksp_private_pinfo_idx_is_null`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_idx_is_null)
    - [`fd_wksp_private_unlock`](fd_wksp_private.h.driver.md#fd_wksp_private_unlock)
    - [`fd_wksp_private_free_treap_same_is_empty`](fd_wksp_private.h.driver.md#fd_wksp_private_free_treap_same_is_empty)
    - [`fd_wksp_private_free_treap_same_remove`](fd_wksp_private.h.driver.md#fd_wksp_private_free_treap_same_remove)
    - [`fd_wksp_private_free_treap_remove`](fd_wksp_free_treap.c.driver.md#fd_wksp_private_free_treap_remove)
    - [`fd_wksp_private_pinfo_idx`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_idx)
    - [`fd_wksp_private_free_treap_insert`](fd_wksp_free_treap.c.driver.md#fd_wksp_private_free_treap_insert)
    - [`fd_wksp_private_split_before`](#fd_wksp_private_split_before)
    - [`fd_wksp_private_split_after`](#fd_wksp_private_split_after)
    - [`fd_wksp_private_used_treap_insert`](fd_wksp_used_treap.c.driver.md#fd_wksp_private_used_treap_insert)
    - [`fd_wksp_laddr_fast`](fd_wksp.h.driver.md#fd_wksp_laddr_fast)


---
### fd\_wksp\_free<!-- {{#callable:fd_wksp_free}} -->
The `fd_wksp_free` function releases a previously allocated partition in a workspace based on a given global address.
- **Inputs**:
    - `wksp`: A pointer to the workspace (`fd_wksp_t`) from which a partition is to be freed.
    - `gaddr`: The global address (`ulong`) of the partition to be freed.
- **Control Flow**:
    - Check if `gaddr` is zero; if so, return immediately as there is nothing to free.
    - Check if `wksp` is NULL; if so, log a warning and return.
    - Retrieve the maximum number of partitions (`part_max`) and the partition information (`pinfo`) from the workspace.
    - Attempt to lock the workspace; if locking fails, return as details are logged internally.
    - Query the used treap to find the partition index `i` corresponding to `gaddr`.
    - If `i` is less than `part_max`, call [`fd_wksp_private_free`](#fd_wksp_private_free) to free the partition and log details.
    - Unlock the workspace after the operation.
    - If `i` is greater than or equal to `part_max` and not equal to `FD_WKSP_PRIVATE_PINFO_IDX_NULL`, log a warning indicating that `gaddr` does not appear to be a current workspace allocation.
- **Output**: The function does not return a value; it performs the operation of freeing a partition in the workspace.
- **Functions called**:
    - [`fd_wksp_private_pinfo`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo)
    - [`fd_wksp_private_lock`](fd_wksp_admin.c.driver.md#fd_wksp_private_lock)
    - [`fd_wksp_private_used_treap_query`](fd_wksp_used_treap.c.driver.md#fd_wksp_private_used_treap_query)
    - [`fd_wksp_private_free`](#fd_wksp_private_free)
    - [`fd_wksp_private_unlock`](fd_wksp_private.h.driver.md#fd_wksp_private_unlock)


---
### fd\_wksp\_tag<!-- {{#callable:fd_wksp_tag}} -->
The `fd_wksp_tag` function retrieves the tag associated with a given global address in a workspace.
- **Inputs**:
    - `wksp`: A pointer to the workspace (`fd_wksp_t`) from which the tag is to be retrieved.
    - `gaddr`: The global address (`ulong`) for which the tag is to be retrieved.
- **Control Flow**:
    - Check if the workspace pointer `wksp` is NULL; if so, return 0UL.
    - Retrieve the maximum number of partitions `part_max` and the partition information array `pinfo` from the workspace.
    - Attempt to lock the workspace; if locking fails, return 0UL.
    - Query the used treap for the index `i` corresponding to the global address `gaddr`.
    - If the index `i` is valid (i.e., less than `part_max`), retrieve the tag from `pinfo[i]`; otherwise, set the tag to 0UL.
    - Unlock the workspace.
    - Return the retrieved tag.
- **Output**: The function returns the tag (`ulong`) associated with the specified global address, or 0UL if the address is invalid or the workspace is NULL.
- **Functions called**:
    - [`fd_wksp_private_pinfo`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo)
    - [`fd_wksp_private_lock`](fd_wksp_admin.c.driver.md#fd_wksp_private_lock)
    - [`fd_wksp_private_used_treap_query`](fd_wksp_used_treap.c.driver.md#fd_wksp_private_used_treap_query)
    - [`fd_wksp_private_unlock`](fd_wksp_private.h.driver.md#fd_wksp_private_unlock)


---
### fd\_wksp\_tag\_query<!-- {{#callable:fd_wksp_tag_query}} -->
The `fd_wksp_tag_query` function queries a workspace for partitions with specific tags and returns information about them.
- **Inputs**:
    - `wksp`: A pointer to the workspace (`fd_wksp_t`) to be queried.
    - `tag`: A pointer to an array of tags (`ulong const *`) to search for in the workspace.
    - `tag_cnt`: The number of tags in the `tag` array to be queried.
    - `info`: A pointer to an array of `fd_wksp_tag_query_info_t` structures where information about matching partitions will be stored.
    - `info_max`: The maximum number of entries that can be stored in the `info` array.
- **Control Flow**:
    - Check if `tag_cnt` is zero and return 0 if true, as there are no tags to query.
    - Validate the input pointers `wksp`, `tag`, and `info` (if `info_max` is non-zero) and log warnings if any are invalid, returning 0.
    - Retrieve the maximum number of partitions (`part_max`) and the partition information array (`pinfo`) from the workspace.
    - Initialize `info_cnt` to zero to count the number of matching partitions found.
    - Lock the workspace to ensure thread safety and increment the workspace's `cycle_tag`.
    - Iterate over the partitions in the workspace using a loop, checking for corruption and marking each visited partition with the current `cycle_tag`.
    - For each partition, compare its tag with the tags in the `tag` array; if a match is found, store the partition's information in the `info` array if there is space.
    - Increment `info_cnt` for each matching partition found.
    - Unlock the workspace after the iteration is complete.
    - Return the count of matching partitions found (`info_cnt`).
- **Output**: The function returns the number of partitions that matched the specified tags (`info_cnt`).
- **Functions called**:
    - [`fd_wksp_private_pinfo`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo)
    - [`fd_wksp_private_lock`](fd_wksp_admin.c.driver.md#fd_wksp_private_lock)
    - [`fd_wksp_private_pinfo_idx`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_idx)
    - [`fd_wksp_private_pinfo_idx_is_null`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_idx_is_null)
    - [`fd_wksp_private_unlock`](fd_wksp_private.h.driver.md#fd_wksp_private_unlock)


---
### fd\_wksp\_tag\_free<!-- {{#callable:fd_wksp_tag_free}} -->
The `fd_wksp_tag_free` function frees all workspace partitions that match any of the specified tags.
- **Inputs**:
    - `wksp`: A pointer to the workspace (`fd_wksp_t`) from which partitions are to be freed.
    - `tag`: A pointer to an array of tags (`ulong const *`) that identify the partitions to be freed.
    - `tag_cnt`: The number of tags in the `tag` array (`ulong`).
- **Control Flow**:
    - Check if `tag_cnt` is zero; if so, return immediately as there are no tags to free.
    - Check if `wksp` or `tag` is NULL; if so, log a warning and return.
    - Retrieve the maximum number of partitions (`part_max`) and the private partition information (`pinfo`) from the workspace.
    - Attempt to lock the workspace; if locking fails, return.
    - Initialize a stack (`top`) to keep track of partitions to be freed and increment the workspace's `cycle_tag`.
    - Iterate over the partitions in the workspace using a loop, checking for corruption and marking visited partitions with the current `cycle_tag`.
    - For each partition, check if its tag matches any of the specified tags; if a match is found, push the partition onto the stack.
    - Once all partitions have been checked, iterate over the stack, freeing each partition using [`fd_wksp_private_free`](#fd_wksp_private_free).
    - Unlock the workspace after all matching partitions have been freed.
- **Output**: The function does not return a value; it performs its operations directly on the workspace.
- **Functions called**:
    - [`fd_wksp_private_pinfo`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo)
    - [`fd_wksp_private_lock`](fd_wksp_admin.c.driver.md#fd_wksp_private_lock)
    - [`fd_wksp_private_pinfo_idx`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_idx)
    - [`fd_wksp_private_pinfo_idx_is_null`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_idx_is_null)
    - [`fd_wksp_private_unlock`](fd_wksp_private.h.driver.md#fd_wksp_private_unlock)
    - [`fd_wksp_private_pinfo_cidx`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_cidx)
    - [`fd_wksp_private_free`](#fd_wksp_private_free)


---
### fd\_wksp\_memset<!-- {{#callable:fd_wksp_memset}} -->
The `fd_wksp_memset` function sets a specified memory region within a workspace to a given value.
- **Inputs**:
    - `wksp`: A pointer to the workspace (`fd_wksp_t`) where the memory region is located.
    - `gaddr`: A global address (`ulong`) within the workspace that identifies the starting point of the memory region to be set.
    - `c`: An integer value (`int`) to which the memory region will be set.
- **Control Flow**:
    - Check if the workspace pointer `wksp` is NULL and log a warning if it is, then return.
    - Retrieve the maximum number of partitions (`part_max`) and the private partition information (`pinfo`) for the workspace.
    - Attempt to lock the workspace; if locking fails, return immediately.
    - Query the used treap to find the partition index `i` corresponding to the global address `gaddr`.
    - If the index `i` is greater than or equal to `part_max`, set an error flag `err` to 1; otherwise, set the memory region starting at the local address corresponding to `gaddr` to the value `c` and set `err` to 0.
    - Unlock the workspace.
    - If an error occurred (i.e., `err` is 1), log a warning indicating that `gaddr` does not point to a current workspace allocation.
- **Output**: The function does not return a value; it performs an in-place operation on the workspace memory.
- **Functions called**:
    - [`fd_wksp_private_pinfo`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo)
    - [`fd_wksp_private_lock`](fd_wksp_admin.c.driver.md#fd_wksp_private_lock)
    - [`fd_wksp_private_used_treap_query`](fd_wksp_used_treap.c.driver.md#fd_wksp_private_used_treap_query)
    - [`fd_wksp_laddr_fast`](fd_wksp.h.driver.md#fd_wksp_laddr_fast)
    - [`fd_wksp_private_pinfo_sz`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_sz)
    - [`fd_wksp_private_unlock`](fd_wksp_private.h.driver.md#fd_wksp_private_unlock)


---
### fd\_wksp\_reset<!-- {{#callable:fd_wksp_reset}} -->
The `fd_wksp_reset` function resets a workspace by clearing all partition tags and rebuilding the workspace with a given seed.
- **Inputs**:
    - `wksp`: A pointer to the workspace (`fd_wksp_t`) to be reset.
    - `seed`: An unsigned integer used as a seed for rebuilding the workspace.
- **Control Flow**:
    - Check if the workspace pointer `wksp` is NULL and log a warning if so, then return.
    - If `FD_HAS_DEEPASAN` is defined, poison the entire workspace except the header and the `pinfo` array, then unpoison the `pinfo` array.
    - Retrieve the maximum number of partitions (`part_max`) and the `pinfo` array from the workspace.
    - Attempt to lock the workspace; if locking fails, return.
    - Iterate over each partition in the `pinfo` array and set its tag to 0.
    - Call [`fd_wksp_rebuild`](fd_wksp_admin.c.driver.md#fd_wksp_rebuild) with the workspace and seed to rebuild the workspace.
    - Unlock the workspace.
    - If [`fd_wksp_rebuild`](fd_wksp_admin.c.driver.md#fd_wksp_rebuild) returns an error, log a warning indicating a corrupt workspace.
- **Output**: The function does not return a value; it performs operations directly on the workspace.
- **Functions called**:
    - [`fd_wksp_footprint`](fd_wksp_admin.c.driver.md#fd_wksp_footprint)
    - [`fd_wksp_private_pinfo_off`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_off)
    - [`fd_wksp_private_pinfo`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo)
    - [`fd_wksp_private_lock`](fd_wksp_admin.c.driver.md#fd_wksp_private_lock)
    - [`fd_wksp_rebuild`](fd_wksp_admin.c.driver.md#fd_wksp_rebuild)
    - [`fd_wksp_private_unlock`](fd_wksp_private.h.driver.md#fd_wksp_private_unlock)


---
### fd\_wksp\_usage<!-- {{#callable:fd_wksp_usage}} -->
The `fd_wksp_usage` function calculates and returns the usage statistics of a workspace, including total, free, and used partitions, based on specified tags.
- **Inputs**:
    - `wksp`: A pointer to the workspace (`fd_wksp_t`) whose usage statistics are to be calculated.
    - `tag`: A pointer to an array of tags (`ulong const *`) used to filter which partitions are considered 'used'.
    - `tag_cnt`: The number of tags in the `tag` array.
    - `usage`: A pointer to an `fd_wksp_usage_t` structure where the usage statistics will be stored.
- **Control Flow**:
    - Check if the `usage` pointer is valid; if not, log a warning and return the `usage` pointer.
    - Initialize the `usage` structure to zero.
    - Check if the `wksp` pointer is valid; if not, log a warning and return the `usage` pointer.
    - Check if the `tag` pointer is valid when `tag_cnt` is non-zero; if not, log a warning and return the `usage` pointer.
    - Lock the workspace to ensure thread safety; if locking fails, log a warning and return the `usage` pointer.
    - Initialize `total_max` in the `usage` structure with the maximum number of partitions (`part_max`).
    - Iterate over each partition in the workspace using a cycle tag to detect corruption and avoid revisiting partitions.
    - For each partition, calculate its size and check if its tag matches any in the `tag` array to determine if it is 'used'.
    - Update the `usage` statistics for total, free, and used partitions based on the tag matching results.
    - Unlock the workspace and return the `usage` structure.
- **Output**: A pointer to the `fd_wksp_usage_t` structure containing the updated usage statistics.
- **Functions called**:
    - [`fd_wksp_private_pinfo`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo)
    - [`fd_wksp_private_lock`](fd_wksp_admin.c.driver.md#fd_wksp_private_lock)
    - [`fd_wksp_private_pinfo_idx`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_idx)
    - [`fd_wksp_private_pinfo_idx_is_null`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_idx_is_null)
    - [`fd_wksp_private_unlock`](fd_wksp_private.h.driver.md#fd_wksp_private_unlock)
    - [`fd_wksp_private_pinfo_sz`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_sz)


