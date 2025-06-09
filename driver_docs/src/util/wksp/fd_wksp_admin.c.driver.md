# Purpose
The provided C source code file is part of a library that manages shared memory workspaces, specifically designed to handle concurrent access and ensure data integrity. The file defines several functions that facilitate the creation, management, and manipulation of these workspaces, which are represented by the `fd_wksp_t` structure. The primary functionality includes locking and unlocking workspaces, estimating maximum partition and data sizes, creating and joining workspaces, and verifying and rebuilding workspace integrity. The code also includes mechanisms for handling situations where a process holding a lock on a workspace dies, allowing for lock recovery and workspace verification or rebuilding if necessary.

The file provides a public API for interacting with the workspace, including functions like [`fd_wksp_new`](#fd_wksp_new), [`fd_wksp_join`](#fd_wksp_join), [`fd_wksp_leave`](#fd_wksp_leave), and [`fd_wksp_delete`](#fd_wksp_delete), which manage the lifecycle of a workspace. It also includes utility functions for estimating workspace parameters and handling errors. The code is designed to be robust against corruption and includes detailed logging and error handling to aid in debugging and maintenance. The use of atomic operations and memory fences ensures that the workspace can be safely accessed and modified in a concurrent environment, making it suitable for high-performance applications that require shared memory management.
# Imports and Dependencies

---
- `fd_wksp_private.h`
- `sys/mman.h`
- `errno.h`


# Functions

---
### fd\_wksp\_private\_lock<!-- {{#callable:fd_wksp_private_lock}} -->
The `fd_wksp_private_lock` function attempts to acquire a lock on a workspace, handling potential lock recovery if the previous owner process is dead.
- **Inputs**:
    - `wksp`: A pointer to the `fd_wksp_t` structure representing the workspace to be locked.
- **Control Flow**:
    - Initialize the current process ID and a pointer to the workspace's owner field.
    - Enter an infinite loop to attempt acquiring the lock.
    - Use a compare-and-swap (CAS) operation to try to set the owner to the current process ID if it is currently unowned (ULONG_MAX).
    - If the lock is successfully acquired, return success.
    - If lock reclaim is enabled, check the status of the current owner process ID.
    - If the owner process is dead, attempt to reclaim the lock and verify or rebuild the workspace if necessary.
    - If the owner process status is unknown, log a warning and retry.
    - If lock reclaim is not enabled, use a spin-lock approach to wait and retry acquiring the lock.
- **Output**: Returns `FD_WKSP_SUCCESS` if the lock is successfully acquired, or `FD_WKSP_ERR_CORRUPT` if the workspace is found to be corrupt during recovery.
- **Functions called**:
    - [`fd_wksp_verify`](#fd_wksp_verify)
    - [`fd_wksp_rebuild`](#fd_wksp_rebuild)


---
### fd\_wksp\_part\_max\_est<!-- {{#callable:fd_wksp_part_max_est}} -->
The `fd_wksp_part_max_est` function estimates the maximum number of partitions that can be created in a workspace given its footprint and a typical partition size.
- **Inputs**:
    - `footprint`: The total size of the workspace in bytes, which is aligned down to the nearest multiple of `FD_WKSP_ALIGN`.
    - `sz_typical`: The typical size of a partition in bytes.
- **Control Flow**:
    - Align the `footprint` down to the nearest multiple of `FD_WKSP_ALIGN`.
    - Calculate `data_end` as `footprint - 1UL`.
    - Retrieve the offset for private partition information using `fd_wksp_private_pinfo_off()`.
    - Calculate `consumed` as the sum of the size of `fd_wksp_private_pinfo_t` and `sz_typical`.
    - Compute `part_max` as the integer division of `(data_end - pinfo_off)` by `(consumed + (ulong)!consumed)` to avoid division by zero.
    - Check if any of the following conditions are true: `footprint` is zero, `sz_typical` is zero, `sz_typical` is greater than `consumed`, or `pinfo_off` is greater than `data_end`. If any condition is true, return `0UL`.
    - Return the minimum of `part_max` and `FD_WKSP_PRIVATE_PINFO_IDX_NULL`.
- **Output**: Returns an unsigned long integer representing the estimated maximum number of partitions that can be created, or `0UL` if the input conditions are invalid.
- **Functions called**:
    - [`fd_wksp_private_pinfo_off`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_off)


---
### fd\_wksp\_data\_max\_est<!-- {{#callable:fd_wksp_data_max_est}} -->
The `fd_wksp_data_max_est` function estimates the maximum data size that can be accommodated in a workspace given its footprint and partition maximum constraints.
- **Inputs**:
    - `footprint`: The total size of the workspace, aligned to `FD_WKSP_ALIGN`.
    - `part_max`: The maximum number of partitions allowed in the workspace.
- **Control Flow**:
    - Align the `footprint` to `FD_WKSP_ALIGN` using `fd_ulong_align_dn`.
    - Calculate `data_end` as `footprint - 1UL`.
    - Calculate `data_off` using `fd_wksp_private_data_off(part_max)`.
    - Check if any of the following conditions are true: `part_max` is zero, `part_max` exceeds `FD_WKSP_PRIVATE_PINFO_IDX_NULL`, `part_max` exceeds the maximum allowable partitions based on `ULONG_MAX`, `footprint` is zero, or `data_off` is greater than or equal to `data_end`.
    - If any condition is true, return `0UL`.
    - Otherwise, return the difference between `data_end` and `data_off`.
- **Output**: Returns the maximum data size that can be accommodated, or `0UL` if constraints are violated.
- **Functions called**:
    - [`fd_wksp_private_data_off`](fd_wksp_private.h.driver.md#fd_wksp_private_data_off)
    - [`fd_wksp_private_pinfo_off`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_off)


---
### fd\_wksp\_align<!-- {{#callable:fd_wksp_align}} -->
The `fd_wksp_align` function returns the alignment value used for workspace operations.
- **Inputs**: None
- **Control Flow**:
    - The function simply returns the value of the macro `FD_WKSP_ALIGN`.
- **Output**: The function outputs an unsigned long integer representing the alignment value `FD_WKSP_ALIGN`.


---
### fd\_wksp\_footprint<!-- {{#callable:fd_wksp_footprint}} -->
The `fd_wksp_footprint` function calculates the aligned memory footprint required for a workspace given the maximum number of partitions and data size.
- **Inputs**:
    - `part_max`: The maximum number of partitions that the workspace can handle.
    - `data_max`: The maximum size of the data that the workspace can accommodate.
- **Control Flow**:
    - Calculate the data offset using `fd_wksp_private_data_off(part_max)`.
    - Check if any of the following conditions are true: `part_max` is zero, `part_max` exceeds `FD_WKSP_PRIVATE_PINFO_IDX_NULL`, `data_max` is zero, `part_max` exceeds the maximum allowable partitions based on system limits, or `data_max` exceeds the maximum allowable data size based on system limits and calculated offsets.
    - If any of the above conditions are true, return 0UL indicating an invalid footprint.
    - Otherwise, calculate the aligned footprint using `fd_ulong_align_up(data_off + data_max + 1UL, FD_WKSP_ALIGN)` and return it.
- **Output**: The function returns an unsigned long integer representing the aligned memory footprint required for the workspace, or 0UL if the input parameters are invalid.
- **Functions called**:
    - [`fd_wksp_private_data_off`](fd_wksp_private.h.driver.md#fd_wksp_private_data_off)
    - [`fd_wksp_private_pinfo_off`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_off)


---
### fd\_wksp\_new<!-- {{#callable:fd_wksp_new}} -->
The `fd_wksp_new` function initializes a new workspace in a given shared memory region with specified parameters and returns a pointer to the initialized workspace.
- **Inputs**:
    - `shmem`: A pointer to the shared memory region where the workspace will be initialized.
    - `name`: A constant character pointer representing the name of the workspace.
    - `seed`: An unsigned integer used as a seed for randomization in the workspace.
    - `part_max`: An unsigned long representing the maximum number of partitions the workspace can handle.
    - `data_max`: An unsigned long representing the maximum data size the workspace can manage.
- **Control Flow**:
    - Cast the `shmem` pointer to a `fd_wksp_t` pointer named `wksp`.
    - Check if `wksp` is NULL or not aligned properly, logging a warning and returning NULL if so.
    - Calculate the length of `name` and check if it is valid, logging a warning and returning NULL if not.
    - Calculate the footprint of the workspace using `part_max` and `data_max`, logging a warning and returning NULL if invalid.
    - Clear the memory for the workspace header and partition info array using `fd_memset`.
    - Initialize various fields of the `wksp` structure, including `part_max`, `data_max`, `gaddr_lo`, `gaddr_hi`, `name`, `seed`, and several index fields.
    - Set the `cycle_tag` to 4 and `owner` to 0, indicating the workspace is locked and under construction.
    - Set the `magic` field to `FD_WKSP_MAGIC` to mark the workspace as initialized.
    - Call [`fd_wksp_rebuild`](#fd_wksp_rebuild) to rebuild the workspace structure, logging a warning and returning NULL if it fails.
    - If `FD_HAS_DEEPASAN` is defined, poison the workspace memory except for the header and partition info array, then unpoison the partition info array.
    - Unlock the workspace using [`fd_wksp_private_unlock`](fd_wksp_private.h.driver.md#fd_wksp_private_unlock).
- **Output**: Returns a pointer to the initialized `fd_wksp_t` structure if successful, or NULL if any error occurs during initialization.
- **Functions called**:
    - [`fd_wksp_footprint`](#fd_wksp_footprint)
    - [`fd_wksp_private_data_off`](fd_wksp_private.h.driver.md#fd_wksp_private_data_off)
    - [`fd_wksp_private_pinfo_cidx`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_cidx)
    - [`fd_wksp_rebuild`](#fd_wksp_rebuild)
    - [`fd_wksp_strerror`](#fd_wksp_strerror)
    - [`fd_wksp_private_pinfo_off`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_off)
    - [`fd_wksp_private_pinfo`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo)
    - [`fd_wksp_private_unlock`](fd_wksp_private.h.driver.md#fd_wksp_private_unlock)


---
### fd\_wksp\_join<!-- {{#callable:fd_wksp_join}} -->
The `fd_wksp_join` function validates and returns a pointer to a workspace structure if the provided shared workspace pointer is valid and correctly aligned.
- **Inputs**:
    - `shwksp`: A void pointer to a shared workspace that needs to be validated and joined.
- **Control Flow**:
    - Cast the input `shwksp` to a `fd_wksp_t` pointer named `wksp`.
    - Check if `wksp` is NULL; if so, log a warning and return NULL.
    - Check if `wksp` is not aligned to `FD_WKSP_ALIGN`; if not, log a warning and return NULL.
    - Check if `wksp->magic` is not equal to `FD_WKSP_MAGIC`; if not, log a warning and return NULL.
    - If all checks pass, return the `wksp` pointer.
- **Output**: Returns a pointer to the `fd_wksp_t` structure if the input is valid, otherwise returns NULL.


---
### fd\_wksp\_leave<!-- {{#callable:fd_wksp_leave}} -->
The `fd_wksp_leave` function checks if a workspace pointer is NULL and returns the workspace pointer if it is not.
- **Inputs**:
    - `wksp`: A pointer to a `fd_wksp_t` structure representing the workspace to be left.
- **Control Flow**:
    - Check if the `wksp` pointer is NULL using `FD_UNLIKELY` macro.
    - If `wksp` is NULL, log a warning message 'NULL wksp' and return NULL.
    - If `wksp` is not NULL, cast it to a `void *` and return it.
- **Output**: Returns the workspace pointer cast to a `void *`, or NULL if the input pointer is NULL.


---
### fd\_wksp\_delete<!-- {{#callable:fd_wksp_delete}} -->
The `fd_wksp_delete` function deletes a workspace by validating its alignment and magic number, then setting its magic number to zero and optionally unpoisoning its memory region.
- **Inputs**:
    - `shwksp`: A pointer to the shared workspace to be deleted, expected to be of type `fd_wksp_t *`.
- **Control Flow**:
    - Cast the input `shwksp` to a `fd_wksp_t *` type and store it in `wksp`.
    - Check if `wksp` is NULL; if so, log a warning and return NULL.
    - Check if `wksp` is not aligned to `FD_WKSP_ALIGN`; if not, log a warning and return NULL.
    - Check if `wksp->magic` is not equal to `FD_WKSP_MAGIC`; if not, log a warning and return NULL.
    - Perform a memory fence operation to ensure memory operations are completed before proceeding.
    - Set `wksp->magic` to 0 to mark the workspace as deleted.
    - Perform another memory fence operation to ensure the magic number update is visible to other threads.
    - If `FD_HAS_DEEPASAN` is defined, calculate the footprint of the workspace and unpoison the memory region using `fd_asan_unpoison`.
    - Return the `wksp` pointer.
- **Output**: Returns a pointer to the deleted workspace if successful, or NULL if any validation checks fail.
- **Functions called**:
    - [`fd_wksp_footprint`](#fd_wksp_footprint)
    - [`fd_wksp_private_pinfo_off`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_off)


---
### fd\_wksp\_name<!-- {{#callable:fd_wksp_name}} -->
The `fd_wksp_name` function retrieves the name of a given workspace.
- **Inputs**:
    - `wksp`: A pointer to a constant `fd_wksp_t` structure representing the workspace whose name is to be retrieved.
- **Control Flow**:
    - The function directly accesses the `name` field of the `wksp` structure and returns it.
- **Output**: A constant character pointer to the name of the workspace.


---
### fd\_wksp\_seed<!-- {{#callable:fd_wksp_seed}} -->
The `fd_wksp_seed` function retrieves the seed value from a given workspace structure.
- **Inputs**:
    - `wksp`: A pointer to a constant `fd_wksp_t` structure from which the seed value is to be retrieved.
- **Control Flow**:
    - The function accesses the `seed` member of the `wksp` structure and returns its value.
- **Output**: The function returns a `uint` representing the seed value of the workspace.


---
### fd\_wksp\_part\_max<!-- {{#callable:fd_wksp_part_max}} -->
The `fd_wksp_part_max` function retrieves the maximum number of partitions allowed in a given workspace.
- **Inputs**:
    - `wksp`: A pointer to a constant `fd_wksp_t` structure representing the workspace from which the maximum number of partitions is to be retrieved.
- **Control Flow**:
    - The function takes a single argument, `wksp`, which is a pointer to a constant `fd_wksp_t` structure.
    - It directly accesses the `part_max` member of the `wksp` structure.
    - The function returns the value of `wksp->part_max`.
- **Output**: The function returns an `ulong` representing the maximum number of partitions allowed in the specified workspace.


---
### fd\_wksp\_data\_max<!-- {{#callable:fd_wksp_data_max}} -->
The `fd_wksp_data_max` function retrieves the maximum data size that a workspace can handle from a given workspace structure.
- **Inputs**:
    - `wksp`: A pointer to a constant `fd_wksp_t` structure representing the workspace from which the maximum data size is to be retrieved.
- **Control Flow**:
    - The function accesses the `data_max` field of the `wksp` structure and returns its value.
- **Output**: The function returns an unsigned long integer representing the maximum data size (`data_max`) of the workspace.


---
### fd\_wksp\_owner<!-- {{#callable:fd_wksp_owner}} -->
The `fd_wksp_owner` function retrieves the current owner of a workspace in a thread-safe manner.
- **Inputs**:
    - `wksp`: A pointer to a constant `fd_wksp_t` structure representing the workspace whose owner is to be retrieved.
- **Control Flow**:
    - The function begins by executing a memory fence (`FD_COMPILER_MFENCE`) to ensure memory operations are completed before proceeding.
    - It then reads the `owner` field from the `wksp` structure using a volatile read (`FD_VOLATILE_CONST`) to prevent compiler optimizations that might reorder operations.
    - Another memory fence is executed to ensure the read operation is completed before any subsequent operations.
    - Finally, the function returns the value of the `owner` field.
- **Output**: The function returns an `ulong` representing the current owner of the workspace.


---
### fd\_wksp\_strerror<!-- {{#callable:fd_wksp_strerror}} -->
The `fd_wksp_strerror` function returns a string description of an error code related to workspace operations.
- **Inputs**:
    - `err`: An integer representing the error code for which a string description is needed.
- **Control Flow**:
    - The function uses a switch statement to match the input error code `err` with predefined error codes.
    - If `err` matches `FD_WKSP_SUCCESS`, it returns the string "success".
    - If `err` matches `FD_WKSP_ERR_INVAL`, it returns the string "inval".
    - If `err` matches `FD_WKSP_ERR_FAIL`, it returns the string "fail".
    - If `err` matches `FD_WKSP_ERR_CORRUPT`, it returns the string "corrupt".
    - If `err` does not match any predefined error codes, it returns the string "unknown".
- **Output**: A constant character pointer to a string that describes the error code.


---
### fd\_wksp\_verify<!-- {{#callable:fd_wksp_verify}} -->
The `fd_wksp_verify` function verifies the integrity of a workspace by checking its metadata, idle stack, partitioning, and treap structures for consistency and correctness.
- **Inputs**:
    - `wksp`: A pointer to the `fd_wksp_t` structure representing the workspace to be verified.
- **Control Flow**:
    - Define a macro `TEST` to log a warning and return an error if a condition is not met.
    - Validate the workspace metadata, including magic number, footprint, and address boundaries.
    - Clear cycle tags for all partitions in the workspace.
    - Verify the integrity of the idle stack by traversing it and marking visited nodes.
    - Verify the partitioning by checking adjacency, size, and uniqueness of partitions, and count free and used partitions.
    - Validate the used treap by ensuring heap properties and uniqueness of nodes, marking them as visited.
    - Validate the free treap by ensuring heap properties, size order, and uniqueness of nodes, marking them as visited.
    - Return success if all checks pass.
- **Output**: Returns `FD_WKSP_SUCCESS` if the workspace is verified successfully, otherwise returns `FD_WKSP_ERR_CORRUPT` if any inconsistency or corruption is detected.
- **Functions called**:
    - [`fd_wksp_footprint`](#fd_wksp_footprint)
    - [`fd_wksp_private_data_off`](fd_wksp_private.h.driver.md#fd_wksp_private_data_off)
    - [`fd_wksp_private_pinfo`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo)
    - [`fd_wksp_private_pinfo_idx`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_idx)
    - [`fd_wksp_private_pinfo_idx_is_null`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_idx_is_null)
    - [`fd_wksp_private_pinfo_cidx`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_cidx)
    - [`fd_wksp_private_pinfo_sz`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_sz)


---
### fd\_wksp\_rebuild<!-- {{#callable:fd_wksp_rebuild}} -->
The `fd_wksp_rebuild` function rebuilds the workspace's partitioning by verifying metadata, organizing partitions into used and idle structures, and ensuring data integrity.
- **Inputs**:
    - `wksp`: A pointer to the workspace structure (`fd_wksp_t`) that needs to be rebuilt.
    - `seed`: An unsigned integer used to randomize heap priorities during the rebuild process.
- **Control Flow**:
    - Check if the workspace pointer is NULL and return an error if so.
    - Load and verify workspace metadata, returning an error if any metadata is invalid.
    - Initialize the workspace's seed and reset the idle stack, used treap, and free treap indices.
    - Iterate over partitions in reverse order, assigning heap priorities and organizing them into idle or used structures based on their tags.
    - Traverse the used treap in order to rebuild the partitioning and fill any gaps with idle partitions, inserting them into the free treap.
    - Return success if the rebuild completes without detecting corruption.
- **Output**: Returns `FD_WKSP_SUCCESS` if the rebuild is successful, or `FD_WKSP_ERR_CORRUPT` if any corruption is detected.
- **Functions called**:
    - [`fd_wksp_footprint`](#fd_wksp_footprint)
    - [`fd_wksp_private_data_off`](fd_wksp_private.h.driver.md#fd_wksp_private_data_off)
    - [`fd_wksp_private_pinfo`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo)
    - [`fd_wksp_private_pinfo_cidx`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_cidx)
    - [`fd_wksp_private_idle_stack_push`](fd_wksp_private.h.driver.md#fd_wksp_private_idle_stack_push)
    - [`fd_wksp_private_used_treap_insert`](fd_wksp_used_treap.c.driver.md#fd_wksp_private_used_treap_insert)
    - [`fd_wksp_private_pinfo_idx`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_idx)
    - [`fd_wksp_private_pinfo_idx_is_null`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_idx_is_null)
    - [`fd_wksp_private_idle_stack_is_empty`](fd_wksp_private.h.driver.md#fd_wksp_private_idle_stack_is_empty)
    - [`fd_wksp_private_idle_stack_pop`](fd_wksp_private.h.driver.md#fd_wksp_private_idle_stack_pop)
    - [`fd_wksp_private_free_treap_insert`](fd_wksp_free_treap.c.driver.md#fd_wksp_private_free_treap_insert)


---
### fd\_wksp\_mprotect<!-- {{#callable:fd_wksp_mprotect}} -->
The `fd_wksp_mprotect` function sets memory protection for a workspace based on the provided flag.
- **Inputs**:
    - `wksp`: A pointer to the workspace (`fd_wksp_t`) whose memory protection is to be set.
    - `flag`: An integer flag indicating the desired memory protection level; if non-zero, set to read-only, otherwise set to read-write.
- **Control Flow**:
    - Check if the `wksp` pointer is NULL and log a warning if it is, then return.
    - Check if the `wksp` pointer is properly aligned according to `FD_WKSP_ALIGN` and log a warning if it is not, then return.
    - Check if the `magic` field of the workspace matches `FD_WKSP_MAGIC` and log a warning if it does not, then return.
    - Calculate the footprint of the workspace using [`fd_wksp_footprint`](#fd_wksp_footprint) with `part_max` and `data_max` from the workspace.
    - Attempt to set the memory protection of the workspace using `mprotect` with the calculated footprint and the appropriate protection flags based on the `flag` input.
    - Log a warning if `mprotect` fails, including the error number and its string representation, then return.
- **Output**: The function does not return a value; it performs its operations and logs warnings if any checks fail or if `mprotect` fails.
- **Functions called**:
    - [`fd_wksp_footprint`](#fd_wksp_footprint)


