# Purpose
The provided C header file, `fd_forks.h`, is part of a larger software system and is designed to manage and manipulate a data structure known as "forks" within a distributed computing environment. This file defines the structures and functions necessary to handle fork management, which is crucial for maintaining the state of a distributed ledger or blockchain system. The primary structure, `fd_fork_t`, represents a fork with attributes such as slot identifiers, execution context, and locking mechanisms to ensure safe concurrent access. The file also defines a `fd_forks_t` structure, which maintains a collection of these forks, known as the frontier, and tracks the highest slots that have been processed, confirmed, and finalized.

The header file provides a comprehensive API for creating, joining, leaving, and deleting forks, as well as for querying and advancing the state of forks within the system. It includes functions for initializing forks, preparing them for execution, updating the system state after execution, and publishing new roots to prune outdated forks. The file also includes utility functions to determine memory alignment and footprint requirements for fork data structures. This header is intended to be included in other parts of the system, providing a consistent interface for fork management and ensuring that the system can efficiently handle the complexities of distributed ledger operations.
# Imports and Dependencies

---
- `../../flamenco/runtime/context/fd_exec_epoch_ctx.h`
- `../../flamenco/runtime/context/fd_exec_slot_ctx.h`
- `../../flamenco/runtime/fd_blockstore.h`
- `../fd_choreo_base.h`
- `../ghost/fd_ghost.h`
- `../voter/fd_voter.h`
- `../../util/tmpl/fd_pool.c`
- `../../util/tmpl/fd_map_chain.c`


# Global Variables

---
### fd\_forks\_new
- **Type**: `function pointer`
- **Description**: `fd_forks_new` is a function that formats an unused memory region for use as a forks data structure. It takes a pointer to shared memory, a maximum number of fork heads, and a seed value as parameters.
- **Use**: This function is used to initialize a memory region to be used for managing fork heads in a distributed system.


---
### fd\_forks\_join
- **Type**: `fd_forks_t *`
- **Description**: The `fd_forks_join` function is a global function that takes a pointer to a memory region (`void * forks`) and returns a pointer to an `fd_forks_t` structure. This function is used to join the caller to the forks, effectively mapping the memory region into the caller's address space.
- **Use**: This function is used to establish a connection to the forks data structure, allowing the caller to interact with the fork management system.


---
### fd\_forks\_leave
- **Type**: `function pointer`
- **Description**: `fd_forks_leave` is a function that allows a process to leave a current local join to a `fd_forks_t` data structure. It returns a pointer to the underlying shared memory region on success, or NULL on failure, logging details of the failure.
- **Use**: This function is used to safely disconnect a process from a shared `fd_forks_t` structure, ensuring that resources are properly released and any necessary cleanup is performed.


---
### fd\_forks\_delete
- **Type**: `function pointer`
- **Description**: `fd_forks_delete` is a function that unformats a memory region used as a forks data structure. It assumes that only the local process is joined to the region and returns a pointer to the underlying shared memory region or NULL if there is an error, such as if the provided pointer is not a valid forks structure.
- **Use**: This function is used to clean up and release the memory associated with a forks data structure, transferring ownership of the memory back to the caller.


---
### fd\_forks\_init
- **Type**: `function pointer`
- **Description**: The `fd_forks_init` is a function pointer that initializes a `fd_forks_t` structure, which manages the outstanding fork heads known as the frontier in a blockchain context. It takes a pointer to a `fd_forks_t` structure and a `fd_exec_slot_ctx_t` structure as arguments, and it inserts the first fork into the frontier using the provided slot context.
- **Use**: This function is used to initialize the forks data structure with a starting fork, typically called by the process that formatted the memory for the forks.


---
### fd\_forks\_query
- **Type**: `function`
- **Description**: The `fd_forks_query` function is a global function that queries a `fd_forks_t` data structure to find a fork corresponding to a specific slot in the frontier. It returns a pointer to the `fd_fork_t` structure if the fork is found, otherwise it returns NULL.
- **Use**: This function is used to retrieve a specific fork from the frontier based on the slot number.


---
### fd\_forks\_query\_const
- **Type**: `fd_fork_t const *`
- **Description**: The `fd_forks_query_const` is a function that returns a constant pointer to an `fd_fork_t` structure. It is used to query for a fork corresponding to a specific slot in the frontier of the `fd_forks_t` data structure.
- **Use**: This function is used to retrieve a read-only reference to a fork in the frontier based on a given slot number.


---
### fd\_forks\_advance
- **Type**: `function`
- **Description**: The `fd_forks_advance` function is designed to advance a given fork to a new slot within the frontier of forks. It assumes that the parent slot of the fork is already present in the frontier and has been replayed, and that the fork is in a frozen state, meaning it is not actively being modified or replayed.
- **Use**: This function is used to update the position of a fork in the frontier to a new slot, effectively moving the fork forward in the execution sequence.


---
### fd\_forks\_prepare
- **Type**: `fd_fork_t *`
- **Description**: The `fd_forks_prepare` function is a global function that prepares a fork for execution within a distributed system. It either retrieves an existing fork from the frontier if the `parent_slot` is already a fork head or starts a new fork at `parent_slot` and adds it to the frontier. The function returns a pointer to the `fd_fork_t` structure on success or NULL on failure.
- **Use**: This function is used to manage and prepare forks for execution in a distributed system, ensuring that the correct fork is available for processing based on the given `parent_slot`.


# Data Structures

---
### fd\_fork
- **Type**: `struct`
- **Members**:
    - `slot`: The fork head and frontier key.
    - `next`: Reserved for use by fd_pool and fd_map_chain.
    - `prev`: Reserved for use by fd_forks_publish.
    - `lock`: A boolean indicating whether a fork's most recent block is still being actively replayed.
    - `end_idx`: The end index of the last batch executed on this fork.
    - `slot_ctx`: A pointer to the execution slot context associated with this fork.
- **Description**: The `fd_fork` structure is a component of a larger system managing forks in a distributed environment. It holds metadata about a specific fork, including its position in the fork chain (`slot`), its relationship to other forks (`next` and `prev`), and its execution state (`lock`). The `end_idx` tracks the last executed batch, while `slot_ctx` provides context for execution. This structure is crucial for managing the state and progression of forks, ensuring that operations are executed in the correct order and that the system can track and manage multiple forks efficiently.


---
### fd\_fork\_t
- **Type**: `struct`
- **Members**:
    - `slot`: The fork head and frontier key.
    - `next`: Reserved for use by fd_pool and fd_map_chain.
    - `prev`: Reserved for use by fd_forks_publish.
    - `lock`: A boolean indicating whether a fork's most recent block is still being actively replayed.
    - `end_idx`: The end index of the last batch executed on this fork.
    - `slot_ctx`: A pointer to the execution slot context associated with this fork.
- **Description**: The `fd_fork_t` structure represents a fork in a blockchain-like system, where each fork is identified by a slot number and contains metadata about its execution state. It includes fields for managing the fork's position in a chain (`next`, `prev`), a lock to indicate active replay status, and a context pointer for execution details. This structure is used within a larger system to manage and track the state of multiple forks, ensuring that operations such as replaying blocks and publishing new roots are handled correctly.


---
### fd\_forks
- **Type**: `struct`
- **Members**:
    - `frontier`: A pointer to a map of slot to fd_fork_t, representing the frontier of fork heads.
    - `pool`: A pointer to a memory pool of fd_fork_t structures.
    - `processed`: An unsigned long representing the highest slot that has been replayed.
    - `confirmed`: An unsigned long representing the highest slot that has been optimistically confirmed.
    - `finalized`: An unsigned long representing the highest slot that has been supermajority rooted.
- **Description**: The `fd_forks` structure is designed to manage and track the state of fork heads within a distributed system, specifically in the context of a blockchain or similar consensus mechanism. It maintains a map of fork heads known as the frontier, with memory pre-allocated in a pool for efficiency. The structure also tracks the highest slots that have reached various levels of commitment: processed, confirmed, and finalized. These slots are not synchronized across nodes but are eventually consistent, reflecting the local state as observed by the Firedancer system. The `fd_forks` structure is integral to managing the lifecycle of forks, including their creation, advancement, and eventual pruning as new roots are published.


---
### fd\_forks\_t
- **Type**: `struct`
- **Members**:
    - `frontier`: A map of slot to fd_fork_t, representing the current fork heads.
    - `pool`: A memory pool of fd_fork_t structures.
    - `processed`: The highest slot that has been replayed.
    - `confirmed`: The highest slot that has been optimistically confirmed by 2/3 of the stake.
    - `finalized`: The highest slot that has been supermajority rooted by 2/3 of the stake.
- **Description**: The `fd_forks_t` structure is designed to manage and track the state of fork heads within a distributed system, specifically in the context of a blockchain or similar consensus-based system. It maintains a map of current fork heads, known as the frontier, and uses a pre-allocated memory pool to manage these fork heads efficiently. The structure also tracks the highest slots that have been processed, confirmed, and finalized, providing a local view of the system's state that is eventually consistent with the rest of the network. This allows for efficient management and querying of fork states, facilitating operations such as advancing, preparing, and publishing forks.


# Functions

---
### fd\_forks\_align<!-- {{#callable:fd_forks_align}} -->
The `fd_forks_align` function returns the memory alignment requirement for the `fd_forks_t` data structure.
- **Inputs**: None
- **Control Flow**:
    - The function uses the `alignof` operator to determine the alignment requirement of the `fd_forks_t` type.
    - It returns this alignment value as an unsigned long integer.
- **Output**: The function returns an unsigned long integer representing the alignment requirement of the `fd_forks_t` data structure.


---
### fd\_forks\_footprint<!-- {{#callable:fd_forks_footprint}} -->
The `fd_forks_footprint` function calculates the memory footprint required for a `fd_forks_t` structure with a specified maximum number of fork heads in the frontier.
- **Inputs**:
    - `max`: The maximum number of fork heads that the `fd_forks_t` structure can accommodate in the frontier.
- **Control Flow**:
    - The function begins by initializing a layout using `FD_LAYOUT_INIT`.
    - It appends the alignment and size of `fd_forks_t` to the layout using `FD_LAYOUT_APPEND`.
    - It appends the alignment and footprint of the fork pool, calculated using `fd_fork_pool_align()` and `fd_fork_pool_footprint(max)`, to the layout.
    - It appends the alignment and footprint of the fork frontier, calculated using `fd_fork_frontier_align()` and `fd_fork_frontier_footprint(max)`, to the layout.
    - Finally, it finalizes the layout with the alignment of `fd_forks_t` using `FD_LAYOUT_FINI` and returns the total calculated footprint.
- **Output**: The function returns an `ulong` representing the total memory footprint required for the `fd_forks_t` structure with the specified maximum number of fork heads.


# Function Declarations (Public API)

---
### fd\_forks\_new<!-- {{#callable_declaration:fd_forks_new}} -->
Formats a memory region for use as a forks data structure.
- **Description**: This function prepares a specified memory region to be used as a forks data structure, which is essential for managing fork heads in a distributed system. It should be called with a valid memory region that meets the required alignment and footprint specifications. The function initializes the memory, setting up the necessary structures for fork management. It is crucial to ensure that the memory region is correctly aligned and has sufficient size to accommodate the maximum number of fork heads specified by the `max` parameter. The function returns a pointer to the initialized memory region on success, or NULL if the input parameters are invalid or the memory is misaligned.
- **Inputs**:
    - `shmem`: A pointer to the memory region to be formatted. Must not be NULL and must be aligned according to `fd_forks_align()`. The caller retains ownership.
    - `max`: The maximum number of fork heads that the memory region should support. Must be a positive integer.
    - `seed`: A seed value used for initializing the fork frontier. It can be any unsigned long value.
- **Output**: Returns a pointer to the formatted memory region on success, or NULL if the input is invalid or the memory is misaligned.
- **See also**: [`fd_forks_new`](fd_forks.c.driver.md#fd_forks_new)  (Implementation)


---
### fd\_forks\_join<!-- {{#callable_declaration:fd_forks_join}} -->
Joins the caller to a shared forks data structure.
- **Description**: This function is used to join a caller to a shared memory region that represents a forks data structure. It should be called when a process needs to access or manipulate the forks data structure that has been previously initialized and formatted. The function requires that the memory region pointed to by the input is properly aligned and not null. If these conditions are not met, the function will log a warning and return null. This function is typically used in a multi-process environment where shared access to the forks data structure is necessary.
- **Inputs**:
    - `shforks`: A pointer to the shared memory region representing the forks. It must not be null and must be aligned according to the requirements of the forks data structure. If the pointer is null or misaligned, the function logs a warning and returns null.
- **Output**: Returns a pointer to the local address space representation of the forks on success, or null if the input is invalid.
- **See also**: [`fd_forks_join`](fd_forks.c.driver.md#fd_forks_join)  (Implementation)


---
### fd\_forks\_leave<!-- {{#callable_declaration:fd_forks_leave}} -->
Leaves a current local join to the forks.
- **Description**: This function is used to leave a current local join to the forks, returning a pointer to the underlying shared memory region if successful. It should be called when the caller no longer needs to be joined to the forks, allowing for cleanup or further operations on the shared memory. The function logs a warning and returns NULL if the provided forks pointer is NULL, indicating an error in usage.
- **Inputs**:
    - `forks`: A pointer to the fd_forks_t structure representing the current local join. Must not be NULL. If NULL, the function logs a warning and returns NULL.
- **Output**: Returns a pointer to the underlying shared memory region on success, or NULL if the forks pointer is NULL.
- **See also**: [`fd_forks_leave`](fd_forks.c.driver.md#fd_forks_leave)  (Implementation)


---
### fd\_forks\_delete<!-- {{#callable_declaration:fd_forks_delete}} -->
Unformats a memory region used as forks.
- **Description**: Use this function to unformat a memory region that was previously used as forks, assuming that only the local process is joined to the region. This function is typically called when the forks are no longer needed, and it transfers ownership of the memory region back to the caller. It returns a pointer to the underlying shared memory region or NULL if the input is obviously invalid, such as when the input is not a properly aligned forks structure. This function logs details in case of errors.
- **Inputs**:
    - `forks`: A pointer to the memory region used as forks. It must not be NULL and must be properly aligned according to fd_forks_align(). If the pointer is NULL or misaligned, the function logs a warning and returns NULL.
- **Output**: Returns a pointer to the underlying shared memory region if successful, or NULL if the input is invalid.
- **See also**: [`fd_forks_delete`](fd_forks.c.driver.md#fd_forks_delete)  (Implementation)


---
### fd\_forks\_init<!-- {{#callable_declaration:fd_forks_init}} -->
Initialize a fork and insert it into the frontier.
- **Description**: This function initializes a fork within the given `forks` structure using the provided `slot_ctx` and inserts it into the frontier. It should be called when setting up the initial state of the forks, typically after loading a snapshot or restoring a bank. The function requires that `forks` is a valid local join and that no other processes are joined to it. The `slot_ctx` must not be null and should be in the same address space as the `forks` data structure. The function returns a pointer to the newly initialized fork on success, or NULL if either `forks` or `slot_ctx` is null, or if the fork cannot be inserted into the frontier.
- **Inputs**:
    - `forks`: A pointer to an `fd_forks_t` structure representing the forks to be initialized. Must not be null and should be a valid local join with no other processes joined.
    - `slot_ctx`: A pointer to an `fd_exec_slot_ctx_t` structure representing the execution slot context. Must not be null and should be in the same address space as the `forks` data structure.
- **Output**: Returns a pointer to the initialized `fd_fork_t` on success, or NULL on failure if `forks` or `slot_ctx` is null, or if the fork cannot be inserted into the frontier.
- **See also**: [`fd_forks_init`](fd_forks.c.driver.md#fd_forks_init)  (Implementation)


---
### fd\_forks\_query<!-- {{#callable_declaration:fd_forks_query}} -->
Queries for a fork corresponding to a given slot in the frontier.
- **Description**: Use this function to retrieve the fork associated with a specific slot from the frontier of outstanding fork heads. This is useful when you need to access or manipulate the fork data for a particular slot. The function returns a pointer to the fork if it exists in the frontier, or NULL if no such fork is found. Ensure that the `forks` structure is properly initialized and joined before calling this function.
- **Inputs**:
    - `forks`: A pointer to an `fd_forks_t` structure representing the collection of fork heads. It must be a valid, non-NULL pointer to a joined forks structure.
    - `slot`: An unsigned long integer representing the slot number for which the fork is being queried. It should correspond to a slot in the frontier.
- **Output**: Returns a pointer to the `fd_fork_t` structure corresponding to the given slot if found, otherwise returns NULL.
- **See also**: [`fd_forks_query`](fd_forks.c.driver.md#fd_forks_query)  (Implementation)


---
### fd\_forks\_query\_const<!-- {{#callable_declaration:fd_forks_query_const}} -->
Retrieve a constant fork from the frontier by slot.
- **Description**: Use this function to obtain a constant pointer to a fork in the frontier that corresponds to a specific slot. This is useful when you need to access fork data without modifying it. The function should be called with a valid `fd_forks_t` structure that has been properly initialized and joined. If the specified slot is not found in the frontier, the function returns `NULL`. This function is read-only and does not alter the state of the `fd_forks_t` structure.
- **Inputs**:
    - `forks`: A pointer to a constant `fd_forks_t` structure representing the collection of fork heads. It must not be null and should be properly initialized and joined.
    - `slot`: An unsigned long integer representing the slot number of the fork to query. It should be a valid slot number within the context of the frontier.
- **Output**: A constant pointer to an `fd_fork_t` structure if the slot is found, or `NULL` if the slot is not present in the frontier.
- **See also**: [`fd_forks_query_const`](fd_forks.c.driver.md#fd_forks_query_const)  (Implementation)


---
### fd\_forks\_prepare<!-- {{#callable_declaration:fd_forks_prepare}} -->
Prepares a fork for execution at a specified parent slot.
- **Description**: This function is used to prepare a fork for execution by either retrieving an existing fork from the frontier if the specified parent slot is already a fork head, or by starting a new fork at the parent slot and adding it to the frontier. It should be called when a fork needs to be prepared for execution, ensuring that the parent slot is present and executed in the blockstore. The function may return NULL if the parent slot is not present in the blockstore, funk, or does not have a valid ancestry, or if the blockstore has pruned past the slot.
- **Inputs**:
    - `forks`: A pointer to a constant fd_forks_t structure representing the collection of fork heads. Must not be null.
    - `parent_slot`: An unsigned long integer representing the slot number of the parent block. It should correspond to a block that is present and executed in the blockstore.
    - `funk`: A pointer to an fd_funk_t structure used for restoring and decoding the slot context. Must not be null.
    - `blockstore`: A pointer to an fd_blockstore_t structure representing the blockstore where the parent block is stored. Must not be null.
    - `epoch_ctx`: A pointer to an fd_exec_epoch_ctx_t structure representing the execution epoch context. Must not be null.
    - `runtime_spad`: A pointer to an fd_spad_t structure used for runtime memory allocation. Must not be null.
- **Output**: Returns a pointer to an fd_fork_t structure representing the prepared fork on success, or NULL on failure or if the fork cannot be prepared due to pruning.
- **See also**: [`fd_forks_prepare`](fd_forks.c.driver.md#fd_forks_prepare)  (Implementation)


---
### fd\_forks\_update<!-- {{#callable_declaration:fd_forks_update}} -->
Updates the blockstore and ghost with the latest state from replaying a slot.
- **Description**: This function should be called immediately after a slot has been replayed to update the blockstore and ghost with the latest state. It assumes that the specified slot is a fork head in the frontier. The function processes votes and roots from the epoch's voters, updating the ghost and forks' confirmed and finalized slots based on the votes and roots that meet certain thresholds. It is crucial for maintaining the consistency and progress of the forks' state.
- **Inputs**:
    - `forks`: A pointer to an fd_forks_t structure representing the current state of forks. Must not be null.
    - `epoch`: A pointer to an fd_epoch_t structure representing the current epoch. Must not be null.
    - `funk`: A pointer to an fd_funk_t structure used for querying voter states. Must not be null.
    - `ghost`: A pointer to an fd_ghost_t structure representing the ghost state. Must not be null.
    - `slot`: An unsigned long integer representing the slot that has been replayed. It must be a fork head in the frontier.
- **Output**: None
- **See also**: [`fd_forks_update`](fd_forks.c.driver.md#fd_forks_update)  (Implementation)


---
### fd\_forks\_publish<!-- {{#callable_declaration:fd_forks_publish}} -->
Publishes a new root into the forks, pruning non-descendant forks.
- **Description**: This function is used to update the forks structure by setting a new root slot and pruning all forks in the frontier that are not descendants of the specified root. It should be called when a new root slot has been determined and replayed. Forks that are not frozen (i.e., still being actively replayed) will not be pruned, and a warning will be logged if handholding is enabled. This function assumes that the root slot is valid and exists in the cluster.
- **Inputs**:
    - `forks`: A pointer to an fd_forks_t structure representing the current state of forks. Must not be null.
    - `slot`: An unsigned long integer representing the new root slot. It must be a valid slot that exists in the cluster and has already been replayed.
    - `ghost`: A constant pointer to an fd_ghost_t structure used to determine ancestry relationships. Must not be null.
- **Output**: None
- **See also**: [`fd_forks_publish`](fd_forks.c.driver.md#fd_forks_publish)  (Implementation)


---
### fd\_forks\_print<!-- {{#callable_declaration:fd_forks_print}} -->
Prints the current state of the forks frontier.
- **Description**: Use this function to output the current state of the forks frontier to the standard output. It iterates over all fork heads in the frontier and prints their slot numbers. This function is useful for debugging or logging purposes to understand the current state of the forks. Ensure that the `forks` parameter is a valid pointer to a `fd_forks_t` structure before calling this function.
- **Inputs**:
    - `forks`: A pointer to a `fd_forks_t` structure representing the forks frontier. Must not be null and should point to a valid, initialized forks structure.
- **Output**: None
- **See also**: [`fd_forks_print`](fd_forks.c.driver.md#fd_forks_print)  (Implementation)


