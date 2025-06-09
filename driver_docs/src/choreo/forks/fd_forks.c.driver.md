# Purpose
The provided C source code file is part of a larger software system, likely related to blockchain or distributed ledger technology, given the terminology and operations involved. This file defines a set of functions for managing "forks" within a shared memory context, which are likely branches or paths in a blockchain or similar data structure. The primary functionality revolves around creating, joining, leaving, deleting, initializing, querying, preparing, updating, and publishing forks. The code is structured to handle memory alignment and allocation, ensuring that operations on forks are performed safely and efficiently. The functions interact with various components such as execution contexts, transaction management, and block storage, indicating a complex system for managing state and transactions across different forks.

The file includes several header files from a "flamenco" runtime, suggesting it is part of a modular system where different components are responsible for specific tasks. The functions defined in this file are not standalone; they rely on external functions and data structures, such as `fd_fork_pool`, `fd_fork_frontier`, and `fd_exec_slot_ctx`, to manage the lifecycle and state of forks. The code also includes logging for error handling and debugging, which is crucial for maintaining the integrity of the system. Overall, this file provides a focused set of functionalities for fork management within a larger runtime environment, likely serving as a critical component in a blockchain or distributed ledger system.
# Imports and Dependencies

---
- `fd_forks.h`
- `../../flamenco/runtime/context/fd_exec_slot_ctx.h`
- `../../flamenco/runtime/fd_acc_mgr.h`
- `../../flamenco/runtime/fd_borrowed_account.h`
- `../../flamenco/runtime/fd_runtime.h`
- `../../flamenco/runtime/program/fd_program_util.h`
- `../../flamenco/runtime/program/fd_vote_program.h`
- `stdio.h`


# Functions

---
### fd\_forks\_new<!-- {{#callable:fd_forks_new}} -->
The `fd_forks_new` function initializes a new fork structure in shared memory, aligning and setting up necessary components for fork management.
- **Inputs**:
    - `shmem`: A pointer to the shared memory region where the fork structure will be initialized.
    - `max`: The maximum number of forks that can be managed.
    - `seed`: A seed value used for initializing the fork frontier.
- **Control Flow**:
    - Check if the `shmem` pointer is NULL and log a warning if it is, returning NULL.
    - Verify that `shmem` is properly aligned according to `fd_forks_align()` and log a warning if it is not, returning NULL.
    - Calculate the memory footprint required for the forks using `fd_forks_footprint(max)` and log a warning if it is zero, returning NULL.
    - Clear the memory region pointed to by `shmem` using `fd_memset`.
    - Align the local address `laddr` to the alignment of `fd_forks_t` and increment it by the size of `fd_forks_t`.
    - Align `laddr` to the alignment required by the fork pool and initialize the fork pool at this address using `fd_fork_pool_new`, then increment `laddr` by the fork pool's footprint.
    - Align `laddr` to the alignment required by the fork frontier and initialize the fork frontier at this address using `fd_fork_frontier_new`, then increment `laddr` by the fork frontier's footprint.
    - Return the original `shmem` pointer.
- **Output**: Returns the original `shmem` pointer if successful, or NULL if any checks fail.
- **Functions called**:
    - [`fd_forks_align`](fd_forks.h.driver.md#fd_forks_align)
    - [`fd_forks_footprint`](fd_forks.h.driver.md#fd_forks_footprint)


---
### fd\_forks\_join<!-- {{#callable:fd_forks_join}} -->
The `fd_forks_join` function initializes and joins a shared memory region as a `fd_forks_t` structure, ensuring proper alignment and setting up internal components like the fork pool and frontier.
- **Inputs**:
    - `shforks`: A pointer to the shared memory region intended to be used as a `fd_forks_t` structure.
- **Control Flow**:
    - Check if `shforks` is NULL and log a warning if so, returning NULL.
    - Check if `shforks` is properly aligned according to `fd_forks_align()` and log a warning if not, returning NULL.
    - Cast `shforks` to a `ulong` and then to a `fd_forks_t` pointer named `forks`.
    - Align the address to the alignment of `fd_forks_t` and increment it by the size of `fd_forks_t`.
    - Align the address to the alignment required by the fork pool, join the fork pool at this address, and update the address by the footprint of the fork pool.
    - Align the address to the alignment required by the fork frontier, join the fork frontier at this address, and update the address by the footprint of the fork frontier.
    - Return the original `shforks` cast to a `fd_forks_t` pointer.
- **Output**: A pointer to the `fd_forks_t` structure initialized from the shared memory, or NULL if there was an error.
- **Functions called**:
    - [`fd_forks_align`](fd_forks.h.driver.md#fd_forks_align)


---
### fd\_forks\_leave<!-- {{#callable:fd_forks_leave}} -->
The `fd_forks_leave` function checks if the given `fd_forks_t` pointer is non-null and returns it cast to a `void *`, logging a warning if it is null.
- **Inputs**:
    - `forks`: A constant pointer to an `fd_forks_t` structure, representing the forks to be left.
- **Control Flow**:
    - Check if the `forks` pointer is null using `FD_UNLIKELY`.
    - If `forks` is null, log a warning message 'NULL forks' and return `NULL`.
    - If `forks` is not null, cast it to a `void *` and return it.
- **Output**: Returns a `void *` pointer to the `fd_forks_t` structure if it is non-null, otherwise returns `NULL`.


---
### fd\_forks\_delete<!-- {{#callable:fd_forks_delete}} -->
The `fd_forks_delete` function checks if a given pointer to a forks structure is valid and aligned, and returns the pointer if it is, or NULL otherwise.
- **Inputs**:
    - `forks`: A pointer to a forks structure that is to be validated and potentially returned.
- **Control Flow**:
    - Check if the `forks` pointer is NULL using `FD_UNLIKELY`; if it is, log a warning and return NULL.
    - Check if the `forks` pointer is aligned according to `fd_forks_align()` using `FD_UNLIKELY`; if it is not, log a warning and return NULL.
    - If both checks pass, return the `forks` pointer.
- **Output**: Returns the `forks` pointer if it is non-NULL and properly aligned; otherwise, returns NULL.
- **Functions called**:
    - [`fd_forks_align`](fd_forks.h.driver.md#fd_forks_align)


---
### fd\_forks\_init<!-- {{#callable:fd_forks_init}} -->
The `fd_forks_init` function initializes a new fork in the given forks structure using the provided execution slot context.
- **Inputs**:
    - `forks`: A pointer to an `fd_forks_t` structure, which manages a collection of forks.
    - `slot_ctx`: A pointer to an `fd_exec_slot_ctx_t` structure, which contains context information for the execution slot.
- **Control Flow**:
    - Check if the `forks` pointer is NULL and log a warning if it is, returning NULL.
    - Check if the `slot_ctx` pointer is NULL and log a warning if it is, returning NULL.
    - Acquire a new fork element from the fork pool associated with the `forks` structure.
    - Initialize the acquired fork's fields using the `slot_ctx` and default values.
    - Attempt to insert the initialized fork into the frontier of the `forks` structure, logging a warning if the insertion fails.
    - Return the initialized fork.
- **Output**: Returns a pointer to the newly initialized `fd_fork_t` structure, or NULL if initialization fails due to invalid inputs or insertion failure.


---
### fd\_forks\_query<!-- {{#callable:fd_forks_query}} -->
The `fd_forks_query` function retrieves a fork element from the frontier based on a given slot number.
- **Inputs**:
    - `forks`: A pointer to an `fd_forks_t` structure, which contains the frontier and pool of fork elements.
    - `slot`: An unsigned long integer representing the slot number to query in the frontier.
- **Control Flow**:
    - The function calls `fd_fork_frontier_ele_query` with the frontier from the `forks` structure, the address of the `slot`, a NULL pointer, and the pool from the `forks` structure.
    - The `fd_fork_frontier_ele_query` function is expected to return a pointer to the fork element corresponding to the given slot, if it exists.
- **Output**: A pointer to an `fd_fork_t` structure representing the fork element for the specified slot, or NULL if no such element exists.


---
### fd\_forks\_query\_const<!-- {{#callable:fd_forks_query_const}} -->
The `fd_forks_query_const` function retrieves a constant pointer to a fork element from the frontier based on a given slot.
- **Inputs**:
    - `forks`: A constant pointer to an `fd_forks_t` structure, representing the collection of forks.
    - `slot`: An unsigned long integer representing the slot number to query in the frontier.
- **Control Flow**:
    - The function calls `fd_fork_frontier_ele_query_const` with the frontier from the `forks` structure, the address of the `slot`, a NULL pointer, and the pool from the `forks` structure.
    - The result of the `fd_fork_frontier_ele_query_const` call is returned directly.
- **Output**: A constant pointer to an `fd_fork_t` structure representing the fork element corresponding to the given slot, or NULL if not found.


---
### slot\_ctx\_restore<!-- {{#callable:slot_ctx_restore}} -->
The `slot_ctx_restore` function restores the execution context for a given slot by verifying the block's existence, querying transaction data, and decoding the bank's record to populate the slot context output.
- **Inputs**:
    - `slot`: The slot number for which the context is being restored.
    - `funk`: A pointer to the `fd_funk_t` structure, which manages transaction data.
    - `blockstore`: A pointer to the `fd_blockstore_t` structure, which contains block data.
    - `epoch_ctx`: A pointer to the `fd_exec_epoch_ctx_t` structure, which holds epoch-related execution context.
    - `runtime_spad`: A pointer to the `fd_spad_t` structure, used for runtime memory allocation.
    - `slot_ctx_out`: A pointer to the `fd_exec_slot_ctx_t` structure, which will be populated with the restored slot context.
- **Control Flow**:
    - Retrieve the transaction map from the `funk` structure.
    - Check if the block for the given slot exists in the `blockstore`; log an error if it does not.
    - Initialize a transaction ID (`xid`) with the slot number and attempt to query the transaction map for this transaction.
    - If the transaction is not found, reset the transaction ID and query again; log an error if still not found.
    - Query the global record for the bank's record using the transaction and check for errors.
    - Verify the magic number in the bank's record to ensure it is valid; log an error if invalid.
    - Decode the bank's record using the runtime scratchpad and check for decoding errors.
    - Populate the `slot_ctx_out` structure with the transaction, funk, blockstore, epoch context, and decoded bank data.
    - Log a notice with the recovered bank's hash and prepare the bank for the next slot by resetting certain fields.
- **Output**: The function does not return a value but populates the `slot_ctx_out` structure with the restored slot context data.


---
### fd\_forks\_prepare<!-- {{#callable:fd_forks_prepare}} -->
The `fd_forks_prepare` function prepares a fork for a given parent slot by checking its presence and execution status in the blockstore, and if necessary, creates a new fork and adds it to the frontier.
- **Inputs**:
    - `forks`: A pointer to a constant `fd_forks_t` structure representing the collection of forks.
    - `parent_slot`: An unsigned long integer representing the slot of the parent block.
    - `funk`: A pointer to an `fd_funk_t` structure used for transaction management.
    - `blockstore`: A pointer to an `fd_blockstore_t` structure representing the block storage.
    - `epoch_ctx`: A pointer to an `fd_exec_epoch_ctx_t` structure representing the execution epoch context.
    - `runtime_spad`: A pointer to an `fd_spad_t` structure used for runtime scratchpad memory allocation.
- **Control Flow**:
    - Check if the parent block is present and executed in the blockstore using `fd_blockstore_shreds_complete` function.
    - Log a warning if the parent block is missing.
    - Query the frontier for the parent slot using `fd_fork_frontier_ele_query`.
    - If the parent block is not in the frontier, allocate a new fork using `fd_fork_pool_ele_acquire`.
    - Initialize the new fork's properties such as `prev`, `slot`, `lock`, and `end_idx`.
    - Allocate memory for the slot context using `fd_spad_alloc` and join it using `fd_exec_slot_ctx_join`.
    - Restore the slot context using [`slot_ctx_restore`](#slot_ctx_restore) function.
    - Insert the new fork into the frontier using `fd_fork_frontier_ele_insert`.
- **Output**: Returns a pointer to the `fd_fork_t` structure representing the prepared fork.
- **Functions called**:
    - [`slot_ctx_restore`](#slot_ctx_restore)


---
### fd\_forks\_update<!-- {{#callable:fd_forks_update}} -->
The `fd_forks_update` function updates the state of forks based on voter information and their votes, ensuring that the ghost tree is consistent with the current fork's state.
- **Inputs**:
    - `forks`: A pointer to an `fd_forks_t` structure representing the current state of forks.
    - `epoch`: A pointer to an `fd_epoch_t` structure containing epoch-related data, including voter information.
    - `funk`: A pointer to an `fd_funk_t` structure used for querying voter state and handling transactions.
    - `ghost`: A pointer to an `fd_ghost_t` structure representing the ghost tree, which tracks votes and roots.
    - `slot`: An unsigned long integer representing the slot number to be updated.
- **Control Flow**:
    - Retrieve the fork corresponding to the given slot from the frontier of forks.
    - Iterate over each voter in the epoch's voter list.
    - For each voter, check if the voter's key is invalid and skip if so.
    - Query the voter's state to retrieve the vote and root slots, retrying if there is a Funk conflict.
    - If the vote slot is valid and exists in the ghost tree, replay the vote in the ghost tree and check if it crosses confirmation thresholds.
    - If the root slot is valid and exists in the ghost tree, replay the root in the ghost tree and check if it crosses finalization thresholds.
    - Update the confirmed and finalized slots in the forks structure based on the percentage of stake.
- **Output**: The function does not return a value; it updates the state of the `forks` and `ghost` structures in place.


---
### fd\_forks\_publish<!-- {{#callable:fd_forks_publish}} -->
The `fd_forks_publish` function prunes stale forks from the frontier of a fork structure based on a given slot and ghost ancestry.
- **Inputs**:
    - `forks`: A pointer to an `fd_forks_t` structure representing the collection of forks to be managed.
    - `slot`: An unsigned long integer representing the current slot used to determine which forks are stale.
    - `ghost`: A constant pointer to an `fd_ghost_t` structure used to check ancestry of forks.
- **Control Flow**:
    - Initialize `tail` and `curr` pointers to NULL for tracking forks to be pruned.
    - Iterate over the forks in the frontier using an iterator initialized with `fd_fork_frontier_iter_init`.
    - For each fork, check if it is stale by comparing its slot with the given slot and checking its ancestry using `fd_ghost_is_ancestor`.
    - If a fork is stale and not locked, add it to the list of forks to be pruned, updating `tail` and `curr` pointers accordingly.
    - Iterate over the list of forks to be pruned, deleting their slot contexts and removing them from the frontier using `fd_fork_frontier_idx_remove`.
    - Release the pool index of each removed fork using `fd_fork_pool_idx_release`.
- **Output**: The function does not return a value; it modifies the `forks` structure by removing stale forks from its frontier.


---
### fd\_forks\_print<!-- {{#callable:fd_forks_print}} -->
The `fd_forks_print` function logs and prints the slots of all forks in the frontier of a given `fd_forks_t` structure.
- **Inputs**:
    - `forks`: A pointer to a constant `fd_forks_t` structure, which contains the frontier and pool of forks to be printed.
- **Control Flow**:
    - Logs a notice indicating the start of the fork printing process.
    - Initializes an iterator for traversing the fork frontier using `fd_fork_frontier_iter_init`.
    - Enters a loop that continues until `fd_fork_frontier_iter_done` returns true, indicating the end of the frontier.
    - Within the loop, retrieves the current fork element using `fd_fork_frontier_iter_ele_const` and prints its slot value.
    - Advances the iterator to the next element in the frontier using `fd_fork_frontier_iter_next`.
    - After the loop, prints a newline to separate the output.
- **Output**: The function does not return a value; it outputs the slot numbers of the forks to the standard output.


