# Purpose
The provided C code is a specialized implementation for managing and executing blockchain-related operations, specifically focusing on vote accounts and stake delegations within a blockchain runtime environment. The code is structured to handle various tasks such as refreshing vote accounts, registering vote accounts and stake delegations, and updating caches for previous epochs. It is designed to be part of a larger system, likely a blockchain node or a testing framework, where it interacts with other components through defined data structures and functions. The code includes functions for creating and destroying execution contexts, executing blocks of transactions, and managing memory and resources efficiently using custom memory allocation strategies.

The code is not a standalone executable but rather a collection of functions that are likely part of a library or module intended to be integrated into a larger blockchain system. It defines several static functions, indicating that these are internal to the file and not intended for external use. The functions handle complex data structures such as vote accounts, stake delegations, and execution contexts, and they perform operations like memory allocation, data copying, and transaction processing. The code is highly specialized, focusing on the efficient management of blockchain state and execution, and it includes mechanisms for handling errors and ensuring data integrity. The use of custom data types and functions suggests that this code is part of a highly tailored system, possibly for testing or simulating blockchain operations in a controlled environment.
# Imports and Dependencies

---
- `fd_block_harness.h`


# Functions

---
### fd\_runtime\_fuzz\_block\_refresh\_vote\_accounts<!-- {{#callable:fd_runtime_fuzz_block_refresh_vote_accounts}} -->
The function `fd_runtime_fuzz_block_refresh_vote_accounts` updates the stake amounts for vote accounts based on the current stake delegations.
- **Inputs**:
    - `vote_accounts_pool`: A pointer to the pool of vote account nodes, used to find and update vote accounts.
    - `vote_accounts_root`: A pointer to the root of the vote accounts map, used as a starting point for searching.
    - `stake_delegations_pool`: A pointer to the pool of stake delegation nodes, used to iterate over current stake delegations.
    - `stake_delegations_root`: A pointer to the root of the stake delegations map, used as a starting point for iterating over delegations.
- **Control Flow**:
    - The function begins by iterating over all nodes in the stake delegations map, starting from the minimum node.
    - For each node, it retrieves the voter's public key and the stake amount from the delegation.
    - A temporary node is created to search for the corresponding vote account in the vote accounts map using the voter's public key.
    - If the vote account is found, the function updates the vote account's stake by adding the current delegation's stake amount.
- **Output**: The function does not return a value; it updates the stake amounts in the vote accounts map in place.


---
### fd\_runtime\_fuzz\_block\_register\_vote\_account<!-- {{#callable:fd_runtime_fuzz_block_register_vote_account}} -->
The function `fd_runtime_fuzz_block_register_vote_account` registers a vote account into a cache if it meets certain criteria and records a timestamp for it.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context, which contains information about the current execution environment.
    - `pool`: A pointer to the pool of vote account map nodes, used for managing the cache of vote accounts.
    - `root`: A double pointer to the root of the vote account map, representing the entry point to the cache structure.
    - `pubkey`: A pointer to the public key of the vote account to be registered.
    - `spad`: A pointer to a shared memory allocator used for dynamic memory allocation during the function's execution.
- **Control Flow**:
    - Initialize a transaction account from the given public key and check if it is valid; return if not.
    - Verify that the account is owned by the vote program; return if not.
    - Check that the account has more than 0 lamports; return if not.
    - Ensure the account is correctly initialized; return if not.
    - Retrieve the vote state from the account data; return if retrieval fails.
    - Check if the account already exists in the cache; return if it does.
    - Acquire a new node for the cache, copy the public key, and populate the node with account data.
    - Insert the new node into the vote account cache.
    - Determine the correct timestamp from the vote state version and record it with the slot context.
- **Output**: The function does not return a value; it modifies the vote account cache and records a timestamp if the account is successfully registered.


---
### fd\_runtime\_fuzz\_block\_register\_stake\_delegation<!-- {{#callable:fd_runtime_fuzz_block_register_stake_delegation}} -->
The function `fd_runtime_fuzz_block_register_stake_delegation` registers a stake delegation account into a cache if it meets certain criteria and is not already present.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context, which contains information about the current execution environment.
    - `pool`: A pointer to the pool of map nodes used for managing stake delegation pairs.
    - `root`: A double pointer to the root of the map node tree, representing the cache of stake delegations.
    - `pubkey`: A pointer to the public key of the account to be registered as a stake delegation.
- **Control Flow**:
    - Initialize a transaction account from the provided public key and execution context; return if initialization fails.
    - Check if the account is owned by the stake program; return if not.
    - Verify that the account has more than 0 lamports; return if not.
    - Retrieve and validate the stake state from the account; return if the state is invalid or not a stake.
    - Skip accounts with 0 stake in their delegation; return if the stake is 0.
    - Check if the account already exists in the cache; return if it does.
    - Acquire a new map node from the pool and copy the public key and delegation information into it.
    - Insert the new node into the cache.
- **Output**: The function does not return a value; it modifies the cache of stake delegations by inserting a new node if the account meets all criteria.


---
### fd\_runtime\_fuzz\_block\_update\_prev\_epoch\_votes\_cache<!-- {{#callable:fd_runtime_fuzz_block_update_prev_epoch_votes_cache}} -->
The function `fd_runtime_fuzz_block_update_prev_epoch_votes_cache` updates a cache with vote account information from a previous epoch.
- **Inputs**:
    - `pool`: A pointer to the pool of map nodes used for vote accounts.
    - `root`: A double pointer to the root of the map where vote accounts are stored.
    - `vote_accounts`: An array of vote account structures containing account state and stake information.
    - `vote_accounts_cnt`: The number of vote accounts in the `vote_accounts` array.
    - `spad`: A pointer to a shared memory allocator used for dynamic memory allocation.
- **Control Flow**:
    - Iterate over each vote account in the `vote_accounts` array.
    - For each vote account, acquire a new map node from the `pool`.
    - Set the stake and copy the vote account's address, executable status, lamports, rent epoch, data length, and owner into the map node.
    - Allocate memory for the vote account's data using `spad` and copy the data into the allocated memory.
    - Insert the map node into the map using the `root` pointer.
- **Output**: The function does not return a value; it updates the map with new vote account nodes.


---
### fd\_runtime\_fuzz\_block\_ctx\_destroy<!-- {{#callable:fd_runtime_fuzz_block_ctx_destroy}} -->
The `fd_runtime_fuzz_block_ctx_destroy` function cleans up and releases resources associated with a block execution context in a fuzz testing environment.
- **Inputs**:
    - `runner`: A pointer to an `fd_runtime_fuzz_runner_t` structure, which manages the fuzz testing environment.
    - `slot_ctx`: A pointer to an `fd_exec_slot_ctx_t` structure, representing the execution context for a slot.
    - `wksp`: A pointer to an `fd_wksp_t` structure, representing the workspace to be detached.
    - `alloc`: A pointer to an `fd_alloc_t` structure, representing the allocator whose resources are to be freed.
- **Control Flow**:
    - Check if `slot_ctx` is NULL and return immediately if it is, as it should not be NULL.
    - Call `fd_alloc_leave` on `alloc` to leave the allocation context.
    - Call `fd_alloc_delete` to delete the allocator context.
    - Call `fd_wksp_free_laddr` to free the local address associated with the allocator.
    - Detach the workspace by calling `fd_wksp_detach` on `wksp`.
    - Cancel all transactions in the `funk` component of `runner` by calling `fd_funk_txn_cancel_all`.
- **Output**: This function does not return any value; it performs cleanup operations.


---
### fd\_runtime\_fuzz\_block\_ctx\_create<!-- {{#callable:fd_runtime_fuzz_block_ctx_create}} -->
The `fd_runtime_fuzz_block_ctx_create` function sets up a block execution context from a test case to execute against the runtime, returning block information on success or NULL on failure.
- **Inputs**:
    - `runner`: A pointer to an `fd_runtime_fuzz_runner_t` structure, which contains the runtime environment and resources needed for the fuzzing process.
    - `slot_ctx`: A pointer to an `fd_exec_slot_ctx_t` structure, which will be initialized and populated with context information for the slot being processed.
    - `test_ctx`: A constant pointer to an `fd_exec_test_block_context_t` structure, which provides the test case data and context needed to set up the block execution environment.
- **Control Flow**:
    - Initialize a unique transaction ID and start a temporary funk transaction.
    - Allocate memory for epoch context and join it to the execution context.
    - Restore feature flags from the test context; return NULL if restoration fails.
    - Set up the slot context with transaction, funk, and epoch context information.
    - Initialize the slot bank with data from the test context, including vote timestamps and fee rate governor settings.
    - Set up epoch context and bank with parameters from the test context, including inflation and genesis creation time.
    - Load accounts with non-zero lamports from the test context, updating vote and stake caches.
    - Add accounts to the BPF program cache and refresh vote accounts to calculate stake delegations.
    - Initialize epoch bank system variables and update vote caches for previous epochs.
    - Update the leader schedule and initialize the blockhash queue from the test context.
    - Allocate memory for rent fresh accounts and set initial values.
    - Set genesis hash and block hash queue last hash to zero.
    - Use the latest lamports per signature from recent block hashes if available.
    - Populate the blockhash queue and recent blockhashes sysvar with data from the test context.
    - Set the current POH from the test context, skipping POH verification.
    - Create a new funk transaction after loading accounts for context.
    - Calculate epoch account hash values and prepare transaction pointers and block/microblock information.
    - Return the populated `fd_runtime_block_info_t` structure.
- **Output**: A pointer to an `fd_runtime_block_info_t` structure containing information about the block execution context, or NULL if an error occurs during setup.
- **Functions called**:
    - [`fd_runtime_fuzz_restore_features`](fd_harness_common.c.driver.md#fd_runtime_fuzz_restore_features)
    - [`fd_runtime_fuzz_load_account`](fd_harness_common.c.driver.md#fd_runtime_fuzz_load_account)
    - [`fd_runtime_fuzz_block_register_vote_account`](#fd_runtime_fuzz_block_register_vote_account)
    - [`fd_runtime_fuzz_block_register_stake_delegation`](#fd_runtime_fuzz_block_register_stake_delegation)
    - [`fd_runtime_fuzz_block_refresh_vote_accounts`](#fd_runtime_fuzz_block_refresh_vote_accounts)
    - [`fd_runtime_fuzz_block_update_prev_epoch_votes_cache`](#fd_runtime_fuzz_block_update_prev_epoch_votes_cache)
    - [`fd_runtime_fuzz_serialize_txn`](fd_txn_harness.c.driver.md#fd_runtime_fuzz_serialize_txn)


---
### fd\_runtime\_fuzz\_block\_ctx\_exec<!-- {{#callable:fd_runtime_fuzz_block_ctx_exec}} -->
The `fd_runtime_fuzz_block_ctx_exec` function executes a block of transactions against a runtime environment using a thread pool and shared memory allocations.
- **Inputs**:
    - `runner`: A pointer to an `fd_runtime_fuzz_runner_t` structure, which contains the runtime environment and shared memory allocations.
    - `slot_ctx`: A pointer to an `fd_exec_slot_ctx_t` structure, which holds the execution context for the current slot.
    - `block_info`: A pointer to an `fd_runtime_block_info_t` structure, which contains information about the block to be executed.
- **Control Flow**:
    - Initialize a thread pool (`tpool`) with a specified number of workers using shared memory from the runner's spad.
    - Allocate and initialize execution spads for each worker in the thread pool.
    - Begin a shared memory frame for the runtime spad and push the current state onto the spad stack.
    - Recalculate partitioned rewards using the slot context, thread pool, and execution spads.
    - Process any new epoch changes, ensuring that any new spad frames are cleared before block execution.
    - Execute the block using the thread pool and execution spads, storing the result in `res`.
    - End the shared memory frame and pop the worker from the thread pool.
- **Output**: Returns an integer `res` which indicates the result of the block execution, with 0 typically indicating success.


---
### FD\_SPAD\_FRAME\_BEGIN<!-- {{#callable:fd_runtime_fuzz_block_ctx_exec::FD_SPAD_FRAME_BEGIN}} -->
The `FD_SPAD_FRAME_BEGIN` function manages the execution of a block within a runtime environment, ensuring proper memory management and execution flow.
- **Inputs**:
    - `runtime_spad`: A pointer to the shared memory area (spad) used for runtime operations.
- **Control Flow**:
    - Pushes the current state onto the runtime spad stack using `fd_spad_push`.
    - Recalculates partitioned rewards by calling `fd_rewards_recalculate_partitioned_rewards`.
    - Stores the current spad frame count in `spad_frame_ct`.
    - Initializes `is_epoch_boundary` to 0 and processes a new epoch with `fd_runtime_block_pre_execute_process_new_epoch`.
    - Checks if new spad frames were added during epoch processing and pops them off the stack if necessary.
    - Executes the block using `fd_runtime_block_execute_tpool`.
- **Output**: The function does not return a value directly; it modifies the runtime environment and potentially updates the execution result stored in `res`.


---
### fd\_runtime\_fuzz\_block\_run<!-- {{#callable:fd_runtime_fuzz_block_run}} -->
The `fd_runtime_fuzz_block_run` function executes a fuzzing test block against a runtime environment and captures the execution effects.
- **Inputs**:
    - `runner`: A pointer to an `fd_runtime_fuzz_runner_t` structure, which manages the fuzzing runtime environment.
    - `input_`: A constant pointer to the input test block context, which is cast to `fd_exec_test_block_context_t`.
    - `output_`: A pointer to a location where the output effects of the block execution will be stored, cast to `fd_exec_test_block_effects_t`.
    - `output_buf`: A buffer where the output effects are temporarily stored during execution.
    - `output_bufsz`: The size of the output buffer, indicating the maximum amount of data that can be stored in `output_buf`.
- **Control Flow**:
    - Begin a new SPAD frame for memory management.
    - Attach to a workspace and initialize memory allocation structures.
    - Allocate and join a slot context for block execution.
    - Create a block execution context using the input test block context.
    - If block context creation fails, destroy the context and return 0.
    - Execute the block using the created context and capture the result.
    - Initialize scratch allocation for storing execution effects.
    - Check if the allocated memory exceeds the buffer size and abort if so.
    - Clear the effects structure and capture error status, capitalization, and hashes.
    - Finalize the scratch allocation and calculate the actual end of the output buffer.
    - Destroy the block execution context and release resources.
    - Store the effects in the output pointer and return the size of the output data.
- **Output**: Returns the size of the output data written to the output buffer, or 0 if block context creation fails.
- **Functions called**:
    - [`fd_runtime_fuzz_block_ctx_exec::FD_SPAD_FRAME_BEGIN`](#fd_runtime_fuzz_block_ctx_execFD_SPAD_FRAME_BEGIN)
    - [`fd_runtime_fuzz_block_ctx_create`](#fd_runtime_fuzz_block_ctx_create)
    - [`fd_runtime_fuzz_block_ctx_destroy`](#fd_runtime_fuzz_block_ctx_destroy)
    - [`fd_runtime_fuzz_block_ctx_exec`](#fd_runtime_fuzz_block_ctx_exec)


