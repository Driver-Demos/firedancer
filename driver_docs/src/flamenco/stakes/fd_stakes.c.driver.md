# Purpose
The provided C code is a comprehensive implementation for managing and processing stake-related data in a blockchain context, likely inspired by Solana's staking mechanism. The code is structured to handle various tasks such as accumulating stakes by node, sorting stake weights, exporting stake data, and refreshing vote accounts. It utilizes data structures like red-black trees and hash maps to efficiently manage and query stake information. The code is designed to be part of a larger system, as indicated by the inclusion of multiple header files and the use of specific data types and functions that suggest integration with a broader runtime environment.

Key components of the code include functions for accumulating stakes by node identity, sorting stake weights, and exporting these weights into a list format. The code also includes functions for deserializing vote accounts, computing stake delegations, and updating vote accounts with new stake information. Additionally, the code provides mechanisms for parallel processing using thread pools, which enhances performance when dealing with large datasets. The functions are designed to be used within a larger application, as they rely on external data structures and runtime contexts. Overall, the code provides a robust framework for managing stake data, which is crucial for maintaining the integrity and efficiency of a proof-of-stake blockchain system.
# Imports and Dependencies

---
- `fd_stakes.h`
- `../runtime/fd_system_ids.h`
- `../runtime/context/fd_exec_epoch_ctx.h`
- `../runtime/context/fd_exec_slot_ctx.h`
- `../runtime/program/fd_stake_program.h`
- `../runtime/sysvar/fd_sysvar_stake_history.h`
- `../../util/tmpl/fd_sort.c`


# Functions

---
### fd\_stakes\_accum\_by\_node<!-- {{#callable:fd_stakes_accum_by_node}} -->
The `fd_stakes_accum_by_node` function accumulates active stakes from vote accounts and maps them to node identities, returning a red-black tree ordered by node identity.
- **Inputs**:
    - `in`: A pointer to a `fd_vote_accounts_t` structure containing the vote accounts and their stakes.
    - `out_pool`: A pointer to a pool of `fd_stake_weight_t_mapnode_t` nodes used for storing the accumulated stakes.
    - `runtime_spad`: A pointer to a `fd_spad_t` structure used for runtime memory allocation and decoding operations.
- **Control Flow**:
    - Initialize pointers to the input vote accounts pool and root.
    - Iterate over each vote account using a red-black tree traversal starting from the minimum node.
    - Skip vote accounts with a stake of zero.
    - Decode the vote account data to retrieve the node identity (pubkey) using `fd_bincode_decode_spad`.
    - Check for decoding errors and log them if any occur.
    - Extract the node pubkey based on the version of the vote state.
    - Skip nodes with a null pubkey and log a warning.
    - Acquire a new node from the output pool to query the existing map for the node identity.
    - If the node identity is found, release the query node and accumulate the stake to the existing node.
    - If the node identity is not found, use the query node to create a new entry in the map with the current stake.
    - Insert the new node into the red-black tree map.
    - Return the root of the red-black tree containing the accumulated stakes.
- **Output**: A pointer to the root of a red-black tree (`fd_stake_weight_t_mapnode_t`) mapping node identities to their accumulated stakes.


---
### fd\_stakes\_sort\_before<!-- {{#callable:fd_stakes_sort_before}} -->
The `fd_stakes_sort_before` function compares two `fd_stake_weight_t` structures to determine their order based on stake and key values.
- **Inputs**:
    - `a`: The first `fd_stake_weight_t` structure to compare.
    - `b`: The second `fd_stake_weight_t` structure to compare.
- **Control Flow**:
    - Check if the stake of `a` is greater than the stake of `b`; if true, return 1.
    - Check if the stake of `a` is less than the stake of `b`; if true, return 0.
    - If stakes are equal, compare the keys of `a` and `b` using `memcmp`; if `a`'s key is greater, return 1.
    - If none of the above conditions are met, return 0.
- **Output**: Returns 1 if `a` should be ordered before `b`, otherwise returns 0.


---
### fd\_stake\_weight\_sort<!-- {{#callable:fd_stake_weight_sort}} -->
The `fd_stake_weight_sort` function sorts an array of stake weights in descending order based on the stake and pubkey tuple.
- **Inputs**:
    - `stakes`: A pointer to an array of `fd_stake_weight_t` structures representing the stake weights to be sorted.
    - `stakes_cnt`: An unsigned long integer representing the number of elements in the `stakes` array.
- **Control Flow**:
    - The function calls `fd_stakes_sort_inplace` with the `stakes` array and `stakes_cnt` as arguments.
    - `fd_stakes_sort_inplace` sorts the array in place based on the criteria defined in `fd_stakes_sort_before`, which compares stake values and pubkeys.
- **Output**: The function does not return a value; it sorts the input array in place.


---
### fd\_stakes\_export<!-- {{#callable:fd_stakes_export}} -->
The `fd_stakes_export` function exports elements from a red-black tree structure into a linear array.
- **Inputs**:
    - `in_pool`: A pointer to the pool of nodes in the red-black tree from which elements are exported.
    - `root`: A pointer to the root node of the red-black tree.
    - `out`: A pointer to the output array where the elements will be stored.
- **Control Flow**:
    - Initialize `out_end` to point to the start of the output array `out`.
    - Iterate over the elements of the red-black tree starting from the minimum element, using `fd_stake_weight_t_map_minimum` to find the starting element and `fd_stake_weight_t_map_successor` to find the next element.
    - For each element in the tree, copy its `elem` field to the current position of `out_end` and increment `out_end`.
    - Continue this process until there are no more elements in the tree.
- **Output**: Returns the number of elements exported to the output array, calculated as the difference between `out_end` and `out`, cast to `ulong`.


---
### fd\_stake\_weights\_by\_node<!-- {{#callable:fd_stake_weights_by_node}} -->
The `fd_stake_weights_by_node` function calculates and sorts the stake weights for each node based on the provided vote accounts.
- **Inputs**:
    - `accs`: A pointer to `fd_vote_accounts_t` which contains the vote accounts pool and root.
    - `weights`: A pointer to an array of `fd_stake_weight_t` where the calculated stake weights will be stored.
    - `runtime_spad`: A pointer to `fd_spad_t` used for memory allocation during runtime.
- **Control Flow**:
    - Calculate the number of vote accounts using `fd_vote_accounts_pair_t_map_size`.
    - Determine the alignment and footprint for the red-black tree using `fd_stake_weight_t_map_align` and `fd_stake_weight_t_map_footprint`.
    - Allocate memory for the red-black tree using `fd_spad_alloc` and initialize it with `fd_stake_weight_t_map_new`.
    - Join the allocated memory to a red-black tree node pool using `fd_stake_weight_t_map_join`.
    - Check if memory allocation was successful; if not, log a critical error.
    - Accumulate stakes into the red-black tree using [`fd_stakes_accum_by_node`](#fd_stakes_accum_by_node).
    - Export the accumulated stakes to a sorted list using [`fd_stakes_export`](#fd_stakes_export).
    - Sort the list of stake weights using [`fd_stake_weight_sort`](#fd_stake_weight_sort).
- **Output**: Returns the number of stake weights calculated and stored in the `weights` array.
- **Functions called**:
    - [`fd_stakes_accum_by_node`](#fd_stakes_accum_by_node)
    - [`fd_stakes_export`](#fd_stakes_export)
    - [`fd_stake_weight_sort`](#fd_stake_weight_sort)


---
### deserialize\_and\_update\_vote\_account<!-- {{#callable:deserialize_and_update_vote_account}} -->
The `deserialize_and_update_vote_account` function deserializes a vote account and updates its stake information based on the provided stake delegations.
- **Inputs**:
    - `slot_ctx`: A pointer to the `fd_exec_slot_ctx_t` structure, which contains context information for the current execution slot.
    - `elem`: A pointer to the `fd_vote_accounts_pair_t_mapnode_t` structure, which will be populated with the updated stake information.
    - `stake_delegations_root`: A pointer to the root of the stake delegations map, used to find the stake associated with the vote account.
    - `stake_delegations_pool`: A pointer to the pool of stake delegations, used to find the stake associated with the vote account.
    - `vote_account_pubkey`: A constant pointer to the `fd_pubkey_t` structure representing the public key of the vote account to be deserialized and updated.
    - `runtime_spad`: A pointer to the `fd_spad_t` structure, which is used for runtime memory allocation and management.
- **Control Flow**:
    - Declare a transaction account for the vote account using `FD_TXN_ACCOUNT_DECL` macro.
    - Initialize the transaction account from the `slot_ctx` using `fd_txn_account_init_from_funk_readonly`; if it fails, log a debug message and return `NULL`.
    - Deserialize the vote account data using `fd_bincode_decode_spad`; if deserialization fails, return `NULL`.
    - Create a temporary map node with the vote account's public key to search for its stake in the stake delegations map.
    - Find the stake amount associated with the vote account in the stake delegations map; if not found, set the stake to 0.
    - Return the deserialized vote state.
- **Output**: Returns a pointer to the deserialized `fd_vote_state_versioned_t` structure if successful, or `NULL` if an error occurs.


---
### compute\_stake\_delegations<!-- {{#callable:compute_stake_delegations}} -->
The `compute_stake_delegations` function calculates and updates stake delegations for a specified range of stake information entries.
- **Inputs**:
    - `temp_info`: A pointer to `fd_epoch_info_t` structure containing temporary epoch information, including stake information.
    - `task_args`: A pointer to `fd_compute_stake_delegations_t` structure containing task arguments such as epoch, stake history, and delegation pools.
    - `worker_idx`: An unsigned long integer representing the index of the worker processing this task.
    - `start_idx`: An unsigned long integer indicating the starting index of the stake information entries to process.
    - `end_idx`: An unsigned long integer indicating the ending index of the stake information entries to process.
- **Control Flow**:
    - Allocate memory for a temporary map to hold delegations using `fd_spad_alloc` and initialize it.
    - Iterate over the stake information entries from `start_idx` to `end_idx`.
    - For each entry, check if the delegation is present in the delegation pool; if not, skip it.
    - Calculate the new stake entry using `fd_stake_activating_and_deactivating` and update the temporary map with the effective stake.
    - After processing all entries, iterate over the temporary map and update the parent delegation pool with the calculated delegation values using atomic operations.
- **Output**: The function does not return a value; it updates the delegation pool with new stake values based on the processed entries.


---
### FD\_SPAD\_FRAME\_BEGIN<!-- {{#callable:accumulate_stake_cache_delegations::FD_SPAD_FRAME_BEGIN}} -->
The `FD_SPAD_FRAME_BEGIN` function processes stake delegations for a specific worker, updating temporary and accumulated stake information.
- **Inputs**:
    - `spad`: A pointer to a shared memory area used for temporary data storage during the function's execution.
- **Control Flow**:
    - The function iterates over a list of delegation nodes specific to a worker, starting from `delegations_roots[worker_idx]` and ending at `end_node`.
    - For each node, it initializes an account from a read-only function and checks if the account is valid and has non-zero lamports.
    - If valid, it retrieves the stake state and checks if it is a valid stake and has a non-zero delegation stake.
    - If all checks pass, it updates the temporary stake information with the current stake and account details.
    - It calculates the effective, activating, and deactivating stake values using `fd_stake_activating_and_deactivating` and accumulates these values.
    - Finally, it updates the global accumulator with the effective, activating, and deactivating values using atomic operations.
- **Output**: The function does not return a value but updates the temporary stake information and the global accumulator with the processed stake data.


---
### compute\_stake\_delegations\_tpool\_task<!-- {{#callable:compute_stake_delegations_tpool_task}} -->
The `compute_stake_delegations_tpool_task` function is a task function designed to compute stake delegations using a thread pool, delegating the actual computation to the [`compute_stake_delegations`](#compute_stake_delegations) function.
- **Inputs**:
    - `tpool`: A pointer to a thread pool, which is used to manage and execute tasks concurrently.
    - `t0`: An unused parameter, typically representing a start time or index.
    - `t1`: An unused parameter, typically representing an end time or index.
    - `args`: A pointer to the arguments for the task, specifically a `fd_compute_stake_delegations_t` structure containing task-specific data.
    - `reduce`: An unused parameter, typically used for reduction operations in parallel computing.
    - `stride`: An unused parameter, typically representing a step size or interval.
    - `l0`: An unused parameter, typically representing a lower bound or start index.
    - `l1`: An unused parameter, typically representing an upper bound or end index.
    - `m0`: A parameter representing the start index for the range of stake delegations to process.
    - `m1`: A parameter representing the end index for the range of stake delegations to process.
    - `n0`: An unused parameter, typically representing a lower bound or start index.
    - `n1`: An unused parameter, typically representing an upper bound or end index.
- **Control Flow**:
    - Cast the `tpool` pointer to a `fd_epoch_info_t` pointer and assign it to `temp_info`.
    - Cast the `args` pointer to a `fd_compute_stake_delegations_t` pointer and assign it to `task_args`.
    - Retrieve the current worker index using `fd_tile_idx()`.
    - Call the [`compute_stake_delegations`](#compute_stake_delegations) function with `temp_info`, `task_args`, `worker_idx`, `m0`, and `m1` as arguments.
- **Output**: This function does not return any value; it performs its operations as a side effect, updating the stake delegations.
- **Functions called**:
    - [`compute_stake_delegations`](#compute_stake_delegations)


---
### deserialize\_vote\_account<!-- {{#callable:deserialize_vote_account}} -->
The `deserialize_vote_account` function decodes a vote account's data into a `fd_vote_state_versioned_t` structure using a specified runtime scratchpad.
- **Inputs**:
    - `elem`: A pointer to a `fd_vote_accounts_pair_t_mapnode_t` structure containing the vote account data to be deserialized.
    - `runtime_spad`: A pointer to a `fd_spad_t` structure used as a scratchpad for temporary data during deserialization.
- **Control Flow**:
    - Call `fd_bincode_decode_spad` with the vote account data from `elem` and the `runtime_spad` to decode the data into a `fd_vote_state_versioned_t` structure.
    - Check if an error occurred during decoding using the `err` variable.
    - If an error occurred (`err` is non-zero), return `NULL`.
    - If no error occurred, return the decoded `fd_vote_state_versioned_t` structure.
- **Output**: Returns a pointer to a `fd_vote_state_versioned_t` structure if decoding is successful, or `NULL` if an error occurs during decoding.


---
### fd\_populate\_vote\_accounts<!-- {{#callable:fd_populate_vote_accounts}} -->
The `fd_populate_vote_accounts` function updates the vote accounts with the current delegated stake information from the next epoch's cached stakes into a temporary information structure.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context, which contains information about the current slot and epoch.
    - `history`: A constant pointer to the stake history, which records the history of stake changes.
    - `new_rate_activation_epoch`: A pointer to an unsigned long that indicates the epoch when a new rate is activated.
    - `temp_info`: A pointer to a temporary epoch information structure used to store intermediate state about vote accounts.
    - `tpool`: A pointer to a thread pool used for parallel execution of tasks.
    - `exec_spads`: An array of pointers to execution scratchpad memory areas used for temporary data storage.
    - `exec_spad_cnt`: The count of execution scratchpad memory areas available.
    - `runtime_spad`: A pointer to a runtime scratchpad memory area used for temporary data storage.
- **Control Flow**:
    - Initialize a temporary vote states cache using the size of the vote accounts and account keys pools.
    - Create a map to store the total stake of each vote account by iterating over the vote accounts and account keys, inserting them into the map with an initial stake of zero.
    - Prepare task arguments for computing stake delegations, including epoch, stake history, and delegation pool information.
    - If a thread pool is available, execute the stake delegation computation in parallel using the thread pool; otherwise, perform the computation serially.
    - Iterate over each vote account in the epoch stakes cache, deserialize the vote account, and update the total epoch stake and temporary vote states cache.
    - Update the total epoch stake in the slot context's epoch context.
- **Output**: The function does not return a value; it updates the temporary vote states cache and the total epoch stake in the slot context's epoch context.
- **Functions called**:
    - [`compute_stake_delegations`](#compute_stake_delegations)
    - [`deserialize_vote_account`](#deserialize_vote_account)


---
### fd\_refresh\_vote\_accounts<!-- {{#callable:fd_refresh_vote_accounts}} -->
The `fd_refresh_vote_accounts` function updates the epoch bank's vote accounts cache by recalculating the total delegated stake for each vote account using current delegation values and merging with new vote account keys for the current epoch.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context, which contains information about the current slot and its associated data.
    - `history`: A constant pointer to the stake history, which provides historical data on stake changes.
    - `new_rate_activation_epoch`: A pointer to an unsigned long that indicates the epoch at which a new rate is activated.
    - `temp_info`: A pointer to temporary epoch information used to store intermediate state about stake and vote accounts.
    - `tpool`: A pointer to a thread pool used for parallel execution of tasks, or NULL if not used.
    - `exec_spads`: An array of pointers to execution scratchpad areas used for temporary data storage during execution.
    - `exec_spad_cnt`: The count of execution scratchpad areas available.
    - `runtime_spad`: A pointer to a runtime scratchpad used for memory allocation during execution.
- **Control Flow**:
    - Initialize a temporary vote states cache and a map to store the total stake of each vote account.
    - Iterate over existing vote accounts and account keys to populate the stake map with initial entries.
    - Prepare task arguments for computing stake delegations, including epoch, stake history, and delegation pool information.
    - If a thread pool is available, execute the stake delegation computation in parallel using the thread pool; otherwise, perform the computation sequentially.
    - Iterate over each vote account in the epoch stakes cache, deserialize and update vote account information, and populate the new vote accounts pool.
    - Update the epoch stakes cache with new vote accounts from the current epoch, ensuring no duplicate processing of vote account keys.
    - Release resources associated with the vote account keys in the slot bank.
- **Output**: The function updates the total epoch stake in the slot context's epoch context and refreshes the vote accounts cache with recalculated stake information.
- **Functions called**:
    - [`compute_stake_delegations`](#compute_stake_delegations)
    - [`deserialize_and_update_vote_account`](#deserialize_and_update_vote_account)


---
### accumulate\_stake\_cache\_delegations<!-- {{#callable:accumulate_stake_cache_delegations}} -->
The function `accumulate_stake_cache_delegations` processes a range of stake delegations to update an accumulator with effective, activating, and deactivating stake values.
- **Inputs**:
    - `delegations_roots`: An array of pointers to the root nodes of delegation trees for each worker.
    - `task_args`: A structure containing various task arguments, including slot context, stake history, accumulator, and other necessary data for processing delegations.
    - `worker_idx`: The index of the current worker, used to access specific data for that worker.
    - `end_node`: A pointer to the node marking the end of the delegation list to process.
- **Control Flow**:
    - Initialize local variables for effective, activating, and deactivating stake counts to zero.
    - Begin a frame for the scratchpad memory (spad) associated with the current worker.
    - Iterate over the delegation nodes starting from the root for the current worker until reaching the end node.
    - For each node, initialize a transaction account from the node's account data and check if it is valid and has non-zero lamports.
    - Retrieve the stake state from the account and check if it is a valid stake with a non-zero delegation stake.
    - If valid, update the temporary information with the stake and account data, and calculate new stake history entries for effective, activating, and deactivating stakes.
    - Accumulate the calculated effective, activating, and deactivating values into the local variables.
    - After processing all nodes, update the global accumulator with the local effective, activating, and deactivating values using atomic operations.
    - End the frame for the scratchpad memory.
- **Output**: The function does not return a value but updates the accumulator with the total effective, activating, and deactivating stake values for the processed delegations.


---
### accumulate\_stake\_cache\_delegations\_tpool\_task<!-- {{#callable:FD_FN_UNUSED::accumulate_stake_cache_delegations_tpool_task}} -->
The `accumulate_stake_cache_delegations_tpool_task` function is a task executed in a thread pool to accumulate stake cache delegations for a specific worker index.
- **Inputs**:
    - `tpool`: A pointer to the thread pool, which is used to manage parallel execution of tasks.
    - `t0`: Unused parameter, typically used for task partitioning.
    - `t1`: Unused parameter, typically used for task partitioning.
    - `args`: A pointer to the task arguments, specifically of type `fd_accumulate_delegations_task_args_t`, which contains necessary data for the task.
    - `reduce`: Unused parameter, typically used for reduction operations in parallel tasks.
    - `stride`: Unused parameter, typically used for task partitioning.
    - `l0`: Unused parameter, typically used for task partitioning.
    - `l1`: Unused parameter, typically used for task partitioning.
    - `m0`: Unused parameter, typically used for task partitioning.
    - `m1`: Unused parameter, typically used for task partitioning.
    - `n0`: Unused parameter, typically used for task partitioning.
    - `n1`: Unused parameter, typically used for task partitioning.
- **Control Flow**:
    - Retrieve the `delegations_roots` from the `tpool` parameter, which is cast to a pointer to an array of `fd_delegation_pair_t_mapnode_t` pointers.
    - Retrieve the `task_args` from the `args` parameter, which is cast to a pointer of type `fd_accumulate_delegations_task_args_t`.
    - Determine the `worker_idx` using the `fd_tile_idx()` function, which identifies the current worker's index in the thread pool.
    - Call the [`accumulate_stake_cache_delegations`](#accumulate_stake_cache_delegations) function with the `delegations_roots`, `task_args`, `worker_idx`, and the end node for the current worker's delegation range.
- **Output**: This function does not return any value; it performs its operations as a side effect, updating the state of the stake cache delegations.
- **Functions called**:
    - [`accumulate_stake_cache_delegations`](#accumulate_stake_cache_delegations)


---
### fd\_accumulate\_stake\_infos<!-- {{#callable:fd_accumulate_stake_infos}} -->
The `fd_accumulate_stake_infos` function accumulates information about epoch stakes into a temporary cache and collects statistics on effective, activating, and deactivating stakes.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context, providing context for the current execution slot.
    - `stakes`: A pointer to the stakes structure, containing information about current stake delegations and epoch.
    - `history`: A pointer to the stake history, which records past stake states.
    - `new_rate_activation_epoch`: A pointer to an unsigned long representing the epoch at which a new rate is activated.
    - `accumulator`: A pointer to a stake history entry structure used to accumulate effective, activating, and deactivating stake values.
    - `temp_info`: A pointer to a temporary epoch information structure used to cache intermediate stake and vote account states.
    - `tpool`: A pointer to a thread pool structure used for parallel execution of tasks.
    - `exec_spads`: An array of pointers to execution scratchpad structures used for temporary storage during execution.
    - `exec_spads_cnt`: An unsigned long representing the count of execution scratchpads available.
    - `runtime_spad`: A pointer to a runtime scratchpad structure used for temporary memory allocation.
- **Control Flow**:
    - Calculate the size of the stake delegations pool and return immediately if it is zero.
    - Determine the number of workers based on the thread pool and execution scratchpads available.
    - Allocate memory for batch delegation roots and index starts using the runtime scratchpad.
    - Partition the delegations pool logically for parallel processing by workers.
    - Iterate over the delegations pool to set batch delegation roots for each worker.
    - Initialize task arguments for accumulating delegations, including context, history, and accumulator.
    - Execute the accumulation task in parallel using the thread pool if available, otherwise execute sequentially.
    - Set the start index for new stake information keys in the temporary info structure.
    - Iterate over account keys in the slot context to update the temporary info and accumulator with stake information.
- **Output**: The function does not return a value but updates the `accumulator` with effective, activating, and deactivating stake values, and populates `temp_info` with intermediate stake information.
- **Functions called**:
    - [`accumulate_stake_cache_delegations`](#accumulate_stake_cache_delegations)


---
### fd\_stakes\_activate\_epoch<!-- {{#callable:fd_stakes_activate_epoch}} -->
The `fd_stakes_activate_epoch` function updates the stake history for the previous epoch by accumulating stake information and adding a new entry to the Stake History sysvar.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context, which contains information about the current execution environment.
    - `new_rate_activation_epoch`: A pointer to an unsigned long that represents the epoch at which a new rate is activated.
    - `temp_info`: A pointer to a temporary epoch information structure used to store intermediate stake information.
    - `tpool`: A pointer to a thread pool used for parallel execution of tasks.
    - `exec_spads`: An array of pointers to execution scratchpad memory areas used for temporary data storage.
    - `exec_spad_cnt`: The count of execution scratchpad memory areas available.
    - `runtime_spad`: A pointer to a runtime scratchpad memory area used for temporary data storage.
- **Control Flow**:
    - Retrieve the epoch bank and stakes from the slot context's epoch context.
    - Read the stake history from the sysvar cache using the slot context's function and transaction.
    - Calculate the size of the stake delegations by summing the sizes of the stake delegations pool and the account keys pool.
    - Allocate memory for temporary stake information and initialize it to zero.
    - Initialize an accumulator for effective, activating, and deactivating stake values.
    - Call [`fd_accumulate_stake_infos`](#fd_accumulate_stake_infos) to gather stake information and update the accumulator with the current stake statistics.
    - Create a new stake history entry with the accumulated stake values and the current epoch.
    - Update the Stake History sysvar with the new entry using the slot context and runtime scratchpad.
- **Output**: The function does not return a value; it updates the Stake History sysvar with new stake information for the previous epoch.
- **Functions called**:
    - [`fd_accumulate_stake_infos`](#fd_accumulate_stake_infos)


---
### write\_stake\_state<!-- {{#callable:write_stake_state}} -->
The `write_stake_state` function encodes a given stake state into a mutable data buffer of a transaction account.
- **Inputs**:
    - `stake_acc_rec`: A pointer to a `fd_txn_account_t` structure representing the transaction account where the stake state will be written.
    - `stake_state`: A pointer to a `fd_stake_state_v2_t` structure representing the stake state to be encoded and written.
- **Control Flow**:
    - Calculate the size of the encoded stake state using `fd_stake_state_v2_size` function.
    - Initialize an encoding context `ctx` with a data buffer obtained from the transaction account's mutable data and set the data end based on the encoded stake state size.
    - Attempt to encode the stake state into the context using `fd_stake_state_v2_encode`.
    - If encoding fails, log an error message using `FD_LOG_ERR`.
    - Return 0 to indicate successful execution.
- **Output**: The function returns an integer value of 0, indicating successful execution.


