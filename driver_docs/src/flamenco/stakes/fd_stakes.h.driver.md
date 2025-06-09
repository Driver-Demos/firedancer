# Purpose
The provided code is a C header file that defines a set of functions and data structures related to managing and processing stake delegations in a distributed system, likely a blockchain or similar decentralized network. The primary focus of this file is to handle operations involving stake weights, stake delegations, and vote accounts, which are crucial for maintaining the integrity and functionality of a proof-of-stake system. The file includes function prototypes for converting unordered lists of stakes into ordered lists, activating stakes for specific epochs, writing stake states, and managing stake delegations by either removing or updating them. Additionally, it provides mechanisms to refresh and populate vote accounts, which are essential for calculating rewards and maintaining the network's consensus.

The header file is designed to be included in other C source files, providing a public API for interacting with stake-related functionalities. It defines several data structures, such as `fd_compute_stake_delegations_t` and `fd_accumulate_delegations_task_args_t`, which encapsulate the necessary information for processing stake delegations and accumulating stake information. The file also includes a workaround function to mimic a specific functionality from an external source, indicating its integration with other systems or libraries. Overall, this header file serves as a critical component for managing stake-related operations in a distributed network, ensuring that stake delegations are processed efficiently and accurately.
# Imports and Dependencies

---
- `../fd_flamenco_base.h`
- `../types/fd_types.h`
- `../runtime/fd_borrowed_account.h`


# Data Structures

---
### fd\_compute\_stake\_delegations
- **Type**: `struct`
- **Members**:
    - `epoch`: Represents the current epoch for which the stake delegations are being computed.
    - `stake_history`: A pointer to a constant stake history structure, which holds historical stake data.
    - `new_rate_activation_epoch`: A pointer to an unsigned long that indicates the epoch when a new rate becomes active.
    - `delegation_pool`: A pointer to a map node structure that represents the pool of stake delegations.
    - `delegation_root`: A pointer to a map node structure that serves as the root of the stake delegation tree.
    - `vote_states_pool_sz`: An unsigned long representing the size of the vote states pool.
    - `spads`: A pointer to an array of pointers to spad structures, used for additional data storage or processing.
- **Description**: The `fd_compute_stake_delegations` structure is designed to manage and compute stake delegations within a given epoch. It holds references to historical stake data, manages the activation of new rates, and organizes stake delegations through a pool and root node structure. Additionally, it maintains the size of the vote states pool and utilizes spad structures for extended data handling, making it a comprehensive structure for managing stake-related computations in a distributed system.


---
### fd\_compute\_stake\_delegations\_t
- **Type**: `struct`
- **Members**:
    - `epoch`: Represents the current epoch for which the stake delegations are being computed.
    - `stake_history`: A pointer to a constant stake history structure, which holds historical stake data.
    - `new_rate_activation_epoch`: A pointer to an unsigned long that indicates the epoch when a new rate becomes active.
    - `delegation_pool`: A pointer to a map node structure that represents the pool of stake delegations.
    - `delegation_root`: A pointer to a map node structure that serves as the root of the stake delegation tree.
    - `vote_states_pool_sz`: An unsigned long representing the size of the pool of vote states.
    - `spads`: A pointer to an array of pointers to spad structures, used for managing shared data.
- **Description**: The `fd_compute_stake_delegations_t` structure is designed to manage and compute stake delegations within a given epoch. It holds references to historical stake data, manages the activation of new rates, and organizes stake delegations using a pool and root node structure. Additionally, it maintains a pool size for vote states and utilizes shared data structures (spads) for efficient data handling and computation.


---
### fd\_accumulate\_delegations\_task\_args
- **Type**: `struct`
- **Members**:
    - `slot_ctx`: A pointer to a constant fd_exec_slot_ctx_t structure, representing the execution context for a slot.
    - `stake_history`: A pointer to a constant fd_stake_history_t structure, representing the history of stakes.
    - `new_rate_activation_epoch`: A pointer to an unsigned long, representing the epoch at which a new rate is activated.
    - `accumulator`: A pointer to an fd_stake_history_entry_t structure, used to accumulate stake history entries.
    - `temp_info`: A pointer to an fd_epoch_info_t structure, used for temporary epoch information.
    - `spads`: A pointer to an array of fd_spad_t pointers, used for managing shared data structures.
    - `stake_delegations_pool`: A pointer to an fd_delegation_pair_t_mapnode_t structure, representing a pool of stake delegations.
    - `epoch`: An unsigned long representing the current epoch.
- **Description**: The `fd_accumulate_delegations_task_args` structure is designed to encapsulate all necessary arguments for a task that accumulates stake delegations. It includes pointers to various data structures such as execution context, stake history, and temporary epoch information, as well as a pool for stake delegations and an array for shared data structures. This structure facilitates the management and processing of stake delegation tasks within a specific epoch.


---
### fd\_accumulate\_delegations\_task\_args\_t
- **Type**: `struct`
- **Members**:
    - `slot_ctx`: A constant pointer to an execution slot context.
    - `stake_history`: A constant pointer to the stake history.
    - `new_rate_activation_epoch`: A pointer to an unsigned long representing the new rate activation epoch.
    - `accumulator`: A pointer to a stake history entry used for accumulation.
    - `temp_info`: A pointer to temporary epoch information.
    - `spads`: A pointer to an array of pointers to spad structures.
    - `stake_delegations_pool`: A pointer to a map node for stake delegations.
    - `epoch`: An unsigned long representing the epoch.
- **Description**: The `fd_accumulate_delegations_task_args_t` structure is designed to encapsulate the arguments required for a task that accumulates stake delegations. It includes pointers to various data structures such as execution slot context, stake history, and temporary epoch information, as well as a pool for stake delegations and an epoch identifier. This structure is used to manage and process stake delegation data efficiently within a specific epoch context.


# Function Declarations (Public API)

---
### fd\_stake\_weights\_by\_node<!-- {{#callable_declaration:fd_stake_weights_by_node}} -->
Converts stakes to an ordered list of node identities by stake weight.
- **Description**: This function processes an unordered list of vote accounts and their associated active stakes, converting them into an ordered list of node identities sorted by descending stake weight and node identity. It should be used when you need a sorted representation of stakes for further processing or analysis. The function requires a pre-allocated array for the weights, which must be large enough to hold the number of vote accounts. It returns the number of items in the weights array, which will be less than or equal to the number of vote accounts. If the function fails, it returns ULONG_MAX, typically due to insufficient space in the bump allocator.
- **Inputs**:
    - `accs`: A pointer to an fd_vote_accounts_t structure containing the unordered list of vote accounts and their active stakes. Must not be null.
    - `weights`: A pointer to an array of fd_stake_weight_t, pre-allocated to hold at least as many items as the number of vote accounts. The caller retains ownership and must ensure the array is sufficiently large.
    - `runtime_spad`: A pointer to an fd_spad_t structure used for temporary memory allocation during the function's execution. Must not be null and should have enough space for the function's operations.
- **Output**: Returns the number of items in the weights array, sorted by stake and node identity. Returns ULONG_MAX on failure.
- **See also**: [`fd_stake_weights_by_node`](fd_stakes.c.driver.md#fd_stake_weights_by_node)  (Implementation)


---
### fd\_stakes\_activate\_epoch<!-- {{#callable_declaration:fd_stakes_activate_epoch}} -->
Activates stake delegations for a new epoch.
- **Description**: This function is used to activate stake delegations for a new epoch within a distributed system. It should be called when transitioning to a new epoch to update the stake history and prepare for the next epoch's stake calculations. The function requires a valid execution slot context and expects the caller to manage memory for temporary epoch information and execution scratchpads. It is crucial to ensure that the runtime scratchpad is properly initialized and that the execution slot context is correctly set up before calling this function.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the execution slot context. Must not be null and should be properly initialized before calling the function.
    - `new_rate_activation_epoch`: A pointer to an unsigned long where the new rate activation epoch will be stored. Must not be null.
    - `temp_info`: A pointer to an fd_epoch_info_t structure used to store temporary epoch information. Must not be null and should be allocated by the caller.
    - `tpool`: A pointer to an fd_tpool_t structure representing the thread pool to be used for parallel processing. Must not be null.
    - `exec_spads`: A pointer to an array of fd_spad_t pointers, representing execution scratchpads. Must not be null and should have at least exec_spad_cnt elements.
    - `exec_spad_cnt`: An unsigned long indicating the number of execution scratchpads available in exec_spads. Must be greater than zero.
    - `runtime_spad`: A pointer to an fd_spad_t structure representing the runtime scratchpad. Must not be null and should be initialized before calling the function.
- **Output**: None
- **See also**: [`fd_stakes_activate_epoch`](fd_stakes.c.driver.md#fd_stakes_activate_epoch)  (Implementation)


---
### stake\_and\_activating<!-- {{#callable_declaration:stake_and_activating}} -->
Calculate the effective and activating stake for a given delegation at a target epoch.
- **Description**: This function computes the effective and activating stake for a given delegation at a specified target epoch, using historical stake data if available. It is useful for determining how much of a delegation's stake is currently effective and how much is in the process of being activated. The function should be called with a valid delegation and target epoch, and optionally with a stake history to refine the calculation. The function handles various edge cases, such as when the delegation is not yet activated or is already deactivated, and returns the appropriate effective and activating stake values.
- **Inputs**:
    - `delegation`: A pointer to a constant fd_delegation_t structure representing the delegation whose stake is being evaluated. Must not be null.
    - `target_epoch`: An unsigned long representing the epoch for which the stake calculation is being performed. Should be a valid epoch number.
    - `stake_history`: A pointer to a constant fd_stake_history_t structure containing historical stake data. Can be null if no historical data is available.
    - `new_rate_activation_epoch`: A pointer to an unsigned long where the function may store the epoch at which a new rate of activation is calculated. Must not be null.
- **Output**: Returns an effective_activating_t structure containing the effective and activating stake values for the given delegation at the target epoch.
- **See also**: [`stake_and_activating`](../runtime/program/fd_stake_program.c.driver.md#stake_and_activating)  (Implementation)


---
### stake\_activating\_and\_deactivating<!-- {{#callable_declaration:stake_activating_and_deactivating}} -->
Determine the stake activation and deactivation status for a given epoch.
- **Description**: This function is used to assess the status of stake activation and deactivation for a specific epoch based on the provided delegation and stake history. It is useful in scenarios where understanding the stake dynamics over time is necessary, such as in financial or blockchain applications. The function requires a valid delegation and optionally a stake history to compute the status. It returns a structure containing the effective, activating, and deactivating stake amounts for the specified epoch. The function handles cases where the target epoch is before, at, or after the deactivation epoch, and it can operate without a stake history, though this may affect the accuracy of the results.
- **Inputs**:
    - `delegation`: A pointer to a constant fd_delegation_t structure representing the stake delegation. Must not be null.
    - `target_epoch`: An unsigned long representing the epoch for which the stake status is being queried. Must be a valid epoch number.
    - `stake_history`: A pointer to a constant fd_stake_history_t structure representing the historical stake data. Can be null, in which case the function will handle the absence of historical data.
    - `new_rate_activation_epoch`: A pointer to an unsigned long where the function may store the epoch at which a new rate becomes active. Must not be null.
- **Output**: Returns an fd_stake_history_entry_t structure containing the effective, activating, and deactivating stake amounts for the specified epoch.
- **See also**: [`stake_activating_and_deactivating`](../runtime/program/fd_stake_program.c.driver.md#stake_activating_and_deactivating)  (Implementation)


---
### write\_stake\_state<!-- {{#callable_declaration:write_stake_state}} -->
Encodes and writes the stake state to a transaction account.
- **Description**: This function is used to encode a given stake state and write it into a specified transaction account. It is essential to ensure that the transaction account is properly initialized and capable of holding the encoded stake state data. The function assumes that the stake state provided is valid and can be encoded successfully. It is typically called when there is a need to update or store the stake state in a persistent manner. The function returns an integer status code, where a return value of 0 indicates success.
- **Inputs**:
    - `stake_acc_rec`: A pointer to a transaction account record where the encoded stake state will be written. This must not be null and should be properly initialized to allow data mutation.
    - `stake_state`: A pointer to the stake state to be encoded and written. This must not be null and should represent a valid stake state that can be encoded.
- **Output**: Returns 0 on successful encoding and writing of the stake state.
- **See also**: [`write_stake_state`](fd_stakes.c.driver.md#write_stake_state)  (Implementation)


---
### fd\_stakes\_remove\_stake\_delegation<!-- {{#callable_declaration:fd_stakes_remove_stake_delegation}} -->
Removes a stake delegation from the slot context.
- **Description**: Use this function to remove a stake delegation associated with a specific stake account from the given execution slot context. This function should be called when a stake delegation is no longer needed or needs to be deactivated. It is important to ensure that the slot context and stake account are properly initialized and valid before calling this function. The function does not perform any operation if the stake accounts pool does not exist in the slot context.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the execution slot context. Must not be null and should be properly initialized before calling this function.
    - `stake_account`: A pointer to an fd_borrowed_account_t structure representing the stake account whose delegation is to be removed. Must not be null and should contain a valid public key.
    - `new_rate_activation_epoch`: A pointer to an unsigned long integer where the new rate activation epoch may be stored. This parameter is not used in the current implementation and can be null.
- **Output**: None
- **See also**: [`fd_stakes_remove_stake_delegation`](../runtime/program/fd_stake_program.c.driver.md#fd_stakes_remove_stake_delegation)  (Implementation)


---
### fd\_stakes\_upsert\_stake\_delegation<!-- {{#callable_declaration:fd_stakes_upsert_stake_delegation}} -->
Upserts a stake delegation in the current execution slot context.
- **Description**: This function is used to insert or update a stake delegation within the current execution slot context. It should be called when a stake account needs to be added or updated in the context of the current epoch. The function requires that the stake account has a non-zero balance of lamports. If the stake delegations pool does not exist, the function will log a debug message and return without making any changes. Similarly, if the stake accounts pool does not exist, it will log a debug message and return. This function does not return any value and does not modify the input parameters directly.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the current execution slot context. Must not be null.
    - `stake_account`: A pointer to an fd_borrowed_account_t structure representing the stake account to be upserted. The account must have a non-zero balance of lamports. Must not be null.
    - `new_rate_activation_epoch`: A pointer to an unsigned long integer where the new rate activation epoch will be stored. Must not be null.
- **Output**: None
- **See also**: [`fd_stakes_upsert_stake_delegation`](../runtime/program/fd_stake_program.c.driver.md#fd_stakes_upsert_stake_delegation)  (Implementation)


---
### fd\_refresh\_vote\_accounts<!-- {{#callable_declaration:fd_refresh_vote_accounts}} -->
Refreshes vote accounts and updates epoch stakes.
- **Description**: This function is used to refresh the vote accounts and update the epoch stakes based on the current slot context and stake history. It should be called when the vote accounts need to be synchronized with the latest stake delegations. The function can operate in parallel if a thread pool is provided, which can improve performance by distributing the workload across multiple threads. It is important to ensure that all input parameters are properly initialized and valid before calling this function.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the current execution slot context. Must not be null.
    - `history`: A pointer to a constant fd_stake_history_t structure containing the stake history. Must not be null.
    - `new_rate_activation_epoch`: A pointer to an unsigned long where the new rate activation epoch will be stored. Must not be null.
    - `temp_info`: A pointer to an fd_epoch_info_t structure used for temporary storage during the function execution. Must not be null.
    - `tpool`: A pointer to an fd_tpool_t structure representing the thread pool for parallel execution. Can be null if parallel execution is not desired.
    - `exec_spads`: A pointer to an array of fd_spad_t pointers used for execution. Must not be null if tpool is provided.
    - `exec_spad_cnt`: An unsigned long representing the count of execution spads. Must be greater than zero if tpool is provided.
    - `runtime_spad`: A pointer to an fd_spad_t structure used for runtime memory allocation. Must not be null.
- **Output**: None
- **See also**: [`fd_refresh_vote_accounts`](fd_stakes.c.driver.md#fd_refresh_vote_accounts)  (Implementation)


---
### fd\_populate\_vote\_accounts<!-- {{#callable_declaration:fd_populate_vote_accounts}} -->
Populates vote accounts with stake information for a given slot context.
- **Description**: This function is used to populate vote accounts with the relevant stake information for a given execution slot context. It should be called when you need to update or initialize the vote accounts with the current stake data, typically as part of a larger process involving stake delegation and vote account management. The function requires a valid slot context and expects the caller to provide necessary resources such as a thread pool and memory allocation structures. It handles both single-threaded and multi-threaded execution based on the availability of a thread pool. Ensure that all input pointers are valid and properly initialized before calling this function.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the execution slot context. Must not be null.
    - `history`: A pointer to a constant fd_stake_history_t structure containing the stake history. Must not be null.
    - `new_rate_activation_epoch`: A pointer to an unsigned long where the new rate activation epoch will be stored. Must not be null.
    - `temp_info`: A pointer to an fd_epoch_info_t structure used for temporary storage during execution. Must not be null.
    - `tpool`: A pointer to an fd_tpool_t structure representing the thread pool for parallel execution. Can be null for single-threaded execution.
    - `exec_spads`: A pointer to an array of fd_spad_t pointers used for execution. Must not be null and should have at least exec_spad_cnt elements.
    - `exec_spad_cnt`: An unsigned long indicating the number of execution spads available. Must be greater than zero.
    - `runtime_spad`: A pointer to an fd_spad_t structure used for runtime memory allocation. Must not be null.
- **Output**: None
- **See also**: [`fd_populate_vote_accounts`](fd_stakes.c.driver.md#fd_populate_vote_accounts)  (Implementation)


---
### fd\_accumulate\_stake\_infos<!-- {{#callable_declaration:fd_accumulate_stake_infos}} -->
Accumulates stake information for a given execution slot context.
- **Description**: This function is used to accumulate stake information based on the provided execution slot context, stakes, and stake history. It is typically called to update stake-related data structures during an epoch. The function requires a valid execution slot context, stakes, and stake history to operate correctly. It can utilize a thread pool for parallel processing if provided, and it requires sufficient space in the runtime scratchpad for temporary allocations. The function updates the accumulator with new stake information and modifies the temporary epoch info structure with the latest stake keys.
- **Inputs**:
    - `slot_ctx`: A pointer to a constant fd_exec_slot_ctx_t structure representing the execution slot context. Must not be null.
    - `stakes`: A pointer to a constant fd_stakes_t structure containing the stakes information. Must not be null.
    - `history`: A pointer to a constant fd_stake_history_t structure representing the stake history. Must not be null.
    - `new_rate_activation_epoch`: A pointer to an unsigned long where the new rate activation epoch will be stored. Must not be null.
    - `accumulator`: A pointer to an fd_stake_history_entry_t structure where accumulated stake information will be stored. Must not be null.
    - `temp_info`: A pointer to an fd_epoch_info_t structure used for temporary storage of epoch information. Must not be null.
    - `tpool`: A pointer to an fd_tpool_t structure representing the thread pool for parallel processing. Can be null, in which case single-threaded processing is used.
    - `exec_spads`: A pointer to an array of fd_spad_t pointers used for execution scratchpads. Must not be null if exec_spads_cnt is greater than zero.
    - `exec_spads_cnt`: An unsigned long indicating the number of execution scratchpads available. Must be greater than zero if exec_spads is not null.
    - `runtime_spad`: A pointer to an fd_spad_t structure used for runtime scratchpad allocations. Must not be null.
- **Output**: None
- **See also**: [`fd_accumulate_stake_infos`](fd_stakes.c.driver.md#fd_accumulate_stake_infos)  (Implementation)


