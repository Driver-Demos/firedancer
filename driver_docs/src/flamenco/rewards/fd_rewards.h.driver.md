# Purpose
This C header file, `fd_reward.h`, is part of a larger software system related to the management and calculation of rewards in a blockchain or distributed ledger context, likely within a framework named "Flamenco." It defines data structures and function prototypes for handling reward calculations and distributions, specifically focusing on stake and vote rewards. The file includes several other headers, indicating dependencies on various components such as execution context, stake programs, vote programs, and system variables related to epochs and rewards. The defined structures, `fd_calculate_points_task_args_t` and `fd_calculate_stake_vote_rewards_task_args_t`, encapsulate the necessary arguments for tasks related to calculating points and stake vote rewards, respectively. The functions declared, such as [`fd_update_rewards`](#fd_update_rewards) and [`fd_distribute_partitioned_epoch_rewards`](#fd_distribute_partitioned_epoch_rewards), suggest a workflow for updating, beginning, recalculating, and distributing rewards in a partitioned manner, likely to optimize performance and scalability in a distributed system.
# Imports and Dependencies

---
- `../fd_flamenco_base.h`
- `../runtime/context/fd_exec_instr_ctx.h`
- `../runtime/program/fd_stake_program.h`
- `../runtime/program/fd_vote_program.h`
- `../runtime/sysvar/fd_sysvar.h`
- `../runtime/sysvar/fd_sysvar_epoch_rewards.h`
- `../runtime/sysvar/fd_sysvar_epoch_schedule.h`
- `../stakes/fd_stakes.h`


# Data Structures

---
### fd\_calculate\_points\_task\_args\_t
- **Type**: `struct`
- **Members**:
    - `stake_history`: A pointer to a constant fd_stake_history_t structure, representing the history of stakes.
    - `new_warmup_cooldown_rate_epoch`: A pointer to an unsigned long integer, representing the new epoch for warmup/cooldown rate.
    - `minimum_stake_delegation`: An unsigned long integer, representing the minimum stake delegation required.
    - `vote_states_root`: A pointer to a fd_vote_info_pair_t_mapnode_t structure, representing the root of vote states.
    - `vote_states_pool`: A pointer to a fd_vote_info_pair_t_mapnode_t structure, representing the pool of vote states.
    - `total_points`: A pointer to a uint128, representing the total points calculated, used as an output field.
- **Description**: The `fd_calculate_points_task_args_t` structure is designed to encapsulate the arguments required for calculating points in a staking and voting system. It includes references to historical stake data, parameters for epoch rate adjustments, and structures for managing vote states. Additionally, it provides an output field for storing the total points calculated, facilitating the integration of this data into broader reward calculation processes.


---
### fd\_calculate\_stake\_vote\_rewards\_task\_args
- **Type**: `struct`
- **Members**:
    - `slot_ctx`: Pointer to the execution slot context.
    - `stake_history`: Pointer to the constant stake history.
    - `rewarded_epoch`: Unsigned long representing the epoch for which rewards are calculated.
    - `new_warmup_cooldown_rate_epoch`: Pointer to an unsigned long for the new warmup cooldown rate epoch.
    - `point_value`: Pointer to the point value structure.
    - `result`: Pointer to the structure holding the results of the reward calculation.
    - `exec_spads`: Pointer to an array of execution SPADs.
    - `exec_spad_cnt`: Unsigned long representing the count of execution SPADs.
- **Description**: The `fd_calculate_stake_vote_rewards_task_args` structure is designed to encapsulate all necessary arguments for calculating stake vote rewards in a distributed system. It includes pointers to various contexts and histories, such as the execution slot context and stake history, as well as parameters like the rewarded epoch and point value. Additionally, it holds pointers to the results and execution SPADs, along with their count, facilitating the management and computation of rewards across different epochs.


---
### fd\_calculate\_stake\_vote\_rewards\_task\_args\_t
- **Type**: `struct`
- **Members**:
    - `slot_ctx`: Pointer to the execution slot context.
    - `stake_history`: Pointer to the constant stake history.
    - `rewarded_epoch`: The epoch for which rewards are being calculated.
    - `new_warmup_cooldown_rate_epoch`: Pointer to the new warmup cooldown rate epoch.
    - `point_value`: Pointer to the point value used in reward calculations.
    - `result`: Pointer to the structure holding the results of the reward calculation.
    - `exec_spads`: Pointer to an array of execution spad pointers.
    - `exec_spad_cnt`: Count of execution spads.
- **Description**: The `fd_calculate_stake_vote_rewards_task_args_t` structure is used to encapsulate the arguments required for calculating stake vote rewards in a distributed system. It includes pointers to various contexts and histories, such as the execution slot context and stake history, as well as parameters like the rewarded epoch and point value. Additionally, it holds pointers to the results and execution spads, which are used in the reward calculation process.


# Function Declarations (Public API)

---
### fd\_update\_rewards<!-- {{#callable_declaration:fd_update_rewards}} -->
Update rewards for a given execution slot context.
- **Description**: This function is used to update the rewards associated with a specific execution slot context. It should be called when rewards need to be recalculated and distributed based on the current epoch and blockhash. The function requires a valid execution slot context and other parameters related to the current state of the epoch and execution environment. It is important to ensure that all pointers provided are valid and that the execution spad count accurately reflects the number of execution spads provided.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the execution slot context. Must not be null.
    - `parent_blockhash`: A pointer to an fd_hash_t structure representing the parent blockhash. Must not be null.
    - `parent_epoch`: An unsigned long representing the parent epoch. Must be a valid epoch number.
    - `temp_info`: A pointer to an fd_epoch_info_t structure used for temporary storage of epoch information. Must not be null.
    - `tpool`: A pointer to an fd_tpool_t structure representing the thread pool to be used for parallel execution. Must not be null.
    - `exec_spads`: A pointer to an array of fd_spad_t pointers representing execution spads. Must not be null and must point to a valid array of spads.
    - `exec_spad_cnt`: An unsigned long representing the count of execution spads. Must accurately reflect the number of spads in the exec_spads array.
    - `runtime_spad`: A pointer to an fd_spad_t structure representing the runtime spad. Must not be null.
- **Output**: None
- **See also**: [`fd_update_rewards`](fd_rewards.c.driver.md#fd_update_rewards)  (Implementation)


---
### fd\_begin\_partitioned\_rewards<!-- {{#callable_declaration:fd_begin_partitioned_rewards}} -->
Initiates the process of calculating and distributing partitioned epoch rewards.
- **Description**: This function is used to start the calculation and distribution of rewards for a specific epoch in a partitioned manner. It should be called when the rewards for a given epoch need to be processed, typically after the epoch has ended. The function requires a valid execution slot context, a block hash of the parent block, and the epoch number of the parent. It also needs temporary epoch information, a thread pool for parallel processing, and a set of execution scratchpads. The function will modify the state of the execution slot context to reflect the initiation of reward distribution.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the execution slot context. Must not be null.
    - `parent_blockhash`: A pointer to an fd_hash_t structure containing the hash of the parent block. Must not be null.
    - `parent_epoch`: An unsigned long representing the epoch number of the parent. Must be a valid epoch number.
    - `temp_info`: A pointer to an fd_epoch_info_t structure used for temporary storage of epoch information. Must not be null.
    - `tpool`: A pointer to an fd_tpool_t structure representing the thread pool used for parallel processing. Must not be null.
    - `exec_spads`: A pointer to an array of fd_spad_t pointers, representing execution scratchpads. Must not be null and must have at least exec_spad_cnt elements.
    - `exec_spad_cnt`: An unsigned long indicating the number of execution scratchpads in the exec_spads array. Must be greater than zero.
    - `runtime_spad`: A pointer to an fd_spad_t structure used as a runtime scratchpad. Must not be null.
- **Output**: None
- **See also**: [`fd_begin_partitioned_rewards`](fd_rewards.c.driver.md#fd_begin_partitioned_rewards)  (Implementation)


---
### fd\_rewards\_recalculate\_partitioned\_rewards<!-- {{#callable_declaration:fd_rewards_recalculate_partitioned_rewards}} -->
Recalculate partitioned rewards for the current epoch.
- **Description**: This function recalculates the partitioned rewards for the current epoch based on the provided execution context and resources. It should be called when the epoch rewards need to be updated, typically after a new epoch begins. The function requires a valid execution slot context, thread pool, and scratchpad memory resources. It handles cases where the epoch rewards are inactive by setting the appropriate status and logs any issues encountered during the process. The function does not return a value but updates the status of epoch rewards based on the recalculated partitions.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the execution context for the current slot. Must not be null.
    - `tpool`: A pointer to an fd_tpool_t structure representing the thread pool to be used for parallel processing. Must not be null.
    - `exec_spads`: A pointer to an array of fd_spad_t pointers, representing the execution scratchpads available for use. Must not be null.
    - `exec_spad_cnt`: An unsigned long representing the number of execution scratchpads available. Must be greater than zero.
    - `runtime_spad`: A pointer to an fd_spad_t structure representing the runtime scratchpad memory. Must not be null.
- **Output**: None
- **See also**: [`fd_rewards_recalculate_partitioned_rewards`](fd_rewards.c.driver.md#fd_rewards_recalculate_partitioned_rewards)  (Implementation)


---
### fd\_distribute\_partitioned\_epoch\_rewards<!-- {{#callable_declaration:fd_distribute_partitioned_epoch_rewards}} -->
Distributes rewards for a partitioned epoch if conditions are met.
- **Description**: This function is used to distribute rewards for a partitioned epoch based on the current block height and the status of epoch rewards. It should be called when there is a need to distribute rewards for a specific epoch, and it will only perform distribution if the epoch reward status is active and the current block height falls within the distribution range. The function also updates the reward status to inactive once distribution is complete. It is important to ensure that the slot context and runtime scratchpad are properly initialized before calling this function.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the execution slot context. Must not be null and should be properly initialized with the current slot and epoch information.
    - `tpool`: A pointer to an fd_tpool_t structure representing the thread pool. This parameter is currently unused in the function.
    - `exec_spads`: A pointer to an array of fd_spad_t pointers representing execution scratchpads. This parameter is currently unused in the function.
    - `exec_spad_cnt`: An unsigned long representing the count of execution scratchpads. This parameter is currently unused in the function.
    - `runtime_spad`: A pointer to an fd_spad_t structure representing the runtime scratchpad. Must not be null and should be properly initialized.
- **Output**: None
- **See also**: [`fd_distribute_partitioned_epoch_rewards`](fd_rewards.c.driver.md#fd_distribute_partitioned_epoch_rewards)  (Implementation)


