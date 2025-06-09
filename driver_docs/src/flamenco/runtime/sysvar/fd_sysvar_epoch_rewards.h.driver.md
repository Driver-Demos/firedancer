# Purpose
This C header file defines the interface for managing the "EpochRewards" system variable within a runtime environment, likely part of a larger blockchain or distributed ledger system. It includes function prototypes for reading the current value of the rent sysvar, distributing rewards, setting the sysvar to inactive, and initializing the sysvar account. The file includes necessary dependencies and context structures, such as `fd_funk_t`, `fd_exec_slot_ctx_t`, and `fd_spad_t`, which are likely used to manage state and transactions within the system. The functions are designed to interact with a system called "funk," which appears to be a component of the runtime environment, and they handle operations related to reward distribution and sysvar state management. The file also references external resources, indicating integration with a broader codebase, as seen in the provided GitHub links.
# Imports and Dependencies

---
- `../../fd_flamenco_base.h`
- `../../types/fd_types.h`
- `../context/fd_exec_slot_ctx.h`


# Function Declarations (Public API)

---
### fd\_sysvar\_epoch\_rewards\_distribute<!-- {{#callable_declaration:fd_sysvar_epoch_rewards_distribute}} -->
Update the EpochRewards sysvar with distributed rewards.
- **Description**: This function updates the EpochRewards sysvar by adding the specified amount of distributed rewards. It should be called when rewards need to be distributed during an epoch. The function requires that the sysvar is active and that the addition of the distributed rewards does not exceed the total rewards available. It is important to ensure that the sysvar is properly initialized and active before calling this function, as it will log an error and terminate if these conditions are not met.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure, which provides the execution context for the slot. Must not be null.
    - `distributed`: The amount of rewards to distribute, specified as an unsigned long integer. Must be a non-negative value that, when added to the current distributed rewards, does not exceed the total rewards.
    - `runtime_spad`: A pointer to an fd_spad_t structure, which is used for runtime operations. Must not be null.
- **Output**: None
- **See also**: [`fd_sysvar_epoch_rewards_distribute`](fd_sysvar_epoch_rewards.c.driver.md#fd_sysvar_epoch_rewards_distribute)  (Implementation)


---
### fd\_sysvar\_epoch\_rewards\_set\_inactive<!-- {{#callable_declaration:fd_sysvar_epoch_rewards_set_inactive}} -->
Set the EpochRewards sysvar to inactive.
- **Description**: This function is used to mark the EpochRewards sysvar as inactive. It should be called when the rewards for an epoch are no longer active or relevant. Before calling this function, ensure that the sysvar has been properly initialized and that the current state of rewards is consistent with the expected distribution. This function will log an error if the sysvar cannot be read or if there is a mismatch in the rewards distribution.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure, which provides context for the current execution slot. Must not be null.
    - `runtime_spad`: A pointer to an fd_spad_t structure, representing the runtime scratchpad memory. Must not be null.
- **Output**: None
- **See also**: [`fd_sysvar_epoch_rewards_set_inactive`](fd_sysvar_epoch_rewards.c.driver.md#fd_sysvar_epoch_rewards_set_inactive)  (Implementation)


---
### fd\_sysvar\_epoch\_rewards\_init<!-- {{#callable_declaration:fd_sysvar_epoch_rewards_init}} -->
Initialize the EpochRewards sysvar account.
- **Description**: This function initializes the EpochRewards sysvar account with the specified parameters, setting it to active status. It should be called to set up the initial state of the EpochRewards sysvar before any rewards distribution occurs. The function requires a valid execution slot context and a hash of the last block. It ensures that the total rewards do not overflow the distributed rewards, logging an error if this condition is violated.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the execution slot context. Must not be null.
    - `total_rewards`: The total amount of rewards to be distributed. Must be greater than or equal to distributed_rewards.
    - `distributed_rewards`: The amount of rewards that have already been distributed. Must not exceed total_rewards.
    - `distribution_starting_block_height`: The block height at which the distribution of rewards starts.
    - `num_partitions`: The number of partitions for the rewards distribution.
    - `point_value`: An fd_point_value_t structure containing point and reward values used for distribution calculations.
    - `last_blockhash`: A pointer to an fd_hash_t structure representing the hash of the last block. Must not be null.
- **Output**: None
- **See also**: [`fd_sysvar_epoch_rewards_init`](fd_sysvar_epoch_rewards.c.driver.md#fd_sysvar_epoch_rewards_init)  (Implementation)


