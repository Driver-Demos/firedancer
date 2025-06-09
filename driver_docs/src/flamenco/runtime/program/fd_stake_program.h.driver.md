# Purpose
This C header file defines the interface for a stake program, which is a native program designed to facilitate the staking of coins on a blockchain validator. The primary purpose of this program is to allow users to stake their coins on a validator, thereby earning inflation rewards. The program interacts with accounts owned by the stake program to manage validator stake weights and distribute staking rewards. The file includes several function prototypes that provide the core functionality of the stake program, such as executing staking instructions, initializing configuration accounts, retrieving stake state, and managing stake delegation.

The file is structured to be included in other C source files, as indicated by the inclusion guards and the use of `#include` directives for context-related headers. It defines a set of functions that form the public API for interacting with the stake program, such as [`fd_stake_program_execute`](#fd_stake_program_execute), which processes staking instructions, and [`fd_stake_program_config_init`](#fd_stake_program_config_init), which initializes configuration accounts. The file also includes constants and data structures necessary for managing stake states and history. This header file is part of a larger system, likely related to blockchain or cryptocurrency management, and provides a focused set of functionalities related to staking operations.
# Imports and Dependencies

---
- `../context/fd_exec_instr_ctx.h`
- `../context/fd_exec_txn_ctx.h`


# Function Declarations (Public API)

---
### fd\_new\_warmup\_cooldown\_rate\_epoch<!-- {{#callable_declaration:fd_new_warmup_cooldown_rate_epoch}} -->
Determine the epoch for warmup and cooldown rate changes based on the current slot and features.
- **Description**: This function calculates the epoch at which stake warmup and cooldown rate changes occur, based on the provided slot and feature set. It should be called when you need to determine the epoch for these rate changes in the context of a stake program. The function requires valid pointers to the necessary context structures and will set an error code if it encounters unsupported system variables. It is important to ensure that the feature set includes the 'reduce_stake_warmup_cooldown' feature, as this function relies on it being active.
- **Inputs**:
    - `slot`: The current slot number, which is used to determine the epoch. It should be a valid unsigned long integer.
    - `funk`: A pointer to an fd_funk_t structure, representing the current funk context. Must not be null.
    - `funk_txn`: A pointer to an fd_funk_txn_t structure, representing the current transaction context. Must not be null.
    - `spad`: A pointer to an fd_spad_t structure, representing the shared pad context. Must not be null.
    - `features`: A pointer to a constant fd_features_t structure, representing the feature set. Must not be null and should include the 'reduce_stake_warmup_cooldown' feature.
    - `epoch`: A pointer to an unsigned long where the calculated epoch will be stored. Must not be null.
    - `err`: A pointer to an integer where the error code will be stored if an error occurs. Must not be null.
- **Output**: Returns 1 if the epoch is successfully determined or if an error occurs, and 0 if the feature is not active. The epoch is written to the location pointed to by 'epoch', and 'err' is set to an error code if applicable.
- **See also**: [`fd_new_warmup_cooldown_rate_epoch`](fd_stake_program.c.driver.md#fd_new_warmup_cooldown_rate_epoch)  (Implementation)


---
### fd\_stake\_program\_execute<!-- {{#callable_declaration:fd_stake_program_execute}} -->
Processes a stake program instruction.
- **Description**: This function serves as the entry point for executing instructions within the stake program. It should be called when a transaction involving stake operations needs to be processed. The function handles various stake-related instructions, such as initializing, authorizing, delegating, splitting, merging, withdrawing, and setting lockups. It ensures that the instructions are valid and that the necessary conditions are met before execution. The function updates the transaction context to indicate if a stake account has been modified. It is important to ensure that the context provided is properly initialized and that the instruction data is valid before calling this function.
- **Inputs**:
    - `ctx`: A pointer to a fd_exec_instr_ctx_t structure that contains the execution context for the instruction. This includes transaction context, instruction data, and other relevant information. The pointer must not be null, and the context should be properly initialized before calling this function. Invalid or null input will result in an error return.
- **Output**: Returns an integer status code indicating the result of the instruction execution. Possible return values include success, various error codes for unsupported program IDs, invalid instruction data, insufficient account keys, and other specific errors related to the stake program operations.
- **See also**: [`fd_stake_program_execute`](fd_stake_program.c.driver.md#fd_stake_program_execute)  (Implementation)


---
### fd\_stake\_program\_config\_init<!-- {{#callable_declaration:fd_stake_program_config_init}} -->
Initializes the stake program configuration account.
- **Description**: This function sets up the configuration account used by the stake program, which is essential for managing staking operations. It should be called to initialize or reset the configuration to default values before any staking operations are performed. This function must be called with a valid execution slot context, and it will write the default configuration values to the provided context.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the execution slot context. This parameter must not be null, and the caller retains ownership. The function writes the default stake configuration to this context.
- **Output**: None
- **See also**: [`fd_stake_program_config_init`](fd_stake_program.c.driver.md#fd_stake_program_config_init)  (Implementation)


---
### fd\_stake\_get\_state<!-- {{#callable_declaration:fd_stake_get_state}} -->
Retrieve the current state of a stake account.
- **Description**: This function is used to obtain the current state of a stake account associated with the stake program. It is typically called when there is a need to inspect or verify the state of a stake account, such as during transaction processing or account management. The function requires a valid stake account and a pre-allocated output structure to store the state information. It is important to ensure that the provided account is valid and that the output structure is properly allocated before calling this function.
- **Inputs**:
    - `self`: A pointer to a constant `fd_txn_account_t` structure representing the stake account whose state is to be retrieved. This parameter must not be null and should point to a valid stake account.
    - `out`: A pointer to an `fd_stake_state_v2_t` structure where the state of the stake account will be stored. This parameter must not be null and should point to a pre-allocated structure capable of holding the state information.
- **Output**: Returns an integer status code indicating success or failure of the operation. A return value of 0 typically indicates success, while a non-zero value indicates an error occurred.
- **See also**: [`fd_stake_get_state`](fd_stake_program.c.driver.md#fd_stake_get_state)  (Implementation)


---
### fd\_stake\_activating\_and\_deactivating<!-- {{#callable_declaration:fd_stake_activating_and_deactivating}} -->
Calculates the activating and deactivating stake for a given epoch.
- **Description**: This function is used to determine the amount of stake that is activating or deactivating for a specific epoch based on the provided delegation and stake history. It is typically called when evaluating stake changes over time, such as during epoch transitions. The function requires a valid delegation and stake history to operate correctly. It also updates the epoch at which a new rate becomes active, if applicable.
- **Inputs**:
    - `self`: A pointer to a constant fd_delegation_t structure representing the delegation for which the stake is being evaluated. Must not be null.
    - `target_epoch`: An unsigned long integer specifying the epoch for which the stake activation and deactivation are being calculated.
    - `stake_history`: A pointer to a constant fd_stake_history_t structure containing the historical stake data. Must not be null.
    - `new_rate_activation_epoch`: A pointer to an unsigned long where the function will store the epoch at which a new rate becomes active, if applicable. Must not be null.
- **Output**: Returns an fd_stake_history_entry_t structure containing the calculated activating and deactivating stake for the specified epoch.
- **See also**: [`fd_stake_activating_and_deactivating`](fd_stake_program.c.driver.md#fd_stake_activating_and_deactivating)  (Implementation)


---
### fd\_store\_stake\_delegation<!-- {{#callable_declaration:fd_store_stake_delegation}} -->
Stores or removes a stake delegation based on the account's state.
- **Description**: This function is used to manage stake delegations by either storing or removing them based on the state of the provided stake account. It should be called when there is a need to update the stake delegation status within the execution slot context. The function checks if the stake account is owned by the stake program and whether it is empty or uninitialized. If the account is empty or uninitialized, the stake delegation is removed; otherwise, it is stored. This function must be called with a valid execution slot context and stake account, and it will acquire a write lock on the vote stake lock during its operation.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the execution slot context. This must be a valid, non-null pointer, and the caller retains ownership.
    - `stake_account`: A pointer to an fd_txn_account_t structure representing the stake account to be checked and potentially updated. This must be a valid, non-null pointer, and the caller retains ownership.
- **Output**: None
- **See also**: [`fd_store_stake_delegation`](fd_stake_program.c.driver.md#fd_store_stake_delegation)  (Implementation)


