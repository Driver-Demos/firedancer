# Purpose
The provided C code is part of a larger system that implements a stake program, likely for a blockchain or distributed ledger technology. This code is responsible for managing stake accounts, which are used to delegate tokens to validators in a proof-of-stake system. The file includes various functionalities such as initializing stake accounts, authorizing changes, delegating stakes, splitting and merging stake accounts, withdrawing tokens, and handling lockups. It also includes error handling and validation to ensure the integrity and correctness of stake operations.

The code is structured into several sections, each handling different aspects of stake management. It defines constants, error codes, and data structures necessary for stake operations. The code also includes functions for encoding and decoding stake states, managing account balances, and performing arithmetic operations safely. The main function, [`fd_stake_program_execute`](#fd_stake_program_execute), processes different stake instructions based on their type, executing the appropriate logic for each operation. This file is part of a larger system that interacts with other components, such as vote programs and system variables, to manage the lifecycle of stake accounts within the network.
# Imports and Dependencies

---
- `limits.h`
- `../../../util/bits/fd_sat.h`
- `../../../util/bits/fd_uwide.h`
- `../fd_borrowed_account.h`
- `../fd_executor.h`
- `../fd_pubkey_utils.h`
- `../fd_system_ids.h`
- `fd_stake_program.h`
- `fd_vote_program.h`
- `../sysvar/fd_sysvar_epoch_schedule.h`
- `../sysvar/fd_sysvar_rent.h`
- `../sysvar/fd_sysvar_stake_history.h`
- `../sysvar/fd_sysvar_clock.h`
- `../sysvar/fd_sysvar_epoch_rewards.h`


# Data Structures

---
### merge\_kind\_inactive
- **Type**: `struct`
- **Members**:
    - `meta`: Holds metadata related to the stake, such as rent exemption and authorization details.
    - `active_stake`: Represents the amount of stake that is currently active.
    - `stake_flags`: Contains flags that indicate the status or properties of the stake.
- **Description**: The `merge_kind_inactive` structure is used to represent a state of a stake account where the stake is inactive. It contains metadata about the stake, the amount of active stake, and flags that provide additional information about the stake's status. This structure is part of a larger system that manages stake accounts, allowing for operations such as merging and splitting stakes based on their current state.


---
### merge\_kind\_inactive\_t
- **Type**: ``struct``
- **Members**:
    - `meta`: Holds metadata related to the stake, such as rent exemption and authorization details.
    - `active_stake`: Represents the amount of active stake in the inactive merge kind.
    - `stake_flags`: Contains flags that indicate specific conditions or states of the stake.
- **Description**: The `merge_kind_inactive_t` structure is part of a union that represents different states of a stake in a staking program. This specific structure is used to represent an inactive state of a stake, where the stake is not currently active in the network. It includes metadata about the stake, the amount of active stake, and any flags that might affect the stake's behavior or status. This structure is used in the context of merging stake accounts, where different states of stakes need to be managed and merged appropriately.


---
### merge\_kind\_activation\_epoch
- **Type**: `struct`
- **Members**:
    - `meta`: Holds metadata related to the stake, such as rent exemption and authorization details.
    - `stake`: Represents the stake amount and its associated delegation details.
    - `stake_flags`: Contains flags that indicate the status or conditions of the stake.
- **Description**: The `merge_kind_activation_epoch` structure is used to represent a specific state of a stake account during the activation epoch in a staking program. It encapsulates metadata, the stake amount, and flags that provide additional information about the stake's status. This structure is part of a larger system that manages stake accounts, allowing for operations such as merging, splitting, and delegating stakes based on their current state and epoch.


---
### merge\_kind\_activation\_epoch\_t
- **Type**: ``struct``
- **Members**:
    - `meta`: Contains metadata related to the stake, such as rent exemption and authorization details.
    - `stake`: Represents the stake amount and its associated delegation details.
    - `stake_flags`: Holds flags that indicate specific conditions or states of the stake.
- **Description**: The `merge_kind_activation_epoch_t` structure is part of a union that represents different states of a stake in a staking program. This particular structure is used when a stake is in the activation epoch state, meaning it is in the process of being activated. It contains metadata about the stake, the stake amount and its delegation details, and flags that indicate specific conditions or states of the stake. This structure is used to manage and track the state of a stake during its lifecycle in a staking program.


---
### merge\_kind\_fully\_active
- **Type**: `struct`
- **Members**:
    - `meta`: Holds metadata related to the stake, such as rent exemption and authorization details.
    - `stake`: Represents the stake amount and its associated delegation details.
- **Description**: The `merge_kind_fully_active` structure is a part of a union that represents different states of a stake account in a staking program. This specific structure is used when the stake is fully active, meaning it is neither activating nor deactivating. It contains metadata about the stake and the stake itself, which includes details about the delegation and the amount of stake. This structure is used to manage and track the state of a stake account that is fully operational and contributing to the network.


---
### merge\_kind\_fully\_active\_t
- **Type**: `struct`
- **Members**:
    - `meta`: Holds metadata related to the stake, such as rent exemption and authorization details.
    - `stake`: Represents the amount of stake and its associated details.
- **Description**: The `merge_kind_fully_active_t` structure is part of a union that represents different states of a stake account in a staking program. This specific structure is used when the stake is fully active, meaning it is neither in the process of being activated nor deactivated. It contains metadata about the stake and the stake itself, which includes the amount and other relevant details. This structure is used to manage and track the state of fully active stakes within the staking program.


---
### merge\_kind\_inner
- **Type**: `union`
- **Members**:
    - `inactive`: Represents an inactive merge kind with associated metadata, active stake, and stake flags.
    - `activation_epoch`: Represents a merge kind that is active during a specific epoch with associated metadata, stake, and stake flags.
    - `fully_active`: Represents a fully active merge kind with associated metadata and stake.
- **Description**: The `merge_kind_inner` union is a data structure used to represent different states of a merge operation in a staking program. It encapsulates three possible states: inactive, activation_epoch, and fully_active, each with its own specific data structure. This union allows for efficient storage and manipulation of these states, enabling the program to handle various scenarios in the staking process, such as transitioning between inactive and active states or managing fully active stakes.


---
### merge\_kind\_inner\_t
- **Type**: `union`
- **Members**:
    - `inactive`: Represents an inactive merge kind with metadata, active stake, and stake flags.
    - `activation_epoch`: Represents a merge kind at the activation epoch with metadata, stake, and stake flags.
    - `fully_active`: Represents a fully active merge kind with metadata and stake.
- **Description**: The `merge_kind_inner_t` is a union that encapsulates different states of a stake merge operation in a staking program. It can represent an inactive state, a state at the activation epoch, or a fully active state, each with its own associated metadata and stake information. This union allows for flexible handling of different merge scenarios in the staking process.


---
### merge\_kind
- **Type**: `struct`
- **Members**:
    - `discriminant`: An unsigned integer used to determine which variant of the union is active.
    - `inner`: A union of different merge kinds, representing the state of the merge.
- **Description**: The `merge_kind` structure is a compound data type that encapsulates a discriminant and a union of different merge states. The discriminant is used to identify which variant of the union is currently active, allowing the structure to represent different states of a merge operation. The union, `merge_kind_inner_t`, can hold one of several types, each corresponding to a different state of a stake merge, such as inactive, activation epoch, or fully active. This structure is used in the context of managing stake operations, particularly in determining the mergeability of stake accounts.


---
### merge\_kind\_t
- **Type**: ``struct``
- **Members**:
    - `discriminant`: An unsigned integer that indicates the type of merge kind.
    - `inner`: A union of different merge kinds, which can be inactive, activation_epoch, or fully_active.
- **Description**: The `merge_kind_t` structure is used to represent different states of a stake merge operation in a staking program. It contains a `discriminant` to identify the specific type of merge kind and an `inner` union that holds the actual data for the merge kind, which can be one of three types: inactive, activation_epoch, or fully_active. This structure is crucial for handling different scenarios in stake merging, allowing the program to manage and execute merge operations based on the current state of the stake.


---
### effective\_activating
- **Type**: `struct`
- **Members**:
    - `effective`: Represents the effective stake amount as an unsigned long integer.
    - `activating`: Represents the activating stake amount as an unsigned long integer.
- **Description**: The `effective_activating` structure is a simple data structure used to represent the state of a stake in terms of its effective and activating amounts. It contains two members, `effective` and `activating`, both of which are unsigned long integers. This structure is typically used in the context of managing and tracking stake activations and deactivations in a staking program, where it helps in determining the current state of a stake in terms of how much is actively contributing to the network and how much is in the process of being activated.


---
### effective\_activating\_t
- **Type**: `typedef`
- **Members**:
    - `effective`: Represents the effective stake amount.
    - `activating`: Represents the stake amount that is in the process of being activated.
- **Description**: The `effective_activating_t` structure is used to represent the state of a stake in terms of its effective and activating amounts. The `effective` field indicates the amount of stake that is currently effective, while the `activating` field indicates the amount of stake that is in the process of being activated. This structure is useful in scenarios where the stake's activation status needs to be tracked and managed, particularly in systems dealing with stake delegation and activation processes.


---
### validated\_delegated\_info
- **Type**: `struct`
- **Members**:
    - `stake_amount`: Represents the amount of stake that has been validated and delegated.
- **Description**: The `validated_delegated_info` structure is a simple data structure used to store information about a validated and delegated stake amount. It contains a single member, `stake_amount`, which holds the value of the stake that has been validated and is ready for delegation. This structure is typically used in the context of stake management systems to keep track of the amount of stake that has been processed and is available for delegation to validators or other entities.


---
### validated\_delegated\_info\_t
- **Type**: ``struct``
- **Members**:
    - `stake_amount`: Represents the amount of stake that has been validated and delegated.
- **Description**: The `validated_delegated_info_t` structure is a simple data structure used to store information about a validated and delegated stake amount. It contains a single member, `stake_amount`, which holds the value of the stake that has been validated and is ready for delegation. This structure is typically used in the context of stake management systems to ensure that the stake amount meets certain criteria before it is delegated to a validator or similar entity.


---
### validated\_split\_info
- **Type**: `struct`
- **Members**:
    - `source_remaining_balance`: Represents the remaining balance in the source account after a split operation.
    - `destination_rent_exempt_reserve`: Indicates the rent-exempt reserve required for the destination account in a split operation.
- **Description**: The `validated_split_info` structure is used to store information about a split operation in a stake program. It contains two fields: `source_remaining_balance`, which holds the remaining balance in the source account after the split, and `destination_rent_exempt_reserve`, which specifies the rent-exempt reserve required for the destination account. This structure is typically used to validate and manage the financial aspects of splitting stake accounts, ensuring that both source and destination accounts meet the necessary financial requirements.


---
### validated\_split\_info\_t
- **Type**: `typedef struct`
- **Members**:
    - `source_remaining_balance`: Represents the remaining balance in the source account after a split operation.
    - `destination_rent_exempt_reserve`: Indicates the rent-exempt reserve required for the destination account in a split operation.
- **Description**: The `validated_split_info_t` structure is used to store information about a validated split operation in a stake program. It contains details about the remaining balance in the source account and the rent-exempt reserve required for the destination account, ensuring that the split operation adheres to the necessary financial constraints and requirements.


# Functions

---
### get\_state<!-- {{#callable:get_state}} -->
The `get_state` function decodes the state of a stake account from its binary representation.
- **Inputs**:
    - `self`: A pointer to a `fd_txn_account_t` structure representing the transaction account from which the state is to be retrieved.
    - `out`: A pointer to a `fd_stake_state_v2_t` structure where the decoded state will be stored.
- **Control Flow**:
    - The function initializes a `fd_bincode_decode_ctx_t` structure to manage the decoding context, using data from the `self` account.
    - It calls `fd_stake_state_v2_decode_footprint` to check the validity of the data and determine the total size required for decoding.
    - If the decoding footprint check fails, it returns an error code indicating invalid account data.
    - If the check is successful, it proceeds to decode the actual state into the `out` parameter using `fd_stake_state_v2_decode`.
    - Finally, it returns 0 to indicate success.
- **Output**: The function returns 0 on success, or an error code if the decoding process fails.


---
### set\_state<!-- {{#callable:set_state}} -->
The `set_state` function updates the state of a borrowed account with a serialized stake state.
- **Inputs**:
    - `borrowed_acct`: A pointer to a `fd_borrowed_account_t` structure representing the account to be updated.
    - `state`: A pointer to a constant `fd_stake_state_v2_t` structure containing the new state to be set.
- **Control Flow**:
    - The function retrieves mutable data and its length from the `borrowed_acct` using `fd_borrowed_account_get_data_mut`.
    - If the retrieval fails, the error is returned immediately.
    - The function calculates the serialized size of the `state` using `fd_stake_state_v2_size`.
    - If the serialized size exceeds the length of the mutable data, an error indicating insufficient data size is returned.
    - An encoding context is initialized for the data buffer.
    - The `fd_stake_state_v2_encode` function is called to encode the `state` into the data buffer.
    - If encoding fails, an error is logged, but the function continues to return 0.
- **Output**: Returns 0 on success, or an error code if any operation fails.


---
### get\_minimum\_delegation<!-- {{#callable:get_minimum_delegation}} -->
The `get_minimum_delegation` function returns the minimum delegation amount based on the active features in the transaction context.
- **Inputs**:
    - `txn_ctx`: A pointer to a constant `fd_exec_txn_ctx_t` structure that contains the feature set and other transaction-related information.
- **Control Flow**:
    - The function checks if the feature `stake_raise_minimum_delegation_to_1_sol` is active in the `txn_ctx`.
    - If the feature is active, it returns the product of `MINIMUM_DELEGATION_SOL` and `LAMPORTS_PER_SOL`.
    - If the feature is not active, it returns a default minimum delegation value of 1.
- **Output**: The function outputs an unsigned long integer representing the minimum delegation amount, which is either 1 SOL or the defined minimum amount in lamports, depending on the active features.


---
### warmup\_cooldown\_rate<!-- {{#callable:warmup_cooldown_rate}} -->
The `warmup_cooldown_rate` function calculates the warmup or cooldown rate based on the current epoch and a specified activation epoch.
- **Inputs**:
    - `current_epoch`: The current epoch represented as an unsigned long integer.
    - `new_rate_activation_epoch`: A pointer to an unsigned long integer that indicates the epoch at which a new rate becomes active, or NULL if no new rate is set.
- **Control Flow**:
    - The function first checks if `new_rate_activation_epoch` is not NULL; if it is NULL, it uses `ULONG_MAX` as the activation epoch.
    - It then compares `current_epoch` with the activation epoch to determine which rate to return.
    - If `current_epoch` is less than the activation epoch, it returns `DEFAULT_WARMUP_COOLDOWN_RATE`; otherwise, it returns `NEW_WARMUP_COOLDOWN_RATE`.
- **Output**: The function returns a double value representing the applicable warmup or cooldown rate based on the current epoch and the activation epoch.


---
### validate\_delegated\_amount<!-- {{#callable:validate_delegated_amount}} -->
Validates the delegated amount for a stake account.
- **Inputs**:
    - `account`: A pointer to the `fd_borrowed_account_t` structure representing the stake account being validated.
    - `meta`: A pointer to the `fd_stake_meta_t` structure containing metadata about the stake account.
    - `txn_ctx`: A pointer to the `fd_exec_txn_ctx_t` structure representing the transaction context.
    - `out`: A pointer to a `validated_delegated_info_t` structure where the validated stake amount will be stored.
    - `custom_err`: A pointer to a `uint` variable that will hold a custom error code if validation fails.
- **Control Flow**:
    - Calculates the `stake_amount` by subtracting the `rent_exempt_reserve` from the total lamports in the account.
    - Checks if the calculated `stake_amount` is less than the minimum required delegation amount obtained from [`get_minimum_delegation`](#get_minimum_delegation).
    - If the `stake_amount` is insufficient, sets the `custom_err` to `FD_STAKE_ERR_INSUFFICIENT_DELEGATION` and returns an error code.
    - If validation is successful, assigns the `stake_amount` to the `out` structure and returns 0.
- **Output**: Returns 0 on successful validation or an error code indicating the type of validation failure.
- **Functions called**:
    - [`get_minimum_delegation`](#get_minimum_delegation)


---
### validate\_split\_amount<!-- {{#callable:validate_split_amount}} -->
The `validate_split_amount` function checks if a specified amount of lamports can be split from a source stake account to a destination stake account.
- **Inputs**:
    - `invoke_context`: A pointer to the execution context containing transaction details.
    - `source_account_index`: The index of the source account from which lamports will be split.
    - `destination_account_index`: The index of the destination account to which lamports will be sent.
    - `lamports`: The amount of lamports to be split from the source account.
    - `source_meta`: Metadata associated with the source stake account.
    - `additional_required_lamports`: Additional lamports required for the operation, typically for rent exemption.
    - `source_is_active`: A flag indicating whether the source account is active.
    - `out`: A pointer to a structure where the results of the validation will be stored.
- **Control Flow**:
    - The function begins by borrowing the source and destination accounts using their respective indices.
    - It retrieves the lamports and data length for both the source and destination accounts.
    - It checks if the specified amount of lamports to split is greater than zero and does not exceed the available balance in the source account.
    - It calculates the minimum balance required for the source account after the split and checks if the remaining balance meets this requirement.
    - It reads the rent information from the system variable and checks if the destination account requires a rent-exempt balance.
    - It validates that the destination account has enough balance to meet the rent-exempt requirement if the source account is active.
    - Finally, it updates the output structure with the remaining balance of the source account and the rent-exempt reserve for the destination account.
- **Output**: The function returns 0 on success, or an error code indicating insufficient funds or other validation failures.


---
### lockup\_is\_in\_force<!-- {{#callable:lockup_is_in_force}} -->
The `lockup_is_in_force` function checks if a lockup period is currently active for a stake account.
- **Inputs**:
    - `self`: A pointer to a `fd_stake_lockup_t` structure representing the lockup details of the stake.
    - `clock`: A pointer to a `fd_sol_sysvar_clock_t` structure providing the current system clock information.
    - `custodian`: A pointer to a `fd_pubkey_t` structure representing the public key of the custodian.
- **Control Flow**:
    - The function first checks if the `custodian` is not NULL and if it matches the custodian stored in the `self` structure.
    - If the custodian matches, the function returns 0, indicating that the lockup is not in force.
    - If the custodian does not match or is NULL, the function checks if the current `unix_timestamp` or `epoch` from `self` is greater than the corresponding values in `clock`.
    - If either condition is true, it indicates that the lockup is in force, and the function returns 1; otherwise, it returns 0.
- **Output**: The function returns an integer: 0 if the lockup is not in force, 1 if it is in force.


---
### authorized\_check<!-- {{#callable:authorized_check}} -->
The `authorized_check` function verifies if the provided signers include the authorized staker or withdrawer based on the stake authorization type.
- **Inputs**:
    - `self`: A pointer to a `fd_stake_authorized_t` structure that contains the public keys of the authorized staker and withdrawer.
    - `signers`: An array of pointers to `fd_pubkey_t` representing the public keys of the signers for the transaction.
    - `stake_authorize`: A `fd_stake_authorize_t` structure that indicates whether the check is for the staker or withdrawer.
- **Control Flow**:
    - The function begins by checking the `discriminant` field of the `stake_authorize` structure to determine the type of authorization being checked.
    - If the type is `fd_stake_authorize_enum_staker`, it checks if the staker's public key is present in the `signers` array using the `fd_signers_contains` function.
    - If the staker's signature is found, the function returns 0, indicating success; otherwise, it returns an error code for a missing required signature.
    - If the type is `fd_stake_authorize_enum_withdrawer`, it performs a similar check for the withdrawer's public key.
    - If neither condition is met, the function defaults to returning an error code for a missing required signature.
- **Output**: The function returns 0 if the required signature is present; otherwise, it returns an error code indicating a missing required signature.


---
### authorized\_authorize<!-- {{#callable:authorized_authorize}} -->
The `authorized_authorize` function updates the authorization status of a stake account based on the provided authorization type.
- **Inputs**:
    - `self`: A pointer to the `fd_stake_authorized_t` structure representing the current authorization state.
    - `signers`: An array of pointers to `fd_pubkey_t` representing the public keys of the signers for the transaction.
    - `new_authorized`: A pointer to the `fd_pubkey_t` structure representing the new authorized public key.
    - `stake_authorize`: A pointer to the `fd_stake_authorize_t` structure indicating the type of authorization being requested (staker or withdrawer).
    - `lockup_custodian_args`: A pointer to the `fd_stake_lockup_custodian_args_t` structure containing lockup and custodian information.
    - `custom_err`: A pointer to a `uint` that will hold custom error codes if any errors occur during execution.
- **Control Flow**:
    - The function begins by checking the `discriminant` of the `stake_authorize` structure to determine the type of authorization being requested.
    - If the authorization type is `fd_stake_authorize_enum_staker`, it checks if the required signatures from the staker or withdrawer are present; if not, it returns an error.
    - If the authorization type is `fd_stake_authorize_enum_withdrawer`, it checks if lockup conditions are in force and validates the presence of the custodian's signature.
    - If the lockup is in force, it checks if the custodian is provided and if their signature is present; if not, it sets a custom error and returns.
    - If all checks pass, it updates the `staker` or `withdrawer` field in the `self` structure with the `new_authorized` public key.
    - Finally, the function returns 0 to indicate success.
- **Output**: The function returns 0 on success, or an error code indicating the type of failure that occurred during the authorization process.
- **Functions called**:
    - [`lockup_is_in_force`](#lockup_is_in_force)
    - [`authorized_check`](#authorized_check)


---
### set\_lockup\_meta<!-- {{#callable:set_lockup_meta}} -->
The `set_lockup_meta` function updates the lockup metadata of a stake account based on provided arguments.
- **Inputs**:
    - `self`: A pointer to the `fd_stake_meta_t` structure representing the stake account metadata.
    - `lockup`: A pointer to the `fd_lockup_args_t` structure containing the new lockup parameters.
    - `signers`: An array of pointers to public keys representing the signers for the transaction.
    - `clock`: A pointer to the `fd_sol_sysvar_clock_t` structure providing the current clock information.
- **Control Flow**:
    - The function first checks if the lockup is currently in force by calling [`lockup_is_in_force`](#lockup_is_in_force) with the current clock.
    - If the lockup is in force, it verifies that the custodian's signature is present in the `signers` array.
    - If the lockup is not in force, it checks that the withdrawer's signature is present in the `signers` array.
    - If any signature check fails, the function returns an error code indicating a missing required signature.
    - If the checks pass, it updates the `unix_timestamp`, `epoch`, and `custodian` fields of the lockup metadata if the corresponding values are provided in the `lockup` argument.
    - Finally, the function returns 0 to indicate success.
- **Output**: The function returns 0 on success or an error code indicating the type of failure encountered.
- **Functions called**:
    - [`lockup_is_in_force`](#lockup_is_in_force)


---
### fd\_stake\_history\_ele\_binary\_search\_const<!-- {{#callable:fd_stake_history_ele_binary_search_const}} -->
Performs a binary search on the stake history to find a specific stake entry based on the given epoch.
- **Inputs**:
    - `history`: A pointer to a constant `fd_stake_history_t` structure that contains the stake history data.
    - `epoch`: An unsigned long integer representing the epoch to search for in the stake history.
- **Control Flow**:
    - Initializes two variables, `start` and `end`, to represent the bounds of the search range within the stake history.
    - Enters a while loop that continues as long as `start` is less than or equal to `end`.
    - Calculates the midpoint index `mid` of the current search range.
    - Checks if the epoch at the midpoint matches the target epoch; if so, returns a pointer to the corresponding stake entry.
    - If the epoch at `mid` is less than the target epoch, adjusts the `end` index to search the left half of the current range.
    - If the epoch at `mid` is greater than the target epoch, adjusts the `start` index to search the right half of the current range.
    - If the loop exits without finding a match, returns NULL.
- **Output**: Returns a pointer to the `fd_stake_history_entry_t` corresponding to the specified epoch if found; otherwise, returns NULL.


---
### fd\_stake\_history\_ele\_query\_const<!-- {{#callable:fd_stake_history_ele_query_const}} -->
Queries the stake history for a specific epoch and returns the corresponding stake history entry.
- **Inputs**:
    - `history`: A pointer to a constant `fd_stake_history_t` structure that contains the stake history data.
    - `epoch`: An unsigned long integer representing the epoch for which the stake history entry is being queried.
- **Control Flow**:
    - Checks if the length of the stake history is zero; if so, returns NULL.
    - Checks if the requested epoch is greater than the most recent epoch in the history; if so, returns NULL.
    - Calculates the offset from the most recent epoch to the requested epoch.
    - If the offset is greater than or equal to the length of the stake history, performs a binary search to find the entry.
    - Calculates the index for the entry based on the offset and the history's offset and size.
    - If the epoch at the calculated index matches the requested epoch, returns the corresponding entry.
    - If the epoch does not match, performs a binary search to find the entry.
- **Output**: Returns a pointer to a constant `fd_stake_history_entry_t` structure representing the stake history entry for the specified epoch, or NULL if not found.
- **Functions called**:
    - [`fd_stake_history_ele_binary_search_const`](#fd_stake_history_ele_binary_search_const)


---
### stake\_and\_activating<!-- {{#callable:stake_and_activating}} -->
Calculates the effective and activating stake for a given delegation at a specified target epoch.
- **Inputs**:
    - `self`: A pointer to a `fd_delegation_t` structure representing the stake delegation.
    - `target_epoch`: An unsigned long integer representing the epoch at which to calculate the stake.
    - `history`: A pointer to a `fd_stake_history_t` structure containing historical stake data.
    - `new_rate_activation_epoch`: A pointer to an unsigned long integer that will be updated with the new rate activation epoch.
- **Control Flow**:
    - The function first retrieves the delegated stake from the `self` structure.
    - It checks if the `activation_epoch` is set to `ULONG_MAX`, returning the delegated stake as effective and zero activating if true.
    - If the `activation_epoch` equals the `deactivation_epoch`, it returns zero for both effective and activating stakes.
    - If the `target_epoch` matches the `activation_epoch`, it returns zero effective and the full delegated stake as activating.
    - If the `target_epoch` is less than the `activation_epoch`, it returns zero for both effective and activating stakes.
    - If a valid `history` is provided, it queries the stake history for the cluster stake at the `activation_epoch`.
    - A loop iterates through epochs starting from the `activation_epoch`, calculating the effective stake based on the warmup/cooldown rate and the activating stake.
    - The loop continues until the current epoch reaches the `target_epoch` or the `deactivation_epoch`, or if there are no more activating stakes.
- **Output**: Returns an `effective_activating_t` structure containing the calculated effective and activating stakes.
- **Functions called**:
    - [`fd_stake_history_ele_query_const`](#fd_stake_history_ele_query_const)
    - [`warmup_cooldown_rate`](#warmup_cooldown_rate)


---
### stake\_activating\_and\_deactivating<!-- {{#callable:stake_activating_and_deactivating}} -->
The `stake_activating_and_deactivating` function calculates the effective and activating stake for a given target epoch based on the stake history and updates the activation status.
- **Inputs**:
    - `self`: A pointer to a `fd_delegation_t` structure representing the current stake delegation.
    - `target_epoch`: An unsigned long integer representing the epoch for which the stake activation status is being calculated.
    - `stake_history`: A pointer to a `fd_stake_history_t` structure containing historical stake data.
    - `new_rate_activation_epoch`: A pointer to an unsigned long integer that will be updated with the new rate activation epoch.
- **Control Flow**:
    - The function first calls [`stake_and_activating`](#stake_and_activating) to get the effective and activating stake for the target epoch.
    - It checks if the target epoch is less than the deactivation epoch of the stake.
    - If the target epoch is less than the deactivation epoch, it checks if the activating stake is zero and returns the appropriate stake history entry.
    - If the target epoch equals the deactivation epoch, it returns a stake history entry indicating that the stake is deactivating.
    - If the target epoch is greater than the deactivation epoch, it retrieves the cluster stake at the deactivation epoch and enters a loop to calculate the current effective stake until the target epoch is reached or the activating stake is depleted.
    - Finally, it returns the calculated stake history entry based on the current effective stake and activating stake.
- **Output**: The function returns a `fd_stake_history_entry_t` structure containing the effective, deactivating, and activating stake values for the specified target epoch.
- **Functions called**:
    - [`stake_and_activating`](#stake_and_activating)
    - [`fd_stake_history_ele_query_const`](#fd_stake_history_ele_query_const)
    - [`warmup_cooldown_rate`](#warmup_cooldown_rate)


---
### delegation\_stake<!-- {{#callable:delegation_stake}} -->
The `delegation_stake` function calculates the effective stake for a given delegation at a specified epoch.
- **Inputs**:
    - `self`: A pointer to a `fd_delegation_t` structure representing the delegation.
    - `epoch`: An unsigned long integer representing the epoch for which the effective stake is to be calculated.
    - `history`: A pointer to a `fd_stake_history_t` structure containing historical stake data.
    - `new_rate_activation_epoch`: A pointer to an unsigned long integer that will be updated with the new rate activation epoch.
- **Control Flow**:
    - The function calls [`stake_activating_and_deactivating`](#stake_activating_and_deactivating) with the provided parameters.
    - It retrieves the effective stake from the result of [`stake_activating_and_deactivating`](#stake_activating_and_deactivating).
- **Output**: Returns an unsigned long integer representing the effective stake for the delegation at the specified epoch.
- **Functions called**:
    - [`stake_activating_and_deactivating`](#stake_activating_and_deactivating)


---
### acceptable\_reference\_epoch\_credits<!-- {{#callable:acceptable_reference_epoch_credits}} -->
The `acceptable_reference_epoch_credits` function checks if the provided epoch credits are acceptable based on the current epoch and a minimum threshold.
- **Inputs**:
    - `epoch_credits`: A pointer to a `fd_vote_epoch_credits_t` structure that contains the epoch credits to be evaluated.
    - `current_epoch`: An unsigned long integer representing the current epoch against which the credits are validated.
- **Control Flow**:
    - The function first retrieves the count of epoch credits from `epoch_credits`.
    - It checks if the count minus a defined minimum threshold for delinquent epochs does not result in an overflow.
    - If the check passes, it enters a loop that iterates backwards through the epoch credits.
    - For each credit, it compares the stored vote epoch with the current epoch.
    - If any vote epoch does not match the current epoch, the function returns 0, indicating failure.
    - If all epochs match, the function returns 1, indicating success.
- **Output**: The function returns 1 if the epoch credits are acceptable (all match the current epoch), or 0 if they are not.


---
### eligible\_for\_deactivate\_delinquent<!-- {{#callable:eligible_for_deactivate_delinquent}} -->
Determines if a vote account is eligible for deactivation due to delinquency based on its voting history.
- **Inputs**:
    - `epoch_credits`: A pointer to a `fd_vote_epoch_credits_t` structure that contains the voting credits for different epochs.
    - `current_epoch`: An unsigned long integer representing the current epoch number.
- **Control Flow**:
    - Checks if the `epoch_credits` structure is empty; if so, returns 1 indicating eligibility for deactivation.
    - Retrieves the last voting epoch from the `epoch_credits` structure.
    - If the last voting epoch is NULL, returns 1 indicating eligibility for deactivation.
    - Calculates the minimum epoch required for deactivation by subtracting a constant from the current epoch.
    - If the last voting epoch is less than or equal to the calculated minimum epoch, returns 1 indicating eligibility for deactivation.
    - Otherwise, returns 0 indicating ineligibility for deactivation.
- **Output**: Returns 1 if the vote account is eligible for deactivation, otherwise returns 0.


---
### stake\_split<!-- {{#callable:stake_split}} -->
The `stake_split` function splits a specified amount of stake from a stake account.
- **Inputs**:
    - `self`: A pointer to the `fd_stake_t` structure representing the stake account from which the stake is being split.
    - `remaining_stake_delta`: The amount of stake to be deducted from the current stake.
    - `split_stake_amount`: The amount of stake to be assigned to the new stake account.
    - `custom_err`: A pointer to a variable where custom error codes can be stored.
    - `out`: A pointer to an `fd_stake_t` structure where the new stake account will be stored.
- **Control Flow**:
    - The function first checks if the `remaining_stake_delta` exceeds the current stake in the `self` account.
    - If the check fails, it sets a custom error code for insufficient stake and returns an error.
    - If the check passes, it deducts the `remaining_stake_delta` from the current stake in `self`.
    - A new `fd_stake_t` structure is created and initialized with the current state of `self`, but with the `delegation.stake` set to `split_stake_amount`.
    - Finally, the new stake account is assigned to the `out` parameter and the function returns success.
- **Output**: The function returns 0 on success, indicating that the stake has been successfully split, or an error code if the operation fails.


---
### stake\_deactivate<!-- {{#callable:stake_deactivate}} -->
The `stake_deactivate` function sets the deactivation epoch for a stake if it has not already been deactivated.
- **Inputs**:
    - `stake`: A pointer to the `fd_stake_t` structure representing the stake account to be deactivated.
    - `epoch`: An unsigned long integer representing the epoch at which the stake should be deactivated.
    - `custom_err`: A pointer to an unsigned integer that will hold a custom error code if the operation fails.
- **Control Flow**:
    - The function first checks if the `deactivation_epoch` of the stake is not equal to `ULONG_MAX`, indicating that it has already been deactivated.
    - If the stake is already deactivated, it sets the `custom_err` to `FD_STAKE_ERR_ALREADY_DEACTIVATED` and returns an error code.
    - If the stake is not deactivated, it sets the `deactivation_epoch` to the provided `epoch` value.
    - Finally, it returns 0 to indicate success.
- **Output**: The function returns 0 on success or an error code indicating the failure reason.


---
### fd\_new\_warmup\_cooldown\_rate\_epoch<!-- {{#callable:fd_new_warmup_cooldown_rate_epoch}} -->
The `fd_new_warmup_cooldown_rate_epoch` function calculates the epoch for a new warmup and cooldown rate based on the current slot and feature flags.
- **Inputs**:
    - `slot`: The current slot number, used to determine the active features.
    - `funk`: A pointer to the `fd_funk_t` structure, representing the current function context.
    - `funk_txn`: A pointer to the `fd_funk_txn_t` structure, representing the current transaction context.
    - `spad`: A pointer to the `fd_spad_t` structure, representing the shared pad.
    - `features`: A pointer to a constant `fd_features_t` structure, representing the feature flags.
    - `epoch`: A pointer to an output variable where the calculated epoch will be stored.
    - `err`: A pointer to an integer where error codes will be stored.
- **Control Flow**:
    - The function initializes the error code to 0.
    - It retrieves the epoch schedule using `fd_sysvar_epoch_schedule_read`.
    - If the epoch schedule is not available, it sets the epoch to ULONG_MAX and returns an error code indicating unsupported system variable.
    - If the feature `reduce_stake_warmup_cooldown` is active for the current slot, it calculates the epoch using `fd_slot_to_epoch` and stores it in the output variable.
    - If the feature is not active, the function returns 0 without modifying the epoch.
- **Output**: The function outputs the calculated epoch in the `epoch` parameter and sets an error code in the `err` parameter if any issues occur.


---
### stake\_state\_v2\_size\_of<!-- {{#callable:stake_state_v2_size_of}} -->
The `stake_state_v2_size_of` function returns a constant size of 200.
- **Inputs**: None
- **Control Flow**:
    - The function directly returns the constant value 200 without any conditions or loops.
- **Output**: The output is a constant value of type `ulong`, specifically 200.


---
### meta<!-- {{#callable:meta}} -->
The `meta` function retrieves the metadata associated with a specific `merge_kind_t` instance.
- **Inputs**:
    - `self`: A pointer to a `merge_kind_t` structure that contains the discriminant and inner union representing different merge kinds.
- **Control Flow**:
    - The function begins by evaluating the `discriminant` field of the `merge_kind_t` structure.
    - Based on the value of `discriminant`, it uses a switch-case statement to determine which type of merge kind is being referenced.
    - For each case, it returns a pointer to the corresponding `meta` field from the appropriate inner structure.
    - If the `discriminant` does not match any known types, it logs an error indicating an invalid discriminant.
- **Output**: The function returns a constant pointer to the `fd_stake_meta_t` structure associated with the specified merge kind, or logs an error if the discriminant is invalid.


---
### active\_stake<!-- {{#callable:active_stake}} -->
The `active_stake` function retrieves the active stake associated with a given `merge_kind_t` structure.
- **Inputs**:
    - `self`: A pointer to a `merge_kind_t` structure that indicates the type of merge kind.
- **Control Flow**:
    - The function begins by evaluating the `discriminant` field of the `merge_kind_t` structure to determine its type.
    - If the type is `merge_kind_inactive`, the function returns NULL, indicating no active stake.
    - If the type is `merge_kind_activation_epoch`, it returns a pointer to the `stake` field within the `activation_epoch` structure.
    - If the type is `merge_kind_fully_active`, it returns a pointer to the `stake` field within the `fully_active` structure.
    - If the `discriminant` does not match any known types, an error is logged.
- **Output**: The function returns a pointer to the active stake (`fd_stake_t`) if applicable, or NULL if the `merge_kind` is inactive.


---
### get\_if\_mergeable<!-- {{#callable:get_if_mergeable}} -->
The `get_if_mergeable` function determines if a stake account can be merged based on its state and returns the appropriate merge kind.
- **Inputs**:
    - `invoke_context`: A pointer to the execution context containing transaction details.
    - `stake_state`: A pointer to the current state of the stake account.
    - `stake_lamports`: The amount of lamports associated with the stake.
    - `clock`: A pointer to the system clock providing the current epoch.
    - `stake_history`: A pointer to the history of stake changes.
    - `out`: A pointer to a `merge_kind_t` structure where the result will be stored.
    - `custom_err`: A pointer to a variable for storing custom error codes.
- **Control Flow**:
    - The function first checks the `discriminant` of the `stake_state` to determine its type.
    - If the state is of type `fd_stake_state_v2_enum_stake`, it retrieves metadata, stake, and flags.
    - It then calculates the new rate activation epoch and checks for errors.
    - The function assesses the activation and deactivation status of the stake using [`stake_activating_and_deactivating`](#stake_activating_and_deactivating).
    - Based on the status, it sets the output `merge_kind_t` to indicate whether the stake is inactive, in an activation epoch, or fully active.
    - If the stake cannot be merged due to transient status, it logs an error and sets a custom error code.
    - If the state is `fd_stake_state_v2_enum_initialized`, it sets the output to inactive with the current stake lamports.
    - If the state is unrecognized, it returns an invalid account data error.
- **Output**: The function returns 0 on success, or an error code indicating the type of failure, while populating the `out` parameter with the determined merge kind.
- **Functions called**:
    - [`fd_new_warmup_cooldown_rate_epoch`](#fd_new_warmup_cooldown_rate_epoch)
    - [`stake_activating_and_deactivating`](#stake_activating_and_deactivating)


---
### metas\_can\_merge<!-- {{#callable:metas_can_merge}} -->
The `metas_can_merge` function checks if two stake metadata can be merged based on their lockup and authorization properties.
- **Inputs**:
    - `invoke_context`: A pointer to the execution context, which is not const to allow logging.
    - `stake`: A pointer to the first stake metadata structure.
    - `source`: A pointer to the second stake metadata structure.
    - `clock`: A pointer to the system clock structure used to check lockup conditions.
    - `custom_err`: A pointer to a variable where custom error codes can be stored.
- **Control Flow**:
    - The function first checks if the lockup conditions of both stake metadata are either identical or not in force.
    - It then compares the `authorized` fields of both stake metadata for equality.
    - If both conditions are satisfied, the function returns 0 indicating success.
    - If any condition fails, it logs an error message and sets a custom error code before returning an error.
- **Output**: The function returns 0 if the metadata can be merged, or an error code indicating the reason for failure.
- **Functions called**:
    - [`lockup_is_in_force`](#lockup_is_in_force)


---
### active\_delegations\_can\_merge<!-- {{#callable:active_delegations_can_merge}} -->
The `active_delegations_can_merge` function checks if two active stake delegations can be merged based on their voter public keys and deactivation epochs.
- **Inputs**:
    - `invoke_context`: A pointer to the execution context, which is not const to allow logging.
    - `stake`: A pointer to the first `fd_delegation_t` structure representing the stake delegation.
    - `source`: A pointer to the second `fd_delegation_t` structure representing the source delegation to be merged.
    - `custom_err`: A pointer to a uint that will hold custom error codes if any error occurs.
- **Control Flow**:
    - The function first compares the `voter_pubkey` fields of the `stake` and `source` delegations using `memcmp`.
    - If the public keys do not match, it logs an error message indicating a voter mismatch, sets the custom error code to `FD_STAKE_ERR_MERGE_MISMATCH`, and returns an error code.
    - If both delegations have `deactivation_epoch` set to `ULONG_MAX`, it indicates that both are active and can be merged, so the function returns 0.
    - If the deactivation epochs are not both `ULONG_MAX`, it logs an error message indicating that merging is not possible due to stake deactivation, sets the custom error code to `FD_STAKE_ERR_MERGE_MISMATCH`, and returns an error code.
- **Output**: The function returns 0 if the delegations can be merged, or an error code indicating the reason for failure.


---
### stake\_weighted\_credits\_observed<!-- {{#callable:stake_weighted_credits_observed}} -->
Calculates the stake-weighted credits observed based on the stake and absorbed credits.
- **Inputs**:
    - `stake`: A pointer to a `fd_stake_t` structure representing the current stake.
    - `absorbed_lamports`: An unsigned long integer representing the amount of lamports absorbed.
    - `absorbed_credits_observed`: An unsigned long integer representing the credits observed that have been absorbed.
    - `out`: A pointer to an unsigned long integer where the result will be stored.
- **Control Flow**:
    - Check if the `credits_observed` in `stake` matches `absorbed_credits_observed`. If they match, set `*out` to `credits_observed` and return 1.
    - If they do not match, calculate the `total_stake` by adding `stake->delegation.stake` and `absorbed_lamports`, checking for overflow.
    - Calculate `stake_weighted_credits` by multiplying `credits_observed` and `stake->delegation.stake` using `fd_uwide_mul`.
    - Calculate `absorbed_weighted_credits` by multiplying `absorbed_credits_observed` and `absorbed_lamports` using `fd_uwide_mul`.
    - Add `stake_weighted_credits` and `absorbed_weighted_credits` to get a partial total, then add `total_stake` and subtract 1, checking for overflow at each step.
    - If the result is zero after subtraction, return 0 to indicate an error.
    - Finally, divide the total weighted credits by `total_stake` to get the result and store it in `*out`.
- **Output**: Returns 1 on success with the calculated credits in `*out`, or 0 on failure due to overflow or invalid calculations.


---
### merge\_delegation\_stake\_and\_credits\_observed<!-- {{#callable:merge_delegation_stake_and_credits_observed}} -->
Merges the delegation stake and credits observed into a stake structure.
- **Inputs**:
    - `invoke_context`: A constant pointer to the execution instruction context.
    - `stake`: A pointer to the `fd_stake_t` structure representing the stake to be updated.
    - `absorbed_lamports`: An unsigned long integer representing the amount of lamports to be added to the stake.
    - `absorbed_credits_observed`: An unsigned long integer representing the credits observed to be merged into the stake.
- **Control Flow**:
    - Calls [`stake_weighted_credits_observed`](#stake_weighted_credits_observed) to calculate the new credits observed based on the absorbed lamports and credits.
    - If the calculation indicates an arithmetic overflow, it returns an error code `FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW`.
    - Uses `fd_ulong_checked_add` to safely add the absorbed lamports to the current stake's delegation stake.
    - If the addition results in an overflow, it returns the corresponding error code.
- **Output**: Returns 0 on success, or an error code indicating the type of failure encountered during the operation.
- **Functions called**:
    - [`stake_weighted_credits_observed`](#stake_weighted_credits_observed)


---
### merge\_kind\_merge<!-- {{#callable:merge_kind_merge}} -->
The `merge_kind_merge` function merges two stake states based on their types and updates the output state accordingly.
- **Inputs**:
    - `self`: The current stake state to merge from.
    - `invoke_context`: The execution context for the function, allowing access to the current transaction and its state.
    - `source`: The stake state to merge into the current state.
    - `clock`: A pointer to the current system clock, used for time-related checks.
    - `out`: A pointer to the output variable where the merged stake state will be stored.
    - `is_some`: A pointer to an integer that indicates if the merge resulted in a valid state.
    - `custom_err`: A pointer to a variable for storing custom error codes.
- **Control Flow**:
    - The function first checks if the metadata of the two stake states can be merged using [`metas_can_merge`](#metas_can_merge).
    - If the metadata is compatible, it retrieves the active stakes from both states.
    - It checks if both stakes can merge their delegations if they exist.
    - Based on the discriminants of the two states, it determines how to merge them, handling various cases for inactive, activation epoch, and fully active states.
    - If the merged state is valid, it updates the output variable and sets the `is_some` flag accordingly.
    - If the merged state is null, it sets `is_some` to 0 and returns.
- **Output**: The function returns 0 on success, or an error code if the merge fails, with the merged stake state stored in the `out` parameter.
- **Functions called**:
    - [`metas_can_merge`](#metas_can_merge)
    - [`meta`](#meta)
    - [`active_stake`](#active_stake)
    - [`active_delegations_can_merge`](#active_delegations_can_merge)
    - [`merge_delegation_stake_and_credits_observed`](#merge_delegation_stake_and_credits_observed)


---
### get\_stake\_status<!-- {{#callable:get_stake_status}} -->
The `get_stake_status` function retrieves the current activation status of a stake account.
- **Inputs**:
    - `invoke_context`: A constant pointer to the execution instruction context, which contains transaction-related information.
    - `stake`: A pointer to the `fd_stake_t` structure representing the stake account whose status is being queried.
    - `clock`: A constant pointer to the system clock variable, providing the current epoch information.
    - `out`: A pointer to an `fd_stake_activation_status_t` structure where the result of the stake status will be stored.
- **Control Flow**:
    - The function begins by reading the stake history from the system variable using the provided `invoke_context`.
    - If the stake history is not available, it returns an error indicating unsupported system variable.
    - It then attempts to determine the new rate activation epoch based on the current slot and transaction context features.
    - If an error occurs during this process, it returns the error immediately.
    - Finally, it calls the [`stake_activating_and_deactivating`](#stake_activating_and_deactivating) function to compute the activation status based on the current epoch, stake history, and new rate activation epoch, storing the result in the `out` parameter.
- **Output**: The function returns 0 on success, indicating that the stake status has been successfully retrieved and stored in the `out` parameter. If any errors occur during execution, an appropriate error code is returned.
- **Functions called**:
    - [`fd_new_warmup_cooldown_rate_epoch`](#fd_new_warmup_cooldown_rate_epoch)
    - [`stake_activating_and_deactivating`](#stake_activating_and_deactivating)


---
### get\_credits<!-- {{#callable:get_credits}} -->
The `get_credits` function retrieves the number of credits from the most recent epoch in the provided vote state.
- **Inputs**:
    - `vote_state`: A constant pointer to a `fd_vote_state_t` structure that contains the voting state, including epoch credits.
- **Control Flow**:
    - The function first checks if the `epoch_credits` queue in the `vote_state` is empty using `deq_fd_vote_epoch_credits_t_empty`.
    - If the queue is empty, it returns 0, indicating no credits are available.
    - If the queue is not empty, it retrieves the count of credits using `deq_fd_vote_epoch_credits_t_cnt` and accesses the last element using `deq_fd_vote_epoch_credits_t_peek_index`.
    - Finally, it returns the `credits` value from the last epoch credit entry.
- **Output**: Returns the number of credits from the most recent epoch, or 0 if there are no credits available.


---
### redelegate\_stake<!-- {{#callable:redelegate_stake}} -->
The `redelegate_stake` function updates the stake delegation parameters for a given stake account.
- **Inputs**:
    - `ctx`: A pointer to the execution instruction context containing transaction details.
    - `stake`: A pointer to the `fd_stake_t` structure representing the stake account being modified.
    - `stake_lamports`: The amount of lamports to be delegated to the new voter.
    - `voter_pubkey`: A pointer to the public key of the new voter to whom the stake is being redelegated.
    - `vote_state`: A pointer to the `fd_vote_state_t` structure containing the current vote state.
    - `clock`: A pointer to the `fd_sol_sysvar_clock_t` structure providing the current epoch and timestamp.
    - `stake_history`: A pointer to the `fd_stake_history_t` structure containing historical stake data.
    - `custom_err`: A pointer to a variable that will hold custom error codes.
- **Control Flow**:
    - The function initializes a variable `new_rate_activation_epoch` to `ULONG_MAX` and calls [`fd_new_warmup_cooldown_rate_epoch`](#fd_new_warmup_cooldown_rate_epoch) to determine if a new warmup/cooldown rate epoch is activated.
    - If the call to [`fd_new_warmup_cooldown_rate_epoch`](#fd_new_warmup_cooldown_rate_epoch) returns an error, the function exits early with that error.
    - The function checks if the current delegation stake is valid by calling [`delegation_stake`](#delegation_stake) with the current epoch and stake history.
    - If the delegation stake is invalid, it checks if the current voter matches the provided `voter_pubkey` and if the current epoch is the deactivation epoch; if so, it resets the deactivation epoch and returns success.
    - If the conditions are not met, it sets a custom error indicating that it is too soon to redelegate and returns an error.
    - If the delegation stake is valid, it updates the stake's delegation parameters, including the amount of stake, activation epoch, deactivation epoch, and voter public key.
    - Finally, it updates the `credits_observed` field with the current credits from the `vote_state` and returns success.
- **Output**: The function returns 0 on success, or an error code indicating the type of failure that occurred.
- **Functions called**:
    - [`fd_new_warmup_cooldown_rate_epoch`](#fd_new_warmup_cooldown_rate_epoch)
    - [`delegation_stake`](#delegation_stake)
    - [`get_credits`](#get_credits)


---
### new\_stake<!-- {{#callable:new_stake}} -->
Creates a new stake object with specified parameters.
- **Inputs**:
    - `stake`: The amount of stake to be assigned.
    - `voter_pubkey`: A pointer to the public key of the voter.
    - `vote_state`: A pointer to the current vote state.
    - `activation_epoch`: The epoch in which the stake is activated.
- **Control Flow**:
    - The function initializes a `fd_stake_t` structure.
    - It sets the `delegation` field with the provided `voter_pubkey`, `stake`, `activation_epoch`, and default values for `deactivation_epoch` and `warmup_cooldown_rate`.
    - The `credits_observed` field is populated by calling the [`get_credits`](#get_credits) function with the provided `vote_state`.
- **Output**: Returns a `fd_stake_t` structure representing the newly created stake.
- **Functions called**:
    - [`get_credits`](#get_credits)


---
### initialize<!-- {{#callable:initialize}} -->
The `initialize` function sets up a stake account with specified authorization and lockup parameters.
- **Inputs**:
    - `stake_account`: A pointer to a `fd_borrowed_account_t` structure representing the stake account to be initialized.
    - `authorized`: A pointer to a constant `fd_stake_authorized_t` structure containing the authorization details for the stake account.
    - `lockup`: A pointer to a constant `fd_stake_lockup_t` structure defining the lockup parameters for the stake account.
    - `rent`: A pointer to a constant `fd_rent_t` structure that provides rent-related information.
- **Control Flow**:
    - The function first checks if the data length of the `stake_account` matches the expected size for a stake state.
    - If the data length is incorrect, it returns an error indicating invalid account data.
    - It retrieves the current state of the stake account and checks if it is uninitialized.
    - If the account is uninitialized, it calculates the rent-exempt reserve based on the provided rent information.
    - It then checks if the account has sufficient lamports to cover the rent-exempt reserve.
    - If sufficient funds are available, it initializes the stake state with the provided authorization and lockup details.
    - Finally, it sets the new state for the stake account and returns success; otherwise, it returns an insufficient funds error.
- **Output**: The function returns an integer indicating the success or failure of the initialization process, with specific error codes for various failure conditions.
- **Functions called**:
    - [`stake_state_v2_size_of`](#stake_state_v2_size_of)
    - [`get_state`](#get_state)
    - [`set_state`](#set_state)


---
### authorize<!-- {{#callable:authorize}} -->
The `authorize` function updates the authority of a stake account based on the current state and provided authorization parameters.
- **Inputs**:
    - `stake_account`: A pointer to the `fd_borrowed_account_t` structure representing the stake account to be authorized.
    - `signers`: An array of pointers to `fd_pubkey_t` representing the signers required for authorization.
    - `new_authority`: A pointer to `fd_pubkey_t` representing the new authority to be set for the stake account.
    - `stake_authorize`: A pointer to `fd_stake_authorize_t` indicating the type of authorization (staker or withdrawer).
    - `clock`: A pointer to `fd_sol_sysvar_clock_t` providing the current clock time for validation.
    - `custodian`: A pointer to `fd_pubkey_t` representing the custodian's public key, if applicable.
    - `custom_err`: A pointer to a `uint` that will hold any custom error codes generated during the function execution.
- **Control Flow**:
    - The function begins by initializing a variable `rc` to hold return codes and a `stake_state` structure to hold the current state of the stake account.
    - It retrieves the current state of the stake account using the [`get_state`](#get_state) function, returning an error code if unsuccessful.
    - A switch statement is used to handle different states of the stake account: 'stake' and 'initialized'.
    - For each case, it prepares the `lockup_custodian_args` structure and calls the [`authorized_authorize`](#authorized_authorize) function to perform the authorization check and update.
    - If the authorization is successful, it updates the state of the stake account using the [`set_state`](#set_state) function.
    - If the state is neither 'stake' nor 'initialized', it returns an error indicating invalid account data.
- **Output**: The function returns an integer indicating the success or failure of the operation, with specific error codes for various failure conditions.
- **Functions called**:
    - [`get_state`](#get_state)
    - [`authorized_authorize`](#authorized_authorize)
    - [`set_state`](#set_state)


---
### authorize\_with\_seed<!-- {{#callable:authorize_with_seed}} -->
The `authorize_with_seed` function authorizes a new authority for a stake account using a derived public key from a base public key and a seed.
- **Inputs**:
    - `ctx`: A constant pointer to the execution instruction context, which contains information about the current transaction and its accounts.
    - `stake_account`: A pointer to a borrowed account representing the stake account that is being authorized.
    - `authority_base_index`: An index indicating the position of the base authority account in the instruction's account list.
    - `authority_seed`: A string used as a seed to derive the new authority's public key.
    - `authority_seed_len`: The length of the authority seed string.
    - `authority_owner`: A pointer to the public key of the owner of the authority that is being derived.
    - `new_authority`: A pointer to the public key of the new authority that will be authorized.
    - `stake_authorize`: A pointer to a structure that specifies the type of authorization being requested (e.g., staker or withdrawer).
    - `clock`: A pointer to the system clock variable, which provides the current time and epoch information.
    - `custodian`: A pointer to the public key of the custodian, if applicable, who may need to sign the authorization.
- **Control Flow**:
    - The function first checks if the account at `authority_base_index` is a signer for the transaction.
    - If it is a signer, it retrieves the base public key from the account at the specified index.
    - Then, it creates a new public key using the `fd_pubkey_create_with_seed` function, which derives a new public key from the base public key and the provided seed.
    - If the public key creation is successful, it adds the newly created public key to the signers array.
    - Finally, it calls the [`authorize`](#authorize) function to perform the actual authorization of the new authority for the stake account.
- **Output**: The function returns an integer indicating the success or failure of the authorization process, with a return value of 0 indicating success.
- **Functions called**:
    - [`authorize`](#authorize)


---
### delegate<!-- {{#callable:delegate}} -->
The `delegate` function manages the delegation of stake to a specified vote account.
- **Inputs**:
    - `ctx`: A pointer to the execution context containing transaction details.
    - `stake_account_index`: The index of the stake account to delegate.
    - `vote_account_index`: The index of the vote account to which the stake is delegated.
    - `clock`: A pointer to the system clock variable.
    - `stake_history`: A pointer to the stake history variable.
    - `signers`: An array of public keys representing the signers of the transaction.
- **Control Flow**:
    - The function begins by borrowing the vote account specified by `vote_account_index`.
    - It checks if the owner of the vote account matches the expected Solana vote program ID.
    - The function retrieves the public key of the vote account and attempts to get its state.
    - Next, it borrows the stake account specified by `stake_account_index` and retrieves its state.
    - Based on the state of the stake account, it checks if it is initialized or already delegated.
    - If the stake account is initialized, it performs authorization checks and validates the delegated amount.
    - If the stake account is already in a delegated state, it performs additional checks and redelegates the stake.
    - Finally, it updates the state of the stake account with the new delegation information.
- **Output**: The function returns an integer indicating the success or failure of the operation, with specific error codes for various failure conditions.
- **Functions called**:
    - [`fd_vote_get_state`](fd_vote_program.c.driver.md#fd_vote_get_state)
    - [`get_state`](#get_state)
    - [`authorized_check`](#authorized_check)
    - [`validate_delegated_amount`](#validate_delegated_amount)
    - [`fd_vote_convert_to_current`](fd_vote_program.c.driver.md#fd_vote_convert_to_current)
    - [`new_stake`](#new_stake)
    - [`set_state`](#set_state)
    - [`redelegate_stake`](#redelegate_stake)


---
### deactivate<!-- {{#callable:deactivate}} -->
The `deactivate` function deactivates a stake account if it is in a valid state.
- **Inputs**:
    - `stake_account`: A pointer to the `fd_borrowed_account_t` structure representing the stake account to be deactivated.
    - `clock`: A pointer to the `fd_sol_sysvar_clock_t` structure providing the current clock information.
    - `signers`: An array of pointers to `fd_pubkey_t` representing the signers authorized to perform the deactivation.
    - `custom_err`: A pointer to a `uint` variable that will hold any custom error codes generated during the operation.
- **Control Flow**:
    - The function begins by initializing a variable `rc` to hold return codes.
    - It retrieves the current state of the stake account using the [`get_state`](#get_state) function.
    - If the state indicates that the account is a stake account, it proceeds to check if the signers are authorized using the [`authorized_check`](#authorized_check) function.
    - If authorized, it calls [`stake_deactivate`](#stake_deactivate) to deactivate the stake, passing the current epoch and custom error variable.
    - Finally, it updates the state of the stake account using the [`set_state`](#set_state) function.
    - If the account is not a stake account, it returns an error indicating invalid account data.
- **Output**: The function returns an integer indicating the success or failure of the operation, with specific error codes for different failure conditions.
- **Functions called**:
    - [`get_state`](#get_state)
    - [`authorized_check`](#authorized_check)
    - [`stake_deactivate`](#stake_deactivate)
    - [`set_state`](#set_state)


---
### set\_lockup<!-- {{#callable:set_lockup}} -->
The `set_lockup` function updates the lockup parameters of a stake account.
- **Inputs**:
    - `stake_account`: A pointer to the `fd_borrowed_account_t` structure representing the stake account to be modified.
    - `lockup`: A pointer to the `fd_lockup_args_t` structure containing the new lockup parameters.
    - `signers`: An array of pointers to `fd_pubkey_t` representing the signers required for the operation.
    - `clock`: A pointer to the `fd_sol_sysvar_clock_t` structure providing the current clock information.
- **Control Flow**:
    - The function begins by initializing a variable `rc` to hold return codes.
    - It retrieves the current state of the stake account using the [`get_state`](#get_state) function.
    - If the state retrieval fails, it returns the error code.
    - The function then checks the discriminant of the state to determine if it is initialized or in stake mode.
    - For both cases, it calls [`set_lockup_meta`](#set_lockup_meta) to update the lockup parameters, passing the relevant metadata, lockup arguments, signers, and clock.
    - If [`set_lockup_meta`](#set_lockup_meta) fails, it returns the error code.
    - Finally, it updates the state of the stake account with the modified state using [`set_state`](#set_state).
- **Output**: The function returns an integer indicating success (0) or an error code if any operation fails.
- **Functions called**:
    - [`get_state`](#get_state)
    - [`set_lockup_meta`](#set_lockup_meta)
    - [`set_state`](#set_state)


---
### split<!-- {{#callable:split}} -->
The `split` function divides a stake account into two separate accounts, transferring a specified amount of lamports to a new account.
- **Inputs**:
    - `ctx`: A pointer to the execution context containing transaction details.
    - `stake_account_index`: The index of the stake account from which lamports will be split.
    - `lamports`: The amount of lamports to be transferred to the new split account.
    - `split_index`: The index of the new account that will receive the split lamports.
    - `signers`: An array of public keys representing the signers authorized to perform the split.
- **Control Flow**:
    - The function begins by attempting to borrow the account at `split_index` and checks for errors.
    - It verifies that the account owner matches the expected program ID and that the account data length is valid.
    - The function retrieves the current state of the split account and checks if it is uninitialized.
    - It checks the balance of the stake account to ensure sufficient funds are available for the split.
    - The function then checks the state of the stake account and performs authorization checks on the signers.
    - It validates the amount to be split, ensuring it meets minimum delegation requirements.
    - The function calculates the remaining balance and the amount to be split, ensuring both are valid.
    - It performs the actual split operation, updating the state of both the original and new accounts.
    - Finally, it updates the lamport balances of both accounts and returns success or an error code.
- **Output**: Returns 0 on success, or an error code indicating the type of failure encountered during the operation.
- **Functions called**:
    - [`stake_state_v2_size_of`](#stake_state_v2_size_of)
    - [`get_state`](#get_state)
    - [`authorized_check`](#authorized_check)
    - [`get_minimum_delegation`](#get_minimum_delegation)
    - [`get_stake_status`](#get_stake_status)
    - [`validate_split_amount`](#validate_split_amount)
    - [`stake_split`](#stake_split)
    - [`set_state`](#set_state)


---
### merge<!-- {{#callable:merge}} -->
The `merge` function combines two stake accounts into one, transferring the stake and updating the states accordingly.
- **Inputs**:
    - `ctx`: A pointer to the execution instruction context, which holds the state and transaction information.
    - `stake_account_index`: The index of the destination stake account in the transaction.
    - `source_account_index`: The index of the source stake account to be merged.
    - `clock`: A pointer to the system clock variable, providing the current epoch and timestamp.
    - `stake_history`: A pointer to the stake history variable, which tracks historical stake data.
    - `signers`: An array of public keys representing the signers of the transaction.
- **Control Flow**:
    - The function begins by borrowing the source account and checking if it belongs to the correct program.
    - It retrieves the indices of both the stake and source accounts within the transaction context.
    - A check is performed to ensure that the stake account and source account are not the same to prevent self-merging.
    - The function then borrows the stake account and retrieves its state.
    - It checks if the destination stake account is mergeable by calling [`get_if_mergeable`](#get_if_mergeable).
    - An authorization check is performed to ensure the signers have the necessary permissions to merge the accounts.
    - The state of the source account is retrieved and checked for mergeability.
    - The actual merging of the stake accounts is performed using [`merge_kind_merge`](#merge_kind_merge), which handles different merge scenarios.
    - If the merge is successful, the state of the destination account is updated with the merged state, and the source account is marked as uninitialized.
    - Finally, the lamports from the source account are transferred to the destination account.
- **Output**: The function returns 0 on success, indicating that the merge operation was completed successfully. If any errors occur during the process, appropriate error codes are returned.
- **Functions called**:
    - [`get_state`](#get_state)
    - [`get_if_mergeable`](#get_if_mergeable)
    - [`authorized_check`](#authorized_check)
    - [`meta`](#meta)
    - [`merge_kind_merge`](#merge_kind_merge)
    - [`set_state`](#set_state)


---
### move\_stake\_or\_lamports\_shared\_checks<!-- {{#callable:move_stake_or_lamports_shared_checks}} -->
The `move_stake_or_lamports_shared_checks` function performs validation checks for moving stake or lamports between accounts.
- **Inputs**:
    - `invoke_context`: A pointer to the execution instruction context, which contains information about the current transaction.
    - `source_account`: A pointer to the source account from which lamports or stake will be moved.
    - `lamports`: The amount of lamports to be moved.
    - `destination_account`: A pointer to the destination account to which lamports or stake will be moved.
    - `stake_authority_index`: The index of the account that has the authority to stake.
    - `source_merge_kind`: A pointer to a `merge_kind_t` structure that will hold the merge kind of the source account.
    - `destination_merge_kind`: A pointer to a `merge_kind_t` structure that will hold the merge kind of the destination account.
    - `custom_err`: A pointer to a variable that will hold custom error codes.
- **Control Flow**:
    - Check if the stake authority is a signer; if not, return an error.
    - Retrieve the public key of the stake authority and check if the source and destination accounts are owned by the correct program.
    - Ensure that the source and destination accounts are not the same.
    - Verify that both accounts are writable.
    - Check that the amount of lamports to move is greater than zero.
    - Read the current clock and stake history from the system variables.
    - Get the state of the source account and check if it is mergeable.
    - Perform an authorized check on the source account's metadata.
    - Get the state of the destination account and check if it is mergeable.
    - Check if the metadata of both accounts can be merged.
- **Output**: Returns 0 on success or an error code indicating the type of failure encountered during the checks.
- **Functions called**:
    - [`get_state`](#get_state)
    - [`get_if_mergeable`](#get_if_mergeable)
    - [`authorized_check`](#authorized_check)
    - [`meta`](#meta)
    - [`metas_can_merge`](#metas_can_merge)


---
### move\_stake<!-- {{#callable:move_stake}} -->
The `move_stake` function transfers a specified amount of stake (lamports) from one account to another within a staking context.
- **Inputs**:
    - `ctx`: A pointer to the execution instruction context, which holds the state and transaction context.
    - `source_account_index`: The index of the source account from which the stake is to be moved.
    - `lamports`: The amount of lamports (stake) to be moved from the source account.
    - `destination_account_index`: The index of the destination account to which the stake is to be moved.
    - `stake_authority_index`: The index of the account that has the authority to move the stake.
    - `custom_err`: A pointer to a variable that will hold any custom error codes generated during execution.
- **Control Flow**:
    - The function begins by borrowing the source and destination accounts using their respective indices.
    - It performs shared checks to ensure that the move operation is valid, including verifying account ownership and ensuring sufficient funds.
    - The function checks the state of the source account to ensure it is fully active and that the amount to be moved does not exceed the available stake.
    - It calculates the final stake for the source account after the move and checks if it meets the minimum delegation requirements.
    - Depending on the state of the destination account, it either merges the stake into an active account or initializes a new inactive account.
    - Finally, it updates the lamport balances of both accounts and checks for rent-exempt reserves before returning success or an error code.
- **Output**: The function returns an integer indicating the success or failure of the operation, with specific error codes for various failure conditions.
- **Functions called**:
    - [`move_stake_or_lamports_shared_checks`](#move_stake_or_lamports_shared_checks)
    - [`stake_state_v2_size_of`](#stake_state_v2_size_of)
    - [`get_minimum_delegation`](#get_minimum_delegation)
    - [`merge_delegation_stake_and_credits_observed`](#merge_delegation_stake_and_credits_observed)
    - [`set_state`](#set_state)


---
### move\_lamports<!-- {{#callable:move_lamports}} -->
The `move_lamports` function transfers a specified amount of lamports from a source account to a destination account after performing necessary checks.
- **Inputs**:
    - `ctx`: A pointer to the execution instruction context, which contains information about the current transaction.
    - `source_account_index`: The index of the source account from which lamports will be deducted.
    - `lamports`: The amount of lamports to be transferred.
    - `destination_account_index`: The index of the destination account to which lamports will be added.
    - `stake_authority_index`: The index of the account that has the authority to perform the stake operation.
- **Control Flow**:
    - The function begins by borrowing the source and destination accounts using their respective indices.
    - It performs shared checks to ensure that the transfer is valid, including verifying that the source account has enough free lamports.
    - The function calculates the available lamports in the source account based on its state (fully active or inactive).
    - If the requested lamports exceed the available amount, an error is returned.
    - The function then deducts the specified lamports from the source account and adds them to the destination account.
    - Finally, it returns a success code if all operations complete without errors.
- **Output**: Returns a success code if the transfer is successful, or an error code if any checks fail or if the operation cannot be completed.
- **Functions called**:
    - [`move_stake_or_lamports_shared_checks`](#move_stake_or_lamports_shared_checks)


---
### withdraw<!-- {{#callable:withdraw}} -->
The `withdraw` function processes a withdrawal from a stake account, ensuring proper authorization and sufficient funds.
- **Inputs**:
    - `ctx`: A pointer to the execution instruction context containing transaction details.
    - `stake_account_index`: The index of the stake account from which funds are to be withdrawn.
    - `lamports`: The amount of lamports to withdraw from the stake account.
    - `to_index`: The index of the account to which the withdrawn lamports will be sent.
    - `clock`: A pointer to the system clock variable providing the current epoch.
    - `stake_history`: A pointer to the stake history variable for tracking stake changes.
    - `withdraw_authority_index`: The index of the account authorized to withdraw funds.
    - `custodian_index`: An optional pointer to the index of the custodian account.
    - `new_rate_activation_epoch`: A pointer to store the new rate activation epoch after withdrawal.
- **Control Flow**:
    - Retrieve the public key of the withdraw authority using its index.
    - Check if the withdraw authority is a signer of the transaction.
    - Borrow the stake account to ensure exclusive access.
    - Get the current state of the stake account.
    - Determine the lockup conditions and whether the account is staked.
    - Check if the lockup is in force and if the withdrawal amount is valid.
    - Calculate the total amount available for withdrawal, including reserves.
    - Verify that the account has sufficient funds for the withdrawal.
    - If the entire balance is withdrawn, mark the account as uninitialized.
    - Subtract the lamports from the stake account and add them to the destination account.
- **Output**: Returns 0 on success, or an error code indicating the type of failure encountered during the withdrawal process.
- **Functions called**:
    - [`get_state`](#get_state)
    - [`authorized_check`](#authorized_check)
    - [`delegation_stake`](#delegation_stake)
    - [`lockup_is_in_force`](#lockup_is_in_force)
    - [`set_state`](#set_state)


---
### deactivate\_delinquent<!-- {{#callable:deactivate_delinquent}} -->
The `deactivate_delinquent` function deactivates a delinquent stake account if certain conditions regarding its voting status and epoch credits are met.
- **Inputs**:
    - `ctx`: A pointer to the execution context containing transaction and instruction information.
    - `stake_account`: A pointer to the borrowed account representing the stake account to be deactivated.
    - `delinquent_vote_account_index`: The index of the delinquent vote account in the instruction's account list.
    - `reference_vote_account_index`: The index of the reference vote account in the instruction's account list.
    - `current_epoch`: The current epoch number used to validate the deactivation conditions.
    - `custom_err`: A pointer to a variable where custom error codes can be stored.
- **Control Flow**:
    - Retrieve the public key of the delinquent vote account using its index.
    - Borrow the delinquent vote account and check if it belongs to the correct program.
    - Get the current state of the delinquent vote account and convert it to the current version.
    - Borrow the reference vote account and check if it belongs to the correct program.
    - Get the current state of the reference vote account and convert it to the current version.
    - Check if the reference vote account has sufficient credits for the current epoch.
    - Retrieve the state of the stake account and check if it is valid.
    - Verify that the delinquent vote account matches the stake account's voter public key.
    - Check if the delinquent account is eligible for deactivation based on its epoch credits.
    - Deactivate the stake if eligible and update the stake account state.
- **Output**: Returns an integer indicating the success or failure of the operation, with specific error codes set in case of failure.
- **Functions called**:
    - [`fd_vote_get_state`](fd_vote_program.c.driver.md#fd_vote_get_state)
    - [`fd_vote_convert_to_current`](fd_vote_program.c.driver.md#fd_vote_convert_to_current)
    - [`acceptable_reference_epoch_credits`](#acceptable_reference_epoch_credits)
    - [`get_state`](#get_state)
    - [`eligible_for_deactivate_delinquent`](#eligible_for_deactivate_delinquent)
    - [`stake_deactivate`](#stake_deactivate)
    - [`set_state`](#set_state)


---
### get\_optional\_pubkey<!-- {{#callable:get_optional_pubkey}} -->
The `get_optional_pubkey` function retrieves an optional public key from a specified account index in the execution context.
- **Inputs**:
    - `ctx`: A pointer to the execution instruction context, which contains information about the current instruction being executed.
    - `acc_idx`: An index representing the account from which to retrieve the public key.
    - `should_be_signer`: An integer flag indicating whether the account at the specified index should be a signer.
    - `pubkey`: A pointer to a pointer where the retrieved public key will be stored.
- **Control Flow**:
    - The function first checks if the account index `acc_idx` is within the valid range of accounts in the context.
    - If the index is valid, it checks if the account at that index is required to be a signer and whether it is indeed a signer.
    - If the account is a signer when it should be, the function returns an error indicating a missing required signature.
    - If the account index is valid and the signer check passes (if applicable), it retrieves the public key of the account at the specified index.
    - If the index is out of bounds, it sets the output public key pointer to NULL.
- **Output**: The function returns 0 on success, or an error code if the account index is invalid or if a required signature is missing.


---
### get\_stake\_account<!-- {{#callable:get_stake_account}} -->
The `get_stake_account` function attempts to borrow a stake account from the execution context and validates its ownership.
- **Inputs**:
    - `ctx`: A pointer to the execution instruction context, which contains information about the current execution state.
    - `out`: A pointer to a `fd_borrowed_account_t` structure where the borrowed account will be stored.
- **Control Flow**:
    - The function first attempts to borrow the instruction account at index 0 from the execution context using `fd_exec_instr_ctx_try_borrow_instr_account`.
    - If borrowing fails (indicated by a non-zero error code), the function returns the error immediately.
    - Next, it retrieves the owner of the borrowed account and compares it to the expected Solana stake program ID.
    - If the owner does not match, it returns an error indicating an invalid account owner.
    - If all checks pass, the function returns a success code.
- **Output**: The function returns an integer indicating success or an error code if any validation fails.


---
### fd\_stake\_program\_execute<!-- {{#callable:fd_stake_program_execute}} -->
The `fd_stake_program_execute` function processes various stake-related instructions in a Solana-like blockchain environment.
- **Inputs**:
    - `ctx`: A pointer to the execution instruction context (`fd_exec_instr_ctx_t`), which contains information about the current transaction and its associated accounts.
- **Control Flow**:
    - Checks if the program is migrated and returns an error if so.
    - Updates the compute units for the execution context.
    - Retrieves the signers for the transaction.
    - Validates the instruction data and decodes it into a specific stake instruction structure.
    - Checks if the epoch rewards system variable is active and validates the instruction accordingly.
    - Sets the transaction context to mark the stake account as dirty after processing.
    - Processes the instruction based on its discriminant using a switch-case structure, handling various stake operations such as initialization, authorization, delegation, splitting, merging, and withdrawal.
- **Output**: Returns an integer status code indicating the success or failure of the operation, with specific error codes for various failure conditions.
- **Functions called**:
    - [`get_stake_account`](#get_stake_account)
    - [`initialize`](#initialize)
    - [`get_optional_pubkey`](#get_optional_pubkey)
    - [`authorize`](#authorize)
    - [`authorize_with_seed`](#authorize_with_seed)
    - [`delegate`](#delegate)
    - [`split`](#split)
    - [`merge`](#merge)
    - [`fd_new_warmup_cooldown_rate_epoch`](#fd_new_warmup_cooldown_rate_epoch)
    - [`withdraw`](#withdraw)
    - [`deactivate`](#deactivate)
    - [`set_lockup`](#set_lockup)
    - [`get_minimum_delegation`](#get_minimum_delegation)
    - [`deactivate_delinquent`](#deactivate_delinquent)
    - [`move_stake`](#move_stake)
    - [`move_lamports`](#move_lamports)


---
### write\_stake\_config<!-- {{#callable:write_stake_config}} -->
The `write_stake_config` function initializes a mutable transaction account for a stake configuration.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution context for the current slot, containing transaction-related information.
    - `stake_config`: A pointer to a constant `fd_stake_config_t` structure that holds the stake configuration data to be written.
- **Control Flow**:
    - Calculates the size of the stake configuration data using `fd_stake_config_size`.
    - Declares a transaction account variable `rec` and initializes it using `fd_txn_account_init_from_funk_mutable` with the account key and size.
    - Sets the lamports, rent epoch, and executable status of the transaction account using the virtual table methods.
    - Encodes the stake configuration data into the transaction account's data section using `fd_stake_config_encode`.
    - Sets the data of the transaction account to the encoded stake configuration.
    - Finalizes the mutable transaction account using `fd_txn_account_mutable_fini`.
- **Output**: The function does not return a value but modifies the state of the transaction account to include the new stake configuration.


---
### fd\_stake\_program\_config\_init<!-- {{#callable:fd_stake_program_config_init}} -->
Initializes the stake program configuration with default values.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution context for the current slot, which contains information about the transaction and its associated accounts.
- **Control Flow**:
    - Creates a `fd_stake_config_t` structure and initializes its fields with default values for `warmup_cooldown_rate` and `slash_penalty`.
    - Calls the [`write_stake_config`](#write_stake_config) function, passing the `slot_ctx` and a pointer to the initialized `stake_config` structure.
- **Output**: The function does not return a value; it writes the initialized stake configuration to the appropriate account in the context.
- **Functions called**:
    - [`write_stake_config`](#write_stake_config)


---
### fd\_stake\_get\_state<!-- {{#callable:fd_stake_get_state}} -->
The `fd_stake_get_state` function retrieves the current state of a stake account.
- **Inputs**:
    - `self`: A pointer to a constant `fd_txn_account_t` structure representing the stake account.
    - `out`: A pointer to a `fd_stake_state_v2_t` structure where the retrieved state will be stored.
- **Control Flow**:
    - The function calls [`get_state`](#get_state), passing the `self` and `out` parameters.
    - The [`get_state`](#get_state) function processes the account data and populates the `out` structure with the current state.
    - The return value of [`get_state`](#get_state) is returned as the output of `fd_stake_get_state`.
- **Output**: Returns an integer indicating the success or failure of the state retrieval operation.
- **Functions called**:
    - [`get_state`](#get_state)


---
### fd\_stake\_activating\_and\_deactivating<!-- {{#callable:fd_stake_activating_and_deactivating}} -->
The `fd_stake_activating_and_deactivating` function manages the activation and deactivation of stake delegations based on the target epoch.
- **Inputs**:
    - `self`: A pointer to a `fd_delegation_t` structure representing the stake delegation.
    - `target_epoch`: An unsigned long integer representing the epoch at which the stake activation or deactivation is targeted.
    - `stake_history`: A pointer to a `fd_stake_history_t` structure containing historical stake data.
    - `new_rate_activation_epoch`: A pointer to an unsigned long integer that will be updated with the new rate activation epoch.
- **Control Flow**:
    - The function calls [`stake_activating_and_deactivating`](#stake_activating_and_deactivating) with the provided parameters.
    - The result from [`stake_activating_and_deactivating`](#stake_activating_and_deactivating) is returned directly.
- **Output**: Returns a `fd_stake_history_entry_t` structure that contains the effective, deactivating, and activating stake values.
- **Functions called**:
    - [`stake_activating_and_deactivating`](#stake_activating_and_deactivating)


---
### fd\_stakes\_remove\_stake\_delegation<!-- {{#callable:fd_stakes_remove_stake_delegation}} -->
Removes a stake delegation from the epoch stakes and updates the associated vote account.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution context for the current slot, containing information about the current state of the slot.
    - `stake_account`: A pointer to the transaction account representing the stake account whose delegation is to be removed.
- **Control Flow**:
    - Copies the public key of the `stake_account` into a key structure for lookup.
    - Checks if the stake accounts pool exists; if not, logs a debug message and returns.
    - Attempts to find the entry corresponding to the `stake_account` in the stake accounts pool.
    - If the entry exists, it removes the entry from the stake accounts pool.
    - The function ends without returning any value.
- **Output**: The function does not return a value; it modifies the state of the stake accounts pool by removing the specified stake delegation if it exists.


---
### fd\_stakes\_upsert\_stake\_delegation<!-- {{#callable:fd_stakes_upsert_stake_delegation}} -->
The `fd_stakes_upsert_stake_delegation` function updates or inserts a stake delegation entry in the epoch's stakes based on the provided stake account.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution context for the current slot, containing information about the epoch and bank.
    - `stake_account`: A pointer to the transaction account representing the stake account to be updated.
- **Control Flow**:
    - The function first checks that the `stake_account` has a non-zero balance of lamports.
    - It retrieves the epoch bank from the execution context and accesses the stakes structure.
    - A key is created from the public key of the `stake_account` to look up existing stake delegations.
    - If the stake delegations pool is not initialized, a debug message is logged and the function returns.
    - The function checks if an entry for the stake account already exists in the stake delegations pool.
    - If no entry exists, it checks for the existence of the stake account in the account keys pool.
    - If the stake account is found, it marks it as existing; if not, it attempts to acquire a new node for the account keys pool.
    - The new node is initialized and inserted into the account keys pool.
- **Output**: The function does not return a value but updates the state of the stake delegations and account keys in the provided context.


---
### fd\_store\_stake\_delegation<!-- {{#callable:fd_store_stake_delegation}} -->
The `fd_store_stake_delegation` function manages the storage of stake delegation information based on the state of a stake account.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution context for the current slot, which contains information about the current transaction and its state.
    - `stake_account`: A pointer to the stake account whose delegation state is being stored.
- **Control Flow**:
    - Retrieve the owner of the `stake_account` using its virtual table method.
    - Check if the owner matches the expected Solana stake program ID; if not, exit the function.
    - Determine if the stake account is empty by checking its lamports balance.
    - Check if the stake account is uninitialized by examining its data length and prefix.
    - Acquire a write lock on the `vote_stake_lock` to ensure thread safety during updates.
    - If the stake account is empty or uninitialized, remove its delegation; otherwise, update the delegation information.
    - Release the write lock after the operation.
- **Output**: The function does not return a value; it modifies the state of the stake delegation in the context of the provided slot.
- **Functions called**:
    - [`fd_stakes_remove_stake_delegation`](#fd_stakes_remove_stake_delegation)
    - [`fd_stakes_upsert_stake_delegation`](#fd_stakes_upsert_stake_delegation)


