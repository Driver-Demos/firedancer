# Purpose
The provided C code is part of a larger software system designed to manage and execute transactions within a blockchain-like environment, specifically tailored for a system similar to Solana. This code is responsible for various runtime operations, including transaction processing, block verification, and epoch management. It is structured to handle both live and offline replay of transactions, ensuring consistency and correctness across different execution contexts.

Key components of the code include functions for initializing the runtime environment from a genesis block, processing transactions within microblocks, and managing epoch transitions. The code also includes mechanisms for verifying the integrity of blocks through proof-of-history (PoH) and handling feature activations and program migrations. Additionally, it provides utilities for managing account states, calculating rewards, and updating system variables.

The code is modular, with distinct sections for handling different aspects of the runtime, such as transaction execution, block preparation, and epoch boundary processing. It also includes support for parallel execution using thread pools, allowing for efficient processing of transactions in a high-throughput environment. Overall, this code is a critical part of a blockchain runtime system, ensuring the secure and efficient execution of transactions and management of the blockchain state.
# Imports and Dependencies

---
- `fd_runtime.h`
- `context/fd_capture_ctx.h`
- `context/fd_exec_epoch_ctx.h`
- `fd_acc_mgr.h`
- `fd_runtime_err.h`
- `fd_runtime_init.h`
- `fd_pubkey_utils.h`
- `fd_executor.h`
- `fd_cost_tracker.h`
- `fd_runtime_public.h`
- `fd_txncache.h`
- `sysvar/fd_sysvar_clock.h`
- `sysvar/fd_sysvar_epoch_schedule.h`
- `sysvar/fd_sysvar_recent_hashes.h`
- `sysvar/fd_sysvar_stake_history.h`
- `sysvar/fd_sysvar.h`
- `../../ballet/base58/fd_base58.h`
- `../../ballet/txn/fd_txn.h`
- `../../ballet/bmtree/fd_bmtree.h`
- `../stakes/fd_stakes.h`
- `../rewards/fd_rewards.h`
- `context/fd_exec_txn_ctx.h`
- `context/fd_exec_instr_ctx.h`
- `info/fd_microblock_batch_info.h`
- `info/fd_microblock_info.h`
- `program/fd_stake_program.h`
- `program/fd_builtin_programs.h`
- `program/fd_system_program.h`
- `program/fd_vote_program.h`
- `program/fd_bpf_program_util.h`
- `program/fd_bpf_loader_program.h`
- `program/fd_compute_budget_program.h`
- `program/fd_address_lookup_table_program.h`
- `sysvar/fd_sysvar_last_restart_slot.h`
- `sysvar/fd_sysvar_rent.h`
- `sysvar/fd_sysvar_slot_hashes.h`
- `sysvar/fd_sysvar_slot_history.h`
- `tests/fd_dump_pb.h`
- `../../ballet/nanopb/pb_decode.h`
- `../../ballet/nanopb/pb_encode.h`
- `../types/fd_solana_block.pb.h`
- `fd_system_ids.h`
- `../vm/fd_vm.h`
- `fd_blockstore.h`
- `../../disco/pack/fd_pack.h`
- `../fd_rwlock.h`
- `stdio.h`
- `ctype.h`
- `unistd.h`
- `sys/stat.h`
- `sys/types.h`
- `errno.h`
- `fcntl.h`


# Data Structures

---
### union\_ba\_t
- **Type**: `union`
- **Members**:
    - `my`: A member of type `my_ba_t` within the union.
    - `normal`: A member of type `pb_bytes_array_t` within the union.
- **Description**: The `union_ba_t` is a union data structure that can store either a `my_ba_t` or a `pb_bytes_array_t` type. This allows for flexible storage of different types of byte arrays within the same memory space, depending on the context in which the union is used. The union is used in an array `writable_ba` with a size determined by `writable_cnt`, allowing for multiple instances of this union to be managed together.


---
### fd\_poh\_verification\_info
- **Type**: ``struct``
- **Members**:
    - `microblock_info`: Pointer to a constant `fd_microblock_info_t` structure containing information about a microblock.
    - `in_poh_hash`: Pointer to a constant `fd_hash_t` structure representing the initial hash for the Proof of History (PoH) verification.
    - `success`: Integer indicating the success status of the PoH verification process.
- **Description**: The `fd_poh_verification_info` structure is used to store information necessary for verifying the Proof of History (PoH) of a microblock. It contains a pointer to the microblock information, the initial PoH hash, and a success flag indicating whether the verification was successful. This structure is typically used in the context of validating the integrity and order of transactions within a blockchain system.


---
### fd\_poh\_verification\_info\_t
- **Type**: `typedef struct`
- **Members**:
    - `microblock_info`: Pointer to the microblock information associated with the verification.
    - `in_poh_hash`: Pointer to the initial Proof of History (PoH) hash for verification.
    - `success`: Integer indicating the success status of the PoH verification.
- **Description**: The `fd_poh_verification_info_t` structure is used to store information necessary for verifying the Proof of History (PoH) of a microblock. It contains a pointer to the microblock information, a pointer to the initial PoH hash, and an integer to indicate the success status of the verification process. This structure is essential for ensuring the integrity and correctness of the PoH process in the blockchain.


# Functions

---
### fd\_runtime\_compute\_max\_tick\_height<!-- {{#callable:fd_runtime_compute_max_tick_height}} -->
Computes the maximum tick height for a given slot based on ticks per slot.
- **Inputs**:
    - `ticks_per_slot`: The number of ticks that occur in a single slot, represented as an unsigned long.
    - `slot`: The current slot number, represented as an unsigned long.
    - `out_max_tick_height`: A pointer to an unsigned long where the computed maximum tick height will be stored.
- **Control Flow**:
    - Initializes max_tick_height to 0.
    - Checks if ticks_per_slot is greater than 0.
    - Calculates the next slot by adding 1 to the current slot.
    - Checks for overflow when calculating next_slot.
    - Checks for overflow when calculating max_tick_height by multiplying next_slot with ticks_per_slot.
    - If no overflow occurs, computes max_tick_height as next_slot multiplied by ticks_per_slot.
    - Stores the computed max_tick_height in the provided output pointer.
- **Output**: Returns FD_RUNTIME_EXECUTE_SUCCESS if the computation is successful, or an error code if an overflow occurs.


---
### fd\_runtime\_register\_new\_fresh\_account<!-- {{#callable:fd_runtime_register_new_fresh_account}} -->
Registers a new fresh account in the runtime by inserting it into the appropriate partition.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context (`fd_exec_slot_ctx_t`) which contains the state of the current execution environment.
    - `pubkey`: A pointer to a constant public key (`fd_pubkey_t`) representing the public key of the new account to be registered.
- **Control Flow**:
    - Calculates the partition for the new account using the [`fd_rent_key_to_partition`](fd_rent_lists.h.driver.md#fd_rent_key_to_partition) function based on the provided public key and the parameters from `slot_ctx`.
    - Retrieves the list of fresh accounts from the `slot_ctx` structure.
    - Iterates through the list of fresh accounts to find an unused account (where `present` is 0).
    - If no unused account is found, logs an error indicating that the fresh accounts list is full.
    - If an unused account is found, updates its partition, public key, and marks it as present.
    - Increments the total count of fresh accounts in the `slot_ctx`.
- **Output**: The function does not return a value, but it modifies the state of the `slot_ctx` by adding a new fresh account to the list of accounts.
- **Functions called**:
    - [`fd_rent_key_to_partition`](fd_rent_lists.h.driver.md#fd_rent_key_to_partition)


---
### fd\_runtime\_repartition\_fresh\_account\_partitions<!-- {{#callable:fd_runtime_repartition_fresh_account_partitions}} -->
Updates the partition for each rent fresh account in the given execution slot context.
- **Inputs**:
    - `slot_ctx`: A pointer to the `fd_exec_slot_ctx_t` structure that contains the execution context for the current slot, including information about the slot bank and fresh accounts.
- **Control Flow**:
    - Retrieve the `rent_fresh_accounts` structure from the `slot_ctx`.
    - Iterate over each fresh account in `rent_fresh_accounts` using a for loop.
    - For each account, check if it is present (i.e., `present` field equals 1).
    - If present, calculate the new partition for the account using the [`fd_rent_key_to_partition`](fd_rent_lists.h.driver.md#fd_rent_key_to_partition) function, passing the account's public key and parameters from `slot_ctx`.
    - Update the `partition` field of the fresh account with the newly calculated partition.
- **Output**: The function does not return a value; it modifies the partition field of each fresh account directly.
- **Functions called**:
    - [`fd_rent_key_to_partition`](fd_rent_lists.h.driver.md#fd_rent_key_to_partition)


---
### fd\_runtime\_update\_slots\_per\_epoch<!-- {{#callable:fd_runtime_update_slots_per_epoch}} -->
Updates the number of slots per epoch in the execution context.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution context structure (`fd_exec_slot_ctx_t`) that holds the current state of the execution environment.
    - `slots_per_epoch`: An unsigned long integer representing the new number of slots per epoch to be set in the execution context.
- **Control Flow**:
    - The function first checks if the new `slots_per_epoch` is the same as the current value in `slot_ctx->slots_per_epoch` using `FD_LIKELY`. If they are equal, the function returns early without making any changes.
    - If the values are different, it updates `slot_ctx->slots_per_epoch` with the new value.
    - Next, it calculates the partition width based on the new `slots_per_epoch` by calling the function [`fd_rent_partition_width`](fd_rent_lists.h.driver.md#fd_rent_partition_width) and updates `slot_ctx->part_width`.
    - Finally, it calls [`fd_runtime_repartition_fresh_account_partitions`](#fd_runtime_repartition_fresh_account_partitions) to repartition the fresh account partitions based on the updated slots per epoch.
- **Output**: The function does not return a value; it modifies the state of the `slot_ctx` directly.
- **Functions called**:
    - [`fd_rent_partition_width`](fd_rent_lists.h.driver.md#fd_rent_partition_width)
    - [`fd_runtime_repartition_fresh_account_partitions`](#fd_runtime_repartition_fresh_account_partitions)


---
### fd\_runtime\_update\_leaders<!-- {{#callable:fd_runtime_update_leaders}} -->
Updates the leader schedule for the current execution slot based on the epoch's stakes and schedule.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution context for the current slot, containing information about the epoch and stakes.
    - `slot`: The current slot number for which the leader schedule is being updated.
    - `runtime_spad`: A pointer to the scratchpad memory used for temporary allocations during the function execution.
- **Control Flow**:
    - Begin a scratchpad frame for temporary allocations.
    - Retrieve the epoch schedule from the `slot_ctx`.
    - Log various parameters of the epoch schedule for debugging purposes.
    - Determine the current epoch and the starting slot of that epoch.
    - Update the number of slots per epoch in the `slot_ctx`.
    - Allocate memory for the stake weights based on the number of vote accounts.
    - Calculate the stake weights for the current epoch's vote accounts.
    - Check for errors in the stake weight calculation and log if necessary.
    - Calculate the footprint for the leader schedule based on stake weights and slot count.
    - If the footprint is valid, proceed to derive the leader schedule.
    - Log the stake weight count and slot count for debugging.
    - Check for maximum limits on stake weight count and slot count, logging errors if exceeded.
    - Allocate memory for the epoch leaders and initialize them based on the calculated values.
    - Join the new leaders into the epoch context and log any errors during initialization.
- **Output**: The function does not return a value but updates the leader schedule in the execution context based on the current epoch's stakes.
- **Functions called**:
    - [`fd_slot_to_epoch`](sysvar/fd_sysvar_epoch_schedule.c.driver.md#fd_slot_to_epoch)
    - [`fd_epoch_slot0`](sysvar/fd_sysvar_epoch_schedule.c.driver.md#fd_epoch_slot0)
    - [`fd_epoch_slot_cnt`](sysvar/fd_sysvar_epoch_schedule.c.driver.md#fd_epoch_slot_cnt)
    - [`fd_runtime_update_slots_per_epoch`](#fd_runtime_update_slots_per_epoch)


---
### FD\_SPAD\_FRAME\_BEGIN<!-- {{#callable:fd_runtime_block_eval_tpool::FD_SPAD_FRAME_BEGIN}} -->
The `FD_SPAD_FRAME_BEGIN` function initializes a frame for executing a series of operations related to the SPAD (Scratchpad) memory.
- **Inputs**:
    - `runtime_spad`: A pointer to the SPAD memory used for temporary storage during the execution of the block.
- **Control Flow**:
    - The function begins by preparing a block for execution using [`fd_runtime_block_prepare`](#fd_runtime_block_prepare), checking for success.
    - It retrieves the transaction count from the prepared block information.
    - It verifies the block using [`fd_runtime_block_verify_tpool`](#fd_runtime_block_verify_tpool), checking for successful verification.
    - If a dump is required, it calls [`fd_dump_block_to_protobuf_tx_only`](tests/fd_dump_pb.c.driver.md#fd_dump_block_to_protobuf_tx_only) to serialize the block information.
    - Finally, it executes the block transactions using [`fd_runtime_block_execute_tpool`](#fd_runtime_block_execute_tpool), checking for execution success.
- **Output**: The function does not return a value but modifies the state of the slot context and may log errors or warnings based on the success of the operations performed.
- **Functions called**:
    - [`fd_runtime_block_prepare`](#fd_runtime_block_prepare)
    - [`fd_runtime_block_verify_tpool`](#fd_runtime_block_verify_tpool)
    - [`fd_dump_block_to_protobuf_tx_only`](tests/fd_dump_pb.c.driver.md#fd_dump_block_to_protobuf_tx_only)
    - [`fd_runtime_block_execute_tpool`](#fd_runtime_block_execute_tpool)


---
### fd\_runtime\_validate\_fee\_collector<!-- {{#callable:fd_runtime_validate_fee_collector}} -->
Validates the fee collector account and the fee amount for a transaction.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context containing the current state of the execution environment.
    - `collector`: A pointer to the transaction account representing the fee collector.
    - `fee`: The fee amount to be validated, represented as an unsigned long integer.
- **Control Flow**:
    - Checks if the fee is less than or equal to zero and logs an error if true.
    - Compares the owner of the collector account with the system program ID and logs a warning if they do not match.
    - Calculates the minimum balance required for the collector account to be rent-exempt.
    - Checks if the collector's balance plus the fee is less than the minimum balance and logs a warning if true.
- **Output**: Returns 0 if validation succeeds; otherwise, returns the fee amount.
- **Functions called**:
    - [`fd_rent_exempt_minimum_balance`](sysvar/fd_sysvar_rent1.c.driver.md#fd_rent_exempt_minimum_balance)


---
### fd\_runtime\_run\_incinerator<!-- {{#callable:fd_runtime_run_incinerator}} -->
The `fd_runtime_run_incinerator` function processes a transaction account for the incinerator, updating the slot bank's capitalization and resetting the account's lamports.
- **Inputs**:
    - `slot_ctx`: A pointer to the `fd_exec_slot_ctx_t` structure that contains the execution context for the current slot, including the slot bank and transaction information.
- **Control Flow**:
    - The function begins by declaring a transaction account record `rec` using `FD_TXN_ACCOUNT_DECL`.
    - It initializes the transaction account from the incinerator's system variable using [`fd_txn_account_init_from_funk_mutable`](fd_txn_account.c.driver.md#fd_txn_account_init_from_funk_mutable).
    - If the initialization fails (indicated by an error code not equal to `FD_ACC_MGR_SUCCESS`), the function returns -1.
    - The function then updates the capitalization of the slot bank by subtracting the lamports of the transaction account.
    - The lamports of the transaction account are then set to zero using `set_lamports`.
    - Finally, the function finalizes the mutable transaction account with [`fd_txn_account_mutable_fini`](fd_txn_account.c.driver.md#fd_txn_account_mutable_fini) and returns 0.
- **Output**: The function returns 0 on success, indicating that the incinerator transaction has been processed successfully, or -1 if there was an error during initialization.
- **Functions called**:
    - [`fd_txn_account_init_from_funk_mutable`](fd_txn_account.c.driver.md#fd_txn_account_init_from_funk_mutable)
    - [`fd_txn_account_mutable_fini`](fd_txn_account.c.driver.md#fd_txn_account_mutable_fini)


---
### fd\_runtime\_slot\_count\_in\_two\_day<!-- {{#callable:fd_runtime_slot_count_in_two_day}} -->
The `fd_runtime_slot_count_in_two_day` function calculates the number of slots in a two-day period based on the provided ticks per slot.
- **Inputs**:
    - `ticks_per_slot`: The number of ticks that occur in a single slot, which is used to determine how many slots fit into a two-day period.
- **Control Flow**:
    - The function begins by multiplying the constant value for the number of seconds in two days (2 days * 86400 seconds/day) by the default ticks per second.
    - It then divides the result by the `ticks_per_slot` input to calculate the total number of slots in two days.
- **Output**: The function returns an unsigned long integer representing the total number of slots that can fit into a two-day period based on the provided `ticks_per_slot`.


---
### fd\_runtime\_use\_multi\_epoch\_collection<!-- {{#callable:fd_runtime_use_multi_epoch_collection}} -->
Determines if multi-epoch collection should be used based on the current epoch and slot conditions.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context structure, which contains information about the current execution environment.
    - `slot`: The current slot number being processed.
- **Control Flow**:
    - Retrieve the epoch bank from the execution context.
    - Obtain the epoch schedule from the epoch bank.
    - Convert the current slot to its corresponding epoch and calculate the offset.
    - Determine the number of slots in a normal epoch.
    - Calculate the total number of slots in a two-day period based on the ticks per slot.
    - Evaluate whether to use multi-epoch collection based on the current epoch and the comparison of slots.
- **Output**: Returns an integer indicating whether multi-epoch collection should be used (1 for true, 0 for false).
- **Functions called**:
    - [`fd_slot_to_epoch`](sysvar/fd_sysvar_epoch_schedule.c.driver.md#fd_slot_to_epoch)
    - [`fd_epoch_slot_cnt`](sysvar/fd_sysvar_epoch_schedule.c.driver.md#fd_epoch_slot_cnt)
    - [`fd_runtime_slot_count_in_two_day`](#fd_runtime_slot_count_in_two_day)


---
### fd\_runtime\_num\_rent\_partitions<!-- {{#callable:fd_runtime_num_rent_partitions}} -->
Calculates the number of rent partitions based on the current execution slot context and slot number.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context structure, which contains information about the current execution environment.
    - `slot`: An unsigned long integer representing the current slot number in the execution context.
- **Control Flow**:
    - Retrieve the epoch bank from the execution context.
    - Obtain the epoch schedule from the epoch bank.
    - Convert the given slot number to the corresponding epoch and calculate the offset.
    - Determine the number of slots per epoch from the epoch schedule.
    - Calculate the total number of slots that can fit in a two-day period based on the ticks per slot.
    - Check if multi-epoch collection should be used based on the current slot context and slot.
    - If multi-epoch collection is enabled, calculate the number of epochs in the two-day cycle and return the product of slots per epoch and epochs in cycle.
    - If multi-epoch collection is not enabled, return the number of slots per epoch.
- **Output**: Returns an unsigned long integer representing the number of rent partitions calculated based on the current slot context and slot number.
- **Functions called**:
    - [`fd_slot_to_epoch`](sysvar/fd_sysvar_epoch_schedule.c.driver.md#fd_slot_to_epoch)
    - [`fd_epoch_slot_cnt`](sysvar/fd_sysvar_epoch_schedule.c.driver.md#fd_epoch_slot_cnt)
    - [`fd_runtime_slot_count_in_two_day`](#fd_runtime_slot_count_in_two_day)
    - [`fd_runtime_use_multi_epoch_collection`](#fd_runtime_use_multi_epoch_collection)


---
### fd\_runtime\_get\_rent\_partition<!-- {{#callable:fd_runtime_get_rent_partition}} -->
The `fd_runtime_get_rent_partition` function calculates the rent partition for a given execution slot based on the epoch schedule.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context structure, which contains information about the current execution environment.
    - `slot`: An unsigned long integer representing the specific execution slot for which the rent partition is to be calculated.
- **Control Flow**:
    - The function first checks if multi-epoch collection is to be used by calling [`fd_runtime_use_multi_epoch_collection`](#fd_runtime_use_multi_epoch_collection).
    - It retrieves the epoch bank and the epoch schedule from the execution context.
    - The function then converts the given slot into its corresponding epoch and calculates the offset within that epoch.
    - It determines the number of slots per epoch and the total number of slots in a two-day period.
    - Based on whether multi-epoch collection is used, it sets the base epoch and calculates the epoch index in the cycle.
    - Finally, it returns the calculated rent partition offset.
- **Output**: The function returns an unsigned long integer representing the calculated rent partition offset for the specified slot.
- **Functions called**:
    - [`fd_runtime_use_multi_epoch_collection`](#fd_runtime_use_multi_epoch_collection)
    - [`fd_slot_to_epoch`](sysvar/fd_sysvar_epoch_schedule.c.driver.md#fd_slot_to_epoch)
    - [`fd_epoch_slot_cnt`](sysvar/fd_sysvar_epoch_schedule.c.driver.md#fd_epoch_slot_cnt)
    - [`fd_runtime_slot_count_in_two_day`](#fd_runtime_slot_count_in_two_day)


---
### fd\_runtime\_update\_rent\_epoch\_account<!-- {{#callable:fd_runtime_update_rent_epoch_account}} -->
Updates the rent epoch of a specified account if necessary.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context, which contains information about the current execution environment.
    - `pubkey`: A pointer to the public key of the account whose rent epoch is to be updated.
- **Control Flow**:
    - Initializes a transaction account record from a read-only state using the provided public key.
    - If the account does not exist, the function returns early.
    - If the account exists but an error occurs during initialization, a warning is logged and the function returns.
    - Checks if the account's current rent epoch is already set to the exempt value; if so, the function returns without making changes.
    - If the rent epoch needs to be updated, the function initializes the account in a mutable state.
    - If an error occurs during mutable initialization, a warning is logged and the function returns.
    - Sets the rent epoch of the account to the exempt value.
    - Finalizes the mutable transaction account.
- **Output**: The function does not return a value; it modifies the rent epoch of the specified account directly.
- **Functions called**:
    - [`fd_txn_account_init_from_funk_readonly`](fd_txn_account.c.driver.md#fd_txn_account_init_from_funk_readonly)
    - [`fd_txn_account_init_from_funk_mutable`](fd_txn_account.c.driver.md#fd_txn_account_init_from_funk_mutable)
    - [`fd_txn_account_mutable_fini`](fd_txn_account.c.driver.md#fd_txn_account_mutable_fini)


---
### fd\_runtime\_update\_rent\_epoch<!-- {{#callable:fd_runtime_update_rent_epoch}} -->
Updates the rent epoch for fresh accounts in the specified execution slot context.
- **Inputs**:
    - `slot_ctx`: A pointer to the `fd_exec_slot_ctx_t` structure that contains the execution context for the current slot, including information about the slot bank and epoch context.
- **Control Flow**:
    - Checks if the feature 'disable_partitioned_rent_collection' is active; if so, the function returns early without making any updates.
    - Retrieves the list of fresh rent accounts from the slot context.
    - If there are no fresh accounts, the function returns early.
    - Calculates the range of slots to iterate over, from the previous slot to the current slot.
    - For each slot in the range, retrieves the corresponding rent partition.
    - Iterates over each fresh rent account and checks if it is present and belongs to the current slot's partition.
    - If both conditions are met, updates the rent epoch for the account and marks it as no longer present.
- **Output**: The function does not return a value; it modifies the state of fresh rent accounts within the provided execution context.
- **Functions called**:
    - [`fd_runtime_get_rent_partition`](#fd_runtime_get_rent_partition)
    - [`fd_runtime_update_rent_epoch_account`](#fd_runtime_update_rent_epoch_account)


---
### fd\_runtime\_freeze<!-- {{#callable:fd_runtime_freeze}} -->
The `fd_runtime_freeze` function finalizes the state of the runtime by updating rent epochs, collecting fees, and managing the capitalization of the slot bank.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context (`fd_exec_slot_ctx_t`) that contains the current state of the slot being processed.
    - `runtime_spad`: A pointer to the scratchpad (`fd_spad_t`) used for temporary storage during the execution of the function.
- **Control Flow**:
    - Calls [`fd_runtime_update_rent_epoch`](#fd_runtime_update_rent_epoch) to update the rent epoch for accounts in the current slot context.
    - Calls [`fd_sysvar_recent_hashes_update`](sysvar/fd_sysvar_recent_hashes.c.driver.md#fd_sysvar_recent_hashes_update) to update the recent hashes in the system variable.
    - Calculates the fees to be collected based on the current execution and priority fees, and determines the amount to be burned.
    - If fees are present, initializes a transaction account for the leader and attempts to collect the fees.
    - Validates the fee collector account if the corresponding feature is active.
    - Updates the capitalization of the slot bank by subtracting the burned amount from the current capitalization.
    - Calls [`fd_runtime_run_incinerator`](#fd_runtime_run_incinerator) to handle the incineration of accounts as necessary.
    - Resets the collected fees and rent in the slot bank.
- **Output**: The function does not return a value but modifies the state of the `slot_ctx` and updates the slot bank's capitalization and collected fees.
- **Functions called**:
    - [`fd_runtime_update_rent_epoch`](#fd_runtime_update_rent_epoch)
    - [`fd_sysvar_recent_hashes_update`](sysvar/fd_sysvar_recent_hashes.c.driver.md#fd_sysvar_recent_hashes_update)
    - [`fd_txn_account_init_from_funk_mutable`](fd_txn_account.c.driver.md#fd_txn_account_init_from_funk_mutable)
    - [`fd_runtime_validate_fee_collector`](#fd_runtime_validate_fee_collector)
    - [`fd_txn_account_mutable_fini`](fd_txn_account.c.driver.md#fd_txn_account_mutable_fini)
    - [`fd_runtime_run_incinerator`](#fd_runtime_run_incinerator)


---
### fd\_runtime\_get\_rent\_due<!-- {{#callable:fd_runtime_get_rent_due}} -->
Calculates the rent due for a given account based on the epoch schedule and rent parameters.
- **Inputs**:
    - `schedule`: A pointer to a `fd_epoch_schedule_t` structure that contains the epoch schedule information.
    - `rent`: A pointer to a `fd_rent_t` structure that contains rent parameters such as lamports per year.
    - `slots_per_year`: A double representing the number of slots in a year.
    - `acc`: A pointer to a `fd_txn_account_t` structure representing the account for which rent is being calculated.
    - `epoch`: An unsigned long representing the current epoch.
- **Control Flow**:
    - First, the function checks if the account is rent-exempt by comparing its balance to the minimum balance required for rent exemption.
    - If the account is rent-exempt, it returns a constant value indicating this status.
    - Next, it calculates the number of slots that have elapsed since the last rent collection based on the account's rent epoch and the current epoch.
    - The function then computes the number of years that have elapsed based on the slots elapsed and the provided slots per year.
    - Finally, it calculates the total rent due by multiplying the years elapsed by the lamports per year, adjusted for the account's data length, and returns this value.
- **Output**: Returns the amount of rent due as a long integer, or a constant indicating that the account is rent-exempt.
- **Functions called**:
    - [`fd_rent_exempt_minimum_balance`](sysvar/fd_sysvar_rent1.c.driver.md#fd_rent_exempt_minimum_balance)
    - [`fd_epoch_slot_cnt`](sysvar/fd_sysvar_epoch_schedule.c.driver.md#fd_epoch_slot_cnt)


---
### fd\_runtime\_collect\_from\_existing\_account<!-- {{#callable:fd_runtime_collect_from_existing_account}} -->
The `fd_runtime_collect_from_existing_account` function collects rent from an existing account based on its current state and updates the account's rent epoch.
- **Inputs**:
    - `slot`: The current slot number in the blockchain.
    - `schedule`: A pointer to the epoch schedule structure that defines the timing of epochs.
    - `rent`: A pointer to the rent structure that contains rent-related parameters.
    - `slots_per_year`: A double representing the number of slots in a year, used for rent calculations.
    - `acc`: A pointer to the transaction account structure representing the account from which rent is to be collected.
    - `epoch`: The current epoch number.
- **Control Flow**:
    - The function begins by initializing a variable to track the amount of rent collected.
    - It sets the current slot for the account regardless of whether rent will be collected.
    - It checks if the account is exempt from rent collection based on its rent epoch.
    - If the account is not exempt, it checks if it should collect rent based on its executable status and public key.
    - The function calculates the rent due using the [`fd_runtime_get_rent_due`](#fd_runtime_get_rent_due) function.
    - Based on the calculated rent due, it determines whether to exempt the account, collect rent, or do nothing.
    - If collecting rent, it either deducts the rent due from the account or reclaims the account if the rent due exceeds its balance.
- **Output**: The function returns the total amount of rent collected from the account.
- **Functions called**:
    - [`fd_runtime_get_rent_due`](#fd_runtime_get_rent_due)


---
### fd\_runtime\_collect\_rent\_from\_account<!-- {{#callable:fd_runtime_collect_rent_from_account}} -->
The `fd_runtime_collect_rent_from_account` function manages the collection of rent fees from a specified account based on the current slot, epoch schedule, and rent parameters.
- **Inputs**:
    - `slot`: The current slot number in the blockchain.
    - `schedule`: A pointer to the epoch schedule structure that defines the timing of epochs.
    - `rent`: A pointer to the rent structure that contains rent-related parameters.
    - `slots_per_year`: A double representing the number of slots in a year, used for rent calculations.
    - `features`: A pointer to a structure that holds feature flags for the current execution context.
    - `acc`: A pointer to the transaction account from which rent is to be collected.
    - `epoch`: The current epoch number.
- **Control Flow**:
    - The function first checks if the rent fee collection feature is active for the current slot using the `FD_FEATURE_ACTIVE` macro.
    - If the feature is active, it calls the [`fd_runtime_collect_from_existing_account`](#fd_runtime_collect_from_existing_account) function to perform the rent collection.
    - If the feature is not active, it checks if the account's rent epoch is not exempt and if the rent due is exempt.
    - If the account is not exempt and the rent due is exempt, it sets the account's rent epoch to exempt.
- **Output**: The function returns the amount of rent collected from the account, or 0 if no rent was collected.
- **Functions called**:
    - [`fd_runtime_collect_from_existing_account`](#fd_runtime_collect_from_existing_account)
    - [`fd_runtime_get_rent_due`](#fd_runtime_get_rent_due)


---
### fd\_runtime\_write\_transaction\_status<!-- {{#callable:fd_runtime_write_transaction_status}} -->
The `fd_runtime_write_transaction_status` function writes the status of a transaction to a capture context after retrieving its details from a blockstore.
- **Inputs**:
    - `capture_ctx`: A pointer to the `fd_capture_ctx_t` structure that holds the context for capturing transaction status.
    - `slot_ctx`: A pointer to the `fd_exec_slot_ctx_t` structure that contains the execution context for the current slot.
    - `txn_ctx`: A pointer to the `fd_exec_txn_ctx_t` structure that contains the context for the transaction being processed.
    - `exec_txn_err`: An integer representing any error that occurred during the execution of the transaction.
- **Control Flow**:
    - The function begins by acquiring a write lock on the transaction status to ensure thread safety.
    - It retrieves the blockstore from the `slot_ctx` and extracts the transaction signature from the `txn_ctx`.
    - The function queries the blockstore for the transaction map entry using the signature.
    - If a valid transaction map entry is found, it retrieves the associated metadata and decodes the transaction status.
    - The function then constructs a `fd_solcap_Transaction` structure with the relevant transaction details, including error codes and compute units used.
    - If there are any failed instructions, it records their indices and paths.
    - Finally, it writes the constructed transaction status to the capture context and releases the write lock.
- **Output**: The function does not return a value but writes the transaction status to the capture context, allowing for later retrieval of transaction execution details.
- **Functions called**:
    - [`fd_capture_ctx_txn_status_start_write`](context/fd_capture_ctx.c.driver.md#fd_capture_ctx_txn_status_start_write)
    - [`fd_blockstore_txn_query`](fd_blockstore.c.driver.md#fd_blockstore_txn_query)
    - [`fd_blockstore_wksp`](fd_blockstore.h.driver.md#fd_blockstore_wksp)
    - [`fd_capture_ctx_txn_status_end_write`](context/fd_capture_ctx.c.driver.md#fd_capture_ctx_txn_status_end_write)


---
### encode\_return\_data<!-- {{#callable:encode_return_data}} -->
Encodes return data from a transaction context into a protobuf stream.
- **Inputs**:
    - `stream`: A pointer to the protobuf output stream where the encoded data will be written.
    - `field`: A pointer to the protobuf field descriptor that specifies how to encode the data.
    - `arg`: A pointer to a pointer that holds the transaction context containing the return data.
- **Control Flow**:
    - The function casts the input argument `arg` to a pointer of type `fd_exec_txn_ctx_t` to access the transaction context.
    - It calls `pb_encode_tag_for_field` to write the appropriate tag for the given field into the stream.
    - Next, it calls `pb_encode_string` to encode the return data from the transaction context into the stream.
    - Finally, it returns true (1) indicating successful encoding.
- **Output**: Returns a boolean value indicating the success of the encoding operation.


---
### fd\_txn\_copy\_meta<!-- {{#callable:fd_txn_copy_meta}} -->
The `fd_txn_copy_meta` function copies transaction metadata from a transaction context to a specified destination buffer.
- **Inputs**:
    - `txn_ctx`: A pointer to the transaction execution context (`fd_exec_txn_ctx_t`) containing details about the transaction being processed.
    - `dest`: A pointer to a destination buffer where the transaction metadata will be copied.
    - `dest_sz`: The size of the destination buffer in bytes.
- **Control Flow**:
    - The function initializes a `fd_solblock_TransactionStatusMeta` structure to hold transaction status metadata.
    - It populates the transaction fee and compute units consumed from the `txn_ctx`.
    - If the transaction version is `FD_TXN_V0`, it retrieves address lookup tables and counts the number of readonly and writable accounts.
    - It allocates memory for writable and readonly addresses and populates them from the `txn_ctx` account keys.
    - The function then sets the pre and post balances for each account in the transaction context.
    - If there is return data, it encodes it into the transaction status metadata.
    - The function checks for custom errors and populates the error information if present.
    - If the destination buffer is NULL, it calculates the size of the encoded metadata and returns it.
    - If the destination buffer is provided, it encodes the transaction status metadata into the buffer and returns the number of bytes written.
- **Output**: The function returns the number of bytes written to the destination buffer if successful, or the size of the metadata if the destination is NULL. If an error occurs during encoding, it returns 0.


---
### fd\_runtime\_finalize\_txns\_update\_blockstore\_meta<!-- {{#callable:fd_runtime_finalize_txns_update_blockstore_meta}} -->
The `fd_runtime_finalize_txns_update_blockstore_meta` function updates transaction metadata in the blockstore after execution, provided that execution recording is enabled.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context structure (`fd_exec_slot_ctx_t`) that contains information about the current execution environment, including the blockstore.
    - `task_info`: An array of `fd_execute_txn_task_info_t` structures that hold information about the transactions being executed, including their contexts.
    - `txn_cnt`: An unsigned long integer representing the number of transactions that have been executed and whose metadata needs to be updated.
- **Control Flow**:
    - The function first checks if execution recording is enabled by evaluating `slot_ctx->enable_exec_recording`. If it is not enabled, the function returns immediately.
    - It retrieves the blockstore, workspace, allocator, and transaction map from the `slot_ctx`.
    - The total size for the transaction metadata is initialized, and a loop iterates over each transaction to calculate the total size of the metadata.
    - For each transaction, it adjusts the starting lamports for the first account and calculates the size of the transaction metadata using [`fd_txn_copy_meta`](#fd_txn_copy_meta).
    - Memory is allocated for the metadata, and if allocation fails, the function returns.
    - The function links the new metadata to the previous allocation and updates the global address and size in the `slot_ctx`.
    - Another loop iterates over each transaction again to copy the metadata into the allocated memory and update the transaction map with the new metadata addresses.
    - Finally, the function deletes the log collector for each transaction context.
- **Output**: The function does not return a value but updates the global state of the transaction metadata in the blockstore, allowing for retrieval of transaction execution results and logs.
- **Functions called**:
    - [`fd_blockstore_wksp`](fd_blockstore.h.driver.md#fd_blockstore_wksp)
    - [`fd_blockstore_alloc`](fd_blockstore.h.driver.md#fd_blockstore_alloc)
    - [`fd_txn_copy_meta`](#fd_txn_copy_meta)


---
### fd\_runtime\_new\_fee\_rate\_governor\_derived<!-- {{#callable:fd_runtime_new_fee_rate_governor_derived}} -->
This function derives a new fee rate governor based on the current execution context and the latest signatures per slot.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context structure, which contains information about the current execution environment.
    - `base_fee_rate_governor`: A structure representing the base fee rate governor, which includes parameters like target signatures and lamports per signature.
    - `latest_singatures_per_slot`: An unsigned long integer representing the latest number of signatures processed per slot.
- **Control Flow**:
    - The function initializes a result structure with values from the base fee rate governor.
    - If the target signatures per slot is greater than zero, it calculates minimum and maximum lamports per signature based on the base governor.
    - It computes the desired lamports per signature based on the latest signatures and adjusts the current lamports per signature accordingly.
    - If the current lamports per signature is zero, it updates the previous lamports per signature.
    - Finally, it sets the current lamports per signature in the slot context and returns the result structure.
- **Output**: The function returns a `fd_fee_rate_governor_t` structure that contains the updated fee rate governor parameters.


---
### fd\_runtime\_block\_sysvar\_update\_pre\_execute<!-- {{#callable:fd_runtime_block_sysvar_update_pre_execute}} -->
The `fd_runtime_block_sysvar_update_pre_execute` function updates system variables and initializes the fee rate governor before executing a block.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context (`fd_exec_slot_ctx_t`) which contains the current state and information for the execution slot.
    - `runtime_spad`: A pointer to the scratchpad (`fd_spad_t`) used for temporary storage during execution.
- **Control Flow**:
    - The function begins by initializing the fee rate governor using the [`fd_runtime_new_fee_rate_governor_derived`](#fd_runtime_new_fee_rate_governor_derived) function, which derives a new fee rate governor based on the current slot context and updates the slot context with this new governor.
    - Next, it logs the time taken to update the clock by calling [`fd_sysvar_clock_update`](sysvar/fd_sysvar_clock.c.driver.md#fd_sysvar_clock_update), measuring the elapsed time using `fd_log_wallclock`.
    - If the current slot is not zero, it updates the slot hashes by calling [`fd_sysvar_slot_hashes_update`](sysvar/fd_sysvar_slot_hashes.c.driver.md#fd_sysvar_slot_hashes_update).
    - Finally, it updates the last restart slot by calling [`fd_sysvar_last_restart_slot_update`](sysvar/fd_sysvar_last_restart_slot.c.driver.md#fd_sysvar_last_restart_slot_update).
- **Output**: The function returns an integer value of 0, indicating successful execution.
- **Functions called**:
    - [`fd_runtime_new_fee_rate_governor_derived`](#fd_runtime_new_fee_rate_governor_derived)
    - [`fd_sysvar_clock_update`](sysvar/fd_sysvar_clock.c.driver.md#fd_sysvar_clock_update)
    - [`fd_sysvar_slot_hashes_update`](sysvar/fd_sysvar_slot_hashes.c.driver.md#fd_sysvar_slot_hashes_update)
    - [`fd_sysvar_last_restart_slot_update`](sysvar/fd_sysvar_last_restart_slot.c.driver.md#fd_sysvar_last_restart_slot_update)


---
### fd\_runtime\_microblock\_verify\_ticks<!-- {{#callable:fd_runtime_microblock_verify_ticks}} -->
Verifies the integrity of microblock ticks in a given execution slot context.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context (`fd_exec_slot_ctx_t`) which contains the state and data for the current execution slot.
    - `slot`: An unsigned long integer representing the current slot number being processed.
    - `hdr`: A pointer to the microblock header (`fd_microblock_hdr_t`) which contains metadata about the microblock.
    - `slot_complete`: A boolean indicating whether the current slot has been completed.
    - `tick_height`: An unsigned long integer representing the current height of ticks processed.
    - `max_tick_height`: An unsigned long integer representing the maximum allowable height of ticks.
    - `hashes_per_tick`: An unsigned long integer indicating the expected number of hashes per tick.
- **Control Flow**:
    - Initializes variables to track invalid tick hash counts and trailing entries.
    - Prepares a block map query for the current slot and checks for errors.
    - Accumulates the tick hash count from the microblock header.
    - If the transaction count in the header is zero, increments the ticks consumed and checks if the accumulated hash count matches the expected hashes per tick.
    - If the slot is complete, checks for trailing entries in the microblock.
    - Calculates the next tick height and publishes the block map query.
    - Checks if the next tick height exceeds the maximum allowed and returns an error if so.
    - Checks if the slot is complete and if the next tick height is less than the maximum allowed, returning an error if so.
    - Checks for trailing entries if the slot is complete and returns an error if found.
    - Validates the tick hash count against the expected count and returns an error if invalid.
    - Returns a success status if all checks pass.
- **Output**: Returns an integer status code indicating the result of the verification process, with FD_BLOCK_OK indicating success.


---
### fd\_runtime\_block\_verify\_ticks<!-- {{#callable:fd_runtime_block_verify_ticks}} -->
Verifies the integrity of a block in a blockchain by checking tick counts and hash alignments.
- **Inputs**:
    - `blockstore`: A pointer to the `fd_blockstore_t` structure that contains the block data.
    - `slot`: The slot number of the block being verified.
    - `block_data`: A pointer to the raw block data that needs to be verified.
    - `block_data_sz`: The size of the block data in bytes.
    - `tick_height`: The current height of ticks in the blockchain.
    - `max_tick_height`: The maximum allowable height of ticks.
    - `hashes_per_tick`: The expected number of hashes per tick.
- **Control Flow**:
    - Initializes variables to track tick counts, hash counts, and trailing entries.
    - Queries the block map to retrieve complete index and data complete indices for the specified slot.
    - Iterates through batches of microblocks, counting ticks and validating hash counts against expected values.
    - Checks if the last entry in the batch is a tick and whether the tick height is within the specified limits.
    - Logs warnings and returns error codes for various validation failures, such as too many or too few ticks, or invalid hash counts.
- **Output**: Returns FD_BLOCK_OK if the block verification is successful, or an error code indicating the type of failure.
- **Functions called**:
    - [`fd_blockstore_slice_query`](fd_blockstore.c.driver.md#fd_blockstore_slice_query)


---
### fd\_runtime\_load\_txn\_address\_lookup\_tables<!-- {{#callable:fd_runtime_load_txn_address_lookup_tables}} -->
The `fd_runtime_load_txn_address_lookup_tables` function loads transaction address lookup tables from a transaction payload.
- **Inputs**:
    - `txn`: A pointer to a constant `fd_txn_t` structure representing the transaction containing address lookup tables.
    - `payload`: A pointer to a constant `uchar` array representing the payload data of the transaction.
    - `funk`: A pointer to a `fd_funk_t` structure used for account management.
    - `funk_txn`: A pointer to a `fd_funk_txn_t` structure representing the current transaction context.
    - `slot`: An unsigned long integer representing the current slot in the blockchain.
    - `hashes`: A pointer to a `fd_slot_hash_t` structure containing hash information for the current slot.
    - `out_accts_alt`: A pointer to an array of `fd_acct_addr_t` structures where the loaded account addresses will be stored.
- **Control Flow**:
    - The function first checks if the transaction version is not `FD_TXN_V0`, returning success if true.
    - It initializes counters for readonly and writable accounts and retrieves address lookup tables from the transaction.
    - For each address lookup table, it retrieves the corresponding account address from the payload.
    - It attempts to initialize the account record from the funk in a readonly manner, returning an error if unsuccessful.
    - It checks if the owner of the account matches the expected program ID, returning an error if it does not.
    - It verifies the data length of the account record to ensure it meets the minimum requirements.
    - It decodes the address lookup table state and checks for validity, returning errors for any discrepancies.
    - It retrieves the active addresses length and validates the indices for writable and readonly accounts, populating the output arrays accordingly.
- **Output**: The function returns `FD_RUNTIME_EXECUTE_SUCCESS` on successful execution or an error code indicating the type of failure encountered during the process.
- **Functions called**:
    - [`fd_txn_account_init_from_funk_readonly`](fd_txn_account.c.driver.md#fd_txn_account_init_from_funk_readonly)
    - [`fd_get_active_addresses_len`](program/fd_address_lookup_table_program.c.driver.md#fd_get_active_addresses_len)


---
### fd\_runtime\_microblock\_verify\_read\_write\_conflicts<!-- {{#callable:fd_runtime_microblock_verify_read_write_conflicts}} -->
The `fd_runtime_microblock_verify_read_write_conflicts` function verifies read-write conflicts among a set of transactions.
- **Inputs**:
    - `txns`: An array of transaction pointers (`fd_txn_p_t`) to be checked for conflicts.
    - `txn_cnt`: The count of transactions in the `txns` array.
    - `acct_map`: A map used to track account conflict detection elements (`fd_conflict_detect_ele_t`).
    - `acct_arr`: An array of account addresses (`fd_acct_addr_t`) associated with the transactions.
    - `funk`: A pointer to the function context (`fd_funk_t`) used for transaction execution.
    - `funk_txn`: A pointer to the transaction context (`fd_funk_txn_t`) used for transaction execution.
    - `slot`: The current slot number (`ulong`) in which the transactions are being processed.
    - `slot_hashes`: A pointer to slot hashes (`fd_slot_hash_t`) used for conflict detection.
    - `features`: A pointer to the features context (`fd_features_t`) that may affect transaction execution.
    - `out_conflict_detected`: A pointer to an integer that will be set to indicate if a conflict was detected.
    - `out_conflict_addr_opt`: An optional pointer to an account address (`fd_acct_addr_t`) where the conflict address will be stored if a conflict is detected.
- **Control Flow**:
    - Initialize the output conflict detection status to 'no conflict detected'.
    - Iterate over each transaction in the `txns` array while no conflict has been detected.
    - For each transaction, load its associated account addresses into `txn_accts`.
    - Check for writable accounts and detect write-write (W-W) and read-write (R-W) conflicts using the `UPDATE_CONFLICT` macro.
    - If a writable account is found to be demoted to read-only, update the conflict status accordingly.
    - After processing all transactions, clear any entries inserted into `acct_map`.
    - Return the appropriate status based on whether a conflict was detected or if the operation was successful.
- **Output**: Returns FD_RUNTIME_EXECUTE_SUCCESS if no conflicts are detected, or an error code indicating the type of conflict detected (write-write or read-write).
- **Functions called**:
    - [`fd_runtime_load_txn_address_lookup_tables`](#fd_runtime_load_txn_address_lookup_tables)
    - [`fd_txn_account_has_bpf_loader_upgradeable`](context/fd_exec_txn_ctx.c.driver.md#fd_txn_account_has_bpf_loader_upgradeable)
    - [`fd_exec_txn_account_is_writable_idx_flat`](context/fd_exec_txn_ctx.c.driver.md#fd_exec_txn_account_is_writable_idx_flat)


---
### fd\_runtime\_poh\_verify<!-- {{#callable:fd_runtime_poh_verify}} -->
Verifies the proof of history (PoH) for a given microblock by comparing the computed hash against the expected hash.
- **Inputs**:
    - `poh_info`: A pointer to a `fd_poh_verifier_t` structure containing information about the PoH verification, including the current hash and microblock data.
- **Control Flow**:
    - Initializes a working hash from the input PoH hash and stores the initial hash for later comparison.
    - Checks if the microblock header indicates that there are no transactions; if so, it appends the hash count to the working hash.
    - If there are transactions, it processes each transaction, appending signatures to a Merkle tree structure.
    - After processing all transactions, it finalizes the Merkle tree and mixes its root hash into the working hash.
    - Finally, it compares the computed working hash with the expected hash from the microblock header and logs a warning if they do not match.
- **Output**: The function does not return a value but updates the `success` field in the `poh_info` structure to indicate whether the verification was successful or not.
- **Functions called**:
    - [`fd_runtime_update_leaders::FD_SPAD_FRAME_BEGIN`](#fd_runtime_update_leadersFD_SPAD_FRAME_BEGIN)


---
### fd\_runtime\_block\_execute\_prepare<!-- {{#callable:fd_runtime_block_execute_prepare}} -->
Prepares the execution context for a block by resetting various counters and updating system variables.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context structure that holds the state and data for the current execution slot.
    - `runtime_spad`: A pointer to the scratchpad memory used for temporary storage during execution.
- **Control Flow**:
    - Checks if the `blockstore` is available and if the current slot is not zero; if so, updates the block height in the blockstore.
    - Resets various counters in the `slot_bank` structure to prepare for the new block execution.
    - Calls [`fd_runtime_block_sysvar_update_pre_execute`](#fd_runtime_block_sysvar_update_pre_execute) to update system variables before executing the block.
    - If the system variable update fails, logs a warning and returns the error code.
    - Returns a success code if all operations complete without error.
- **Output**: Returns FD_RUNTIME_EXECUTE_SUCCESS on successful preparation, or an error code if any operation fails.
- **Functions called**:
    - [`fd_blockstore_block_height_update`](fd_blockstore.c.driver.md#fd_blockstore_block_height_update)
    - [`fd_runtime_block_sysvar_update_pre_execute`](#fd_runtime_block_sysvar_update_pre_execute)


---
### fd\_runtime\_block\_execute\_finalize\_start<!-- {{#callable:fd_runtime_block_execute_finalize_start}} -->
The `fd_runtime_block_execute_finalize_start` function finalizes the execution of a block by updating system variables, freezing the execution context, and preparing data for account hash tasks.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution context for the current slot, containing information about the current state of the execution.
    - `runtime_spad`: A pointer to the scratchpad memory used for temporary storage during execution.
    - `task_data`: A double pointer to hold the address of the task data structure that will be allocated to collect modified account data.
    - `lt_hash_cnt`: An unsigned long integer representing the count of hash values to be processed.
- **Control Flow**:
    - Calls [`fd_sysvar_slot_history_update`](sysvar/fd_sysvar_slot_history.c.driver.md#fd_sysvar_slot_history_update) to update the slot history in the system variables.
    - Calls [`fd_runtime_freeze`](#fd_runtime_freeze) to freeze the current execution context, preventing further modifications.
    - Attempts to create a BPF program cache entry using [`fd_bpf_scan_and_create_bpf_program_cache_entry`](program/fd_bpf_program_util.c.driver.md#fd_bpf_scan_and_create_bpf_program_cache_entry), logging a warning if it fails.
    - Allocates memory for `task_data` to hold the list of changed accounts that will be added to the bank hash.
    - Allocates memory for `lthash_values` within `task_data` to store hash values based on `lt_hash_cnt`.
    - Initializes the allocated `lthash_values` to zero using `fd_lthash_zero`.
    - Calls [`fd_collect_modified_accounts`](fd_hashes.c.driver.md#fd_collect_modified_accounts) to collect the modified accounts and populate `task_data`.
- **Output**: The function does not return a value but modifies the `task_data` pointer to point to the allocated task data structure containing information about modified accounts.
- **Functions called**:
    - [`fd_sysvar_slot_history_update`](sysvar/fd_sysvar_slot_history.c.driver.md#fd_sysvar_slot_history_update)
    - [`fd_runtime_freeze`](#fd_runtime_freeze)
    - [`fd_bpf_scan_and_create_bpf_program_cache_entry`](program/fd_bpf_program_util.c.driver.md#fd_bpf_scan_and_create_bpf_program_cache_entry)
    - [`fd_collect_modified_accounts`](fd_hashes.c.driver.md#fd_collect_modified_accounts)


---
### fd\_runtime\_block\_execute\_finalize\_finish<!-- {{#callable:fd_runtime_block_execute_finalize_finish}} -->
Finalizes the execution of a runtime block by updating the hash bank and saving the slot bank.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context structure, which contains the state of the current execution slot.
    - `capture_ctx`: A pointer to the capture context structure, which is used for capturing transaction data.
    - `block_info`: A pointer to the block information structure that contains details about the block being finalized.
    - `runtime_spad`: A pointer to the scratchpad memory used for temporary storage during execution.
    - `task_data`: A pointer to the task data structure that holds information about the accounts that have been modified.
    - `lt_hash_cnt`: The count of hash values to be processed for the accounts that have been modified.
- **Control Flow**:
    - Calls [`fd_update_hash_bank_exec_hash`](fd_hashes.c.driver.md#fd_update_hash_bank_exec_hash) to update the hash bank with the execution results.
    - Checks for errors during the hash update and logs an error if it fails.
    - Calls [`fd_runtime_save_slot_bank`](fd_runtime_init.c.driver.md#fd_runtime_save_slot_bank) to save the current state of the slot bank.
    - Checks for errors during the slot bank save and logs a warning if it fails.
    - Resets the total compute units requested in the slot context.
    - Returns success status after completing the operations.
- **Output**: Returns FD_RUNTIME_EXECUTE_SUCCESS on successful completion, or an error code if any operation fails.
- **Functions called**:
    - [`fd_update_hash_bank_exec_hash`](fd_hashes.c.driver.md#fd_update_hash_bank_exec_hash)
    - [`fd_runtime_save_slot_bank`](fd_runtime_init.c.driver.md#fd_runtime_save_slot_bank)


---
### block\_finalize\_tpool\_wrapper<!-- {{#callable:block_finalize_tpool_wrapper}} -->
The `block_finalize_tpool_wrapper` function distributes tasks among worker threads to finalize account hash computations in a thread pool.
- **Inputs**:
    - `para_arg_1`: A pointer to the thread pool (`fd_tpool_t`) used for executing tasks.
    - `para_arg_2`: An unused parameter, typically reserved for future use.
    - `arg_1`: A pointer to `fd_accounts_hash_task_data_t`, which contains the data necessary for the hash tasks.
    - `arg_2`: A pointer to an argument that is expected to be a count of worker threads.
    - `arg_3`: A pointer to `fd_exec_slot_ctx_t`, which holds the execution context for the current slot.
    - `arg_4`: An unused parameter, typically reserved for future use.
- **Control Flow**:
    - The function begins by casting `para_arg_1` to `fd_tpool_t` to access the thread pool.
    - It retrieves the task data from `arg_1` and the worker count from `arg_2`.
    - The number of tasks each worker will handle is calculated based on the total size of the task data and the number of workers.
    - A loop iterates over each worker index, starting from 1, to assign tasks to each worker thread.
    - For each worker, it calculates the start and end indices for the task data to be processed by that worker.
    - The `fd_tpool_exec` function is called to execute the hash task for the assigned range of data.
    - After all tasks are dispatched, another loop waits for each worker to complete its execution using `fd_tpool_wait`.
- **Output**: The function does not return a value; it performs operations that finalize account hash computations in a multi-threaded environment.


---
### fd\_runtime\_block\_execute\_finalize\_para<!-- {{#callable:fd_runtime_block_execute_finalize_para}} -->
The `fd_runtime_block_execute_finalize_para` function finalizes the execution of a runtime block by managing the execution context and invoking a callback for parallel processing.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context structure, which holds the state and data for the current execution slot.
    - `capture_ctx`: A pointer to the capture context structure, which is used for capturing execution results and transaction statuses.
    - `block_info`: A constant pointer to the runtime block information structure, which contains details about the block being processed.
    - `worker_cnt`: An unsigned long integer representing the number of worker threads available for parallel execution.
    - `runtime_spad`: A pointer to the shared pad memory used for runtime allocations during execution.
    - `exec_para_ctx`: A pointer to the execution parameter callback context structure, which holds function arguments for the execution callback.
- **Control Flow**:
    - The function begins by initializing a pointer for task data to NULL.
    - It calls [`fd_runtime_block_execute_finalize_start`](#fd_runtime_block_execute_finalize_start) to prepare the execution context and allocate necessary resources.
    - The function sets up the execution parameter context with task data and worker count, and invokes the execution callback function via [`fd_exec_para_call_func`](fd_runtime_public.h.driver.md#FD_FN_UNUSEDfd_exec_para_call_func).
    - Finally, it calls [`fd_runtime_block_execute_finalize_finish`](#fd_runtime_block_execute_finalize_finish) to complete the block finalization process, including saving the execution results.
- **Output**: The function returns an integer value, typically 0, indicating successful execution of the block finalization process.
- **Functions called**:
    - [`fd_runtime_block_execute_finalize_start`](#fd_runtime_block_execute_finalize_start)
    - [`FD_FN_UNUSED::fd_exec_para_call_func`](fd_runtime_public.h.driver.md#FD_FN_UNUSEDfd_exec_para_call_func)
    - [`fd_runtime_block_execute_finalize_finish`](#fd_runtime_block_execute_finalize_finish)


---
### fd\_runtime\_prepare\_txns\_start<!-- {{#callable:fd_runtime_prepare_txns_start}} -->
The `fd_runtime_prepare_txns_start` function initializes transaction contexts and prepares them for execution.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context structure, which holds the state and configuration for the current execution slot.
    - `task_info`: An array of task information structures that will be populated with context for each transaction.
    - `txns`: An array of transaction pointers that need to be prepared for execution.
    - `txn_cnt`: The count of transactions to be prepared.
    - `runtime_spad`: A pointer to the scratchpad memory used for temporary allocations during transaction preparation.
- **Control Flow**:
    - The function initializes a result variable `res` to 0 to track any errors during preparation.
    - It enters a loop that iterates over each transaction index from 0 to `txn_cnt - 1`.
    - For each transaction, it allocates memory for the transaction context in the scratchpad using `fd_spad_alloc`.
    - It sets up the task information for the current transaction, including initializing execution results and linking the transaction pointer.
    - The function prepares a raw transaction structure from the transaction payload.
    - It calls [`fd_execute_txn_prepare_start`](fd_executor.c.driver.md#fd_execute_txn_prepare_start) to prepare the transaction for execution, passing the slot context, transaction context, transaction descriptor, and raw transaction.
    - If an error occurs during preparation, it updates the execution result for the transaction and sets the transaction flags to indicate failure.
- **Output**: The function returns an integer indicating the result of the preparation process, where 0 indicates success and any non-zero value indicates an error.
- **Functions called**:
    - [`fd_execute_txn_prepare_start`](fd_executor.c.driver.md#fd_execute_txn_prepare_start)


---
### fd\_runtime\_pre\_execute\_check<!-- {{#callable:fd_runtime_pre_execute_check}} -->
Checks the pre-execution conditions for a transaction and performs necessary setup.
- **Inputs**:
    - `task_info`: A pointer to a `fd_execute_txn_task_info_t` structure containing information about the transaction to be executed.
    - `dump_txn`: A flag indicating whether to dump the transaction to protobuf format.
- **Control Flow**:
    - Checks if the transaction has been sanitized successfully; if not, it returns early.
    - Sets up the execution context for the transaction by calling [`fd_executor_setup_accounts_for_txn`](fd_executor.c.driver.md#fd_executor_setup_accounts_for_txn).
    - If `dump_txn` is true, it dumps the transaction context to protobuf format.
    - Verifies precompile conditions unless the feature to move precompile verification is active.
    - Validates account locks using [`fd_executor_validate_account_locks`](fd_executor.c.driver.md#fd_executor_validate_account_locks).
    - Checks the validity of transactions using [`fd_executor_check_transactions`](fd_executor.c.driver.md#fd_executor_check_transactions).
    - Validates the transaction fee payer using [`fd_executor_validate_transaction_fee_payer`](fd_executor.c.driver.md#fd_executor_validate_transaction_fee_payer).
    - Attempts to load transaction accounts using [`fd_executor_load_transaction_accounts`](fd_executor.c.driver.md#fd_executor_load_transaction_accounts), handling errors appropriately.
- **Output**: The function does not return a value but modifies the `task_info` structure to reflect the execution result and flags.
- **Functions called**:
    - [`fd_executor_setup_accounts_for_txn`](fd_executor.c.driver.md#fd_executor_setup_accounts_for_txn)
    - [`fd_dump_txn_to_protobuf`](tests/fd_dump_pb.c.driver.md#fd_dump_txn_to_protobuf)
    - [`fd_executor_verify_precompiles`](fd_executor.c.driver.md#fd_executor_verify_precompiles)
    - [`fd_executor_validate_account_locks`](fd_executor.c.driver.md#fd_executor_validate_account_locks)
    - [`fd_executor_check_transactions`](fd_executor.c.driver.md#fd_executor_check_transactions)
    - [`fd_executor_validate_transaction_fee_payer`](fd_executor.c.driver.md#fd_executor_validate_transaction_fee_payer)
    - [`fd_executor_load_transaction_accounts`](fd_executor.c.driver.md#fd_executor_load_transaction_accounts)


---
### fd\_runtime\_finalize\_txn<!-- {{#callable:fd_runtime_finalize_txn}} -->
Finalizes the execution of a transaction by updating account states, collecting fees, and handling transaction status.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context structure that holds the state of the current execution environment.
    - `capture_ctx`: A pointer to the capture context structure that manages transaction capturing for logging or debugging purposes.
    - `task_info`: A pointer to the task information structure that contains details about the transaction being finalized.
    - `finalize_spad`: A pointer to the scratchpad memory used for temporary storage during the finalization process.
- **Control Flow**:
    - The function begins by collecting execution fees from the transaction context and adding them to the slot context's bank.
    - If the capture context is valid and capturing is enabled, it writes the transaction status to the capture context.
    - The function then checks for errors in the transaction execution result.
    - If an error occurred, it handles the rollback of accounts, specifically the nonce and fee payer accounts.
    - If the transaction was successful, it iterates through the accounts involved in the transaction, saving their states as necessary.
    - It also checks for dirty accounts related to voting and staking, updating their states accordingly.
    - Finally, it updates the counts of non-vote transactions and failed transactions based on the execution result.
- **Output**: The function does not return a value but modifies the state of the slot context and captures transaction status updates.
- **Functions called**:
    - [`fd_runtime_write_transaction_status`](#fd_runtime_write_transaction_status)
    - [`fd_txn_account_save`](fd_txn_account.c.driver.md#fd_txn_account_save)
    - [`fd_exec_txn_ctx_account_is_writable_idx`](context/fd_exec_txn_ctx.c.driver.md#fd_exec_txn_ctx_account_is_writable_idx)
    - [`fd_vote_store_account`](program/fd_vote_program.c.driver.md#fd_vote_store_account)
    - [`fd_vote_record_timestamp_vote_with_slot`](program/fd_vote_program.c.driver.md#fd_vote_record_timestamp_vote_with_slot)
    - [`fd_store_stake_delegation`](program/fd_stake_program.c.driver.md#fd_store_stake_delegation)
    - [`fd_runtime_register_new_fresh_account`](#fd_runtime_register_new_fresh_account)


---
### fd\_runtime\_prepare\_and\_execute\_txn<!-- {{#callable:fd_runtime_prepare_and_execute_txn}} -->
This function prepares and executes a transaction within the context of a given execution slot.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context, which contains information about the current execution environment.
    - `txn`: A pointer to the transaction to be executed.
    - `task_info`: A pointer to the task information structure that holds execution results and context for the transaction.
    - `exec_spad`: A pointer to the execution scratchpad, which is used for temporary storage during execution.
    - `capture_ctx`: A pointer to the capture context, which may contain information for logging or debugging purposes.
- **Control Flow**:
    - The function begins by determining if the transaction should be dumped for debugging purposes based on the capture context.
    - It initializes the transaction context and prepares the transaction for execution by calling [`fd_execute_txn_prepare_start`](fd_executor.c.driver.md#fd_execute_txn_prepare_start).
    - If the preparation fails, it resets the transaction flags and returns an error.
    - The function then verifies the transaction's signature using [`fd_executor_txn_verify`](fd_executor.c.driver.md#fd_executor_txn_verify).
    - If the signature verification fails, it logs a warning and sets the execution result to indicate a signature failure.
    - Next, it performs pre-execution checks using [`fd_runtime_pre_execute_check`](#fd_runtime_pre_execute_check).
    - If any of these checks fail, it returns an error.
    - If all checks pass, it marks the transaction as successfully executed and calls [`fd_execute_txn`](fd_executor.c.driver.md#fd_execute_txn) to perform the actual execution.
    - If the execution is successful, it reclaims accounts associated with the transaction.
- **Output**: The function returns an integer indicating the result of the execution process, where a value of 0 indicates success and negative values indicate various types of errors.
- **Functions called**:
    - [`fd_execute_txn_prepare_start`](fd_executor.c.driver.md#fd_execute_txn_prepare_start)
    - [`fd_executor_txn_verify`](fd_executor.c.driver.md#fd_executor_txn_verify)
    - [`fd_runtime_pre_execute_check`](#fd_runtime_pre_execute_check)
    - [`fd_execute_txn`](fd_executor.c.driver.md#fd_execute_txn)
    - [`fd_txn_reclaim_accounts`](fd_executor.c.driver.md#fd_txn_reclaim_accounts)


---
### fd\_runtime\_prepare\_execute\_finalize\_txn\_task<!-- {{#callable:fd_runtime_prepare_execute_finalize_txn_task}} -->
The `fd_runtime_prepare_execute_finalize_txn_task` function prepares, executes, and finalizes a transaction task within a thread pool context.
- **Inputs**:
    - `tpool`: A pointer to the thread pool context used for executing the transaction.
    - `t0`: A pointer to the `fd_capture_ctx_t` structure containing capture context information.
    - `t1`: A pointer to the `fd_txn_p_t` structure representing the transaction to be executed.
    - `args`: A pointer to the `fd_execute_txn_task_info_t` structure containing task information for the transaction execution.
    - `reduce`: A pointer to the `fd_spad_t` structure used for execution scratchpad.
    - `stride`: An unused parameter that may be used for future enhancements.
    - `l0`: An unused parameter that may be used for future enhancements.
    - `l1`: An unused parameter that may be used for future enhancements.
    - `m0`: An unused parameter that may be used for future enhancements.
    - `m1`: An unused parameter that may be used for future enhancements.
    - `n0`: An unused parameter that may be used for future enhancements.
    - `n1`: An unused parameter that may be used for future enhancements.
- **Control Flow**:
    - The function begins by casting the input parameters to their respective types for further processing.
    - It calls the [`fd_runtime_prepare_and_execute_txn`](#fd_runtime_prepare_and_execute_txn) function to prepare and execute the transaction.
    - If the transaction execution is not successful, the function returns early without further processing.
    - If the transaction execution is successful, it proceeds to call [`fd_runtime_finalize_txn`](#fd_runtime_finalize_txn) to finalize the transaction.
- **Output**: The function does not return a value; instead, it modifies the state of the transaction context and captures the results of the transaction execution.
- **Functions called**:
    - [`fd_runtime_prepare_and_execute_txn`](#fd_runtime_prepare_and_execute_txn)
    - [`fd_runtime_finalize_txn`](#fd_runtime_finalize_txn)


---
### fd\_runtime\_process\_txns\_in\_microblock\_stream<!-- {{#callable:fd_runtime_process_txns_in_microblock_stream}} -->
Processes transactions in a microblock stream using a thread pool.
- **Inputs**:
    - `slot_ctx`: Pointer to the execution slot context containing the current execution state.
    - `capture_ctx`: Pointer to the capture context for transaction capturing.
    - `txns`: Pointer to an array of transactions to be processed.
    - `txn_cnt`: The number of transactions in the array.
    - `tpool`: Pointer to the thread pool used for executing tasks.
    - `exec_spads`: Pointer to an array of execution scratchpad pointers.
    - `exec_spad_cnt`: The count of execution scratchpads.
    - `runtime_spad`: Pointer to the runtime scratchpad used for temporary allocations.
    - `cost_tracker_opt`: Optional pointer to a cost tracker for monitoring execution costs.
- **Control Flow**:
    - Initialize transaction flags to indicate successful sanitization.
    - Allocate memory for task information for each transaction.
    - Iterate through the transactions and assign them to available workers in the thread pool.
    - Push a new scratchpad frame for each execution scratchpad before processing transactions.
    - Check if the worker is idle before assigning a transaction to it.
    - Execute the transaction preparation, execution, and finalization tasks in the thread pool.
    - Wait for all workers to finish processing before dispatching new tasks.
    - If a cost tracker is provided, verify cost limits for processed transactions.
    - Pop the scratchpad frame after processing all transactions.
- **Output**: Returns 0 on success or an error code if any issues occur during processing.
- **Functions called**:
    - [`fd_calculate_cost_for_executed_transaction`](fd_cost_tracker.c.driver.md#fd_calculate_cost_for_executed_transaction)
    - [`fd_cost_tracker_try_add`](fd_cost_tracker.c.driver.md#fd_cost_tracker_try_add)


---
### fd\_update\_stake\_delegations<!-- {{#callable:fd_update_stake_delegations}} -->
Updates the stake delegations in the epoch stakes cache based on new stake information.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution context for the current slot, containing information about the current state of the slot.
    - `temp_info`: A pointer to temporary epoch information that includes new stake information to be processed.
- **Control Flow**:
    - Fetches the epoch bank and slot bank from the execution context.
    - Iterates over the new stake information starting from the specified index.
    - For each stake account, checks if a delegation entry already exists in the stakes cache.
    - If no entry exists, acquires a new entry, sets the account and delegation values, and inserts it into the stakes cache.
    - Releases the account keys tree in the slot bank.
- **Output**: The function does not return a value but updates the epoch stakes cache with the new delegation information.


---
### fd\_update\_epoch\_stakes<!-- {{#callable:fd_update_epoch_stakes}} -->
Updates the epoch stakes in the slot context from the next epoch stakes in the epoch bank.
- **Inputs**:
    - `slot_ctx`: A pointer to the `fd_exec_slot_ctx_t` structure that contains the context for the current execution slot.
- **Control Flow**:
    - Retrieve the `epoch_bank` from the `slot_ctx`.
    - Release the current `epoch_stakes` in the `slot_bank` to free up resources.
    - Iterate through the `next_epoch_stakes` in the `epoch_bank`.
    - For each valid vote account in `next_epoch_stakes`, acquire a new node from the `vote_accounts_pool`.
    - Insert the new node into the `epoch_stakes` of the `slot_bank`.
- **Output**: The function does not return a value, but it updates the `epoch_stakes` in the `slot_bank` with the latest stakes from the `next_epoch_stakes`.


---
### fd\_update\_next\_epoch\_stakes<!-- {{#callable:fd_update_next_epoch_stakes}} -->
The `fd_update_next_epoch_stakes` function updates the next epoch's stakes in the epoch bank by copying the current stakes and preparing for the next epoch.
- **Inputs**:
    - `slot_ctx`: A pointer to the `fd_exec_slot_ctx_t` structure that contains the execution context for the current slot, including the epoch context.
- **Control Flow**:
    - The function retrieves the `epoch_bank` from the `slot_ctx`.
    - It releases the current vote accounts from the `next_epoch_stakes` in the `epoch_bank`.
    - It populates the `next_epoch_stakes` with the results from `fd_exec_epoch_ctx_next_epoch_stakes_join`.
    - It initializes the `vote_accounts_root` to NULL.
    - It iterates through the current vote accounts in `epoch_bank->stakes.vote_accounts`.
    - For each vote account, it acquires a new node for the `next_epoch_stakes` and inserts the current vote account into it.
- **Output**: The function does not return a value; it modifies the `next_epoch_stakes` in the `epoch_bank` directly.


---
### fd\_new\_target\_program\_account<!-- {{#callable:fd_new_target_program_account}} -->
The `fd_new_target_program_account` function creates a new target program account with specified properties.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context, which contains information about the current execution environment.
    - `target_program_data_address`: A pointer to the public key of the target program data address that will be associated with the new program account.
    - `out_rec`: A pointer to the transaction account record that will be modified to represent the new program account.
- **Control Flow**:
    - The function first sets the rent epoch of the output record to 0.
    - It initializes a state structure for the BPF upgradeable loader with the target program data address.
    - It retrieves the current rent information from the slot context and checks if it is valid.
    - The function sets the lamports of the output record to the minimum balance required to be rent-exempt.
    - It prepares a context for encoding the BPF upgradeable loader state into the output record's data.
    - The state is encoded into the output record's data, and the owner of the record is set to the BPF loader upgradeable program ID.
    - Finally, the function marks the output record as executable and returns a success status.
- **Output**: The function returns an integer status code indicating success (FD_RUNTIME_EXECUTE_SUCCESS) or an error code if any operation fails.
- **Functions called**:
    - [`fd_rent_exempt_minimum_balance`](sysvar/fd_sysvar_rent1.c.driver.md#fd_rent_exempt_minimum_balance)


---
### fd\_new\_target\_program\_data\_account<!-- {{#callable:fd_new_target_program_data_account}} -->
The `fd_new_target_program_data_account` function creates a new target program data account for a BPF migration.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context, which contains information about the current execution environment.
    - `config_upgrade_authority_address`: A pointer to the public key of the upgrade authority address, which may be NULL.
    - `buffer_acc_rec`: A pointer to the transaction account record that serves as the source buffer for the program data.
    - `new_target_program_data_account`: A pointer to the transaction account record that will be initialized as the new target program data account.
    - `runtime_spad`: A pointer to the SPAD (scratchpad) memory used for temporary allocations during execution.
- **Control Flow**:
    - The function begins by initializing a SPAD frame for temporary allocations.
    - It decodes the state of the buffer account record to retrieve the BPF upgradeable loader state.
    - If the decoding fails or the state is not a buffer, it returns an error.
    - If a configuration upgrade authority address is provided, it checks if it matches the authority address in the state.
    - It retrieves the rent information from the slot context and calculates the required lamports for the new account.
    - The function then prepares the program data metadata structure and sets the lamports for the new target program data account.
    - It encodes the program data metadata into the new target program data account.
    - Finally, it copies the ELF data from the buffer account to the new target program data account and returns success.
- **Output**: The function returns FD_RUNTIME_EXECUTE_SUCCESS on success, or an error code if any operation fails.
- **Functions called**:
    - [`fd_rent_exempt_minimum_balance`](sysvar/fd_sysvar_rent1.c.driver.md#fd_rent_exempt_minimum_balance)


---
### fd\_migrate\_builtin\_to\_core\_bpf<!-- {{#callable:fd_migrate_builtin_to_core_bpf}} -->
The `fd_migrate_builtin_to_core_bpf` function migrates a built-in program to a Core BPF program, handling both stateless and stateful migrations.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context, which contains the current execution state.
    - `upgrade_authority_address`: A pointer to the public key of the upgrade authority for the program.
    - `builtin_program_id`: A pointer to the public key of the built-in program being migrated.
    - `source_buffer_address`: A pointer to the public key of the source buffer account containing the program data.
    - `stateless`: A flag indicating whether the migration is for a stateless program (1) or a stateful program (0).
    - `runtime_spad`: A pointer to the scratchpad memory used for temporary storage during execution.
- **Control Flow**:
    - The function begins by declaring a variable for error handling and initializing a target program account.
    - It checks if the program exists and whether it should be migrated based on the stateless flag.
    - If the program is stateful, it verifies that the program account exists and is owned by the native loader.
    - If the program is stateless, it ensures that the program account does not already exist.
    - The function then checks for the existence of the program data account and the source buffer account, logging warnings if any checks fail.
    - It starts a transaction to prepare for the migration, initializing the new target program account and program data account.
    - The function then deploys the new Core BPF program and updates the capitalization based on the migration.
    - Finally, it publishes the transaction and handles any errors that may have occurred during the process.
- **Output**: The function does not return a value but modifies the state of the slot context and logs warnings or errors as necessary.
- **Functions called**:
    - [`fd_txn_account_init_from_funk_readonly`](fd_txn_account.c.driver.md#fd_txn_account_init_from_funk_readonly)
    - [`fd_pubkey_find_program_address`](fd_pubkey_utils.c.driver.md#fd_pubkey_find_program_address)
    - [`fd_txn_account_init_from_funk_mutable`](fd_txn_account.c.driver.md#fd_txn_account_init_from_funk_mutable)
    - [`fd_new_target_program_account`](#fd_new_target_program_account)
    - [`fd_txn_account_mutable_fini`](fd_txn_account.c.driver.md#fd_txn_account_mutable_fini)
    - [`fd_new_target_program_data_account`](#fd_new_target_program_data_account)
    - [`fd_directly_invoke_loader_v3_deploy`](program/fd_bpf_loader_program.c.driver.md#fd_directly_invoke_loader_v3_deploy)


---
### fd\_apply\_builtin\_program\_feature\_transitions<!-- {{#callable:fd_apply_builtin_program_feature_transitions}} -->
Applies transitions for builtin program features, migrating stateless builtins to core BPF and enabling features as necessary.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context structure, which contains the current state and configuration for the execution environment.
    - `runtime_spad`: A pointer to the scratchpad memory used for temporary storage during execution.
- **Control Flow**:
    - Begins a scratchpad frame for temporary allocations.
    - Retrieves the list of builtin programs and iterates through them.
    - For each builtin, checks if it has a migration configuration and if the feature is active; if so, it migrates the builtin to core BPF.
    - Checks if the feature associated with the builtin is just activated; if so, it enables the builtin program.
    - Retrieves the list of stateless builtins and performs similar checks and migrations as for the builtins.
    - Retrieves precompile programs and enables them if they have just been activated.
    - Ends the scratchpad frame.
- **Output**: The function does not return a value but modifies the state of the execution context and the builtin programs based on the current slot and feature activations.
- **Functions called**:
    - [`fd_builtins`](program/fd_builtin_programs.c.driver.md#fd_builtins)
    - [`fd_num_builtins`](program/fd_builtin_programs.c.driver.md#fd_num_builtins)
    - [`fd_migrate_builtin_to_core_bpf`](#fd_migrate_builtin_to_core_bpf)
    - [`fd_write_builtin_account`](program/fd_builtin_programs.c.driver.md#fd_write_builtin_account)
    - [`fd_stateless_builtins`](program/fd_builtin_programs.c.driver.md#fd_stateless_builtins)
    - [`fd_num_stateless_builtins`](program/fd_builtin_programs.c.driver.md#fd_num_stateless_builtins)
    - [`fd_precompiles`](program/fd_builtin_programs.c.driver.md#fd_precompiles)
    - [`fd_num_precompiles`](program/fd_builtin_programs.c.driver.md#fd_num_precompiles)


---
### fd\_feature\_activate<!-- {{#callable:fd_feature_activate}} -->
The `fd_feature_activate` function activates a feature if it has not been reverted and updates its state in the account.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context containing the current execution state.
    - `id`: A pointer to the feature ID structure that identifies the feature to be activated.
    - `acct`: A static array of 32 unsigned characters representing the account associated with the feature.
    - `runtime_spad`: A pointer to the scratchpad memory used for temporary storage during execution.
- **Control Flow**:
    - Check if the feature has been reverted; if so, exit the function.
    - Initialize a read-only transaction account from the provided account public key.
    - Decode the feature data from the account into a feature structure.
    - If the feature is already activated, log this information and update the feature's activation time in the epoch context.
    - If the feature is not activated, log the activation attempt, initialize a mutable transaction account, and update the feature's state to activated.
    - Encode the updated feature data back into the account.
    - Finalize the mutable transaction account.
- **Output**: The function does not return a value; it modifies the state of the feature in the account and logs relevant information.
- **Functions called**:
    - [`fd_txn_account_init_from_funk_readonly`](fd_txn_account.c.driver.md#fd_txn_account_init_from_funk_readonly)
    - [`fd_txn_account_init_from_funk_mutable`](fd_txn_account.c.driver.md#fd_txn_account_init_from_funk_mutable)
    - [`fd_txn_account_mutable_fini`](fd_txn_account.c.driver.md#fd_txn_account_mutable_fini)


---
### fd\_features\_activate<!-- {{#callable:fd_features_activate}} -->
The `fd_features_activate` function activates all features by iterating through feature IDs and calling [`fd_feature_activate`](#fd_feature_activate) for each.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context structure, which contains the current execution state.
    - `runtime_spad`: A pointer to the scratchpad memory used for runtime operations.
- **Control Flow**:
    - The function initializes an iterator for feature IDs using `fd_feature_iter_init()`.
    - It enters a loop that continues until all feature IDs have been processed, as determined by `fd_feature_iter_done()`.
    - For each feature ID, it calls `fd_feature_activate()` with the current slot context, feature ID, the key of the feature ID, and the runtime scratchpad.
- **Output**: The function does not return a value; it modifies the state of features in the system by activating them.
- **Functions called**:
    - [`fd_feature_activate`](#fd_feature_activate)


---
### fd\_runtime\_is\_epoch\_boundary<!-- {{#callable:fd_runtime_is_epoch_boundary}} -->
The `fd_runtime_is_epoch_boundary` function checks if the current slot marks the boundary of a new epoch.
- **Inputs**:
    - `epoch_bank`: A pointer to an `fd_epoch_bank_t` structure that contains the epoch schedule information.
    - `curr_slot`: The current slot number being evaluated.
    - `prev_slot`: The previous slot number to compare against.
- **Control Flow**:
    - The function first initializes a variable `slot_idx` to hold the index of the current slot.
    - It then calls [`fd_slot_to_epoch`](sysvar/fd_sysvar_epoch_schedule.c.driver.md#fd_slot_to_epoch) twice: once for `prev_slot` to determine the previous epoch and once for `curr_slot` to determine the new epoch.
    - Finally, it checks if the previous epoch is less than the new epoch or if the `slot_idx` is zero, indicating an epoch boundary.
- **Output**: The function returns a non-zero value (true) if the current slot is an epoch boundary, otherwise it returns zero (false).
- **Functions called**:
    - [`fd_slot_to_epoch`](sysvar/fd_sysvar_epoch_schedule.c.driver.md#fd_slot_to_epoch)


---
### fd\_runtime\_process\_new\_epoch<!-- {{#callable:fd_runtime_process_new_epoch}} -->
The `fd_runtime_process_new_epoch` function processes the transition to a new epoch in the runtime environment, updating various state variables and activating new features.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context structure that holds the current state of the slot.
    - `parent_epoch`: The epoch number of the parent epoch that is being transitioned from.
    - `tpool`: A pointer to the thread pool used for parallel processing.
    - `exec_spads`: An array of pointers to execution scratchpad memory for executing tasks.
    - `exec_spad_cnt`: The count of execution scratchpad memory pointers.
    - `runtime_spad`: A pointer to the runtime scratchpad memory used for temporary allocations.
- **Control Flow**:
    - Logs the start of the new epoch processing.
    - Records the start time for performance measurement.
    - Retrieves the current epoch bank and calculates the new epoch based on the current slot.
    - Activates new features and restores previous features from the runtime scratchpad.
    - Applies transitions for built-in program features.
    - Updates the speed of the proof of history (PoH) clock based on activated features.
    - Determines the new rate activation epoch and updates the epoch information.
    - Updates the stakes for the current epoch and refreshes vote accounts.
    - Distributes rewards based on the current epoch's configuration.
    - Updates the stakes for the previous epochs.
    - Calculates the hash values for the epoch accounts.
    - Logs the end of the new epoch processing and the time taken.
- **Output**: The function does not return a value but updates the state of the runtime environment to reflect the new epoch, including updated stakes, activated features, and distributed rewards.
- **Functions called**:
    - [`fd_slot_to_epoch`](sysvar/fd_sysvar_epoch_schedule.c.driver.md#fd_slot_to_epoch)
    - [`fd_features_activate`](#fd_features_activate)
    - [`fd_features_restore`](fd_runtime_init.c.driver.md#fd_features_restore)
    - [`fd_apply_builtin_program_feature_transitions`](#fd_apply_builtin_program_feature_transitions)
    - [`fd_new_warmup_cooldown_rate_epoch`](program/fd_stake_program.c.driver.md#fd_new_warmup_cooldown_rate_epoch)
    - [`fd_update_epoch_stakes`](#fd_update_epoch_stakes)
    - [`fd_update_stake_delegations`](#fd_update_stake_delegations)
    - [`fd_sysvar_stake_history_read`](sysvar/fd_sysvar_stake_history.c.driver.md#fd_sysvar_stake_history_read)
    - [`fd_update_next_epoch_stakes`](#fd_update_next_epoch_stakes)
    - [`fd_runtime_update_leaders`](#fd_runtime_update_leaders)
    - [`fd_calculate_epoch_accounts_hash_values`](fd_hashes.c.driver.md#fd_calculate_epoch_accounts_hash_values)


---
### fd\_runtime\_parse\_microblock\_hdr<!-- {{#callable:fd_runtime_parse_microblock_hdr}} -->
Parses the header of a microblock and checks if the buffer size is sufficient.
- **Inputs**:
    - `buf`: A pointer to the buffer containing the microblock header data.
    - `buf_sz`: The size of the buffer in bytes.
- **Control Flow**:
    - The function first checks if the buffer size is less than the size of `fd_microblock_hdr_t`.
    - If the buffer size is insufficient, it returns -1 indicating an error.
    - If the buffer size is sufficient, it returns 0 indicating success.
- **Output**: Returns 0 if the buffer size is sufficient; otherwise, returns -1.


---
### find\_next\_txn\_in\_raw\_block<!-- {{#callable:find_next_txn_in_raw_block}} -->
The `find_next_txn_in_raw_block` function iterates through a raw block's microblocks to find the next transaction.
- **Inputs**:
    - `orig_data`: A pointer to the original data buffer containing the raw block data.
    - `batches`: A pointer to the current batch of block entries being processed.
    - `batch_cnt`: The total number of batches available, including the current one.
    - `curr_offset`: The current offset in the original data buffer for reading transactions.
    - `num_microblocks`: The number of microblocks present in the current batch.
- **Control Flow**:
    - The function first checks if there are remaining microblocks in the current batch.
    - It iterates through each microblock, parsing the header and checking for transactions.
    - If a microblock with transactions is found, it returns an iterator with the current state.
    - If no transactions are found in the current batch, it moves to the next batch and repeats the process.
    - If no transactions are found in any batch, it returns an iterator indicating no remaining transactions.
- **Output**: Returns an `fd_raw_block_txn_iter_t` structure containing the current state of the transaction iterator, including the current batch, remaining transactions, and offsets.
- **Functions called**:
    - [`fd_runtime_parse_microblock_hdr`](#fd_runtime_parse_microblock_hdr)


---
### fd\_raw\_block\_txn\_iter\_init<!-- {{#callable:fd_raw_block_txn_iter_init}} -->
Initializes a raw block transaction iterator.
- **Inputs**:
    - `orig_data`: A pointer to the original data buffer containing the raw block data.
    - `batches`: A pointer to an array of block entry batches that represent the structure of the block.
    - `batch_cnt`: The count of batches available in the block.
- **Control Flow**:
    - Loads the number of microblocks from the original data buffer.
    - Calls [`find_next_txn_in_raw_block`](#find_next_txn_in_raw_block) to find the next transaction in the raw block using the loaded number of microblocks.
- **Output**: Returns an iterator structure `fd_raw_block_txn_iter_t` that contains information about the current batch, remaining batches, remaining microblocks, and the current offset in the original data.
- **Functions called**:
    - [`find_next_txn_in_raw_block`](#find_next_txn_in_raw_block)


---
### fd\_raw\_block\_txn\_iter\_done<!-- {{#callable:fd_raw_block_txn_iter_done}} -->
Checks if all transaction batches, microblocks, and transactions in the iterator are completed.
- **Inputs**:
    - `iter`: An instance of `fd_raw_block_txn_iter_t` that contains the current state of the transaction iterator.
- **Control Flow**:
    - Evaluates if `remaining_batches`, `remaining_microblocks`, and `remaining_txns` in the iterator are all zero.
    - Returns 1 (true) if all counts are zero, otherwise returns 0 (false).
- **Output**: Returns a non-zero value (true) if all transaction iterations are complete, otherwise returns zero (false).


---
### fd\_raw\_block\_txn\_iter\_next<!-- {{#callable:fd_raw_block_txn_iter_next}} -->
The `fd_raw_block_txn_iter_next` function retrieves the next transaction from a raw block transaction iterator.
- **Inputs**:
    - `iter`: An iterator of type `fd_raw_block_txn_iter_t` that contains the current state of the transaction iteration, including offsets and counts.
- **Control Flow**:
    - The function checks if the current transaction size is set to `ULONG_MAX`, indicating that a new transaction needs to be parsed.
    - If so, it attempts to parse the next transaction from the original data using `fd_txn_parse_core`, updating the current offset and checking for errors.
    - If the current transaction size is not `ULONG_MAX`, it simply increments the current offset by the size of the last transaction.
    - The function decrements the remaining transaction count and checks if there are more transactions left to process.
    - If there are no remaining transactions, it calls [`find_next_txn_in_raw_block`](#find_next_txn_in_raw_block) to find the next transaction in the raw block.
- **Output**: The function returns an updated `fd_raw_block_txn_iter_t` iterator, which reflects the current state after attempting to retrieve the next transaction.
- **Functions called**:
    - [`find_next_txn_in_raw_block`](#find_next_txn_in_raw_block)


---
### fd\_raw\_block\_txn\_iter\_ele<!-- {{#callable:fd_raw_block_txn_iter_ele}} -->
The `fd_raw_block_txn_iter_ele` function extracts a transaction from a raw block iterator.
- **Inputs**:
    - `iter`: An iterator of type `fd_raw_block_txn_iter_t` that contains the current state of the block transaction iteration.
    - `out_txn`: A pointer to a transaction structure (`fd_txn_p_t`) where the extracted transaction will be stored.
- **Control Flow**:
    - The function retrieves the end offset of the current batch from `iter.curr_batch->end_off`.
    - It initializes a variable `payload_sz` to zero to hold the size of the transaction payload.
    - It calls `fd_txn_parse_core` to parse the transaction from the original data at the current offset, using the minimum of the remaining data size and the maximum transaction size (`FD_TXN_MTU`).
    - If the parsed transaction size is invalid (zero or exceeds `FD_TXN_MTU`), it logs an error message.
    - It copies the payload of the transaction from the original data to the `out_txn->payload` and sets the size of the payload in `out_txn->payload_sz`.
    - Finally, it updates `iter.curr_txn_sz` with the size of the current transaction payload.
- **Output**: The function does not return a value; instead, it populates the `out_txn` structure with the extracted transaction data.


---
### fd\_runtime\_parse\_microblock\_txns<!-- {{#callable:fd_runtime_parse_microblock_txns}} -->
The `fd_runtime_parse_microblock_txns` function parses transactions from a microblock buffer and populates output transaction structures.
- **Inputs**:
    - `buf`: A pointer to the buffer containing the raw microblock data.
    - `buf_sz`: The size of the buffer in bytes.
    - `microblock_hdr`: A pointer to the header of the microblock, which contains metadata about the transactions.
    - `out_txns`: An array of transaction pointers where the parsed transactions will be stored.
    - `out_signature_cnt`: A pointer to a variable where the total count of signatures from the parsed transactions will be stored.
    - `out_account_cnt`: A pointer to a variable where the total count of accounts referenced by the parsed transactions will be stored.
    - `out_microblock_txns_sz`: A pointer to a variable where the total size of the parsed transactions will be stored.
- **Control Flow**:
    - The function initializes offsets and counters for signatures and accounts.
    - It iterates over the number of transactions specified in the microblock header.
    - For each transaction, it attempts to parse the transaction data from the buffer.
    - If parsing is successful, it copies the transaction payload into the output structure and updates the counts for signatures and accounts.
    - If any parsing fails (e.g., invalid size or payload), the function returns an error code.
- **Output**: The function returns 0 on success, or -1 if an error occurs during parsing.


---
### fd\_runtime\_microblock\_prepare<!-- {{#callable:fd_runtime_microblock_prepare}} -->
The `fd_runtime_microblock_prepare` function prepares a microblock for processing by parsing its header and transactions.
- **Inputs**:
    - `buf`: A pointer to the buffer containing the raw microblock data.
    - `buf_sz`: The size of the buffer in bytes.
    - `runtime_spad`: A pointer to the shared pad memory used for allocation.
    - `out_microblock_info`: A pointer to a `fd_microblock_info_t` structure where the parsed microblock information will be stored.
- **Control Flow**:
    - The function initializes a `fd_microblock_info_t` structure to hold parsed information.
    - It checks if the microblock header can be parsed from the provided buffer; if not, it returns an error.
    - The header is stored in the `microblock_info` structure, and the offset for the next read is updated.
    - The function allocates memory for the transactions in the microblock using `fd_spad_alloc`.
    - It then attempts to parse the transactions from the buffer, updating the transaction count and other relevant fields.
    - If any parsing step fails, the function returns an error.
    - Finally, it updates the size of the raw microblock and assigns the populated `microblock_info` to the output parameter.
- **Output**: Returns 0 on success, or -1 if any parsing step fails.
- **Functions called**:
    - [`fd_runtime_parse_microblock_hdr`](#fd_runtime_parse_microblock_hdr)
    - [`fd_runtime_parse_microblock_txns`](#fd_runtime_parse_microblock_txns)


---
### fd\_runtime\_microblock\_batch\_prepare<!-- {{#callable:fd_runtime_microblock_batch_prepare}} -->
Prepares a batch of microblocks from a given buffer.
- **Inputs**:
    - `buf`: A pointer to the buffer containing the raw microblock data.
    - `buf_sz`: The size of the buffer in bytes.
    - `runtime_spad`: A pointer to the shared pad memory used for allocations.
    - `out_microblock_batch_info`: A pointer to a structure where the prepared microblock batch information will be stored.
- **Control Flow**:
    - Checks if the buffer size is less than the size of an unsigned long; if so, logs a warning and returns -1.
    - Loads the number of microblocks from the buffer and updates the buffer offset.
    - Allocates memory for the microblock information based on the number of microblocks.
    - Iterates over each microblock, preparing it by calling [`fd_runtime_microblock_prepare`](#fd_runtime_microblock_prepare) and updating counts for signatures, transactions, and accounts.
    - Updates the output structure with the total counts and sizes of the prepared microblocks.
- **Output**: Returns 0 on success, or -1 if an error occurs during preparation.
- **Functions called**:
    - [`fd_runtime_microblock_prepare`](#fd_runtime_microblock_prepare)


---
### fd\_runtime\_block\_prepare<!-- {{#callable:fd_runtime_block_prepare}} -->
Prepares a runtime block for execution by extracting and organizing its data.
- **Inputs**:
    - `blockstore`: A pointer to the `fd_blockstore_t` structure that contains the block data.
    - `block`: A pointer to the `fd_block_t` structure representing the block to be prepared.
    - `slot`: The slot number associated with the block being prepared.
    - `runtime_spad`: A pointer to the `fd_spad_t` structure used for runtime allocations.
    - `out_block_info`: A pointer to an `fd_runtime_block_info_t` structure where the prepared block information will be stored.
- **Control Flow**:
    - The function retrieves the block data and its size from the `blockstore`.
    - It initializes a `fd_runtime_block_info_t` structure to hold the block information.
    - It iterates over the batches of microblocks in the block, preparing each microblock by calling [`fd_runtime_microblock_batch_prepare`](#fd_runtime_microblock_batch_prepare).
    - For each microblock batch, it accumulates counts of signatures, transactions, and accounts.
    - It checks for any trailing bytes in the buffer and logs warnings if necessary.
    - Finally, it populates the `out_block_info` with the collected data and returns success.
- **Output**: Returns 0 on success, or a negative error code if preparation fails.
- **Functions called**:
    - [`fd_blockstore_block_data_laddr`](fd_rocksdb.h.driver.md#fd_blockstore_block_data_laddr)
    - [`fd_runtime_microblock_batch_prepare`](#fd_runtime_microblock_batch_prepare)


---
### fd\_runtime\_microblock\_collect\_txns<!-- {{#callable:fd_runtime_microblock_collect_txns}} -->
The `fd_runtime_microblock_collect_txns` function collects transactions from a microblock and copies them to an output array.
- **Inputs**:
    - `microblock_info`: A pointer to a `fd_microblock_info_t` structure that contains information about the microblock, including its header and transactions.
    - `out_txns`: A pointer to an array of transaction pointers where the collected transactions will be stored.
- **Control Flow**:
    - The function retrieves the transaction count from the microblock header.
    - It uses `fd_memcpy` to copy the transactions from the microblock's transaction array to the output array.
    - Finally, it returns the count of transactions collected.
- **Output**: The function returns the number of transactions collected from the microblock.


---
### fd\_runtime\_microblock\_batch\_collect\_txns<!-- {{#callable:fd_runtime_microblock_batch_collect_txns}} -->
The function `fd_runtime_microblock_batch_collect_txns` collects transactions from a batch of microblocks and stores them in the provided output array.
- **Inputs**:
    - `microblock_batch_info`: A pointer to a `fd_microblock_batch_info_t` structure that contains information about the microblock batch, including the number of microblocks and their details.
    - `out_txns`: A pointer to an array of transaction pointers (`fd_txn_p_t`) where the collected transactions will be stored.
- **Control Flow**:
    - The function iterates over each microblock in the `microblock_batch_info` structure.
    - For each microblock, it calls [`fd_runtime_microblock_collect_txns`](#fd_runtime_microblock_collect_txns) to collect its transactions.
    - The collected transactions are appended to the `out_txns` array.
- **Output**: The function returns the total number of transactions collected from all microblocks in the batch.
- **Functions called**:
    - [`fd_runtime_microblock_collect_txns`](#fd_runtime_microblock_collect_txns)


---
### fd\_runtime\_block\_collect\_txns<!-- {{#callable:fd_runtime_block_collect_txns}} -->
The `fd_runtime_block_collect_txns` function collects transactions from multiple microblock batches into a specified output array.
- **Inputs**:
    - `block_info`: A pointer to a `fd_runtime_block_info_t` structure that contains information about the block, including the number of microblock batches.
    - `out_txns`: A pointer to an array of `fd_txn_p_t` where the collected transactions will be stored.
- **Control Flow**:
    - Iterates over each microblock batch in the `block_info` structure.
    - For each microblock batch, it calls [`fd_runtime_microblock_batch_collect_txns`](#fd_runtime_microblock_batch_collect_txns) to collect transactions from that batch.
    - The collected transactions are appended to the `out_txns` array.
- **Output**: Returns the total number of transactions in the block as specified by `block_info->txn_cnt`.
- **Functions called**:
    - [`fd_runtime_microblock_batch_collect_txns`](#fd_runtime_microblock_batch_collect_txns)


---
### fd\_runtime\_init\_program<!-- {{#callable:fd_runtime_init_program}} -->
Initializes the runtime environment for a program by setting up various system variables.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context structure, which holds the state and configuration for the current execution slot.
    - `runtime_spad`: A pointer to the scratchpad memory used for temporary storage during runtime operations.
- **Control Flow**:
    - Calls [`fd_sysvar_recent_hashes_init`](sysvar/fd_sysvar_recent_hashes.c.driver.md#fd_sysvar_recent_hashes_init) to initialize recent hashes in the system variable context.
    - Calls [`fd_sysvar_clock_init`](sysvar/fd_sysvar_clock.c.driver.md#fd_sysvar_clock_init) to set up the clock system variable.
    - Calls [`fd_sysvar_slot_history_init`](sysvar/fd_sysvar_slot_history.c.driver.md#fd_sysvar_slot_history_init) to initialize the slot history system variable.
    - Calls [`fd_sysvar_slot_hashes_init`](sysvar/fd_sysvar_slot_hashes.c.driver.md#fd_sysvar_slot_hashes_init) to set up the slot hashes system variable.
    - Calls [`fd_sysvar_epoch_schedule_init`](sysvar/fd_sysvar_epoch_schedule.c.driver.md#fd_sysvar_epoch_schedule_init) to initialize the epoch schedule system variable.
    - Calls [`fd_sysvar_rent_init`](sysvar/fd_sysvar_rent.c.driver.md#fd_sysvar_rent_init) to set up the rent system variable.
    - Calls [`fd_sysvar_stake_history_init`](sysvar/fd_sysvar_stake_history.c.driver.md#fd_sysvar_stake_history_init) to initialize the stake history system variable.
    - Calls [`fd_sysvar_last_restart_slot_init`](sysvar/fd_sysvar_last_restart_slot.c.driver.md#fd_sysvar_last_restart_slot_init) to set up the last restart slot system variable.
    - Calls [`fd_builtin_programs_init`](program/fd_builtin_programs.c.driver.md#fd_builtin_programs_init) to initialize built-in programs.
    - Calls [`fd_stake_program_config_init`](program/fd_stake_program.c.driver.md#fd_stake_program_config_init) to set up the stake program configuration.
- **Output**: The function does not return a value; it initializes various system variables and configurations necessary for the program's execution environment.
- **Functions called**:
    - [`fd_sysvar_recent_hashes_init`](sysvar/fd_sysvar_recent_hashes.c.driver.md#fd_sysvar_recent_hashes_init)
    - [`fd_sysvar_clock_init`](sysvar/fd_sysvar_clock.c.driver.md#fd_sysvar_clock_init)
    - [`fd_sysvar_slot_history_init`](sysvar/fd_sysvar_slot_history.c.driver.md#fd_sysvar_slot_history_init)
    - [`fd_sysvar_slot_hashes_init`](sysvar/fd_sysvar_slot_hashes.c.driver.md#fd_sysvar_slot_hashes_init)
    - [`fd_sysvar_epoch_schedule_init`](sysvar/fd_sysvar_epoch_schedule.c.driver.md#fd_sysvar_epoch_schedule_init)
    - [`fd_sysvar_rent_init`](sysvar/fd_sysvar_rent.c.driver.md#fd_sysvar_rent_init)
    - [`fd_sysvar_stake_history_init`](sysvar/fd_sysvar_stake_history.c.driver.md#fd_sysvar_stake_history_init)
    - [`fd_sysvar_last_restart_slot_init`](sysvar/fd_sysvar_last_restart_slot.c.driver.md#fd_sysvar_last_restart_slot_init)
    - [`fd_builtin_programs_init`](program/fd_builtin_programs.c.driver.md#fd_builtin_programs_init)
    - [`fd_stake_program_config_init`](program/fd_stake_program.c.driver.md#fd_stake_program_config_init)


---
### fd\_runtime\_init\_bank\_from\_genesis<!-- {{#callable:fd_runtime_init_bank_from_genesis}} -->
Initializes the runtime bank state from the genesis block.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context that holds the current state of the slot.
    - `genesis_block`: A pointer to the genesis block structure containing initial blockchain parameters.
    - `genesis_hash`: A pointer to the hash of the genesis block.
    - `runtime_spad`: A pointer to the scratchpad memory used for temporary allocations.
- **Control Flow**:
    - Sets the current slot in the slot context to 0.
    - Copies the genesis hash into the slot bank's proof of history (POH) structure.
    - Initializes various parameters in the slot bank and epoch bank using values from the genesis block.
    - Allocates memory for the block hash queue and initializes it.
    - Processes accounts from the genesis block to set up vote and stake accounts.
    - Updates the epoch stakes and initializes the stakes cache in the bank structure.
- **Output**: The function does not return a value but modifies the state of the slot context and initializes the bank with values derived from the genesis block.
- **Functions called**:
    - [`fd_txn_account_init_from_meta_and_data_mutable`](fd_txn_account.c.driver.md#fd_txn_account_init_from_meta_and_data_mutable)
    - [`fd_stake_get_state`](program/fd_stake_program.c.driver.md#fd_stake_get_state)


---
### fd\_runtime\_process\_genesis\_block<!-- {{#callable:fd_runtime_process_genesis_block}} -->
Processes the genesis block by initializing various parameters and updating the state.
- **Inputs**:
    - `slot_ctx`: Pointer to the execution slot context containing the current state of the slot.
    - `capture_ctx`: Pointer to the capture context used for logging and capturing state.
    - `runtime_spad`: Pointer to the scratchpad memory used for temporary storage during execution.
- **Control Flow**:
    - Calculates the number of hashes to perform based on the current epoch's configuration.
    - Performs SHA-256 hashing for the calculated number of times to update the Proof of History (PoH) value.
    - Resets various fee and transaction counters in the slot context.
    - Updates the slot history in the system variables.
    - Updates the leaders for the current slot.
    - If partitioned rent collection is not disabled, registers all genesis accounts into the rent fresh list.
    - Freezes the current state of the slot context.
    - Updates the bank hash using the current state and captures context.
    - Saves the epoch bank and slot bank states.
- **Output**: Returns a success status code indicating the result of processing the genesis block.
- **Functions called**:
    - [`fd_sysvar_slot_history_update`](sysvar/fd_sysvar_slot_history.c.driver.md#fd_sysvar_slot_history_update)
    - [`fd_runtime_update_leaders`](#fd_runtime_update_leaders)
    - [`fd_funk_key_is_acc`](fd_acc_mgr.h.driver.md#fd_funk_key_is_acc)
    - [`fd_runtime_register_new_fresh_account`](#fd_runtime_register_new_fresh_account)
    - [`fd_runtime_freeze`](#fd_runtime_freeze)
    - [`fd_update_hash_bank_tpool`](fd_hashes.c.driver.md#fd_update_hash_bank_tpool)
    - [`fd_runtime_save_epoch_bank`](fd_runtime_init.c.driver.md#fd_runtime_save_epoch_bank)
    - [`fd_runtime_save_slot_bank`](fd_runtime_init.c.driver.md#fd_runtime_save_slot_bank)


---
### fd\_runtime\_read\_genesis<!-- {{#callable:fd_runtime_read_genesis}} -->
The `fd_runtime_read_genesis` function reads the genesis block from a specified file and initializes the runtime environment.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context structure that holds the current execution state.
    - `genesis_filepath`: A string representing the file path to the genesis block.
    - `is_snapshot`: A flag indicating whether the read operation is for a snapshot.
    - `capture_ctx`: A pointer to the capture context used for logging and capturing execution details.
    - `runtime_spad`: A pointer to the scratchpad memory used for temporary allocations during runtime.
- **Control Flow**:
    - The function first checks if the `genesis_filepath` is empty and returns early if it is.
    - It then attempts to retrieve the file status using `stat` and logs an error if the file cannot be opened.
    - The file is opened in read-only mode, and its contents are read into a buffer allocated from the `runtime_spad`.
    - The buffer is then decoded into a `genesis_block` structure, and an error is logged if decoding fails.
    - A SHA-256 hash of the buffer is computed and stored in the `epoch_bank`.
    - If `is_snapshot` is false, the function initializes the bank and program state from the genesis block, processes accounts, and initializes various system variables.
    - Finally, it sets up account key pools for stake and vote accounts.
- **Output**: The function does not return a value but initializes the runtime environment based on the contents of the genesis block, setting up necessary structures and logging any errors encountered during the process.
- **Functions called**:
    - [`fd_runtime_init_bank_from_genesis`](#fd_runtime_init_bank_from_genesis)
    - [`fd_runtime_init_program`](#fd_runtime_init_program)
    - [`fd_txn_account_init_from_funk_mutable`](fd_txn_account.c.driver.md#fd_txn_account_init_from_funk_mutable)
    - [`fd_txn_account_mutable_fini`](fd_txn_account.c.driver.md#fd_txn_account_mutable_fini)
    - [`fd_write_builtin_account`](program/fd_builtin_programs.c.driver.md#fd_write_builtin_account)
    - [`fd_features_restore`](fd_runtime_init.c.driver.md#fd_features_restore)
    - [`fd_runtime_process_genesis_block`](#fd_runtime_process_genesis_block)


---
### fd\_runtime\_microblock\_verify\_info\_collect<!-- {{#callable:fd_runtime_microblock_verify_info_collect}} -->
Collects verification information for a microblock and its associated hash.
- **Inputs**:
    - `microblock_info`: A pointer to a `fd_microblock_info_t` structure containing information about the microblock being verified.
    - `in_poh_hash`: A pointer to a `fd_hash_t` structure representing the hash that is currently in the Proof of History (PoH).
    - `poh_verification_info`: A pointer to a `fd_poh_verification_info_t` structure where the collected verification information will be stored.
- **Control Flow**:
    - The function assigns the `microblock_info` and `in_poh_hash` to the corresponding fields in the `poh_verification_info` structure.
    - It initializes the `success` field of `poh_verification_info` to 0, indicating that the verification process has not yet been completed.
- **Output**: The function does not return a value, but it populates the `poh_verification_info` structure with the collected information for further verification processes.


---
### fd\_runtime\_microblock\_batch\_verify\_info\_collect<!-- {{#callable:fd_runtime_microblock_batch_verify_info_collect}} -->
The `fd_runtime_microblock_batch_verify_info_collect` function collects verification information for each microblock in a batch.
- **Inputs**:
    - `microblock_batch_info`: A pointer to a `fd_microblock_batch_info_t` structure that contains information about the batch of microblocks.
    - `in_poh_hash`: A pointer to a `fd_hash_t` structure representing the hash used in the Proof of History (PoH) verification.
    - `poh_verification_info`: A pointer to an array of `fd_poh_verification_info_t` structures where the collected verification information will be stored.
- **Control Flow**:
    - The function iterates over each microblock in the provided `microblock_batch_info`.
    - For each microblock, it retrieves the corresponding `fd_microblock_info_t` structure.
    - It calls the [`fd_runtime_microblock_verify_info_collect`](#fd_runtime_microblock_verify_info_collect) function to collect verification information for the current microblock, passing the current PoH hash and the corresponding verification info structure.
    - The PoH hash is updated to the hash of the current microblock's header after each iteration.
- **Output**: The function does not return a value; instead, it populates the `poh_verification_info` array with the collected verification information for each microblock.
- **Functions called**:
    - [`fd_runtime_microblock_verify_info_collect`](#fd_runtime_microblock_verify_info_collect)


---
### fd\_runtime\_block\_verify\_info\_collect<!-- {{#callable:fd_runtime_block_verify_info_collect}} -->
The `fd_runtime_block_verify_info_collect` function collects verification information for each microblock in a runtime block.
- **Inputs**:
    - `block_info`: A pointer to a `fd_runtime_block_info_t` structure that contains information about the block being verified.
    - `in_poh_hash`: A pointer to a `fd_hash_t` structure representing the hash used in the Proof of History (PoH) verification.
    - `poh_verification_info`: A pointer to an array of `fd_poh_verification_info_t` structures where the collected verification information will be stored.
- **Control Flow**:
    - Iterates over each microblock batch in the `block_info` structure using a for loop.
    - For each microblock batch, it calls the [`fd_runtime_microblock_batch_verify_info_collect`](#fd_runtime_microblock_batch_verify_info_collect) function to collect verification information.
    - Updates the `in_poh_hash` to the hash of the last microblock processed in the current batch.
    - Advances the pointer for `poh_verification_info` to store the next set of verification information.
- **Output**: The function does not return a value; instead, it populates the `poh_verification_info` array with collected verification data for each microblock.
- **Functions called**:
    - [`fd_runtime_microblock_batch_verify_info_collect`](#fd_runtime_microblock_batch_verify_info_collect)


---
### fd\_runtime\_poh\_verify\_wide\_task<!-- {{#callable:fd_runtime_poh_verify_wide_task}} -->
`fd_runtime_poh_verify_wide_task` verifies the proof of history (PoH) for a microblock by computing a hash and comparing it against the expected hash.
- **Inputs**:
    - `tpool`: A pointer to the thread pool used for executing tasks.
    - `m0`: An index used to access the `poh_info` structure in the thread pool.
    - `m1`: An unused parameter.
    - `args`: Unused parameter.
    - `reduce`: Unused parameter.
    - `stride`: Unused parameter.
    - `l0`: Unused parameter.
    - `l1`: Unused parameter.
    - `n0`: Unused parameter.
    - `n1`: Unused parameter.
- **Control Flow**:
    - The function retrieves the `poh_info` structure from the thread pool using the index `m0`.
    - It initializes `out_poh_hash` and `init_poh_hash_cpy` with the input PoH hash.
    - It checks if the microblock is a tick (i.e., has no transactions) and appends the hash count to `out_poh_hash` if true.
    - If there are transactions, it processes each transaction to collect signatures and appends them to a Merkle tree.
    - After processing, it computes the root of the Merkle tree and mixes it into `out_poh_hash`.
    - Finally, it compares the computed `out_poh_hash` with the expected hash from the microblock header and logs a warning if they do not match.
- **Output**: The function does not return a value but updates the `success` field in the `poh_info` structure to indicate whether the verification was successful or not.


---
### fd\_runtime\_poh\_verify\_tpool<!-- {{#callable:fd_runtime_poh_verify_tpool}} -->
The `fd_runtime_poh_verify_tpool` function verifies the proof of history (PoH) for a set of microblocks using a thread pool.
- **Inputs**:
    - `poh_verification_info`: A pointer to an array of `fd_poh_verification_info_t` structures containing information about the microblocks to verify.
    - `poh_verification_info_cnt`: The count of `fd_poh_verification_info_t` structures in the array.
    - `tpool`: A pointer to a thread pool (`fd_tpool_t`) used to execute the verification tasks concurrently.
- **Control Flow**:
    - The function calls `fd_tpool_exec_all_rrobin` to distribute the verification tasks across the available workers in the thread pool.
    - Each worker executes the `fd_runtime_poh_verify_wide_task` function, which processes each microblock and updates the PoH hash.
    - After all tasks are executed, the function checks the success status of each verification in the `poh_verification_info` array.
    - If any verification fails (indicated by a non-zero success value), the function returns -1; otherwise, it returns 0.
- **Output**: The function returns 0 if all verifications succeed, or -1 if any verification fails.


---
### fd\_runtime\_block\_verify\_tpool<!-- {{#callable:fd_runtime_block_verify_tpool}} -->
Verifies the integrity of a runtime block using a thread pool for concurrent processing.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context, which contains information about the current execution environment.
    - `block_info`: A pointer to the runtime block information structure that contains details about the block to be verified.
    - `in_poh_hash`: A pointer to the input proof of history hash that is used for verification.
    - `out_poh_hash`: A pointer to the output proof of history hash that will be populated with the result of the verification.
    - `tpool`: A pointer to the thread pool used for concurrent execution of verification tasks.
    - `runtime_spad`: A pointer to the scratchpad memory used for temporary allocations during the verification process.
- **Control Flow**:
    - The function begins by initializing a frame in the scratchpad memory.
    - It records the start time for block verification.
    - It allocates memory for temporary proof of history verification information based on the number of microblocks in the block.
    - It collects verification information for each microblock in the block.
    - It allocates memory for block data and verifies the ticks in the block.
    - If the tick verification fails, it logs a warning and returns an error.
    - It then calls another function to verify the proof of history using the thread pool.
    - The output proof of history hash is populated with the last microblock's hash.
    - Finally, it logs the elapsed time for the verification process and returns the result of the verification.
- **Output**: Returns an integer indicating the success or failure of the block verification process.
- **Functions called**:
    - [`fd_runtime_block_verify_info_collect`](#fd_runtime_block_verify_info_collect)
    - [`fd_runtime_block_verify_ticks`](#fd_runtime_block_verify_ticks)
    - [`fd_runtime_poh_verify_tpool`](#fd_runtime_poh_verify_tpool)


---
### fd\_runtime\_publish\_old\_txns<!-- {{#callable:fd_runtime_publish_old_txns}} -->
The `fd_runtime_publish_old_txns` function publishes transactions that are older than a specified number of slots.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context structure, which contains information about the current execution environment.
    - `capture_ctx`: A pointer to the capture context structure, which is used for checkpointing and capturing transaction data.
    - `tpool`: A pointer to the thread pool structure used for parallel execution of tasks.
    - `runtime_spad`: A pointer to the scratchpad memory used for temporary storage during execution.
- **Control Flow**:
    - The function starts a write transaction on the `funk` object to ensure atomicity during the publishing process.
    - If `capture_ctx` is not NULL, it calls [`fd_runtime_checkpt`](#fd_runtime_checkpt) to checkpoint the current state.
    - It initializes a variable `do_eah` to track whether to perform an EAH calculation later.
    - It iterates through the transaction pool, checking the depth of each transaction.
    - When the depth reaches a threshold (defined by `FD_RUNTIME_NUM_ROOT_BLOCKS`), it logs the transaction being published.
    - Depending on the state of the `status_cache`, it registers the transaction's slot as either a root or constipated slot.
    - If the `constipate_root` flag is set, it attempts to publish the transaction into its parent.
    - If the transaction meets certain conditions, it updates the `last_snapshot_slot` and sets the `constipate_root` flag.
    - Finally, it checks if the transaction's ID is greater than or equal to `eah_start_slot` and sets `do_eah` accordingly.
    - After finishing the transaction write, it performs the EAH calculation if necessary.
- **Output**: The function returns 0 upon successful completion, indicating that the transactions have been published without errors.
- **Functions called**:
    - [`fd_runtime_checkpt`](#fd_runtime_checkpt)
    - [`fd_txncache_get_is_constipated`](fd_txncache.c.driver.md#fd_txncache_get_is_constipated)
    - [`fd_txncache_register_root_slot`](fd_txncache.c.driver.md#fd_txncache_register_root_slot)
    - [`fd_txncache_register_constipated_slot`](fd_txncache.c.driver.md#fd_txncache_register_constipated_slot)
    - [`fd_runtime_is_epoch_boundary`](#fd_runtime_is_epoch_boundary)
    - [`fd_txncache_set_is_constipated`](fd_txncache.c.driver.md#fd_txncache_set_is_constipated)
    - [`fd_accounts_hash`](fd_hashes.c.driver.md#fd_accounts_hash)


---
### fd\_runtime\_block\_execute\_tpool<!-- {{#callable:fd_runtime_block_execute_tpool}} -->
The `fd_runtime_block_execute_tpool` function executes a block of transactions in a thread pool.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution context for the current slot.
    - `capture_ctx`: A pointer to the capture context, which may be used for logging or capturing transaction data.
    - `block_info`: A pointer to the block information structure containing details about the transactions to be executed.
    - `tpool`: A pointer to the thread pool used for executing transactions concurrently.
    - `exec_spads`: An array of pointers to SPADs (scratchpad memory) used for execution.
    - `exec_spad_cnt`: The count of execution SPADs available.
    - `runtime_spad`: A pointer to the runtime scratchpad used for temporary storage during execution.
- **Control Flow**:
    - Checks if the capture context is valid and sets the current slot in the capture context if applicable.
    - Records the start time for block execution.
    - Calls [`fd_runtime_block_execute_prepare`](#fd_runtime_block_execute_prepare) to prepare the execution context.
    - Allocates memory for transaction pointers based on the transaction count in the block info.
    - Collects transactions from the block info into the allocated transaction pointers.
    - Initializes a cost tracker if the feature is active.
    - Iterates over each microblock in the block info, executing transactions in each microblock using the thread pool.
    - Calls [`fd_runtime_process_txns_in_microblock_stream`](#fd_runtime_process_txns_in_microblock_stream) for each microblock to process transactions concurrently.
    - Finalizes the execution by calling [`fd_runtime_block_execute_finalize_para`](#fd_runtime_block_execute_finalize_para) to handle any post-execution tasks.
    - Logs the execution time and returns success or failure based on the execution results.
- **Output**: Returns `FD_RUNTIME_EXECUTE_SUCCESS` if the block is executed successfully, or an error code if any step fails.
- **Functions called**:
    - [`fd_runtime_block_execute_prepare`](#fd_runtime_block_execute_prepare)
    - [`fd_runtime_block_collect_txns`](#fd_runtime_block_collect_txns)
    - [`fd_cost_tracker_init`](fd_cost_tracker.c.driver.md#fd_cost_tracker_init)
    - [`fd_runtime_process_txns_in_microblock_stream`](#fd_runtime_process_txns_in_microblock_stream)
    - [`fd_runtime_block_execute_finalize_para`](#fd_runtime_block_execute_finalize_para)


---
### fd\_runtime\_block\_pre\_execute\_process\_new\_epoch<!-- {{#callable:fd_runtime_block_pre_execute_process_new_epoch}} -->
The `fd_runtime_block_pre_execute_process_new_epoch` function updates the block height, checks for epoch boundaries, and processes epoch transitions if necessary.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context structure, which holds the current state of the slot being processed.
    - `tpool`: A pointer to the thread pool used for parallel processing of tasks.
    - `exec_spads`: An array of pointers to execution scratchpad areas used for temporary data storage during execution.
    - `exec_spad_cnt`: The count of execution scratchpad areas available.
    - `runtime_spad`: A pointer to the runtime scratchpad area used for temporary data storage during the function execution.
    - `is_epoch_boundary`: A pointer to an integer that will be set to indicate whether the current slot is at an epoch boundary.
- **Control Flow**:
    - The function begins by incrementing the block height in the `slot_ctx` structure.
    - If the current slot is not zero, it checks if the current slot is at an epoch boundary by comparing the previous and current epochs.
    - If an epoch boundary is detected, it calls [`fd_runtime_process_new_epoch`](#fd_runtime_process_new_epoch) to handle the transition to the new epoch.
    - The function sets the `is_epoch_boundary` output parameter to indicate whether an epoch boundary was crossed.
    - If the current slot is not zero and certain features are active, it calls `fd_distribute_partitioned_epoch_rewards` to distribute rewards for the epoch.
- **Output**: The function does not return a value but modifies the `is_epoch_boundary` output parameter to indicate if the current slot is at an epoch boundary.
- **Functions called**:
    - [`fd_slot_to_epoch`](sysvar/fd_sysvar_epoch_schedule.c.driver.md#fd_slot_to_epoch)
    - [`fd_runtime_process_new_epoch`](#fd_runtime_process_new_epoch)


---
### fd\_runtime\_block\_eval\_tpool<!-- {{#callable:fd_runtime_block_eval_tpool}} -->
Evaluates a block in a thread pool context, processing transactions and managing state updates.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution context for the current slot, containing state and configuration.
    - `block`: A pointer to the block structure that contains the transactions to be evaluated.
    - `capture_ctx`: A pointer to the capture context for managing transaction capture and logging.
    - `tpool`: A pointer to the thread pool used for executing tasks concurrently.
    - `scheduler`: An unsigned long value representing the scheduler configuration (unused in this function).
    - `txn_cnt`: A pointer to an unsigned long where the count of transactions processed will be stored.
    - `exec_spads`: A double pointer to an array of execution scratchpad pointers used for temporary storage.
    - `exec_spad_cnt`: An unsigned long representing the count of execution scratchpads available.
    - `runtime_spad`: A pointer to the runtime scratchpad used for temporary allocations during execution.
- **Control Flow**:
    - The function begins by publishing any old transactions that need to be processed.
    - It initializes a new transaction context for the current block evaluation.
    - If the capture context is valid, it prepares to dump the block state for logging.
    - It checks if the current slot is at an epoch boundary and processes the new epoch if necessary.
    - The function prepares the block for execution by verifying its integrity and collecting transactions.
    - It executes the transactions in the block using the thread pool, handling any errors that arise.
    - Finally, it logs the evaluation results and updates the slot context for the next slot.
- **Output**: Returns 0 on successful evaluation of the block, or an error code indicating the failure reason.
- **Functions called**:
    - [`fd_runtime_publish_old_txns`](#fd_runtime_publish_old_txns)
    - [`fd_dump_block_to_protobuf`](tests/fd_dump_pb.c.driver.md#fd_dump_block_to_protobuf)
    - [`fd_runtime_block_pre_execute_process_new_epoch`](#fd_runtime_block_pre_execute_process_new_epoch)
    - [`fd_runtime_block_prepare`](#fd_runtime_block_prepare)
    - [`fd_runtime_block_verify_tpool`](#fd_runtime_block_verify_tpool)
    - [`fd_dump_block_to_protobuf_tx_only`](tests/fd_dump_pb.c.driver.md#fd_dump_block_to_protobuf_tx_only)
    - [`fd_runtime_block_execute_tpool`](#fd_runtime_block_execute_tpool)
    - [`fd_runtime_save_slot_bank`](fd_runtime_init.c.driver.md#fd_runtime_save_slot_bank)


---
### fd\_runtime\_checkpt<!-- {{#callable:fd_runtime_checkpt}} -->
The `fd_runtime_checkpt` function performs a checkpoint operation based on the current slot and capture context.
- **Inputs**:
    - `capture_ctx`: A pointer to the `fd_capture_ctx_t` structure that contains context for capturing state, including checkpoint frequency and path.
    - `slot_ctx`: A pointer to the `fd_exec_slot_ctx_t` structure that holds execution context for the current slot.
    - `slot`: An unsigned long integer representing the current slot number.
- **Control Flow**:
    - The function first checks if the `capture_ctx` is not NULL and if the current `slot` is a multiple of the checkpoint frequency defined in `capture_ctx`.
    - It also checks if the `slot` is equal to `ULONG_MAX`, which indicates an abort condition.
    - If neither condition is met, the function returns early without performing any actions.
    - If the `checkpt_path` in `capture_ctx` is not NULL, it logs a notice indicating the checkpointing action, either at the current slot or after a mismatch.
    - The function then attempts to unlink (delete) the existing checkpoint file at the specified path.
    - Finally, it calls the `fd_wksp_checkpt` function to perform the actual checkpoint operation, passing the workspace and the checkpoint path, and logs an error if the operation fails.
- **Output**: The function does not return a value; it performs side effects such as logging and file operations.


