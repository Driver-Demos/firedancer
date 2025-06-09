# Purpose
The provided C source code file is part of a larger system that appears to be related to executing and managing transactions in a blockchain or distributed ledger environment. The file includes a variety of headers and implements functions that handle transaction execution, account management, and validation processes. It defines structures and functions for looking up and executing native programs, verifying transaction signatures, managing account states, and calculating transaction fees. The code is structured to interact with a broader system, likely involving multiple components such as account databases, transaction caches, and runtime environments.

Key components of the code include the [`fd_executor_lookup_native_program`](#fd_executor_lookup_native_program) function, which determines the appropriate instruction processor for a given program ID, and the [`fd_executor_check_transactions`](#fd_executor_check_transactions) function, which validates transactions against a status cache. The file also implements mechanisms for handling account rent states, ensuring that accounts meet certain conditions before and after transactions. Additionally, the code includes logic for managing instruction execution stacks, verifying precompiled programs, and calculating transaction fees based on various parameters. Overall, the file provides a comprehensive set of functionalities for executing and validating transactions within a distributed ledger system, with a focus on ensuring correctness and efficiency.
# Imports and Dependencies

---
- `fd_executor.h`
- `context/fd_exec_epoch_ctx.h`
- `fd_acc_mgr.h`
- `fd_hashes.h`
- `fd_runtime.h`
- `fd_runtime_err.h`
- `context/fd_exec_slot_ctx.h`
- `context/fd_exec_txn_ctx.h`
- `context/fd_exec_instr_ctx.h`
- `../../util/rng/fd_rng.h`
- `fd_system_ids.h`
- `program/fd_address_lookup_table_program.h`
- `program/fd_bpf_loader_program.h`
- `program/fd_loader_v4_program.h`
- `program/fd_compute_budget_program.h`
- `program/fd_config_program.h`
- `program/fd_precompiles.h`
- `program/fd_stake_program.h`
- `program/fd_system_program.h`
- `program/fd_vote_program.h`
- `program/fd_zk_elgamal_proof_program.h`
- `program/fd_bpf_program_util.h`
- `sysvar/fd_sysvar_slot_history.h`
- `sysvar/fd_sysvar_epoch_schedule.h`
- `sysvar/fd_sysvar_instructions.h`
- `sysvar/fd_sysvar_slot_hashes.h`
- `sysvar/fd_sysvar_rent.h`
- `tests/fd_dump_pb.h`
- `../../ballet/base58/fd_base58.h`
- `../../disco/pack/fd_pack.h`
- `../../disco/pack/fd_pack_cost.h`
- `../../util/bits/fd_uwide.h`
- `assert.h`
- `math.h`
- `stdio.h`
- `fcntl.h`
- `unistd.h`
- `time.h`
- `../../util/tmpl/fd_map_perfect.c`


# Data Structures

---
### fd\_native\_prog\_info
- **Type**: `struct`
- **Members**:
    - `key`: A public key associated with the native program.
    - `fn`: A function pointer to the execution function for the native program.
- **Description**: The `fd_native_prog_info` structure is used to store information about a native program, specifically its associated public key and the function that executes the program. This structure is part of a system that manages and executes native programs, allowing for efficient lookup and execution of program functions based on their public keys.


---
### fd\_native\_prog\_info\_t
- **Type**: `struct`
- **Members**:
    - `key`: A public key of type `fd_pubkey_t` associated with the native program.
    - `fn`: A function pointer of type `fd_exec_instr_fn_t` that points to the instruction execution function for the native program.
- **Description**: The `fd_native_prog_info_t` structure is used to store information about native programs, specifically in the context of a program execution environment. It contains a public key (`key`) that uniquely identifies the native program and a function pointer (`fn`) that points to the function responsible for executing instructions associated with that program. This structure is integral to the execution of native programs, allowing for the dynamic lookup and invocation of program-specific execution functions based on the program's public key.


# Functions

---
### fd\_executor\_lookup\_native\_precompile\_program<!-- {{#callable:fd_executor_lookup_native_precompile_program}} -->
The function `fd_executor_lookup_native_precompile_program` retrieves the execution function for a given native precompile program based on its public key.
- **Inputs**:
    - `prog_acc`: A pointer to a `fd_txn_account_t` structure representing the program account, which contains the public key of the program to be looked up.
- **Control Flow**:
    - Extract the public key from the provided program account structure.
    - Define a `null_function` of type `fd_native_prog_info_t` initialized to zero.
    - Call `fd_native_precompile_program_fn_lookup_tbl_query` with the public key and `null_function` to retrieve the corresponding function pointer.
    - Return the function pointer from the lookup table query result.
- **Output**: Returns a function pointer of type `fd_exec_instr_fn_t` corresponding to the native precompile program associated with the given public key, or a null function if not found.


---
### fd\_executor\_lookup\_native\_program<!-- {{#callable:fd_executor_lookup_native_program}} -->
The `fd_executor_lookup_native_program` function determines the appropriate instruction processor for a given native program ID, checking if it is a precompile or a native program, and returns an error if the program ID is unsupported.
- **Inputs**:
    - `prog_acc`: A pointer to a `fd_txn_account_t` structure representing the program account to be checked.
    - `txn_ctx`: A pointer to a `fd_exec_txn_ctx_t` structure representing the transaction context.
    - `native_prog_fn`: A pointer to a `fd_exec_instr_fn_t` where the function will store the found native program function, if any.
    - `is_precompile`: A pointer to an `uchar` where the function will store whether the program is a precompile (1) or not (0).
- **Control Flow**:
    - Initialize `is_precompile` to 0 and attempt to find a precompile function using [`fd_executor_lookup_native_precompile_program`](#fd_executor_lookup_native_precompile_program).
    - If a precompile function is found, set `is_precompile` to 1 and return 0.
    - Retrieve the program's public key and owner from `prog_acc`.
    - Check if the program is owned by the native loader to determine if it is a native program.
    - If the program is not native and a specific feature is active, check if the owner matches any known BPF loader IDs; return an error if not.
    - Determine the lookup key based on whether the program is native or not, and query the native program function lookup table.
    - Store the found function in `native_prog_fn` and return 0.
- **Output**: Returns 0 on success, indicating that a native program function was found, or an error code if the program ID is unsupported.
- **Functions called**:
    - [`fd_executor_lookup_native_precompile_program`](#fd_executor_lookup_native_precompile_program)


---
### fd\_executor\_is\_system\_nonce\_account<!-- {{#callable:fd_executor_is_system_nonce_account}} -->
The function `fd_executor_is_system_nonce_account` checks if a given account is a valid and initialized system nonce account.
- **Inputs**:
    - `account`: A pointer to an `fd_txn_account_t` structure representing the account to be checked.
    - `exec_spad`: A pointer to an `fd_spad_t` structure used for decoding and processing the account's data.
- **Control Flow**:
    - The function first checks if the account's owner matches the Solana system program ID.
    - If the account's data length is zero, it returns 0, indicating the account is not a nonce account.
    - If the data length is not equal to `FD_SYSTEM_PROGRAM_NONCE_DLEN`, it returns -1, indicating an invalid nonce account.
    - The function decodes the account's data into `fd_nonce_state_versions_t` using `fd_bincode_decode_spad`.
    - If decoding fails, it returns -1.
    - It checks if the decoded nonce state is current or legacy and assigns the appropriate state.
    - If the nonce state is initialized, it returns 1, indicating a valid nonce account.
    - If none of the conditions are met, it returns -1.
- **Output**: The function returns 1 if the account is a valid and initialized system nonce account, 0 if it is not a nonce account, and -1 if it is invalid or an error occurs.


---
### fd\_executor\_rent\_transition\_allowed<!-- {{#callable:fd_executor_rent_transition_allowed}} -->
The `fd_executor_rent_transition_allowed` function determines if a transition between two rent states is permissible based on specific conditions.
- **Inputs**:
    - `pre_rent_state`: A pointer to the initial rent state (`fd_rent_state_t`) before the transition.
    - `post_rent_state`: A pointer to the rent state (`fd_rent_state_t`) after the transition.
- **Control Flow**:
    - The function checks the `discriminant` of the `post_rent_state` to determine the type of rent state transition.
    - If the `post_rent_state` is either `fd_rent_state_enum_uninitialized` or `fd_rent_state_enum_rent_exempt`, the function returns 1, indicating the transition is allowed.
    - If the `post_rent_state` is `fd_rent_state_enum_rent_paying`, it further checks the `discriminant` of the `pre_rent_state`.
    - If the `pre_rent_state` is `fd_rent_state_enum_uninitialized` or `fd_rent_state_enum_rent_exempt`, the function returns 0, indicating the transition is not allowed.
    - If both `pre_rent_state` and `post_rent_state` are `fd_rent_state_enum_rent_paying`, it checks if the `data_size` is the same and if the `lamports` in `post_rent_state` are less than or equal to those in `pre_rent_state`, returning the result of this condition.
    - The function uses `__builtin_unreachable()` for default cases, indicating that these cases should never occur.
- **Output**: The function returns an `uchar` (unsigned char) indicating whether the rent state transition is allowed (1) or not (0).


---
### fd\_executor\_check\_rent\_state\_with\_account<!-- {{#callable:fd_executor_check_rent_state_with_account}} -->
The function `fd_executor_check_rent_state_with_account` checks if the rent state transition of an account is valid and returns an error code if it is not.
- **Inputs**:
    - `account`: A pointer to a `fd_txn_account_t` structure representing the account whose rent state transition is being checked.
    - `pre_rent_state`: A pointer to a `fd_rent_state_t` structure representing the rent state of the account before the transaction.
    - `post_rent_state`: A pointer to a `fd_rent_state_t` structure representing the rent state of the account after the transaction.
- **Control Flow**:
    - The function first checks if the account's public key matches the incinerator ID using `memcmp` and if the rent transition is not allowed using [`fd_executor_rent_transition_allowed`](#fd_executor_rent_transition_allowed).
    - If both conditions are true, it returns the error code `FD_RUNTIME_TXN_ERR_INSUFFICIENT_FUNDS_FOR_RENT`.
    - If the conditions are not met, it returns `FD_RUNTIME_EXECUTE_SUCCESS`.
- **Output**: The function returns an integer error code: `FD_RUNTIME_TXN_ERR_INSUFFICIENT_FUNDS_FOR_RENT` if the rent state transition is invalid, or `FD_RUNTIME_EXECUTE_SUCCESS` if it is valid.
- **Functions called**:
    - [`fd_executor_rent_transition_allowed`](#fd_executor_rent_transition_allowed)


---
### fd\_executor\_get\_account\_rent\_state<!-- {{#callable:fd_executor_get_account_rent_state}} -->
The function `fd_executor_get_account_rent_state` determines the rent state of a given account based on its lamports and data size in relation to rent exemption criteria.
- **Inputs**:
    - `account`: A pointer to an `fd_txn_account_t` structure representing the account whose rent state is to be determined.
    - `rent`: A pointer to an `fd_rent_t` structure containing rent-related parameters used to determine rent exemption.
- **Control Flow**:
    - Check if the account's lamports are zero; if true, return a rent state indicating the account is uninitialized.
    - Check if the account's lamports are greater than or equal to the rent-exempt minimum balance for the account's data size; if true, return a rent state indicating the account is rent-exempt.
    - If neither condition is met, return a rent state indicating the account is rent-paying, including the current lamports and data size.
- **Output**: Returns an `fd_rent_state_t` structure representing the rent state of the account, which can be uninitialized, rent-exempt, or rent-paying.
- **Functions called**:
    - [`fd_rent_exempt_minimum_balance`](sysvar/fd_sysvar_rent1.c.driver.md#fd_rent_exempt_minimum_balance)


---
### fd\_validate\_fee\_payer<!-- {{#callable:fd_validate_fee_payer}} -->
The `fd_validate_fee_payer` function checks if a transaction's fee payer account has sufficient funds and is valid for fee deduction.
- **Inputs**:
    - `account`: A pointer to an `fd_txn_account_t` structure representing the account to be validated as the fee payer.
    - `rent`: A constant pointer to an `fd_rent_t` structure containing rent-related information.
    - `fee`: An unsigned long integer representing the fee amount to be deducted from the account.
    - `exec_spad`: A pointer to an `fd_spad_t` structure used for execution context.
- **Control Flow**:
    - Check if the account has zero lamports and return `FD_RUNTIME_TXN_ERR_ACCOUNT_NOT_FOUND` if true.
    - Determine if the account is a system nonce account using [`fd_executor_is_system_nonce_account`](#fd_executor_is_system_nonce_account) and return `FD_RUNTIME_TXN_ERR_INVALID_ACCOUNT_FOR_FEE` if invalid.
    - Calculate the minimum balance required if the account is a nonce account.
    - Check if the account has sufficient lamports to cover both the minimum balance and the fee; return `FD_RUNTIME_TXN_ERR_INSUFFICIENT_FUNDS_FOR_FEE` if not.
    - Retrieve the account's rent state before fee deduction using [`fd_executor_get_account_rent_state`](#fd_executor_get_account_rent_state).
    - Attempt to deduct the fee from the account's lamports using `checked_sub_lamports`; return `FD_RUNTIME_TXN_ERR_INSUFFICIENT_FUNDS_FOR_FEE` if unsuccessful.
    - Retrieve the account's rent state after fee deduction.
    - Check the rent state transition using [`fd_executor_check_rent_state_with_account`](#fd_executor_check_rent_state_with_account) and return the result.
- **Output**: Returns an integer status code indicating success or a specific error related to account validation or fee deduction.
- **Functions called**:
    - [`fd_executor_is_system_nonce_account`](#fd_executor_is_system_nonce_account)
    - [`fd_rent_exempt_minimum_balance`](sysvar/fd_sysvar_rent1.c.driver.md#fd_rent_exempt_minimum_balance)
    - [`fd_executor_get_account_rent_state`](#fd_executor_get_account_rent_state)
    - [`fd_executor_check_rent_state_with_account`](#fd_executor_check_rent_state_with_account)


---
### status\_check\_tower<!-- {{#callable:status_check_tower}} -->
The `status_check_tower` function checks if a given slot is valid based on the current transaction context and slot history.
- **Inputs**:
    - `slot`: An unsigned long integer representing the slot number to be checked.
    - `_ctx`: A pointer to a context object, specifically of type `fd_exec_txn_ctx_t`, which contains transaction-related data.
- **Control Flow**:
    - Cast the `_ctx` pointer to a `fd_exec_txn_ctx_t` type and store it in `ctx`.
    - Check if the `slot` is equal to `ctx->slot`; if true, return 1 indicating the slot is valid.
    - Check if the `slot` is rooted in `ctx->status_cache` using `fd_txncache_is_rooted_slot`; if true, return 1.
    - Read the slot history using [`fd_sysvar_slot_history_read`](sysvar/fd_sysvar_slot_history.c.driver.md#fd_sysvar_slot_history_read) and store it in `slot_history`.
    - If `slot_history` is NULL, log an error and exit.
    - Check if the `slot` is found in `slot_history` using [`fd_sysvar_slot_history_find_slot`](sysvar/fd_sysvar_slot_history.c.driver.md#fd_sysvar_slot_history_find_slot); if found, return 1.
    - If none of the above conditions are met, return 0 indicating the slot is not valid.
- **Output**: Returns an integer, 1 if the slot is valid according to the checks, otherwise 0.
- **Functions called**:
    - [`fd_sysvar_slot_history_read`](sysvar/fd_sysvar_slot_history.c.driver.md#fd_sysvar_slot_history_read)
    - [`fd_sysvar_slot_history_find_slot`](sysvar/fd_sysvar_slot_history.c.driver.md#fd_sysvar_slot_history_find_slot)


---
### fd\_executor\_check\_status\_cache<!-- {{#callable:fd_executor_check_status_cache}} -->
The `fd_executor_check_status_cache` function checks the status cache for a transaction context and returns an error code based on the cache query result.
- **Inputs**:
    - `txn_ctx`: A pointer to a `fd_exec_txn_ctx_t` structure representing the transaction context, which contains information about the transaction and its execution environment.
- **Control Flow**:
    - Check if the `status_cache` in `txn_ctx` is NULL; if so, return `FD_RUNTIME_EXECUTE_SUCCESS`.
    - Retrieve the blockhash from the transaction's raw data using the offset specified in the transaction descriptor.
    - Initialize a `fd_txncache_query_t` structure with the blockhash and compute the Blake3 hash of the transaction message.
    - Perform a batch query on the status cache using the `fd_txncache_query_batch` function, passing the query, transaction context, and a callback function `status_check_tower`.
    - Return the error code from the cache query operation.
- **Output**: Returns an integer error code indicating the result of the status cache check, where `FD_RUNTIME_EXECUTE_SUCCESS` indicates success and other values indicate specific errors.


---
### fd\_executor\_check\_transactions<!-- {{#callable:fd_executor_check_transactions}} -->
The `fd_executor_check_transactions` function verifies the validity of transactions by checking their age and status cache.
- **Inputs**:
    - `txn_ctx`: A pointer to an `fd_exec_txn_ctx_t` structure representing the transaction context to be checked.
- **Control Flow**:
    - Call [`fd_check_transaction_age`](program/fd_system_program_nonce.c.driver.md#fd_check_transaction_age) with `txn_ctx` to verify the transaction's age.
    - If the age check fails, return the error code from [`fd_check_transaction_age`](program/fd_system_program_nonce.c.driver.md#fd_check_transaction_age).
    - Call [`fd_executor_check_status_cache`](#fd_executor_check_status_cache) with `txn_ctx` to verify the transaction's status cache.
    - If the status cache check fails, return the error code from [`fd_executor_check_status_cache`](#fd_executor_check_status_cache).
    - If both checks pass, return `FD_RUNTIME_EXECUTE_SUCCESS`.
- **Output**: Returns an integer indicating success (`FD_RUNTIME_EXECUTE_SUCCESS`) or an error code if any of the checks fail.
- **Functions called**:
    - [`fd_check_transaction_age`](program/fd_system_program_nonce.c.driver.md#fd_check_transaction_age)
    - [`fd_executor_check_status_cache`](#fd_executor_check_status_cache)


---
### fd\_executor\_verify\_precompiles<!-- {{#callable:fd_executor_verify_precompiles}} -->
The `fd_executor_verify_precompiles` function verifies the execution of precompiled programs within a transaction context.
- **Inputs**:
    - `txn_ctx`: A pointer to an `fd_exec_txn_ctx_t` structure representing the transaction context, which contains transaction details and execution state.
- **Control Flow**:
    - Initialize `instr_cnt` with the number of instructions in the transaction and `err` to 0.
    - Iterate over each instruction in the transaction using a for loop.
    - For each instruction, retrieve the instruction information and the associated program account.
    - Look up the precompile function for the program account using [`fd_executor_lookup_native_precompile_program`](#fd_executor_lookup_native_precompile_program).
    - Check if the precompile function is NULL or if the program is a feature-gated precompile that is not active; if so, continue to the next instruction.
    - Create a mock instruction context `instr_ctx` with the current transaction context and instruction.
    - Invoke the precompile function with `instr_ctx` and check for errors.
    - If an error occurs, log the error and return `FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR`.
    - If all instructions are processed without errors, return `FD_RUNTIME_EXECUTE_SUCCESS`.
- **Output**: Returns an integer status code: `FD_RUNTIME_EXECUTE_SUCCESS` if all precompiles are verified successfully, or `FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR` if an error occurs during precompile execution.
- **Functions called**:
    - [`fd_executor_lookup_native_precompile_program`](#fd_executor_lookup_native_precompile_program)


---
### fd\_executor\_setup\_instr\_infos\_from\_txn\_instrs<!-- {{#callable:fd_executor_setup_instr_infos_from_txn_instrs}} -->
The function `fd_executor_setup_instr_infos_from_txn_instrs` initializes instruction information structures for a transaction based on its transaction descriptor.
- **Inputs**:
    - `txn_ctx`: A pointer to a `fd_exec_txn_ctx_t` structure representing the transaction context, which contains the transaction descriptor and will store the initialized instruction information.
- **Control Flow**:
    - Retrieve the instruction count from the transaction descriptor within the transaction context.
    - Iterate over each instruction in the transaction descriptor.
    - For each instruction, initialize the corresponding instruction information structure in the transaction context using [`fd_instr_info_init_from_txn_instr`](info/fd_instr_info.c.driver.md#fd_instr_info_init_from_txn_instr).
    - Set the instruction information count in the transaction context to the number of instructions processed.
- **Output**: The function does not return a value; it modifies the `txn_ctx` structure in place to set up instruction information.
- **Functions called**:
    - [`fd_instr_info_init_from_txn_instr`](info/fd_instr_info.c.driver.md#fd_instr_info_init_from_txn_instr)


---
### accumulate\_and\_check\_loaded\_account\_data\_size<!-- {{#callable:accumulate_and_check_loaded_account_data_size}} -->
The function `accumulate_and_check_loaded_account_data_size` adds a given account size to an accumulated size and checks if it exceeds a specified limit, returning an error code if it does.
- **Inputs**:
    - `acc_size`: The size of the account data to be added to the accumulated size.
    - `requested_loaded_accounts_data_size`: The maximum allowed size for the accumulated account data.
    - `accumulated_account_size`: A pointer to the current accumulated size of account data, which will be updated by the function.
- **Control Flow**:
    - The function begins by adding `acc_size` to the value pointed to by `accumulated_account_size` using the `fd_ulong_sat_add` function, which performs a saturated addition to prevent overflow.
    - It then checks if the updated `accumulated_account_size` exceeds `requested_loaded_accounts_data_size`.
    - If the accumulated size exceeds the requested size, the function returns the error code `FD_RUNTIME_TXN_ERR_MAX_LOADED_ACCOUNTS_DATA_SIZE_EXCEEDED`.
    - If the accumulated size is within the limit, the function returns `FD_RUNTIME_EXECUTE_SUCCESS`.
- **Output**: The function returns an integer status code: `FD_RUNTIME_EXECUTE_SUCCESS` if the accumulated size is within the limit, or `FD_RUNTIME_TXN_ERR_MAX_LOADED_ACCOUNTS_DATA_SIZE_EXCEEDED` if it exceeds the limit.


---
### load\_transaction\_account<!-- {{#callable:load_transaction_account}} -->
The `load_transaction_account` function handles loading a transaction account, collecting rent if applicable, and processing sysvar instructions.
- **Inputs**:
    - `txn_ctx`: A pointer to the transaction context (`fd_exec_txn_ctx_t`) which contains information about the current transaction being processed.
    - `acct`: A pointer to the transaction account (`fd_txn_account_t`) that needs to be loaded or processed.
    - `is_writable`: An unsigned character indicating whether the account is writable (non-zero) or not (zero).
    - `epoch`: An unsigned long integer representing the current epoch, used for rent calculations.
    - `unknown_acc`: An unsigned character indicating whether the account is unknown (non-zero) or known (zero).
- **Control Flow**:
    - Check if the account is the sysvar instructions account by comparing its public key with `fd_sysvar_instructions_id.key`.
    - If it is the sysvar instructions account, serialize the account using [`fd_sysvar_instructions_serialize_account`](sysvar/fd_sysvar_instructions.c.driver.md#fd_sysvar_instructions_serialize_account) and return.
    - If the account is not unknown, check if it is writable.
    - If the account is writable, collect rent from it using [`fd_runtime_collect_rent_from_account`](fd_runtime.c.driver.md#fd_runtime_collect_rent_from_account) and update its starting lamports.
    - Return after processing a known account.
    - If the account is unknown, the function does nothing further as unknown accounts are already set up elsewhere.
- **Output**: The function does not return a value; it performs operations on the transaction context and account in place.
- **Functions called**:
    - [`fd_sysvar_instructions_serialize_account`](sysvar/fd_sysvar_instructions.c.driver.md#fd_sysvar_instructions_serialize_account)
    - [`fd_runtime_collect_rent_from_account`](fd_runtime.c.driver.md#fd_runtime_collect_rent_from_account)


---
### fd\_executor\_load\_transaction\_accounts<!-- {{#callable:fd_executor_load_transaction_accounts}} -->
The `fd_executor_load_transaction_accounts` function loads transaction accounts, checks their validity, and accumulates their data sizes for execution in a transaction context.
- **Inputs**:
    - `txn_ctx`: A pointer to the transaction context (`fd_exec_txn_ctx_t`) which contains information about the transaction, including accounts, slots, and other execution parameters.
- **Control Flow**:
    - Initialize the requested loaded accounts data size from the transaction context.
    - Read the epoch schedule sysvar and calculate the current epoch based on the transaction's slot.
    - Iterate over each account in the transaction context to load and validate them.
    - For each account, determine if it is unknown, calculate its size, and check if it is writable.
    - If the account is the fee payer, accumulate its data size and continue to the next account.
    - For other accounts, load the transaction account and accumulate its data size, returning an error if the size exceeds the limit.
    - Initialize a list to track validated loaders for instruction accounts.
    - Iterate over each instruction in the transaction to handle special cases for loading instruction accounts.
    - For each instruction, check if the program ID matches the native loader and skip if it does.
    - Load the program account for the instruction and check its validity, returning errors for invalid accounts or programs.
    - Check if the program account's owner has been seen before to avoid duplicate checks and size accumulation.
    - Accumulate the owner's data size for program accounts, ensuring no double counting of repeated owners.
    - Return success if all accounts and instructions are loaded and validated successfully.
- **Output**: Returns an integer status code indicating success (`FD_RUNTIME_EXECUTE_SUCCESS`) or an error code if any validation or loading step fails.
- **Functions called**:
    - [`fd_sysvar_epoch_schedule_read`](sysvar/fd_sysvar_epoch_schedule.c.driver.md#fd_sysvar_epoch_schedule_read)
    - [`fd_slot_to_epoch`](sysvar/fd_sysvar_epoch_schedule.c.driver.md#fd_slot_to_epoch)
    - [`fd_exec_txn_ctx_get_account_at_index`](context/fd_exec_txn_ctx.c.driver.md#fd_exec_txn_ctx_get_account_at_index)
    - [`fd_exec_txn_ctx_account_is_writable_idx`](context/fd_exec_txn_ctx.c.driver.md#fd_exec_txn_ctx_account_is_writable_idx)
    - [`accumulate_and_check_loaded_account_data_size`](#accumulate_and_check_loaded_account_data_size)
    - [`load_transaction_account`](#load_transaction_account)
    - [`fd_txn_account_init_from_funk_readonly`](fd_txn_account.c.driver.md#fd_txn_account_init_from_funk_readonly)


---
### fd\_executor\_validate\_account\_locks<!-- {{#callable:fd_executor_validate_account_locks}} -->
The function `fd_executor_validate_account_locks` checks if the number of account keys in a transaction exceeds a predefined limit and ensures there are no duplicate account keys.
- **Inputs**:
    - `txn_ctx`: A pointer to a constant `fd_exec_txn_ctx_t` structure representing the transaction context, which contains information about the transaction being processed, including account keys and their count.
- **Control Flow**:
    - Retrieve the transaction account lock limit using [`get_transaction_account_lock_limit`](fd_executor.h.driver.md#get_transaction_account_lock_limit) with `txn_ctx` as input.
    - Check if the number of accounts (`txn_ctx->accounts_cnt`) exceeds the transaction account lock limit; if so, return `FD_RUNTIME_TXN_ERR_TOO_MANY_ACCOUNT_LOCKS`.
    - Iterate over each account key in `txn_ctx->account_keys` to check for duplicates.
    - For each pair of account keys, compare them using `memcmp`; if any two keys are identical, return `FD_RUNTIME_TXN_ERR_ACCOUNT_LOADED_TWICE`.
    - If no errors are found, return `FD_RUNTIME_EXECUTE_SUCCESS`.
- **Output**: The function returns an integer status code: `FD_RUNTIME_TXN_ERR_TOO_MANY_ACCOUNT_LOCKS` if the account count exceeds the limit, `FD_RUNTIME_TXN_ERR_ACCOUNT_LOADED_TWICE` if duplicate account keys are found, or `FD_RUNTIME_EXECUTE_SUCCESS` if validation passes.
- **Functions called**:
    - [`get_transaction_account_lock_limit`](fd_executor.h.driver.md#get_transaction_account_lock_limit)


---
### compute\_priority\_fee<!-- {{#callable:compute_priority_fee}} -->
The `compute_priority_fee` function calculates the priority fee and total fee for a transaction based on its prioritization fee type and compute unit limits.
- **Inputs**:
    - `txn_ctx`: A constant pointer to a `fd_exec_txn_ctx_t` structure containing transaction context information, including prioritization fee type, compute unit price, and compute unit limit.
    - `fee`: A pointer to an unsigned long where the computed fee will be stored.
    - `priority`: A pointer to an unsigned long where the computed priority fee will be stored.
- **Control Flow**:
    - The function begins by checking the `prioritization_fee_type` from the `txn_ctx` structure.
    - If the fee type is `FD_COMPUTE_BUDGET_PRIORITIZATION_FEE_TYPE_DEPRECATED`, it checks if `compute_unit_limit` is zero; if so, it sets `priority` to zero.
    - If `compute_unit_limit` is not zero, it calculates `micro_lamport_fee` as the product of `compute_unit_price` and `MICRO_LAMPORTS_PER_LAMPORT`, then computes `_priority` as `micro_lamport_fee` divided by `compute_unit_limit`, and assigns `priority` the lesser of `_priority` and `ULONG_MAX`.
    - It sets `fee` to `compute_unit_price` and returns.
    - If the fee type is `FD_COMPUTE_BUDGET_PRIORITIZATION_FEE_TYPE_COMPUTE_UNIT_PRICE`, it calculates `micro_lamport_fee` as the product of `compute_unit_price` and `compute_unit_limit`, sets `priority` to `compute_unit_price`, and computes `_fee` as `micro_lamport_fee` divided by `MICRO_LAMPORTS_PER_LAMPORT`, rounding up.
    - It assigns `fee` the lesser of `_fee` and `ULONG_MAX` and returns.
    - If the fee type is not recognized, it calls `__builtin_unreachable()` indicating an unexpected code path.
- **Output**: The function outputs the calculated `fee` and `priority` values through the pointers provided as arguments.


---
### fd\_executor\_lamports\_per\_signature<!-- {{#callable:fd_executor_lamports_per_signature}} -->
The function `fd_executor_lamports_per_signature` calculates the fee in lamports per signature by halving the target lamports per signature from the fee rate governor.
- **Inputs**:
    - `fee_rate_governor`: A pointer to a constant `fd_fee_rate_governor_t` structure that contains the target lamports per signature.
- **Control Flow**:
    - The function takes a single input, `fee_rate_governor`, which is a pointer to a structure containing the target lamports per signature.
    - It accesses the `target_lamports_per_signature` field of the `fee_rate_governor` structure.
    - The function returns the result of dividing `target_lamports_per_signature` by 2.
- **Output**: The function returns an unsigned long integer representing half of the target lamports per signature.


---
### fd\_executor\_calculate\_fee<!-- {{#callable:fd_executor_calculate_fee}} -->
The `fd_executor_calculate_fee` function calculates the execution and priority fees for a transaction based on its context, descriptor, and raw data.
- **Inputs**:
    - `txn_ctx`: A pointer to the transaction context (`fd_exec_txn_ctx_t`) which contains information about the transaction execution environment.
    - `txn_descriptor`: A constant pointer to the transaction descriptor (`fd_txn_t`) which provides details about the transaction, such as the number of signatures and instructions.
    - `txn_raw`: A constant pointer to the raw transaction data (`fd_rawtxn_b_t`) which contains the raw bytes of the transaction.
    - `ret_execution_fee`: A pointer to an unsigned long where the calculated execution fee will be stored.
    - `ret_priority_fee`: A pointer to an unsigned long where the calculated priority fee will be stored.
- **Control Flow**:
    - Initialize `priority` and `priority_fee` to zero and call [`compute_priority_fee`](#compute_priority_fee) to calculate the priority fee based on the transaction context.
    - Initialize `num_signatures` with the number of signatures from the transaction descriptor.
    - Iterate over each instruction in the transaction descriptor to check if the program ID matches specific cryptographic program IDs, and if so, adjust `num_signatures` based on the instruction data.
    - Calculate `signature_fee` by multiplying the number of signatures by the lamports per signature obtained from the transaction context's fee rate governor.
    - Calculate `write_lock_fee` as zero since `lamports_per_write_lock` is set to zero.
    - Compute `execution_fee` as the sum of `signature_fee` and `write_lock_fee`, and ensure it does not exceed `ULONG_MAX`.
    - Set `ret_execution_fee` to `execution_fee` and `ret_priority_fee` to `priority_fee`, ensuring neither exceeds `ULONG_MAX`.
- **Output**: The function outputs the calculated execution fee and priority fee through the pointers `ret_execution_fee` and `ret_priority_fee`, respectively.
- **Functions called**:
    - [`compute_priority_fee`](#compute_priority_fee)
    - [`fd_executor_lamports_per_signature`](#fd_executor_lamports_per_signature)


---
### fd\_executor\_create\_rollback\_fee\_payer\_account<!-- {{#callable:fd_executor_create_rollback_fee_payer_account}} -->
The function `fd_executor_create_rollback_fee_payer_account` sets up a rollback account for the fee payer in a transaction, ensuring that transaction fees can be deducted and the account state can be restored if necessary.
- **Inputs**:
    - `txn_ctx`: A pointer to the transaction context (`fd_exec_txn_ctx_t`) which contains information about the transaction, including accounts and their states.
    - `total_fee`: An unsigned long integer representing the total fee to be deducted from the fee payer's account.
- **Control Flow**:
    - Retrieve the fee payer account from the transaction context using a predefined index.
    - Check if the fee payer is also the nonce account; if so, use the rollback nonce account and update its rent epoch.
    - If the fee payer is not the nonce account, initialize a rollback fee payer account from a read-only copy of the fee payer account.
    - Allocate memory for the fee payer data and make the rollback account mutable.
    - If a nonce account is present in the transaction, update the rent epoch of the rollback fee payer account.
    - Deduct the transaction fees from the rollback account, logging an error if this fails.
- **Output**: The function does not return a value; it modifies the transaction context to set up a rollback account for the fee payer.
- **Functions called**:
    - [`fd_txn_account_init_from_funk_readonly`](fd_txn_account.c.driver.md#fd_txn_account_init_from_funk_readonly)
    - [`fd_txn_account_make_mutable`](fd_txn_account.c.driver.md#fd_txn_account_make_mutable)


---
### fd\_executor\_validate\_transaction\_fee\_payer<!-- {{#callable:fd_executor_validate_transaction_fee_payer}} -->
The function `fd_executor_validate_transaction_fee_payer` validates the fee payer of a transaction by executing budget instructions, collecting rent, calculating fees, and setting up rollback accounts.
- **Inputs**:
    - `txn_ctx`: A pointer to the transaction context (`fd_exec_txn_ctx_t`) which contains all necessary information about the transaction being processed.
- **Control Flow**:
    - Execute compute budget program instructions using [`fd_executor_compute_budget_program_execute_instructions`](program/fd_compute_budget_program.c.driver.md#fd_executor_compute_budget_program_execute_instructions) and check for success.
    - Retrieve the fee payer account using [`fd_exec_txn_ctx_get_account_at_index`](context/fd_exec_txn_ctx.c.driver.md#fd_exec_txn_ctx_get_account_at_index) and ensure it is writable.
    - Collect rent from the fee payer account using [`fd_runtime_collect_rent_from_account`](fd_runtime.c.driver.md#fd_runtime_collect_rent_from_account).
    - Calculate the execution and priority fees using [`fd_executor_calculate_fee`](#fd_executor_calculate_fee) and sum them to get the total fee.
    - Check if the feature to remove rounding in fee calculation is active; if not, round the total fee.
    - Validate the fee payer's ability to pay the total fee using [`fd_validate_fee_payer`](#fd_validate_fee_payer).
    - Create a rollback account for the fee payer using [`fd_executor_create_rollback_fee_payer_account`](#fd_executor_create_rollback_fee_payer_account).
    - Set the starting lamports for the fee payer account to avoid unbalanced lamports issues.
    - Store the calculated execution and priority fees in the transaction context.
    - Return success if all steps are completed without errors.
- **Output**: Returns an integer status code, `FD_RUNTIME_EXECUTE_SUCCESS` on success, or an error code if any validation step fails.
- **Functions called**:
    - [`fd_executor_compute_budget_program_execute_instructions`](program/fd_compute_budget_program.c.driver.md#fd_executor_compute_budget_program_execute_instructions)
    - [`fd_exec_txn_ctx_get_account_at_index`](context/fd_exec_txn_ctx.c.driver.md#fd_exec_txn_ctx_get_account_at_index)
    - [`fd_slot_to_epoch`](sysvar/fd_sysvar_epoch_schedule.c.driver.md#fd_slot_to_epoch)
    - [`fd_runtime_collect_rent_from_account`](fd_runtime.c.driver.md#fd_runtime_collect_rent_from_account)
    - [`fd_executor_calculate_fee`](#fd_executor_calculate_fee)
    - [`fd_validate_fee_payer`](#fd_validate_fee_payer)
    - [`fd_executor_create_rollback_fee_payer_account`](#fd_executor_create_rollback_fee_payer_account)


---
### fd\_executor\_setup\_accessed\_accounts\_for\_txn<!-- {{#callable:fd_executor_setup_accessed_accounts_for_txn}} -->
The function `fd_executor_setup_accessed_accounts_for_txn` initializes and sets up the accessed accounts for a transaction context, handling both standard and version-specific account setups.
- **Inputs**:
    - `txn_ctx`: A pointer to a `fd_exec_txn_ctx_t` structure representing the transaction context to be set up.
- **Control Flow**:
    - Initialize `accounts_cnt` to 0.
    - Calculate the starting address of the transaction's account keys using the transaction descriptor's account address offset.
    - Copy the account keys from the transaction's raw data into the transaction context's account keys array.
    - Update the `accounts_cnt` with the number of account addresses specified in the transaction descriptor.
    - Check if the transaction version is `FD_TXN_V0`.
    - If the version is `FD_TXN_V0`, read the global slot hashes using [`fd_sysvar_slot_hashes_read`](sysvar/fd_sysvar_slot_hashes.c.driver.md#fd_sysvar_slot_hashes_read).
    - If the slot hashes are not found, return `FD_RUNTIME_TXN_ERR_ACCOUNT_NOT_FOUND`.
    - Join the slot hash data and prepare to load additional account addresses using [`fd_runtime_load_txn_address_lookup_tables`](fd_runtime.c.driver.md#fd_runtime_load_txn_address_lookup_tables).
    - Update `accounts_cnt` with the additional account addresses count from the address lookup tables.
    - Return `FD_RUNTIME_EXECUTE_SUCCESS` if all operations are successful.
- **Output**: Returns an integer status code, `FD_RUNTIME_EXECUTE_SUCCESS` on success, or an error code if an error occurs during setup.
- **Functions called**:
    - [`fd_sysvar_slot_hashes_read`](sysvar/fd_sysvar_slot_hashes.c.driver.md#fd_sysvar_slot_hashes_read)
    - [`fd_runtime_load_txn_address_lookup_tables`](fd_runtime.c.driver.md#fd_runtime_load_txn_address_lookup_tables)


---
### fd\_txn\_ctx\_push<!-- {{#callable:fd_txn_ctx_push}} -->
The `fd_txn_ctx_push` function pushes a new instruction onto the transaction context's instruction stack and trace, ensuring lamport balance consistency and updating sysvar instructions if necessary.
- **Inputs**:
    - `txn_ctx`: A pointer to the transaction context (`fd_exec_txn_ctx_t`) which maintains the state of the transaction execution.
    - `instr`: A pointer to the instruction information (`fd_instr_info_t`) that is to be pushed onto the instruction stack.
- **Control Flow**:
    - Initialize starting lamports to zero and calculate the sum of account lamports for the given instruction using [`fd_instr_info_sum_account_lamports`](info/fd_instr_info.c.driver.md#fd_instr_info_sum_account_lamports).
    - Check if the caller's lamport sum has changed by comparing the current and original lamport sums if the instruction stack size is greater than zero.
    - If the instruction trace length exceeds the maximum allowed, return an error indicating the trace length limit has been exceeded.
    - Increment the instruction trace length and stack size counters.
    - Find the index of the sysvar instructions account and update the current instruction index if the account is found and can be borrowed mutably.
    - Return success if all operations complete without errors.
- **Output**: Returns an integer status code indicating success or the type of error encountered during the operation.
- **Functions called**:
    - [`fd_instr_info_sum_account_lamports`](info/fd_instr_info.c.driver.md#fd_instr_info_sum_account_lamports)
    - [`fd_exec_txn_ctx_find_index_of_account`](context/fd_exec_txn_ctx.h.driver.md#fd_exec_txn_ctx_find_index_of_account)
    - [`fd_exec_txn_ctx_get_account_at_index`](context/fd_exec_txn_ctx.c.driver.md#fd_exec_txn_ctx_get_account_at_index)
    - [`fd_sysvar_instructions_update_current_instr_idx`](sysvar/fd_sysvar_instructions.c.driver.md#fd_sysvar_instructions_update_current_instr_idx)


---
### fd\_instr\_stack\_push<!-- {{#callable:fd_instr_stack_push}} -->
The `fd_instr_stack_push` function attempts to push a new instruction onto the instruction stack, checking for unsupported program IDs and reentrancy violations, and increments the stack and trace size counters if successful.
- **Inputs**:
    - `txn_ctx`: A pointer to the transaction context (`fd_exec_txn_ctx_t`) which holds the state and data for the current transaction execution.
    - `instr`: A pointer to the instruction information (`fd_instr_info_t`) that is to be pushed onto the instruction stack.
- **Control Flow**:
    - Retrieve the program ID public key for the instruction's program ID using [`fd_exec_txn_ctx_get_key_of_account_at_index`](context/fd_exec_txn_ctx.c.driver.md#fd_exec_txn_ctx_get_key_of_account_at_index).
    - Check if the program ID is unsupported by comparing it to the native loader ID; return an error if it is unsupported.
    - If the instruction stack is not empty, iterate through the stack to check for reentrancy violations by comparing program IDs of instructions in the stack.
    - If a reentrancy violation is detected (i.e., a program ID is found in the stack that is not the last one), return an error.
    - If no errors are encountered, call [`fd_txn_ctx_push`](#fd_txn_ctx_push) to increment the stack and trace size counters.
- **Output**: Returns an integer status code: `FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID` if the program ID is unsupported, `FD_EXECUTOR_INSTR_ERR_REENTRANCY_NOT_ALLOWED` if a reentrancy violation is detected, or the result of [`fd_txn_ctx_push`](#fd_txn_ctx_push) if successful.
- **Functions called**:
    - [`fd_exec_txn_ctx_get_key_of_account_at_index`](context/fd_exec_txn_ctx.c.driver.md#fd_exec_txn_ctx_get_key_of_account_at_index)
    - [`fd_txn_ctx_push`](#fd_txn_ctx_push)


---
### fd\_instr\_stack\_pop<!-- {{#callable:fd_instr_stack_pop}} -->
The `fd_instr_stack_pop` function removes an instruction from the instruction stack, ensuring that all executable accounts have no outstanding references and that lamports are balanced before and after the instruction.
- **Inputs**:
    - `txn_ctx`: A pointer to the transaction context (`fd_exec_txn_ctx_t`) which holds the state and data for the current transaction execution.
    - `instr`: A constant pointer to the instruction information (`fd_instr_info_t`) that is being popped from the stack.
- **Control Flow**:
    - Check if the instruction stack size is zero; if so, return an error indicating call depth exceeded.
    - Decrement the instruction stack size to pop the instruction.
    - Iterate over each account in the instruction to verify that executable accounts have no outstanding references; return an error if any are found.
    - Calculate the sum of lamports for the accounts involved in the instruction and compare it to the starting lamports; return an error if they do not match.
    - Return success if all checks pass.
- **Output**: Returns an integer status code indicating success or the type of error encountered during the pop operation.
- **Functions called**:
    - [`fd_instr_info_sum_account_lamports`](info/fd_instr_info.c.driver.md#fd_instr_info_sum_account_lamports)


---
### fd\_execute\_instr\_end<!-- {{#callable:fd_execute_instr_end}} -->
The `fd_execute_instr_end` function finalizes the execution of an instruction by popping it from the stack and handling any errors that occur during this process.
- **Inputs**:
    - `instr_ctx`: A pointer to the `fd_exec_instr_ctx_t` structure representing the context of the instruction being executed.
    - `instr`: A pointer to the `fd_instr_info_t` structure containing information about the instruction.
    - `instr_exec_result`: An integer representing the result of the instruction execution, indicating success or a specific error code.
- **Control Flow**:
    - Call [`fd_instr_stack_pop`](#fd_instr_stack_pop) to remove the instruction from the stack and capture any errors during this process.
    - Check if the instruction execution was successful and if there was a stack pop error; if so, overwrite the execution result with the stack pop error.
    - If the instruction execution resulted in an error and no previous instruction has failed, update the transaction context with the failed instruction and error information.
    - Return the final instruction execution result, which may be modified by stack pop errors.
- **Output**: The function returns an integer representing the final result of the instruction execution, which may be modified by stack pop errors.
- **Functions called**:
    - [`fd_instr_stack_pop`](#fd_instr_stack_pop)


---
### fd\_execute\_instr<!-- {{#callable:fd_execute_instr}} -->
The `fd_execute_instr` function executes a given instruction within a transaction context, handling stack operations, native program lookups, and logging results.
- **Inputs**:
    - `txn_ctx`: A pointer to the transaction context (`fd_exec_txn_ctx_t`) which contains the state and data necessary for executing the instruction.
    - `instr`: A pointer to the instruction information (`fd_instr_info_t`) that needs to be executed.
- **Control Flow**:
    - Begin a transaction scratchpad frame using `FD_RUNTIME_TXN_SPAD_FRAME_BEGIN` macro.
    - Check if there is a parent instruction context by examining the instruction stack size.
    - Push the current instruction onto the instruction stack using [`fd_instr_stack_push`](#fd_instr_stack_push) and handle any errors by logging and returning the error code.
    - Initialize the current instruction context (`fd_exec_instr_ctx_t`) with details from the transaction context and the instruction.
    - Encode the program ID of the instruction into a Base58 string for logging purposes.
    - Update the instruction trace with the current instruction and stack height.
    - Look up the native program function for the instruction's program ID using [`fd_executor_lookup_native_program`](#fd_executor_lookup_native_program).
    - If a native program function is found, log the program invocation and reset return data if it's not a precompile.
    - Execute the native program function if applicable, otherwise return success for precompiled programs.
    - If no native program function is found, log an unsupported program ID error and return the error code.
    - Log the success or failure of the instruction execution based on the result.
    - End the transaction scratchpad frame using `FD_RUNTIME_TXN_SPAD_FRAME_END`.
- **Output**: Returns an integer indicating the result of the instruction execution, where success is typically indicated by `FD_EXECUTOR_INSTR_SUCCESS` and errors are represented by specific error codes.
- **Functions called**:
    - [`fd_instr_stack_push`](#fd_instr_stack_push)
    - [`fd_executor_lookup_native_program`](#fd_executor_lookup_native_program)
    - [`fd_exec_txn_ctx_reset_return_data`](context/fd_exec_txn_ctx.c.driver.md#fd_exec_txn_ctx_reset_return_data)
    - [`fd_execute_instr_end`](#fd_execute_instr_end)


---
### fd\_txn\_reclaim\_accounts<!-- {{#callable:fd_txn_reclaim_accounts}} -->
The `fd_txn_reclaim_accounts` function updates the slot of writable accounts and clears data and ownership for accounts with zero lamports in a transaction context.
- **Inputs**:
    - `txn_ctx`: A pointer to an `fd_exec_txn_ctx_t` structure representing the transaction context, which contains information about the accounts involved in the transaction.
- **Control Flow**:
    - Iterate over each account in the transaction context using a loop.
    - For each account, check if it is writable using [`fd_exec_txn_ctx_account_is_writable_idx`](context/fd_exec_txn_ctx.c.driver.md#fd_exec_txn_ctx_account_is_writable_idx).
    - If the account is writable, update its slot using `set_slot`.
    - Check if the account's lamports are zero using `get_lamports`.
    - If the account's lamports are zero, set its data length to zero using `set_data_len` and clear its owner using `clear_owner`.
- **Output**: This function does not return a value; it performs operations directly on the accounts within the transaction context.
- **Functions called**:
    - [`fd_exec_txn_ctx_account_is_writable_idx`](context/fd_exec_txn_ctx.c.driver.md#fd_exec_txn_ctx_account_is_writable_idx)


---
### fd\_executor\_is\_blockhash\_valid\_for\_age<!-- {{#callable:fd_executor_is_blockhash_valid_for_age}} -->
The function `fd_executor_is_blockhash_valid_for_age` checks if a given blockhash is valid within a specified maximum age in a block hash queue.
- **Inputs**:
    - `block_hash_queue`: A pointer to a `fd_block_hash_queue_t` structure that contains the block hash queue to be checked.
    - `blockhash`: A pointer to a `fd_hash_t` structure representing the blockhash to be validated.
    - `max_age`: An unsigned long integer representing the maximum allowable age for the blockhash to be considered valid.
- **Control Flow**:
    - A `fd_hash_hash_age_pair_t_mapnode_t` key is created and its key is set to the provided blockhash.
    - The function `fd_hash_hash_age_pair_t_map_find` is called to find the age of the blockhash in the block hash queue.
    - If the blockhash is not found (`hash_age` is NULL), the function returns 0, indicating the blockhash is not valid.
    - If the blockhash is found, the age is calculated by subtracting the hash index of the found blockhash from the last hash index in the queue.
    - The function returns 1 if the calculated age is less than or equal to `max_age`, otherwise it returns 0.
- **Output**: The function returns an integer: 1 if the blockhash is valid within the specified age, or 0 if it is not.


---
### fd\_exec\_txn\_ctx\_from\_exec\_slot\_ctx<!-- {{#callable:fd_exec_txn_ctx_from_exec_slot_ctx}} -->
The function `fd_exec_txn_ctx_from_exec_slot_ctx` initializes a transaction context (`fd_exec_txn_ctx_t`) from a given execution slot context (`fd_exec_slot_ctx_t`) and associated workspaces and addresses.
- **Inputs**:
    - `slot_ctx`: A constant pointer to an `fd_exec_slot_ctx_t` structure representing the execution slot context from which the transaction context will be initialized.
    - `ctx`: A pointer to an `fd_exec_txn_ctx_t` structure where the transaction context will be initialized.
    - `funk_wksp`: A constant pointer to an `fd_wksp_t` structure representing the workspace for the 'funk' operations.
    - `runtime_pub_wksp`: A constant pointer to an `fd_wksp_t` structure representing the runtime public workspace.
    - `funk_txn_gaddr`: An unsigned long integer representing the global address of the funk transaction.
    - `funk_gaddr`: An unsigned long integer representing the global address of the funk.
- **Control Flow**:
    - Assigns the `runtime_pub_wksp` to the `runtime_pub_wksp` field of the transaction context.
    - Retrieves the local address of the funk transaction using `fd_wksp_laddr` and assigns it to `ctx->funk_txn`.
    - Checks if `ctx->funk_txn` is valid; logs an error if not.
    - Attempts to join the funk using `fd_funk_join` and checks for success; logs an error if it fails.
    - Copies various fields from `slot_ctx` to `ctx`, including `features`, `status_cache`, `bank_hash_cmp`, `prev_lamports_per_signature`, `enable_exec_recording`, `total_epoch_stake`, `slot`, `fee_rate_governor`, and `block_hash_queue`.
    - Retrieves the epoch bank from `slot_ctx->epoch_ctx` and assigns its fields (`epoch_schedule`, `rent`, `slots_per_year`, `stakes`) to the corresponding fields in `ctx`.
- **Output**: The function does not return a value; it initializes the `fd_exec_txn_ctx_t` structure pointed to by `ctx` with data from the provided `slot_ctx` and other parameters.
- **Functions called**:
    - [`fd_exec_epoch_ctx_epoch_bank_const`](context/fd_exec_epoch_ctx.h.driver.md#fd_exec_epoch_ctx_epoch_bank_const)


---
### fd\_executor\_setup\_txn\_account<!-- {{#callable:fd_executor_setup_txn_account}} -->
The `fd_executor_setup_txn_account` function initializes a transaction account from a given context and index, promoting it to mutable if necessary, and sets up its metadata.
- **Inputs**:
    - `txn_ctx`: A pointer to the transaction context (`fd_exec_txn_ctx_t`) containing transaction-related data and state.
    - `idx`: An unsigned short integer representing the index of the account within the transaction context to be set up.
- **Control Flow**:
    - Retrieve the public key of the account at the specified index from the transaction context.
    - Initialize the transaction account from the funk database in a read-only mode using the public key and transaction context.
    - Check for errors during initialization and log an error if the account is neither successfully initialized nor an unknown account.
    - Copy the public key into the transaction account's public key field.
    - If the account is writable or is the fee payer, allocate memory for the account data and promote the account to mutable.
    - If the account is unknown, set its rent epoch to `ULONG_MAX`.
    - Retrieve the account's metadata and check if it is `NULL`.
    - If metadata is `NULL`, set up a sentinel metadata for the account and return `NULL`.
    - Return the transaction account.
- **Output**: A pointer to the initialized transaction account (`fd_txn_account_t *`), or `NULL` if the account's metadata is not set up.
- **Functions called**:
    - [`fd_txn_account_init_from_funk_readonly`](fd_txn_account.c.driver.md#fd_txn_account_init_from_funk_readonly)
    - [`fd_exec_txn_ctx_account_is_writable_idx`](context/fd_exec_txn_ctx.c.driver.md#fd_exec_txn_ctx_account_is_writable_idx)
    - [`fd_txn_account_make_mutable`](fd_txn_account.c.driver.md#fd_txn_account_make_mutable)
    - [`fd_txn_account_setup_sentinel_meta_readonly`](fd_txn_account.c.driver.md#fd_txn_account_setup_sentinel_meta_readonly)


---
### fd\_executor\_setup\_executable\_account<!-- {{#callable:fd_executor_setup_executable_account}} -->
The function `fd_executor_setup_executable_account` initializes an executable account in a transaction context if it is a valid BPF upgradeable program.
- **Inputs**:
    - `txn_ctx`: A pointer to the transaction context (`fd_exec_txn_ctx_t`) which holds information about the transaction being processed.
    - `acc_idx`: An unsigned short integer representing the index of the account in the transaction context that is being checked and potentially set up as executable.
    - `executable_idx`: A pointer to an unsigned short integer that tracks the current index in the list of executable accounts, which will be incremented if a valid executable account is set up.
- **Control Flow**:
    - Initialize an error variable `err` to 0.
    - Read the BPF upgradeable loader state for the program at the given account index (`acc_idx`) using [`read_bpf_upgradeable_loader_state_for_program`](program/fd_bpf_loader_program.c.driver.md#read_bpf_upgradeable_loader_state_for_program).
    - If the loader state is not successfully read (i.e., `program_loader_state` is NULL), return immediately.
    - Check if the loader state represents a program using `fd_bpf_upgradeable_loader_state_is_program`. If not, return immediately.
    - Retrieve the program data account's public key from the loader state.
    - Attempt to initialize the executable account from the program data account using [`fd_txn_account_init_from_funk_readonly`](fd_txn_account.c.driver.md#fd_txn_account_init_from_funk_readonly).
    - If the initialization is successful, increment the `executable_idx` to reflect the addition of a new executable account.
- **Output**: The function does not return a value; it modifies the transaction context and executable index in place.
- **Functions called**:
    - [`read_bpf_upgradeable_loader_state_for_program`](program/fd_bpf_loader_program.c.driver.md#read_bpf_upgradeable_loader_state_for_program)
    - [`fd_txn_account_init_from_funk_readonly`](fd_txn_account.c.driver.md#fd_txn_account_init_from_funk_readonly)


---
### fd\_executor\_setup\_accounts\_for\_txn<!-- {{#callable:fd_executor_setup_accounts_for_txn}} -->
The function `fd_executor_setup_accounts_for_txn` initializes and sets up transaction accounts and executable accounts for a given transaction context.
- **Inputs**:
    - `txn_ctx`: A pointer to the transaction context (`fd_exec_txn_ctx_t`) that contains information about the transaction being processed.
- **Control Flow**:
    - Initialize a counter `j` to zero, which will track the number of executable accounts.
    - Clear the memory for the accounts in the transaction context using `fd_memset`.
    - Iterate over each account index from 0 to `txn_ctx->accounts_cnt`.
    - For each account, call [`fd_executor_setup_txn_account`](#fd_executor_setup_txn_account) to initialize the transaction account.
    - Check if the account is owned by the BPF loader upgradeable program by comparing the owner's key with `fd_solana_bpf_loader_upgradeable_program_id.key`.
    - If the account is owned by the BPF loader upgradeable program, call [`fd_executor_setup_executable_account`](#fd_executor_setup_executable_account) to set up the executable account and increment the executable account counter `j`.
    - Set `txn_ctx->nonce_account_idx_in_txn` to `ULONG_MAX` to indicate no nonce account is present.
    - Set `txn_ctx->executable_cnt` to the value of `j`, representing the number of executable accounts.
    - Call [`fd_executor_setup_instr_infos_from_txn_instrs`](#fd_executor_setup_instr_infos_from_txn_instrs) to set up instruction information from the transaction instructions.
- **Output**: The function does not return a value; it modifies the transaction context (`txn_ctx`) in place, setting up accounts and executable accounts for the transaction.
- **Functions called**:
    - [`fd_executor_setup_txn_account`](#fd_executor_setup_txn_account)
    - [`fd_executor_setup_executable_account`](#fd_executor_setup_executable_account)
    - [`fd_executor_setup_instr_infos_from_txn_instrs`](#fd_executor_setup_instr_infos_from_txn_instrs)


---
### fd\_execute\_txn\_prepare\_start<!-- {{#callable:fd_execute_txn_prepare_start}} -->
The `fd_execute_txn_prepare_start` function initializes a transaction context and sets up accessed accounts for a transaction execution.
- **Inputs**:
    - `slot_ctx`: A constant pointer to an `fd_exec_slot_ctx_t` structure representing the execution slot context.
    - `txn_ctx`: A pointer to an `fd_exec_txn_ctx_t` structure where the transaction context will be initialized.
    - `txn_descriptor`: A constant pointer to an `fd_txn_t` structure representing the transaction descriptor.
    - `txn_raw`: A constant pointer to an `fd_rawtxn_b_t` structure representing the raw transaction data.
- **Control Flow**:
    - Retrieve the `funk` and `funk_wksp` from the `slot_ctx` and obtain the runtime workspace using `fd_wksp_containing`.
    - Calculate the global addresses for `funk_txn` and `funk` using `fd_wksp_gaddr`.
    - Initialize the transaction context `txn_ctx` using [`fd_exec_txn_ctx_new`](context/fd_exec_txn_ctx.c.driver.md#fd_exec_txn_ctx_new).
    - Set up the transaction context from the execution slot context using [`fd_exec_txn_ctx_from_exec_slot_ctx`](#fd_exec_txn_ctx_from_exec_slot_ctx).
    - Configure the transaction context with the transaction descriptor and raw transaction data using [`fd_exec_txn_ctx_setup`](context/fd_exec_txn_ctx.c.driver.md#fd_exec_txn_ctx_setup).
    - Set up accessed accounts for the transaction using [`fd_executor_setup_accessed_accounts_for_txn`](#fd_executor_setup_accessed_accounts_for_txn).
    - Return the result of setting up accessed accounts.
- **Output**: Returns an integer result indicating the success or failure of setting up accessed accounts for the transaction.
- **Functions called**:
    - [`fd_exec_txn_ctx_new`](context/fd_exec_txn_ctx.c.driver.md#fd_exec_txn_ctx_new)
    - [`fd_exec_txn_ctx_from_exec_slot_ctx`](#fd_exec_txn_ctx_from_exec_slot_ctx)
    - [`fd_exec_txn_ctx_setup`](context/fd_exec_txn_ctx.c.driver.md#fd_exec_txn_ctx_setup)
    - [`fd_executor_setup_accessed_accounts_for_txn`](#fd_executor_setup_accessed_accounts_for_txn)


---
### fd\_executor\_txn\_verify<!-- {{#callable:fd_executor_txn_verify}} -->
The `fd_executor_txn_verify` function verifies the signatures of a transaction using the Ed25519 algorithm.
- **Inputs**:
    - `txn_ctx`: A pointer to an `fd_exec_txn_ctx_t` structure that contains the transaction context, including transaction descriptor and raw transaction data.
- **Control Flow**:
    - Initialize an array of `fd_sha512_t` pointers to store SHA-512 contexts for signature verification.
    - Iterate over the maximum number of signatures (`FD_TXN_ACTUAL_SIG_MAX`) and allocate memory for each SHA-512 context, joining them to the workspace.
    - Retrieve the number of signatures, signature offset, account address offset, and message offset from the transaction descriptor within `txn_ctx`.
    - Extract pointers to the signatures, public keys, and message from the raw transaction data using the offsets.
    - Calculate the size of the message by subtracting the message offset from the total transaction size.
    - Call `fd_ed25519_verify_batch_single_msg` to verify the batch of signatures against the message and public keys using the SHA-512 contexts.
    - If the verification fails, return -1; otherwise, return 0.
- **Output**: Returns 0 if all signatures are successfully verified, otherwise returns -1 if verification fails.


---
### fd\_execute\_txn<!-- {{#callable:fd_execute_txn}} -->
The `fd_execute_txn` function executes a transaction by processing its instructions and performing necessary checks, returning an error code if any issues occur.
- **Inputs**:
    - `task_info`: A pointer to an `fd_execute_txn_task_info_t` structure containing information about the transaction to be executed, including the transaction context and execution result.
- **Control Flow**:
    - Check if the transaction is fee-only and return the existing error if true.
    - Initialize the transaction context and determine if instruction dumping is needed based on the capture context and slot conditions.
    - Initialize log collection for the transaction execution.
    - Iterate over each instruction in the transaction descriptor, updating the current instruction index.
    - If instruction dumping is enabled, convert the instruction to a Protobuf message.
    - Execute each instruction using [`fd_execute_instr`](#fd_execute_instr) and check for execution success.
    - If an instruction execution fails, set the instruction error index and return an instruction error code.
    - Perform a final transaction check using [`fd_executor_txn_check`](#fd_executor_txn_check) and return any errors encountered.
    - Return 0 if all instructions execute successfully and the transaction check passes.
- **Output**: Returns an integer error code indicating the success or failure of the transaction execution, with 0 indicating success.
- **Functions called**:
    - [`fd_dump_instr_to_protobuf`](tests/fd_dump_pb.c.driver.md#fd_dump_instr_to_protobuf)
    - [`fd_execute_instr`](#fd_execute_instr)
    - [`fd_executor_txn_check`](#fd_executor_txn_check)


---
### fd\_executor\_txn\_check<!-- {{#callable:fd_executor_txn_check}} -->
The `fd_executor_txn_check` function verifies the consistency of account lamport balances and rent states after a transaction execution.
- **Inputs**:
    - `txn_ctx`: A pointer to the transaction context (`fd_exec_txn_ctx_t`) containing details about the transaction and its accounts.
- **Control Flow**:
    - Initialize pointers to rent information and variables for tracking starting and ending lamport balances.
    - Iterate over each account in the transaction context.
    - For each account, check if it was written to by verifying if its metadata is not NULL.
    - If the account was written to, update the ending lamport balances using the account's current lamports.
    - Determine the account's rent state after the transaction (uninitialized, rent-paying, or rent-exempt).
    - If the account is not the incinerator, check if the account's rent state transition is valid.
    - If the account's rent state transition is invalid, log a debug message and return an error code for insufficient funds for rent.
    - If the account's starting lamports are not ULONG_MAX, update the starting lamport balances.
    - After processing all accounts, compare the starting and ending lamport balances.
    - If the starting and ending lamport balances do not match, log a debug message and return an error code for an unbalanced transaction.
    - If all checks pass, return a success code.
- **Output**: Returns an integer status code indicating success (`FD_RUNTIME_EXECUTE_SUCCESS`) or specific error codes for insufficient funds for rent or unbalanced transactions.
- **Functions called**:
    - [`fd_rent_exempt_minimum_balance`](sysvar/fd_sysvar_rent1.c.driver.md#fd_rent_exempt_minimum_balance)


---
### fd\_executor\_instr\_strerror<!-- {{#callable:fd_executor_instr_strerror}} -->
The `fd_executor_instr_strerror` function returns a human-readable error message corresponding to a given error code related to instruction execution.
- **Inputs**:
    - `err`: An integer representing the error code for which a descriptive error message is needed.
- **Control Flow**:
    - The function uses a switch statement to match the input error code against predefined error codes.
    - For each matched case, it returns a corresponding error message string.
    - If the error code is not recognized, it defaults to returning an empty string.
- **Output**: A constant character pointer to a string containing the error message corresponding to the input error code, or an empty string if the error code is not recognized or should be omitted.


---
### fd\_debug\_symbology<!-- {{#callable:fd_debug_symbology}} -->
The `fd_debug_symbology` function calls the `fd_get_types_yaml` function to ensure its inclusion for debugging purposes.
- **Inputs**: None
- **Control Flow**:
    - The function calls `fd_get_types_yaml` and discards its return value using a cast to void.
- **Output**: The function does not produce any output.


