# Purpose
The provided C code is part of a system program implementation that manages nonce accounts, which are used to ensure transaction uniqueness and prevent replay attacks in a blockchain environment, specifically within the Solana ecosystem. This code is designed to handle various operations related to nonce accounts, such as advancing, withdrawing from, initializing, authorizing, and upgrading nonce accounts. It also includes functionality to check the age of a transaction to ensure it is valid based on recent blockhashes or a valid nonce account.

The code is structured around several static and public functions that perform specific tasks related to nonce account management. Key components include functions for verifying account requirements, reading system variables, and manipulating nonce account states. The code interacts with various system variables and contexts, such as `fd_exec_instr_ctx_t` and `fd_exec_txn_ctx_t`, to execute these operations. It also includes error handling to ensure that operations are performed correctly and securely. The code is intended to be part of a larger system, likely a blockchain node or validator, where it would be integrated with other components to manage transaction processing and account state updates.
# Imports and Dependencies

---
- `fd_system_program.h`
- `../fd_borrowed_account.h`
- `../fd_acc_mgr.h`
- `../fd_system_ids.h`
- `../context/fd_exec_slot_ctx.h`
- `../context/fd_exec_txn_ctx.h`
- `../sysvar/fd_sysvar_rent.h`
- `../sysvar/fd_sysvar_recent_hashes.h`
- `../fd_executor.h`


# Functions

---
### require\_acct<!-- {{#callable:require_acct}} -->
The `require_acct` function checks if a specific account key at a given index in the execution context matches a provided public key.
- **Inputs**:
    - `ctx`: A pointer to the execution instruction context (`fd_exec_instr_ctx_t`), which contains information about the current execution environment.
    - `idx`: An unsigned short integer representing the index of the account in the context to be checked.
    - `pubkey`: A constant pointer to a `fd_pubkey_t` structure representing the public key to be compared against the account key at the specified index.
- **Control Flow**:
    - Initialize a pointer `acc_key` to `NULL` to hold the account key.
    - Call `fd_exec_instr_ctx_get_key_of_account_at_index` to retrieve the account key at the specified index `idx` from the context `ctx` and store it in `acc_key`.
    - If the retrieval function returns an error, return that error immediately.
    - Compare the retrieved account key `acc_key` with the provided `pubkey` using `memcmp`.
    - If the keys do not match, return `FD_EXECUTOR_INSTR_ERR_INVALID_ARG`.
    - If the keys match, return `FD_EXECUTOR_INSTR_SUCCESS`.
- **Output**: The function returns an integer status code: `FD_EXECUTOR_INSTR_SUCCESS` if the account key matches the provided public key, or an error code if there is a mismatch or if the account key retrieval fails.


---
### require\_acct\_rent<!-- {{#callable:require_acct_rent}} -->
The `require_acct_rent` function checks if a specific account is a rent sysvar account and retrieves the rent information if available.
- **Inputs**:
    - `ctx`: A pointer to the execution instruction context (`fd_exec_instr_ctx_t`), which contains transaction context and other relevant execution data.
    - `idx`: An unsigned short integer representing the index of the account to be checked within the context.
    - `out_rent`: A pointer to a constant pointer of type `fd_rent_t`, which will be set to point to the rent information if the function succeeds.
- **Control Flow**:
    - The function begins by calling [`require_acct`](#require_acct) with the provided context, index, and a reference to the rent sysvar ID to ensure the account at the given index is a rent sysvar account.
    - If [`require_acct`](#require_acct) returns an error, the function immediately returns this error code.
    - The function then attempts to read the rent information using `fd_sysvar_rent_read` with the transaction context's funk, funk_txn, and spad.
    - If the rent information is not available (i.e., `fd_sysvar_rent_read` returns NULL), the function returns an error code indicating an unsupported sysvar.
    - If the rent information is successfully retrieved, it is assigned to `*out_rent`, and the function returns a success code.
- **Output**: The function returns an integer status code: `FD_EXECUTOR_INSTR_SUCCESS` on success, or an error code if the account is not a rent sysvar or if the rent information cannot be retrieved.
- **Functions called**:
    - [`require_acct`](#require_acct)


---
### require\_acct\_recent\_blockhashes<!-- {{#callable:require_acct_recent_blockhashes}} -->
The `require_acct_recent_blockhashes` function ensures that a specific account in the execution context is the recent blockhashes system variable and retrieves the recent blockhashes data.
- **Inputs**:
    - `ctx`: A pointer to the execution instruction context (`fd_exec_instr_ctx_t`), which contains transaction context and other execution-related data.
    - `idx`: An unsigned short integer representing the index of the account to be checked within the execution context.
    - `out`: A double pointer to `fd_recent_block_hashes_t`, where the function will store the retrieved recent blockhashes data.
- **Control Flow**:
    - The function first calls [`require_acct`](#require_acct) to verify that the account at the given index matches the recent blockhashes system variable ID.
    - If [`require_acct`](#require_acct) returns an error, the function immediately returns this error.
    - The function then reads the recent blockhashes global data using `fd_sysvar_recent_hashes_read`.
    - If the read operation fails (returns NULL), the function returns an error indicating unsupported system variable.
    - The function sets the `hashes` field of the `out` parameter to point to the recent blockhashes data using `deq_fd_block_block_hash_entry_t_join`.
    - Finally, the function returns a success code.
- **Output**: The function returns an integer status code, which is `FD_EXECUTOR_INSTR_SUCCESS` on success or an error code if any step fails.
- **Functions called**:
    - [`require_acct`](#require_acct)


---
### most\_recent\_block\_hash<!-- {{#callable:most_recent_block_hash}} -->
The `most_recent_block_hash` function retrieves the most recent block hash from a transaction context and returns it, handling errors if the block hash is not set.
- **Inputs**:
    - `ctx`: A pointer to an `fd_exec_instr_ctx_t` structure, which contains the transaction context including the block hash queue.
    - `out`: A pointer to an `fd_hash_t` structure where the most recent block hash will be stored.
- **Control Flow**:
    - Retrieve the last block hash from the block hash queue in the transaction context (`ctx->txn_ctx->block_hash_queue.last_hash`).
    - Check if the retrieved block hash is NULL, indicating it was never set.
    - If the block hash is NULL, set a custom error in the transaction context (`ctx->txn_ctx->custom_err`) and return a custom error code (`FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR`).
    - If the block hash is not NULL, copy it to the output parameter (`*out = *last_hash`).
    - Return success code (`FD_EXECUTOR_INSTR_SUCCESS`).
- **Output**: The function returns an integer status code: `FD_EXECUTOR_INSTR_SUCCESS` on success, or `FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR` if the block hash was not set.


---
### fd\_durable\_nonce\_from\_blockhash<!-- {{#callable:fd_durable_nonce_from_blockhash}} -->
The `fd_durable_nonce_from_blockhash` function generates a durable nonce by hashing a predefined string with a given blockhash using SHA-256.
- **Inputs**:
    - `out`: A pointer to an `fd_hash_t` where the resulting durable nonce will be stored.
    - `blockhash`: A constant pointer to an `fd_hash_t` representing the blockhash to be used in generating the durable nonce.
- **Control Flow**:
    - Declare a buffer `buf` of 45 bytes.
    - Copy the string "DURABLE_NONCE" into the first 13 bytes of `buf`.
    - Copy the contents of `blockhash` into `buf` starting at the 14th byte.
    - Call `fd_sha256_hash` to compute the SHA-256 hash of `buf` and store the result in `out`.
- **Output**: The function outputs a SHA-256 hash stored in the `out` parameter, representing the durable nonce.


---
### fd\_system\_program\_set\_nonce\_state<!-- {{#callable:fd_system_program_set_nonce_state}} -->
The `fd_system_program_set_nonce_state` function updates the state of a nonce account with a new nonce state if the account's data buffer is large enough to accommodate the new state.
- **Inputs**:
    - `account`: A pointer to an `fd_borrowed_account_t` structure representing the nonce account to be updated.
    - `new_state`: A pointer to a `fd_nonce_state_versions_t` structure containing the new nonce state to be set in the account.
- **Control Flow**:
    - Initialize a pointer `data` and a length `dlen` to hold the account's mutable data and its length.
    - Call `fd_borrowed_account_get_data_mut` to retrieve the mutable data pointer and length of the account; return an error if this fails.
    - Check if the size of `new_state` exceeds the account's data length; return `FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL` if true.
    - Initialize a `fd_bincode_encode_ctx_t` structure with the data pointer and its end.
    - Encode `new_state` into the account's data using `fd_nonce_state_versions_encode`; return `FD_EXECUTOR_INSTR_ERR_GENERIC_ERR` if encoding fails.
    - Return `FD_EXECUTOR_INSTR_SUCCESS` to indicate success.
- **Output**: Returns an integer status code: `FD_EXECUTOR_INSTR_SUCCESS` on success, or an error code if an error occurs during data retrieval, size check, or encoding.


---
### fd\_system\_program\_advance\_nonce\_account<!-- {{#callable:fd_system_program_advance_nonce_account}} -->
The `fd_system_program_advance_nonce_account` function advances the nonce of a Solana account if certain conditions are met, ensuring the account is writable, signed, and the nonce is not reused within the same slot.
- **Inputs**:
    - `ctx`: A pointer to the execution instruction context (`fd_exec_instr_ctx_t`), which contains information about the current transaction and execution environment.
    - `account`: A pointer to the borrowed account (`fd_borrowed_account_t`) that represents the nonce account to be advanced.
    - `instr_acc_idx`: An unsigned short integer representing the index of the account in the instruction's account list.
- **Control Flow**:
    - Check if the account at `instr_acc_idx` is writable; if not, log an error and return an invalid argument error code.
    - Decode the nonce state from the account's data; if decoding fails, return an invalid account data error code.
    - Determine the current state of the nonce account based on its version and state discriminants.
    - If the nonce account is initialized, check if the authority has signed the transaction; if not, log an error and return a missing signature error code.
    - Retrieve the most recent block hash and compute the next durable nonce from it.
    - Check if the current durable nonce matches the next durable nonce; if they match, log an error and return a custom error code indicating the nonce cannot advance more than once per slot.
    - Create a new nonce state with the updated durable nonce and set it on the account; if setting the state fails, return the error code.
    - If the nonce account is uninitialized, log an error and return an invalid account data error code.
    - Return success if all operations complete without errors.
- **Output**: Returns an integer status code indicating success (`FD_EXECUTOR_INSTR_SUCCESS`) or an error code if any checks or operations fail.
- **Functions called**:
    - [`most_recent_block_hash`](#most_recent_block_hash)
    - [`fd_durable_nonce_from_blockhash`](#fd_durable_nonce_from_blockhash)
    - [`fd_system_program_set_nonce_state`](#fd_system_program_set_nonce_state)


---
### fd\_system\_program\_exec\_advance\_nonce\_account<!-- {{#callable:fd_system_program_exec_advance_nonce_account}} -->
The function `fd_system_program_exec_advance_nonce_account` advances the nonce of a Solana account by verifying account conditions and updating the nonce state.
- **Inputs**:
    - `ctx`: A pointer to an `fd_exec_instr_ctx_t` structure, which contains the execution context for the instruction, including account information and transaction context.
- **Control Flow**:
    - Check if the number of accounts in the instruction context is less than 1, and return an error if true.
    - Set the instruction account index to 0 and attempt to borrow the account at this index, returning an error if unsuccessful.
    - Initialize a `fd_recent_block_hashes_t` object and attempt to require recent blockhashes, returning an error if unsuccessful.
    - Check if the recent blockhash list is empty, log a message, set a custom error, and return an error if true.
    - Call [`fd_system_program_advance_nonce_account`](#fd_system_program_advance_nonce_account) with the context, account, and account index to advance the nonce.
    - Return the result of the nonce advancement operation.
- **Output**: Returns an integer error code indicating success or the type of error encountered during the nonce advancement process.
- **Functions called**:
    - [`require_acct_recent_blockhashes`](#require_acct_recent_blockhashes)
    - [`fd_system_program_advance_nonce_account`](#fd_system_program_advance_nonce_account)


---
### fd\_system\_program\_withdraw\_nonce\_account<!-- {{#callable:fd_system_program_withdraw_nonce_account}} -->
The function `fd_system_program_withdraw_nonce_account` handles the withdrawal of lamports from a nonce account, ensuring the account's state and signature requirements are met.
- **Inputs**:
    - `ctx`: A pointer to the execution instruction context (`fd_exec_instr_ctx_t`), which contains information about the current transaction and instruction.
    - `requested_lamports`: The amount of lamports requested to be withdrawn from the nonce account.
    - `rent`: A pointer to the rent system variable (`fd_rent_t`), which provides information about rent-exempt minimum balances.
- **Control Flow**:
    - Initialize variables for account indices and attempt to borrow the 'from' account using the context.
    - Check if the 'from' account is writable; if not, log an error and return an invalid argument error.
    - Decode the nonce state from the 'from' account's data and handle any decoding errors.
    - Determine the current state of the nonce account (uninitialized or initialized) and handle each case separately.
    - For uninitialized state, check if the requested lamports exceed the account's balance and handle insufficient funds.
    - For initialized state, check if the requested lamports equal the account's balance and handle nonce advancement or insufficient funds accordingly.
    - Ensure the signer is set correctly based on the nonce state and check if the signer has signed the transaction.
    - Subtract the requested lamports from the 'from' account and handle any errors.
    - Borrow the 'to' account and add the requested lamports to it, handling any errors.
    - Return success if all operations complete without errors.
- **Output**: Returns an integer status code indicating success (`FD_EXECUTOR_INSTR_SUCCESS`) or an error code if any checks or operations fail.
- **Functions called**:
    - [`most_recent_block_hash`](#most_recent_block_hash)
    - [`fd_durable_nonce_from_blockhash`](#fd_durable_nonce_from_blockhash)
    - [`fd_system_program_set_nonce_state`](#fd_system_program_set_nonce_state)


---
### fd\_system\_program\_exec\_withdraw\_nonce\_account<!-- {{#callable:fd_system_program_exec_withdraw_nonce_account}} -->
The function `fd_system_program_exec_withdraw_nonce_account` executes the withdrawal of lamports from a nonce account, ensuring necessary conditions and requirements are met.
- **Inputs**:
    - `ctx`: A pointer to the execution instruction context (`fd_exec_instr_ctx_t`), which contains information about the current instruction and transaction context.
    - `requested_lamports`: The amount of lamports requested to be withdrawn from the nonce account.
- **Control Flow**:
    - Check if the number of account keys in the instruction context is less than 2, returning an error if true.
    - Initialize a `fd_recent_block_hashes_t` object and call [`require_acct_recent_blockhashes`](#require_acct_recent_blockhashes) to ensure the recent blockhashes account is present and valid, returning an error if not.
    - Initialize a `fd_rent_t` pointer and call [`require_acct_rent`](#require_acct_rent) to ensure the rent account is present and valid, returning an error if not.
    - Call [`fd_system_program_withdraw_nonce_account`](#fd_system_program_withdraw_nonce_account) with the context, requested lamports, and rent to perform the actual withdrawal operation.
- **Output**: Returns an integer status code indicating success or the type of error encountered during execution.
- **Functions called**:
    - [`require_acct_recent_blockhashes`](#require_acct_recent_blockhashes)
    - [`require_acct_rent`](#require_acct_rent)
    - [`fd_system_program_withdraw_nonce_account`](#fd_system_program_withdraw_nonce_account)


---
### fd\_system\_program\_initialize\_nonce\_account<!-- {{#callable:fd_system_program_initialize_nonce_account}} -->
The function `fd_system_program_initialize_nonce_account` initializes a nonce account by setting its state to initialized with a durable nonce and an authorized public key, ensuring the account is writable and has sufficient lamports.
- **Inputs**:
    - `ctx`: A pointer to the execution instruction context (`fd_exec_instr_ctx_t`), which provides the necessary context for executing the instruction.
    - `account`: A pointer to the borrowed account (`fd_borrowed_account_t`) that is to be initialized as a nonce account.
    - `authorized`: A constant pointer to the public key (`fd_pubkey_t`) that will be authorized to manage the nonce account.
    - `rent`: A constant pointer to the rent system variable (`fd_rent_t`) used to determine the minimum balance required for rent exemption.
- **Control Flow**:
    - Check if the account is writable; if not, log an error and return an invalid argument error code.
    - Decode the account's data to determine its current nonce state version; if decoding fails, return an invalid account data error code.
    - Based on the decoded state, check if the account is uninitialized or already initialized.
    - If uninitialized, calculate the minimum balance required for rent exemption and check if the account has sufficient lamports; if not, log an error and return an insufficient funds error code.
    - Retrieve the most recent block hash and derive a durable nonce from it.
    - Create a new nonce state with the current version, setting the state to initialized with the durable nonce and authorized public key.
    - Attempt to set the new nonce state on the account; if this fails, return the error code.
    - If the account is already initialized, log an error and return an invalid account data error code.
- **Output**: Returns an integer status code indicating success (`FD_EXECUTOR_INSTR_SUCCESS`) or an error code if any checks or operations fail.
- **Functions called**:
    - [`most_recent_block_hash`](#most_recent_block_hash)
    - [`fd_durable_nonce_from_blockhash`](#fd_durable_nonce_from_blockhash)
    - [`fd_system_program_set_nonce_state`](#fd_system_program_set_nonce_state)


---
### fd\_system\_program\_exec\_initialize\_nonce\_account<!-- {{#callable:fd_system_program_exec_initialize_nonce_account}} -->
The function `fd_system_program_exec_initialize_nonce_account` initializes a nonce account in the Solana system program by verifying account conditions and setting the nonce state.
- **Inputs**:
    - `ctx`: A pointer to the execution instruction context (`fd_exec_instr_ctx_t`), which contains information about the current instruction and transaction context.
    - `authorized`: A pointer to a `fd_pubkey_t` structure representing the public key of the account authorized to manage the nonce account.
- **Control Flow**:
    - Check if the instruction context has at least one account key; if not, return an error indicating insufficient account keys.
    - Attempt to borrow the account at index 0 from the instruction context and check for errors.
    - Retrieve recent blockhashes and check for errors; if the list is empty, log a message and return a custom error.
    - Retrieve the rent sysvar and check for errors.
    - Call [`fd_system_program_initialize_nonce_account`](#fd_system_program_initialize_nonce_account) to initialize the nonce account with the borrowed account, authorized public key, and rent information.
    - Return the result of the initialization function.
- **Output**: Returns an integer error code, where 0 indicates success and non-zero values indicate various error conditions encountered during execution.
- **Functions called**:
    - [`require_acct_recent_blockhashes`](#require_acct_recent_blockhashes)
    - [`require_acct_rent`](#require_acct_rent)
    - [`fd_system_program_initialize_nonce_account`](#fd_system_program_initialize_nonce_account)


---
### fd\_system\_program\_authorize\_nonce\_account<!-- {{#callable:fd_system_program_authorize_nonce_account}} -->
The function `fd_system_program_authorize_nonce_account` authorizes a new authority for a nonce account in the Solana system program.
- **Inputs**:
    - `ctx`: A pointer to the execution instruction context (`fd_exec_instr_ctx_t`), which contains information about the current transaction and execution environment.
    - `account`: A pointer to the borrowed account (`fd_borrowed_account_t`) representing the nonce account to be authorized.
    - `instr_acc_idx`: An unsigned short integer representing the index of the account in the instruction's account list that should be writable.
    - `nonce_authority`: A pointer to the public key (`fd_pubkey_t`) of the new authority to be set for the nonce account.
- **Control Flow**:
    - Check if the account at `instr_acc_idx` is writable; if not, log an error and return an invalid argument error.
    - Decode the nonce state versions from the account's data; if decoding fails, return an invalid account data error.
    - Determine the current state of the nonce account based on its version discriminant.
    - Check if the nonce account is initialized; if not, log an error and return an invalid account data error.
    - Verify that the current authority of the nonce account has signed the transaction; if not, log an error and return a missing required signature error.
    - Create a new nonce state with the new authority and the existing durable nonce and fee calculator.
    - Create a new versioned nonce state based on the current version and set the new state in the account.
    - Return success if all operations complete without error.
- **Output**: Returns an integer status code indicating success or the type of error encountered during execution.
- **Functions called**:
    - [`fd_system_program_set_nonce_state`](#fd_system_program_set_nonce_state)


---
### fd\_system\_program\_exec\_authorize\_nonce\_account<!-- {{#callable:fd_system_program_exec_authorize_nonce_account}} -->
The function `fd_system_program_exec_authorize_nonce_account` authorizes a nonce account by verifying the account's authority and updating its state with a new nonce authority.
- **Inputs**:
    - `ctx`: A pointer to the execution instruction context (`fd_exec_instr_ctx_t`), which contains information about the current instruction and transaction.
    - `nonce_authority`: A pointer to a `fd_pubkey_t` structure representing the new authority for the nonce account.
- **Control Flow**:
    - Check if the number of accounts in the instruction context is less than 1; if so, return an error indicating not enough account keys.
    - Attempt to borrow the first account from the instruction context; if this fails, return the error encountered.
    - Call [`fd_system_program_authorize_nonce_account`](#fd_system_program_authorize_nonce_account) to authorize the nonce account with the provided nonce authority.
    - Return the result of the authorization operation.
- **Output**: Returns an integer error code, where 0 indicates success and any non-zero value indicates an error occurred during the authorization process.
- **Functions called**:
    - [`fd_system_program_authorize_nonce_account`](#fd_system_program_authorize_nonce_account)


---
### fd\_system\_program\_exec\_upgrade\_nonce\_account<!-- {{#callable:fd_system_program_exec_upgrade_nonce_account}} -->
The function `fd_system_program_exec_upgrade_nonce_account` upgrades a nonce account from a legacy version to the current version if certain conditions are met.
- **Inputs**:
    - `ctx`: A pointer to an `fd_exec_instr_ctx_t` structure, which contains the execution context for the instruction, including transaction and instruction details.
- **Control Flow**:
    - Check if the number of accounts in the instruction context is less than 1, returning an error if true.
    - Attempt to borrow the nonce account using the index 0, returning an error if unsuccessful.
    - Verify that the owner of the account matches the expected Solana system program ID, returning an error if not.
    - Check if the account is writable, returning an error if it is not.
    - Decode the nonce state versions from the account data, returning an error if decoding fails.
    - Ensure the nonce state version is legacy and initialized, returning an error if not.
    - Update the durable nonce using the current blockhash.
    - Create a new state with the current version and set it to the account, returning an error if setting fails.
    - Return success if all operations complete without errors.
- **Output**: Returns an integer status code, `FD_EXECUTOR_INSTR_SUCCESS` on success, or an error code indicating the type of failure encountered during execution.
- **Functions called**:
    - [`fd_durable_nonce_from_blockhash`](#fd_durable_nonce_from_blockhash)
    - [`fd_system_program_set_nonce_state`](#fd_system_program_set_nonce_state)


---
### fd\_check\_transaction\_age<!-- {{#callable:fd_check_transaction_age}} -->
The `fd_check_transaction_age` function verifies the validity of a transaction's age by checking if its blockhash is recent or if it contains a valid nonce account.
- **Inputs**:
    - `txn_ctx`: A pointer to a `fd_exec_txn_ctx_t` structure representing the transaction context, which includes details like the block hash queue and transaction descriptor.
- **Control Flow**:
    - Retrieve the last blockhash from the transaction context's block hash queue.
    - Generate a durable nonce from the last blockhash.
    - Extract the recent blockhash from the transaction's raw data using the offset from the transaction descriptor.
    - Check if the recent blockhash is valid within the maximum allowed recent blockhash entries; if valid, return success.
    - Compare the generated durable nonce with the recent blockhash; if they match, return a blockhash not found error.
    - Verify that the transaction descriptor contains instructions; if not, return a blockhash not found error.
    - Check if the first instruction's program ID matches the system program ID and if it is an advance nonce account instruction; if not, return a blockhash not found error.
    - Ensure the first instruction account is writable; if not, return a blockhash not found error.
    - Initialize a durable nonce account record and verify its owner matches the system program ID; if not, return a blockhash not found error.
    - Decode the nonce state and verify it is not legacy or uninitialized; if it is, return a blockhash not found error.
    - Compare the decoded durable nonce with the recent blockhash; if they do not match, return a blockhash not found error.
    - Check if any accounts in the nonce instruction are signers and if the authority matches; if so, update the nonce state and return success.
    - If no valid conditions are met, return a blockhash not found error.
- **Output**: The function returns an integer status code indicating success (`FD_RUNTIME_EXECUTE_SUCCESS`) or various error conditions (`FD_RUNTIME_TXN_ERR_BLOCKHASH_NOT_FOUND`).
- **Functions called**:
    - [`fd_durable_nonce_from_blockhash`](#fd_durable_nonce_from_blockhash)


