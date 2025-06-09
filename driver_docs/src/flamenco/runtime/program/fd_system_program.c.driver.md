# Purpose
This C source code file is part of a system program implementation for the Solana blockchain, specifically designed to handle various system instructions. The file provides a set of functions that execute different system instructions, such as creating accounts, transferring funds, allocating space, and assigning account ownership. These functions are implemented to match the behavior of the Solana Labs' system processor, as indicated by the numerous references to the Solana Labs' GitHub repository. The code is structured to handle specific cases, such as operations involving seeds, which are used to derive addresses deterministically. The functions are designed to be executed within a transaction context, utilizing various utility functions and data structures to manage accounts and public keys.

The file includes several key components, such as functions for verifying seed-derived addresses, transferring funds with and without verification, allocating and assigning account space, and creating accounts with or without seeds. Each function is carefully crafted to ensure that operations are performed securely and correctly, with error handling and logging mechanisms in place to manage potential issues. The code is intended to be part of a larger system, likely a library or module, that can be integrated into Solana's execution environment. It defines a public API for executing system instructions, making it a crucial component for developers working with Solana's system program.
# Imports and Dependencies

---
- `../fd_executor.h`
- `fd_system_program.h`
- `../fd_acc_mgr.h`
- `../fd_borrowed_account.h`
- `../fd_system_ids.h`
- `../fd_pubkey_utils.h`
- `../sysvar/fd_sysvar_rent.h`
- `../context/fd_exec_epoch_ctx.h`
- `../context/fd_exec_slot_ctx.h`
- `../context/fd_exec_txn_ctx.h`


# Functions

---
### verify\_seed\_address<!-- {{#callable:verify_seed_address}} -->
The `verify_seed_address` function re-derives a public key from given inputs and checks if it matches an expected value, logging an error if there is a mismatch.
- **Inputs**:
    - `ctx`: A pointer to the execution instruction context (`fd_exec_instr_ctx_t`), which provides the necessary context for the function execution.
    - `expected`: A pointer to the expected public key (`fd_pubkey_t`) that the derived key should match.
    - `base`: A pointer to the base public key (`fd_pubkey_t`) used in the derivation process.
    - `seed`: A constant character pointer to the seed string used in the key derivation.
    - `seed_sz`: An unsigned long representing the size of the seed.
    - `owner`: A pointer to the owner's public key (`fd_pubkey_t`) used in the derivation process.
- **Control Flow**:
    - Initialize an array `actual` to store the derived public key.
    - Call `fd_pubkey_create_with_seed` to derive a public key using the base, seed, and owner, storing the result in `actual`.
    - If the derivation function returns an error, immediately return that error.
    - Compare the derived public key `actual` with the `expected` public key using `memcmp`.
    - If the keys do not match, log an error message indicating the mismatch and set a custom error in the context.
    - Return a custom error code if there is a mismatch, otherwise return 0 indicating success.
- **Output**: Returns 0 on success if the derived public key matches the expected one, or an error code if there is a mismatch or if the key derivation fails.


---
### fd\_system\_program\_transfer\_verified<!-- {{#callable:fd_system_program_transfer_verified}} -->
The `fd_system_program_transfer_verified` function performs a verified transfer of lamports between two accounts, ensuring sufficient balance and no data in the source account.
- **Inputs**:
    - `ctx`: A pointer to the execution instruction context (`fd_exec_instr_ctx_t`), which contains transaction and instruction details.
    - `transfer_amount`: The amount of lamports to be transferred from the source account to the destination account.
    - `from_acct_idx`: The index of the source account in the instruction's account list.
    - `to_acct_idx`: The index of the destination account in the instruction's account list.
- **Control Flow**:
    - Attempt to borrow the source account using the provided index and check for errors.
    - Verify that the source account does not contain any data; if it does, log an error and return an invalid argument error code.
    - Check if the source account has sufficient lamports for the transfer; if not, log an error and return a custom error code indicating insufficient funds.
    - Subtract the transfer amount from the source account's lamports, ensuring no error occurs due to the prior balance check.
    - Release the borrowed source account.
    - Attempt to borrow the destination account using the provided index and check for errors.
    - Add the transfer amount to the destination account's lamports, checking for errors.
    - Return 0 to indicate successful execution.
- **Output**: Returns 0 on success, or an error code if any validation or operation fails.


---
### fd\_system\_program\_transfer<!-- {{#callable:fd_system_program_transfer}} -->
The `fd_system_program_transfer` function initiates a transfer of lamports between two accounts, ensuring the 'from' account has signed the transaction before delegating the actual transfer to a verified function.
- **Inputs**:
    - `ctx`: A pointer to the execution instruction context (`fd_exec_instr_ctx_t`), which contains transaction and instruction details.
    - `transfer_amount`: The amount of lamports to be transferred, specified as an unsigned long integer.
    - `from_acct_idx`: The index of the account from which lamports are to be transferred, specified as an unsigned short integer.
    - `to_acct_idx`: The index of the account to which lamports are to be transferred, specified as an unsigned short integer.
- **Control Flow**:
    - Check if the 'from' account has signed the transaction using `fd_instr_acc_is_signer_idx` function.
    - If the 'from' account has not signed, log an error message and return an error code `FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE`.
    - If the 'from' account has signed, call [`fd_system_program_transfer_verified`](#fd_system_program_transfer_verified) to perform the actual transfer.
- **Output**: Returns an integer status code, where 0 indicates success, and non-zero values indicate various error conditions.
- **Functions called**:
    - [`fd_system_program_transfer_verified`](#fd_system_program_transfer_verified)


---
### fd\_system\_program\_allocate<!-- {{#callable:fd_system_program_allocate}} -->
The `fd_system_program_allocate` function allocates a specified amount of space for a given account, ensuring that the account is not already in use and that the allocation request is valid.
- **Inputs**:
    - `ctx`: A pointer to the execution instruction context (`fd_exec_instr_ctx_t`), which contains information about the current execution environment.
    - `account`: A pointer to the borrowed account (`fd_borrowed_account_t`) for which space is to be allocated.
    - `space`: An unsigned long integer representing the amount of space to allocate for the account.
    - `authority`: A constant pointer to the public key (`fd_pubkey_t`) of the authority that must sign the allocation request.
- **Control Flow**:
    - Check if the authority has signed the request using `fd_exec_instr_ctx_any_signed`; if not, log an error and return a missing signature error code.
    - Verify that the account is not already in use by checking its data length and owner; if it is in use, log an error, set a custom error code, and return a custom error code.
    - Ensure the requested space does not exceed the maximum allowed size (`FD_ACC_SZ_MAX`); if it does, log an error, set a custom error code, and return a custom error code.
    - Attempt to set the data length of the account to the requested space using `fd_borrowed_account_set_data_length`; if this fails, return the error code from this operation.
    - If all checks pass and the space is successfully allocated, return a success code (`FD_EXECUTOR_INSTR_SUCCESS`).
- **Output**: The function returns an integer status code indicating success (`FD_EXECUTOR_INSTR_SUCCESS`) or an error code if any checks fail.


---
### fd\_system\_program\_assign<!-- {{#callable:fd_system_program_assign}} -->
The `fd_system_program_assign` function assigns a new owner to a borrowed account if the current owner is different and the authority has signed the transaction.
- **Inputs**:
    - `ctx`: A pointer to the execution instruction context (`fd_exec_instr_ctx_t`), which contains information about the current execution environment.
    - `account`: A pointer to the borrowed account (`fd_borrowed_account_t`) that is to be assigned a new owner.
    - `owner`: A pointer to the public key (`fd_pubkey_t`) representing the new owner of the account.
    - `authority`: A pointer to the public key (`fd_pubkey_t`) representing the authority that must sign the transaction for the assignment to proceed.
- **Control Flow**:
    - Check if the current owner of the account matches the new owner; if they match, return 0 indicating no change is needed.
    - If the current owner does not match the new owner, check if the authority has signed the transaction using `fd_exec_instr_ctx_any_signed`.
    - If the authority has not signed, log an error message and return an error code `FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE`.
    - If the authority has signed, proceed to set the new owner of the account using `fd_borrowed_account_set_owner` and return the result of this operation.
- **Output**: Returns 0 if the owner is already correct or if the assignment is successful; otherwise, returns an error code indicating a missing required signature or other issues.


---
### fd\_system\_program\_allocate\_and\_assign<!-- {{#callable:fd_system_program_allocate_and_assign}} -->
The `fd_system_program_allocate_and_assign` function allocates space for an account and assigns it to a specified owner using the provided authority.
- **Inputs**:
    - `ctx`: A pointer to the execution instruction context (`fd_exec_instr_ctx_t`) which contains the execution environment and state.
    - `account`: A pointer to the borrowed account (`fd_borrowed_account_t`) that is to be allocated and assigned.
    - `space`: An unsigned long integer specifying the amount of space to allocate for the account.
    - `owner`: A constant pointer to the public key (`fd_pubkey_t`) representing the new owner of the account.
    - `authority`: A constant pointer to the public key (`fd_pubkey_t`) representing the authority that can authorize the allocation and assignment.
- **Control Flow**:
    - The function begins by calling [`fd_system_program_allocate`](#fd_system_program_allocate) with the provided context, account, space, and authority to allocate the specified space for the account.
    - If the allocation fails (indicated by a non-zero error code), the function immediately returns this error code.
    - If the allocation is successful, the function proceeds to call [`fd_system_program_assign`](#fd_system_program_assign) with the context, account, owner, and authority to assign the account to the specified owner.
    - The function returns the result of the [`fd_system_program_assign`](#fd_system_program_assign) call, which indicates success or failure of the assignment.
- **Output**: The function returns an integer status code, where 0 indicates success and any non-zero value indicates an error occurred during allocation or assignment.
- **Functions called**:
    - [`fd_system_program_allocate`](#fd_system_program_allocate)
    - [`fd_system_program_assign`](#fd_system_program_assign)


---
### fd\_system\_program\_create\_account<!-- {{#callable:fd_system_program_create_account}} -->
The `fd_system_program_create_account` function creates a new account by allocating space, assigning an owner, and transferring lamports from a source account to the new account.
- **Inputs**:
    - `ctx`: A pointer to the execution instruction context (`fd_exec_instr_ctx_t`), which contains the necessary context for executing the instruction.
    - `from_acct_idx`: An unsigned short representing the index of the source account from which lamports will be transferred.
    - `to_acct_idx`: An unsigned short representing the index of the destination account to be created.
    - `lamports`: An unsigned long representing the amount of lamports to transfer from the source account to the new account.
    - `space`: An unsigned long representing the amount of space to allocate for the new account.
    - `owner`: A pointer to a `fd_pubkey_t` structure representing the public key of the owner of the new account.
    - `authority`: A pointer to a `fd_pubkey_t` structure representing the authority that can sign for the new account.
- **Control Flow**:
    - Check if the destination account (to account) is already in use by borrowing the account and checking its lamports; if it is in use, log an error and return a custom error code.
    - If the account is not in use, call [`fd_system_program_allocate_and_assign`](#fd_system_program_allocate_and_assign) to allocate space and assign the owner and authority to the new account.
    - If the allocation and assignment are successful, call [`fd_system_program_transfer`](#fd_system_program_transfer) to transfer the specified lamports from the source account to the new account.
- **Output**: Returns an integer status code, where 0 indicates success, and any non-zero value indicates an error, such as the account already being in use or a failure in allocation, assignment, or transfer.
- **Functions called**:
    - [`fd_system_program_allocate_and_assign`](#fd_system_program_allocate_and_assign)
    - [`fd_system_program_transfer`](#fd_system_program_transfer)


---
### fd\_system\_program\_exec\_create\_account<!-- {{#callable:fd_system_program_exec_create_account}} -->
The `fd_system_program_exec_create_account` function executes the creation of a new account in the Solana system program by validating inputs and delegating the task to [`fd_system_program_create_account`](#fd_system_program_create_account).
- **Inputs**:
    - `ctx`: A pointer to the execution instruction context (`fd_exec_instr_ctx_t`), which contains information about the current instruction and transaction context.
    - `create_acc`: A pointer to a `fd_system_program_instruction_create_account_t` structure containing the parameters for the account creation, such as lamports, space, and owner.
- **Control Flow**:
    - Check if the number of account keys in the instruction context is less than 2; if so, return an error indicating not enough account keys.
    - Define `from_acct_idx` as 0 and `to_acct_idx` as 1, representing the indices of the source and destination accounts, respectively.
    - Retrieve the authority key for the destination account using `fd_exec_instr_ctx_get_key_of_account_at_index`; if an error occurs, return it.
    - Call [`fd_system_program_create_account`](#fd_system_program_create_account) with the context, account indices, and parameters from `create_acc`, along with the retrieved authority, to perform the account creation.
- **Output**: Returns an integer status code, where 0 indicates success and non-zero values indicate various errors, such as insufficient account keys or errors from the account creation process.
- **Functions called**:
    - [`fd_system_program_create_account`](#fd_system_program_create_account)


---
### fd\_system\_program\_exec\_assign<!-- {{#callable:fd_system_program_exec_assign}} -->
The `fd_system_program_exec_assign` function assigns a new owner to an account within the context of a system program execution.
- **Inputs**:
    - `ctx`: A pointer to an `fd_exec_instr_ctx_t` structure, which provides the execution context for the instruction.
    - `owner`: A pointer to a `fd_pubkey_t` structure representing the new owner's public key.
- **Control Flow**:
    - Check if the number of accounts in the instruction context is less than 1; if so, return an error code `FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS`.
    - Attempt to borrow the first account from the instruction context using `FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK`; if this fails, return the error code.
    - Call [`fd_system_program_assign`](#fd_system_program_assign) with the context, the borrowed account, the new owner, and the account's current public key to assign the new owner; if this fails, return the error code.
    - Return 0 to indicate success.
- **Output**: Returns 0 on success or an error code if an error occurs during execution.
- **Functions called**:
    - [`fd_system_program_assign`](#fd_system_program_assign)


---
### fd\_system\_program\_exec\_transfer<!-- {{#callable:fd_system_program_exec_transfer}} -->
The `fd_system_program_exec_transfer` function executes a transfer operation by verifying account keys and delegating the transfer to another function.
- **Inputs**:
    - `ctx`: A pointer to an `fd_exec_instr_ctx_t` structure, which contains the execution context for the instruction.
    - `transfer_amount`: An unsigned long integer representing the amount to be transferred.
- **Control Flow**:
    - Check if the number of account keys in the instruction context is less than 2; if so, return an error code `FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS`.
    - Call the [`fd_system_program_transfer`](#fd_system_program_transfer) function with the context, transfer amount, and fixed account indices 0 and 1, and return its result.
- **Output**: Returns an integer status code, which is either an error code if there are not enough account keys or the result of the [`fd_system_program_transfer`](#fd_system_program_transfer) function.
- **Functions called**:
    - [`fd_system_program_transfer`](#fd_system_program_transfer)


---
### fd\_system\_program\_exec\_create\_account\_with\_seed<!-- {{#callable:fd_system_program_exec_create_account_with_seed}} -->
The function `fd_system_program_exec_create_account_with_seed` creates a new account with a derived address using a seed, transferring lamports and allocating space for it.
- **Inputs**:
    - `ctx`: A pointer to the execution instruction context (`fd_exec_instr_ctx_t`), which contains the necessary context for executing the instruction.
    - `args`: A pointer to a structure (`fd_system_program_instruction_create_account_with_seed_t`) containing the parameters for creating the account, including the base public key, seed, seed length, owner public key, lamports, and space.
- **Control Flow**:
    - Check if the number of instruction accounts in the context is less than 2, returning an error if true.
    - Retrieve the public key of the account at index 1 and store it in `to_address`, returning an error if retrieval fails.
    - Verify the derived address using the base, seed, seed length, and owner from `args`, returning an error if verification fails.
    - Define `from_acct_idx` as 0 and `to_acct_idx` as 1, representing the indices of the source and destination accounts.
    - Call [`fd_system_program_create_account`](#fd_system_program_create_account) with the context, account indices, lamports, space, owner, and base to create the account.
- **Output**: Returns an integer status code, where 0 indicates success and any non-zero value indicates an error.
- **Functions called**:
    - [`verify_seed_address`](#verify_seed_address)
    - [`fd_system_program_create_account`](#fd_system_program_create_account)


---
### fd\_system\_program\_exec\_allocate<!-- {{#callable:fd_system_program_exec_allocate}} -->
The `fd_system_program_exec_allocate` function attempts to allocate a specified amount of space for an account within the execution context.
- **Inputs**:
    - `ctx`: A pointer to the `fd_exec_instr_ctx_t` structure, which contains the execution context for the instruction.
    - `space`: An unsigned long integer representing the amount of space to allocate.
- **Control Flow**:
    - Check if the number of accounts in the instruction context is less than 1; if so, return an error indicating insufficient account keys.
    - Attempt to borrow the first account from the instruction context using a guarded borrow mechanism.
    - Call [`fd_system_program_allocate`](#fd_system_program_allocate) with the context, the borrowed account, the space to allocate, and the account's public key as the authority.
    - If the allocation call returns an error, return that error.
    - Return 0 to indicate success if no errors occurred.
- **Output**: Returns 0 on success or an error code if an error occurs during the allocation process.
- **Functions called**:
    - [`fd_system_program_allocate`](#fd_system_program_allocate)


---
### fd\_system\_program\_exec\_allocate\_with\_seed<!-- {{#callable:fd_system_program_exec_allocate_with_seed}} -->
The function `fd_system_program_exec_allocate_with_seed` verifies a seed-derived address and allocates space for an account, assigning it to a specified owner.
- **Inputs**:
    - `ctx`: A pointer to the execution instruction context (`fd_exec_instr_ctx_t`), which contains information about the current instruction and transaction context.
    - `args`: A pointer to a constant structure (`fd_system_program_instruction_allocate_with_seed_t`) containing the parameters for the allocation, including the base public key, seed, seed length, owner public key, and space to allocate.
- **Control Flow**:
    - Check if the number of account keys in the instruction context is less than 1; if so, return an error indicating insufficient account keys.
    - Attempt to borrow the first account from the instruction context; if unsuccessful, return an error.
    - Verify the address derived from the seed matches the expected public key using [`verify_seed_address`](#verify_seed_address); if it fails, return the error.
    - Call [`fd_system_program_allocate_and_assign`](#fd_system_program_allocate_and_assign) to allocate the specified space and assign the account to the owner; if it fails, return the error.
    - Return 0 to indicate success.
- **Output**: Returns 0 on success, or an error code if any step in the process fails.
- **Functions called**:
    - [`verify_seed_address`](#verify_seed_address)
    - [`fd_system_program_allocate_and_assign`](#fd_system_program_allocate_and_assign)


---
### fd\_system\_program\_exec\_assign\_with\_seed<!-- {{#callable:fd_system_program_exec_assign_with_seed}} -->
The function `fd_system_program_exec_assign_with_seed` verifies a seed-derived address and assigns a new owner to an account if the verification is successful.
- **Inputs**:
    - `ctx`: A pointer to the execution instruction context (`fd_exec_instr_ctx_t`), which contains information about the current instruction being executed.
    - `args`: A pointer to a constant structure (`fd_system_program_instruction_assign_with_seed_t`) containing the base public key, seed, seed length, and the new owner's public key for the assignment operation.
- **Control Flow**:
    - Check if the number of account keys in the instruction context is less than 1; if so, return an error indicating not enough account keys.
    - Attempt to borrow the first account from the instruction context using `FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK`; if this fails, return the error.
    - Call [`verify_seed_address`](#verify_seed_address) to ensure the derived address from the seed matches the expected public key; if verification fails, return the error.
    - Call [`fd_system_program_assign`](#fd_system_program_assign) to assign the new owner to the account; if this fails, return the error.
    - Return 0 to indicate success.
- **Output**: Returns 0 on success, or an error code if any of the operations (account borrowing, seed verification, or assignment) fail.
- **Functions called**:
    - [`verify_seed_address`](#verify_seed_address)
    - [`fd_system_program_assign`](#fd_system_program_assign)


---
### fd\_system\_program\_exec\_transfer\_with\_seed<!-- {{#callable:fd_system_program_exec_transfer_with_seed}} -->
The function `fd_system_program_exec_transfer_with_seed` executes a transfer of lamports between accounts using a derived address from a seed, ensuring the 'from' account is correctly signed and matches the derived address.
- **Inputs**:
    - `ctx`: A pointer to the execution instruction context (`fd_exec_instr_ctx_t`), which contains information about the current transaction and instruction.
    - `args`: A pointer to the `fd_system_program_instruction_transfer_with_seed_t` structure, which contains the parameters for the transfer, including the seed, seed length, owner, and lamports to transfer.
- **Control Flow**:
    - Check if the number of instruction accounts is at least 3; if not, return an error for insufficient account keys.
    - Define indices for 'from', 'from_base', and 'to' accounts.
    - Verify that the 'from_base' account is a signer; if not, log an error and return a missing signature error.
    - Retrieve the base public key from the 'from_base' account index; return an error if retrieval fails.
    - Create a derived address using the base public key, seed, seed length, and owner; return an error if creation fails.
    - Retrieve the 'from' account public key; return an error if retrieval fails.
    - Compare the derived address with the 'from' account public key; if they do not match, log an error, set a custom error, and return a custom error code.
    - Call [`fd_system_program_transfer_verified`](#fd_system_program_transfer_verified) to perform the transfer of lamports from the 'from' account to the 'to' account.
- **Output**: The function returns an integer status code, which indicates success or the type of error encountered during execution.
- **Functions called**:
    - [`fd_system_program_transfer_verified`](#fd_system_program_transfer_verified)


---
### fd\_system\_program\_execute<!-- {{#callable:fd_system_program_execute}} -->
The `fd_system_program_execute` function processes a system instruction by deserializing it and executing the corresponding operation based on the instruction's type.
- **Inputs**:
    - `ctx`: A pointer to an `fd_exec_instr_ctx_t` structure, which contains the execution context for the instruction, including the instruction data and transaction context.
- **Control Flow**:
    - Update the execution context with a constant value using `FD_EXEC_CU_UPDATE`.
    - Check if the instruction data is NULL and return an error if so.
    - Deserialize the instruction data into a `fd_system_program_instruction_t` structure using `fd_bincode_decode1_spad`.
    - Check for decoding errors or if the decoded size exceeds a maximum threshold, returning an error if any issues are found.
    - Initialize the result variable to `FD_EXECUTOR_INSTR_ERR_INVALID_ARG`.
    - Use a switch statement to determine the type of system instruction based on the `discriminant` field of the deserialized instruction.
    - For each case in the switch statement, call the corresponding execution function (e.g., [`fd_system_program_exec_create_account`](#fd_system_program_exec_create_account)) with the appropriate arguments.
    - Return the result of the executed instruction.
- **Output**: The function returns an integer status code indicating the result of the instruction execution, with specific error codes for invalid data, arguments, or other issues.
- **Functions called**:
    - [`fd_system_program_exec_create_account`](#fd_system_program_exec_create_account)
    - [`fd_system_program_exec_assign`](#fd_system_program_exec_assign)
    - [`fd_system_program_exec_transfer`](#fd_system_program_exec_transfer)
    - [`fd_system_program_exec_create_account_with_seed`](#fd_system_program_exec_create_account_with_seed)
    - [`fd_system_program_exec_advance_nonce_account`](fd_system_program_nonce.c.driver.md#fd_system_program_exec_advance_nonce_account)
    - [`fd_system_program_exec_withdraw_nonce_account`](fd_system_program_nonce.c.driver.md#fd_system_program_exec_withdraw_nonce_account)
    - [`fd_system_program_exec_initialize_nonce_account`](fd_system_program_nonce.c.driver.md#fd_system_program_exec_initialize_nonce_account)
    - [`fd_system_program_exec_authorize_nonce_account`](fd_system_program_nonce.c.driver.md#fd_system_program_exec_authorize_nonce_account)
    - [`fd_system_program_exec_allocate`](#fd_system_program_exec_allocate)
    - [`fd_system_program_exec_allocate_with_seed`](#fd_system_program_exec_allocate_with_seed)
    - [`fd_system_program_exec_assign_with_seed`](#fd_system_program_exec_assign_with_seed)
    - [`fd_system_program_exec_transfer_with_seed`](#fd_system_program_exec_transfer_with_seed)
    - [`fd_system_program_exec_upgrade_nonce_account`](fd_system_program_nonce.c.driver.md#fd_system_program_exec_upgrade_nonce_account)


