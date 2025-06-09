# Purpose
This C header file defines the interface for a system program within the "Flamenco" runtime environment. It provides a collection of function prototypes and error definitions that facilitate the execution of various system-level operations, such as account creation, assignment, transfer of lamports (a unit of currency), and nonce account management. The file is structured to support the execution of these operations through a central entry point function, [`fd_system_program_execute`](#fd_system_program_execute), which likely serves as the main dispatcher for handling different system instructions. The file also defines a set of custom error codes that correspond to specific system errors, providing a standardized way to handle and report errors that may occur during the execution of these operations.

The header file is designed to be included in other C source files, allowing them to utilize the defined system program functionalities. It includes references to other header files, such as `fd_flamenco_base.h` and `fd_types.h`, indicating dependencies on base definitions and type declarations. The file also defines a user API function, [`fd_check_transaction_age`](#fd_check_transaction_age), which checks the validity of a transaction's age based on blockhash or nonce validity. This suggests that the system program is part of a larger framework that manages transactions and account states, likely in a blockchain or distributed ledger context. Overall, the file provides a focused set of functionalities related to system-level account and transaction management within the Flamenco runtime.
# Imports and Dependencies

---
- `../../fd_flamenco_base.h`
- `../../types/fd_types.h`


# Function Declarations (Public API)

---
### fd\_system\_program\_execute<!-- {{#callable_declaration:fd_system_program_execute}} -->
Executes a system program instruction based on the provided context.
- **Description**: This function serves as the entry point for executing system program instructions. It should be called with a valid execution instruction context, which contains the instruction data to be processed. The function decodes the instruction and dispatches it to the appropriate handler based on the instruction type. It is essential that the context provided is properly initialized and contains valid instruction data, as invalid data will result in an error code being returned. This function is typically used within a transaction processing system where system program instructions need to be executed as part of a larger transaction.
- **Inputs**:
    - `ctx`: A pointer to an fd_exec_instr_ctx_t structure that contains the execution context for the instruction. This must not be null and should be properly initialized with valid instruction data. If the data is null or invalid, the function will return an error code.
- **Output**: Returns an integer status code indicating the result of the execution. A non-zero value indicates an error, such as invalid instruction data or arguments.
- **See also**: [`fd_system_program_execute`](fd_system_program.c.driver.md#fd_system_program_execute)  (Implementation)


---
### fd\_system\_program\_exec\_create\_account<!-- {{#callable_declaration:fd_system_program_exec_create_account}} -->
Executes a create account instruction in the system program.
- **Description**: This function is used to execute a create account instruction within the system program context. It should be called when a new account needs to be created with specific parameters such as lamports, space, and owner. The function requires that the instruction context contains at least two account keys, and it performs an authorization check before proceeding. It is important to ensure that the context and instruction data are correctly set up before calling this function to avoid errors.
- **Inputs**:
    - `ctx`: A pointer to the execution instruction context, which must not be null. It contains the necessary information about the current execution state and account keys. The context must have at least two account keys, or the function will return an error.
    - `create_acc`: A pointer to a constant structure containing the parameters for the account creation, including lamports, space, and owner. This parameter must not be null, and the structure should be properly initialized with valid values.
- **Output**: Returns an integer status code indicating success or a specific error. Possible errors include not having enough account keys in the context or issues with account authorization.
- **See also**: [`fd_system_program_exec_create_account`](fd_system_program.c.driver.md#fd_system_program_exec_create_account)  (Implementation)


---
### fd\_system\_program\_exec\_assign<!-- {{#callable_declaration:fd_system_program_exec_assign}} -->
Assigns a new owner to an account in the execution context.
- **Description**: This function is used to assign a new owner to an account specified within the execution context. It should be called when there is a need to change the ownership of an account during the execution of a system program instruction. The function requires that the execution context contains at least one account key; otherwise, it returns an error indicating insufficient account keys. The caller must ensure that the context and owner parameters are valid and properly initialized before calling this function.
- **Inputs**:
    - `ctx`: A pointer to an fd_exec_instr_ctx_t structure representing the execution context. This must not be null and should be properly initialized with at least one account key.
    - `owner`: A pointer to an fd_pubkey_t structure representing the new owner's public key. This must not be null and should be a valid public key.
- **Output**: Returns 0 on success, or a non-zero error code if the operation fails, such as when there are not enough account keys in the context.
- **See also**: [`fd_system_program_exec_assign`](fd_system_program.c.driver.md#fd_system_program_exec_assign)  (Implementation)


---
### fd\_system\_program\_exec\_transfer<!-- {{#callable_declaration:fd_system_program_exec_transfer}} -->
Executes a transfer of lamports between accounts.
- **Description**: This function facilitates the transfer of a specified amount of lamports between accounts within the context of a system program execution. It should be used when a transfer operation is required as part of a transaction. The function requires that the context provided contains at least two account keys, as it needs both a source and a destination account for the transfer. If the context does not meet this requirement, the function will return an error indicating insufficient account keys. This function is typically called as part of a larger transaction processing workflow.
- **Inputs**:
    - `ctx`: A pointer to an fd_exec_instr_ctx_t structure that provides the execution context for the instruction. This context must include at least two account keys. The caller retains ownership and must ensure this pointer is not null.
    - `transfer_amount`: The amount of lamports to transfer. This is an unsigned long integer representing the number of lamports to be moved from the source account to the destination account.
- **Output**: Returns an integer status code. If the context does not have enough account keys, it returns FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS. Otherwise, it returns the result of the transfer operation.
- **See also**: [`fd_system_program_exec_transfer`](fd_system_program.c.driver.md#fd_system_program_exec_transfer)  (Implementation)


---
### fd\_system\_program\_exec\_create\_account\_with\_seed<!-- {{#callable_declaration:fd_system_program_exec_create_account_with_seed}} -->
Creates an account with a seed in the system program.
- **Description**: This function is used to create a new account in the system program using a seed, which allows for deterministic account address generation. It should be called when you need to create an account with a specific seed and base public key. The function requires a valid execution context and instruction arguments, and it checks for the necessary number of account keys. It returns an error code if the account creation fails due to insufficient account keys, invalid seed address, or other system program errors.
- **Inputs**:
    - `ctx`: A pointer to the execution instruction context, which must not be null. It provides the necessary context for executing the instruction, including access to account keys.
    - `args`: A pointer to a structure containing the arguments for creating an account with a seed. This includes the base public key, seed, seed length, owner public key, lamports, and space. The pointer must not be null, and the seed length must not exceed the maximum allowed length.
- **Output**: Returns an integer error code indicating success or the type of failure encountered during account creation.
- **See also**: [`fd_system_program_exec_create_account_with_seed`](fd_system_program.c.driver.md#fd_system_program_exec_create_account_with_seed)  (Implementation)


---
### fd\_system\_program\_exec\_advance\_nonce\_account<!-- {{#callable_declaration:fd_system_program_exec_advance_nonce_account}} -->
Advances the nonce account in the system program.
- **Description**: This function is used to advance the nonce account within the system program, which is part of the Solana blockchain infrastructure. It should be called when you need to update the nonce account to a new state, typically as part of transaction processing. The function requires a valid execution instruction context, which must contain at least one account key. If the context does not meet this requirement, the function will return an error indicating insufficient account keys. Additionally, the function checks for the presence of recent blockhashes, and if none are available, it logs an error and returns a custom error code. This function is essential for maintaining the correct state of nonce accounts and ensuring the security and validity of transactions.
- **Inputs**:
    - `ctx`: A pointer to an fd_exec_instr_ctx_t structure representing the execution instruction context. This context must contain at least one account key. The caller retains ownership and must ensure it is not null. If the account count is less than one, the function returns an error.
- **Output**: Returns an integer status code. A return value of 0 indicates success, while non-zero values indicate various errors, such as insufficient account keys or missing recent blockhashes.
- **See also**: [`fd_system_program_exec_advance_nonce_account`](fd_system_program_nonce.c.driver.md#fd_system_program_exec_advance_nonce_account)  (Implementation)


---
### fd\_system\_program\_exec\_withdraw\_nonce\_account<!-- {{#callable_declaration:fd_system_program_exec_withdraw_nonce_account}} -->
Withdraws lamports from a nonce account.
- **Description**: This function is used to withdraw a specified amount of lamports from a nonce account within the context of a system program execution. It should be called when there is a need to transfer lamports from a nonce account, ensuring that the account has enough lamports and that the necessary account keys are available. The function requires at least two account keys to be present in the execution context. It handles the retrieval of recent blockhashes and rent information as part of its operation. The function returns an error code if there are not enough account keys or if any required account information cannot be retrieved.
- **Inputs**:
    - `ctx`: A pointer to an fd_exec_instr_ctx_t structure representing the execution context. This must not be null and should be properly initialized with at least two account keys.
    - `requested_lamports`: The number of lamports to withdraw from the nonce account. This should be a non-negative value representing the amount to be withdrawn.
- **Output**: Returns an integer error code indicating success or the type of error encountered, such as insufficient account keys or issues retrieving necessary account information.
- **See also**: [`fd_system_program_exec_withdraw_nonce_account`](fd_system_program_nonce.c.driver.md#fd_system_program_exec_withdraw_nonce_account)  (Implementation)


---
### fd\_system\_program\_exec\_initialize\_nonce\_account<!-- {{#callable_declaration:fd_system_program_exec_initialize_nonce_account}} -->
Initializes a nonce account with the specified authorized public key.
- **Description**: This function is used to initialize a nonce account within the system program, setting the specified public key as the authorized key for future operations. It must be called with a valid execution instruction context and a non-null public key. The function checks for the presence of recent blockhashes and rent information, which are necessary for the initialization process. If these conditions are not met, or if the account is already in use, the function will return an error code. This function is typically used when setting up a new nonce account to ensure secure transaction processing.
- **Inputs**:
    - `ctx`: A pointer to an fd_exec_instr_ctx_t structure representing the execution instruction context. Must not be null and should be properly initialized before calling this function.
    - `pubkey`: A pointer to an fd_pubkey_t structure representing the public key to be authorized for the nonce account. Must not be null.
- **Output**: Returns an integer error code. A return value of 0 indicates success, while a non-zero value indicates an error, such as insufficient account keys or missing recent blockhashes.
- **See also**: [`fd_system_program_exec_initialize_nonce_account`](fd_system_program_nonce.c.driver.md#fd_system_program_exec_initialize_nonce_account)  (Implementation)


---
### fd\_system\_program\_exec\_authorize\_nonce\_account<!-- {{#callable_declaration:fd_system_program_exec_authorize_nonce_account}} -->
Authorizes a nonce account with a specified authority.
- **Description**: This function is used to authorize a nonce account within the context of a system program execution. It should be called when there is a need to set or change the authority of a nonce account. The function requires a valid execution context and a public key representing the new nonce authority. It is important to ensure that the execution context contains at least one account key, as the function will return an error if this precondition is not met. The function will attempt to borrow the first account from the context and authorize it with the provided nonce authority. If any errors occur during this process, such as insufficient account keys or issues with borrowing the account, the function will return an appropriate error code.
- **Inputs**:
    - `ctx`: A pointer to an fd_exec_instr_ctx_t structure representing the execution context. This must not be null and must contain at least one account key.
    - `nonce_authority`: A pointer to an fd_pubkey_t structure representing the public key of the new nonce authority. This must not be null.
- **Output**: Returns an integer error code. A return value of 0 indicates success, while a non-zero value indicates an error, such as insufficient account keys or failure to borrow the account.
- **See also**: [`fd_system_program_exec_authorize_nonce_account`](fd_system_program_nonce.c.driver.md#fd_system_program_exec_authorize_nonce_account)  (Implementation)


---
### fd\_system\_program\_exec\_allocate<!-- {{#callable_declaration:fd_system_program_exec_allocate}} -->
Allocates space for an account in the system program.
- **Description**: This function is used to allocate a specified amount of space for an account within the system program context. It should be called when there is a need to reserve space for account data. The function requires that the instruction context has at least one account key available. If the account is already in use or if there are any errors during the allocation process, the function will return an error code. It is important to ensure that the context is properly initialized and that the account is not already allocated before calling this function.
- **Inputs**:
    - `ctx`: A pointer to a fd_exec_instr_ctx_t structure representing the execution context. This must not be null and should be properly initialized with at least one account key.
    - `space`: An unsigned long integer specifying the amount of space to allocate for the account. The value should be a positive number representing the required space in bytes.
- **Output**: Returns 0 on success, or a non-zero error code if the allocation fails or if preconditions are not met.
- **See also**: [`fd_system_program_exec_allocate`](fd_system_program.c.driver.md#fd_system_program_exec_allocate)  (Implementation)


---
### fd\_system\_program\_exec\_allocate\_with\_seed<!-- {{#callable_declaration:fd_system_program_exec_allocate_with_seed}} -->
Allocates account space with a seed-derived address.
- **Description**: This function is used to allocate space for an account in a system program, using a seed to derive the account's address. It should be called when you need to allocate space for an account that is identified by a seed-derived address. The function requires a valid execution context and instruction arguments, and it performs necessary checks such as verifying the seed address and ensuring authorization. It returns an error code if any validation fails or if the allocation cannot be completed.
- **Inputs**:
    - `ctx`: A pointer to an fd_exec_instr_ctx_t structure representing the execution context. It must not be null and should be properly initialized before calling this function. The context should contain at least one account key.
    - `args`: A pointer to a constant fd_system_program_instruction_allocate_with_seed_t structure containing the instruction arguments. This includes the base public key, seed, seed length, owner, and space to allocate. The structure must not be null and should be correctly populated with valid data.
- **Output**: Returns 0 on success or a non-zero error code on failure, indicating the type of error encountered during execution.
- **See also**: [`fd_system_program_exec_allocate_with_seed`](fd_system_program.c.driver.md#fd_system_program_exec_allocate_with_seed)  (Implementation)


---
### fd\_system\_program\_exec\_assign\_with\_seed<!-- {{#callable_declaration:fd_system_program_exec_assign_with_seed}} -->
Executes an account assignment with a seed in the system program.
- **Description**: This function is used to assign an account to a new owner using a seed, within the context of a system program execution. It should be called when you need to change the ownership of an account based on a seed-derived address. The function requires that the instruction context has at least one account key available. It performs necessary checks, including verifying the seed address and ensuring authorization, before proceeding with the assignment. The function returns an error code if any of these checks fail or if the operation cannot be completed.
- **Inputs**:
    - `ctx`: A pointer to an fd_exec_instr_ctx_t structure representing the execution context. This must not be null and should be properly initialized with at least one account key.
    - `args`: A pointer to a constant fd_system_program_instruction_assign_with_seed_t structure containing the assignment parameters, including the base public key, seed, seed length, and new owner. This must not be null and should be correctly populated with valid data.
- **Output**: Returns 0 on success or a non-zero error code on failure, indicating the type of error encountered during execution.
- **See also**: [`fd_system_program_exec_assign_with_seed`](fd_system_program.c.driver.md#fd_system_program_exec_assign_with_seed)  (Implementation)


---
### fd\_system\_program\_exec\_transfer\_with\_seed<!-- {{#callable_declaration:fd_system_program_exec_transfer_with_seed}} -->
Executes a transfer of lamports between accounts using a derived address from a seed.
- **Description**: This function facilitates the transfer of lamports from one account to another, where the source account's address is derived from a seed. It should be used when a transfer needs to be executed with an account that is not directly specified but derived using a seed and a base public key. The function requires that the 'from' account signs the transaction and that the derived address matches the expected address. It returns specific error codes if preconditions are not met, such as missing signatures or address mismatches.
- **Inputs**:
    - `ctx`: A pointer to an fd_exec_instr_ctx_t structure representing the execution context. It must not be null, and the context should be properly initialized before calling this function.
    - `args`: A pointer to a constant fd_system_program_instruction_transfer_with_seed_t structure containing the transfer parameters, including the seed and the amount of lamports to transfer. It must not be null, and the structure should be correctly populated with valid data.
- **Output**: Returns an integer status code indicating success or a specific error condition, such as FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS, FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE, or FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR.
- **See also**: [`fd_system_program_exec_transfer_with_seed`](fd_system_program.c.driver.md#fd_system_program_exec_transfer_with_seed)  (Implementation)


---
### fd\_system\_program\_exec\_upgrade\_nonce\_account<!-- {{#callable_declaration:fd_system_program_exec_upgrade_nonce_account}} -->
Upgrades a nonce account to the current version.
- **Description**: This function is used to upgrade a nonce account to the current version within the system program. It should be called when a nonce account needs to be updated to ensure compatibility with the latest system program features. The function requires a valid execution instruction context and expects the nonce account to be the first account in the instruction's account list. It checks for sufficient account keys, valid account ownership, and writable account status. If any of these conditions are not met, the function returns an appropriate error code. The function modifies the nonce account state to reflect the upgrade.
- **Inputs**:
    - `ctx`: A pointer to an fd_exec_instr_ctx_t structure representing the execution instruction context. This must not be null and should contain at least one account. The caller retains ownership of this context.
- **Output**: Returns an integer status code. FD_EXECUTOR_INSTR_SUCCESS is returned on success, while various error codes are returned for invalid input conditions, such as insufficient account keys, invalid account owner, non-writable account, or invalid account data.
- **See also**: [`fd_system_program_exec_upgrade_nonce_account`](fd_system_program_nonce.c.driver.md#fd_system_program_exec_upgrade_nonce_account)  (Implementation)


---
### fd\_check\_transaction\_age<!-- {{#callable_declaration:fd_check_transaction_age}} -->
Checks if the transaction's age is valid based on blockhash or nonce.
- **Description**: Use this function to verify the validity of a transaction's age by checking the blockhash or nonce provided in the transaction context. It is essential to ensure that the transaction context is properly initialized and contains valid blockhash and nonce information before calling this function. The function returns a success code if the transaction's age is valid, or an error code if it is not, allowing the caller to handle invalid transactions appropriately.
- **Inputs**:
    - `txn_ctx`: A pointer to a fd_exec_txn_ctx_t structure representing the transaction context. It must be properly initialized and contain valid blockhash and nonce information. The caller retains ownership and must ensure it is not null.
- **Output**: Returns 0 if the transaction's age is valid, or a non-zero error code if it is not.
- **See also**: [`fd_check_transaction_age`](fd_system_program_nonce.c.driver.md#fd_check_transaction_age)  (Implementation)


