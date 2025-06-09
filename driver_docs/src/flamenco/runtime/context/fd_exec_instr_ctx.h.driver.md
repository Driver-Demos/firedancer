# Purpose
This C header file defines the structure and functions necessary for managing the execution context of a single instruction within a transaction, specifically in a blockchain or distributed ledger environment. The primary structure, `fd_exec_instr_ctx_t`, encapsulates all the necessary data to execute an instruction, including transaction context, parent-child relationships, error handling, and program identification. The file provides a set of functions and macros to manipulate this context, such as creating and deleting contexts, checking the number of accounts associated with an instruction, and borrowing accounts for execution. These operations are crucial for ensuring that instructions are executed correctly and efficiently, with proper error handling and resource management.

The file also includes several functions that mirror the behavior of functions from the Agave project, specifically from the Solana SDK, indicating that this code is part of a larger system that interacts with or emulates Solana's transaction processing. The functions provide capabilities such as finding account indices, retrieving program keys, and checking signer status, which are essential for executing instructions in a blockchain environment. The header file is designed to be included in other C source files, providing a public API for managing instruction execution contexts, and it ensures proper alignment and memory management through defined macros and attributes.
# Imports and Dependencies

---
- `../info/fd_instr_info.h`
- `../fd_executor_err.h`
- `../../../funk/fd_funk.h`


# Global Variables

---
### fd\_exec\_instr\_ctx\_new
- **Type**: `function pointer`
- **Description**: The `fd_exec_instr_ctx_new` is a function pointer that serves as a constructor for creating a new execution instruction context. It takes a single argument, `mem`, which is a pointer to memory where the new context will be initialized.
- **Use**: This function is used to allocate and initialize a new `fd_exec_instr_ctx_t` structure in the provided memory space.


---
### fd\_exec\_instr\_ctx\_join
- **Type**: `fd_exec_instr_ctx_t *`
- **Description**: The `fd_exec_instr_ctx_join` is a function that returns a pointer to a `fd_exec_instr_ctx_t` structure. This structure represents the context needed to execute a single instruction, which includes various fields such as transaction context, parent context, depth, index, and others related to the execution of instructions.
- **Use**: This function is used to join or initialize a `fd_exec_instr_ctx_t` context from a given memory location.


---
### fd\_exec\_instr\_ctx\_leave
- **Type**: `function pointer`
- **Description**: The `fd_exec_instr_ctx_leave` is a function that takes a pointer to an `fd_exec_instr_ctx_t` structure as an argument and returns a `void` pointer. This function is likely used to perform cleanup or finalization tasks when leaving an execution instruction context.
- **Use**: This function is used to exit or leave an execution instruction context, possibly performing necessary cleanup operations.


---
### fd\_exec\_instr\_ctx\_delete
- **Type**: `void *`
- **Description**: The `fd_exec_instr_ctx_delete` function is a global function that takes a pointer to memory (`void * mem`) and is responsible for deleting or cleaning up the execution instruction context associated with that memory. It is part of a set of functions that manage the lifecycle of `fd_exec_instr_ctx_t` structures, which are used to execute a single instruction in a transaction context.
- **Use**: This function is used to properly delete or clean up an execution instruction context, ensuring that any resources associated with it are released.


# Data Structures

---
### fd\_borrowed\_account\_t
- **Type**: `typedef struct fd_borrowed_account fd_borrowed_account_t;`
- **Description**: The `fd_borrowed_account_t` is a forward declaration of a structure named `fd_borrowed_account`. This indicates that the structure is defined elsewhere, and the current file only provides a type alias for it. This is typically used to avoid circular dependencies in header files, allowing the structure to be referenced without needing its full definition at this point.


---
### fd\_exec\_instr\_ctx
- **Type**: `struct`
- **Members**:
    - `magic`: A unique identifier for the structure, set to FD_EXEC_INSTR_CTX_MAGIC.
    - `txn_ctx`: Pointer to the transaction context associated with this instruction.
    - `parent`: Pointer to the parent instruction context, if any.
    - `depth`: Indicates the depth of the instruction in the execution hierarchy, starting at 0.
    - `index`: The number of preceding instructions with the same parent.
    - `child_cnt`: The number of child instructions under this context.
    - `instr_err`: Stores error information related to the instruction execution.
    - `funk_txn`: Pointer to the funk transaction associated with this instruction.
    - `funk`: Pointer to the funk context associated with this instruction.
    - `program_id_base58`: Base58 encoded program ID, computed once for reuse.
    - `instr`: Pointer to the instruction information structure.
- **Description**: The `fd_exec_instr_ctx` structure is designed to encapsulate the context required for executing a single instruction within a transaction. It includes metadata such as the instruction's depth in the execution hierarchy, its index among sibling instructions, and the number of child instructions. The structure also maintains pointers to related contexts, such as the transaction context (`txn_ctx`), parent instruction context (`parent`), and funk contexts (`funk_txn` and `funk`). Additionally, it stores a precomputed Base58 encoded program ID for efficiency and a pointer to the instruction's detailed information (`instr`). The `magic` field serves as a unique identifier for the structure, ensuring its integrity and correct usage.


# Functions

---
### fd\_exec\_instr\_ctx\_check\_num\_insn\_accounts<!-- {{#callable:fd_exec_instr_ctx_check_num_insn_accounts}} -->
The function `fd_exec_instr_ctx_check_num_insn_accounts` checks if the number of accounts provided in an instruction context meets or exceeds the expected number of accounts.
- **Inputs**:
    - `ctx`: A pointer to a constant `fd_exec_instr_ctx_t` structure representing the instruction context.
    - `expected_accounts`: An unsigned integer representing the expected number of accounts for the instruction.
- **Control Flow**:
    - The function checks if the actual number of accounts (`ctx->instr->acct_cnt`) is less than the `expected_accounts` using the `FD_UNLIKELY` macro to hint that this condition is rare.
    - If the condition is true, the function returns `FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS`, indicating an error due to insufficient accounts.
    - If the condition is false, the function returns `FD_EXECUTOR_INSTR_SUCCESS`, indicating that the number of accounts is sufficient.
- **Output**: The function returns an integer status code: `FD_EXECUTOR_INSTR_SUCCESS` if the number of accounts is sufficient, or `FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS` if there are not enough accounts.


---
### fd\_exec\_instr\_ctx\_get\_index\_of\_instr\_account\_in\_transaction<!-- {{#callable:fd_exec_instr_ctx_get_index_of_instr_account_in_transaction}} -->
The function retrieves the index of an instruction account within a transaction, given its index within the instruction, and returns an error if the index is out of bounds.
- **Inputs**:
    - `ctx`: A pointer to a constant fd_exec_instr_ctx_t structure, representing the context needed to execute a single instruction.
    - `idx_in_instr`: An unsigned short integer representing the index of the account within the instruction.
    - `idx_in_txn`: A pointer to an unsigned short integer where the index of the account within the transaction will be stored.
- **Control Flow**:
    - Check if the provided idx_in_instr is greater than or equal to the number of accounts in the instruction (ctx->instr->acct_cnt).
    - If the index is out of bounds, return the error code FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS.
    - If the index is valid, retrieve the index of the account within the transaction from ctx->instr->accounts[idx_in_instr].index_in_transaction and store it in idx_in_txn.
    - Return the success code FD_EXECUTOR_INSTR_SUCCESS.
- **Output**: The function returns an integer status code: FD_EXECUTOR_INSTR_SUCCESS if successful, or FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS if the index is out of bounds.


---
### fd\_exec\_instr\_ctx\_get\_number\_of\_program\_accounts<!-- {{#callable:fd_exec_instr_ctx_get_number_of_program_accounts}} -->
The function `fd_exec_instr_ctx_get_number_of_program_accounts` returns the fixed number of program accounts associated with an instruction context, which is always 1.
- **Inputs**:
    - `ctx`: A pointer to a constant `fd_exec_instr_ctx_t` structure, representing the context of an instruction execution.
- **Control Flow**:
    - The function takes a single input parameter `ctx`, which is a pointer to a constant `fd_exec_instr_ctx_t` structure.
    - The function does not utilize the `ctx` parameter in its logic, as indicated by the `(void) ctx;` statement, which is used to suppress unused parameter warnings.
    - The function returns the constant value `1U`, indicating that there is always one program account per instruction context.
- **Output**: The function returns an `ushort` value of `1U`, representing the number of program accounts, which is always one.


---
### fd\_signers\_contains<!-- {{#callable:fd_signers_contains}} -->
The `fd_signers_contains` function checks if a given public key is present in a list of signer public keys.
- **Inputs**:
    - `signers`: An array of pointers to `fd_pubkey_t` representing the list of signer public keys, with a maximum size defined by `FD_TXN_SIG_MAX`.
    - `pubkey`: A pointer to an `fd_pubkey_t` representing the public key to search for in the signers list.
- **Control Flow**:
    - Iterates over the `signers` array up to `FD_TXN_SIG_MAX` or until a null pointer is encountered.
    - For each non-null signer, compares it with the `pubkey` using `memcmp`.
    - If a match is found (i.e., `memcmp` returns 0), the function returns 1, indicating the public key is in the list.
    - If no match is found after checking all non-null signers, the function returns 0.
- **Output**: Returns 1 if the `pubkey` is found in the `signers` array, otherwise returns 0.


# Function Declarations (Public API)

---
### fd\_exec\_instr\_ctx\_new<!-- {{#callable_declaration:fd_exec_instr_ctx_new}} -->
Initialize a new instruction execution context.
- **Description**: This function initializes a new instruction execution context using the provided memory buffer. It should be called when a new execution context is needed for processing an instruction. The memory buffer must be properly aligned and of sufficient size to hold the context structure. If the memory is null or misaligned, the function will return null and log a warning. This function sets up the context with default values and prepares it for use in instruction execution.
- **Inputs**:
    - `mem`: A pointer to a memory buffer where the context will be initialized. The buffer must be aligned to `FD_EXEC_INSTR_CTX_ALIGN` and have a size of at least `FD_EXEC_INSTR_CTX_FOOTPRINT`. The caller retains ownership of the memory. If null or misaligned, the function returns null.
- **Output**: Returns a pointer to the initialized context on success, or null if the input memory is null or misaligned.
- **See also**: [`fd_exec_instr_ctx_new`](fd_exec_instr_ctx.c.driver.md#fd_exec_instr_ctx_new)  (Implementation)


---
### fd\_exec\_instr\_ctx\_join<!-- {{#callable_declaration:fd_exec_instr_ctx_join}} -->
Validates and returns a pointer to an instruction execution context.
- **Description**: Use this function to obtain a valid `fd_exec_instr_ctx_t` pointer from a memory block that is expected to contain an instruction execution context. This function checks that the provided memory block is not null and that it contains a valid context by verifying a magic number. It should be called when you need to work with an instruction context that has been previously initialized. If the memory block is invalid or uninitialized, the function will return null, and a warning will be logged.
- **Inputs**:
    - `mem`: A pointer to a memory block that is expected to contain a valid `fd_exec_instr_ctx_t` structure. Must not be null. The memory block should have been initialized with the correct magic number. If null or if the magic number is incorrect, the function returns null.
- **Output**: Returns a pointer to `fd_exec_instr_ctx_t` if the memory block is valid; otherwise, returns null.
- **See also**: [`fd_exec_instr_ctx_join`](fd_exec_instr_ctx.c.driver.md#fd_exec_instr_ctx_join)  (Implementation)


---
### fd\_exec\_instr\_ctx\_leave<!-- {{#callable_declaration:fd_exec_instr_ctx_leave}} -->
Exits an instruction context and returns a pointer to it.
- **Description**: Use this function to safely exit an instruction context, ensuring that the context is valid before returning a pointer to it. This function should be called when you are done with an instruction context and need to leave it, typically as part of a cleanup or context-switching operation. It checks that the provided context is not null and that it has the correct magic number, which indicates a valid context. If these checks fail, the function logs a warning and returns null, indicating an error.
- **Inputs**:
    - `ctx`: A pointer to the instruction context to be exited. Must not be null and must have a valid magic number. If the context is null or has an incorrect magic number, the function logs a warning and returns null.
- **Output**: Returns a pointer to the instruction context if it is valid; otherwise, returns null if the context is null or has an incorrect magic number.
- **See also**: [`fd_exec_instr_ctx_leave`](fd_exec_instr_ctx.c.driver.md#fd_exec_instr_ctx_leave)  (Implementation)


---
### fd\_exec\_instr\_ctx\_delete<!-- {{#callable_declaration:fd_exec_instr_ctx_delete}} -->
Deletes an instruction context from memory.
- **Description**: Use this function to safely delete an instruction context previously created with `fd_exec_instr_ctx_new`. It checks if the provided memory pointer is valid, aligned, and contains the correct magic number before proceeding with the deletion. This function should be called when the instruction context is no longer needed to free up resources. It returns the memory pointer if successful, or NULL if the input is invalid or the memory is misaligned.
- **Inputs**:
    - `mem`: A pointer to the memory location of the instruction context to be deleted. Must not be null, must be aligned to `FD_EXEC_INSTR_CTX_ALIGN`, and must contain the correct magic number `FD_EXEC_INSTR_CTX_MAGIC`. If these conditions are not met, the function logs a warning and returns NULL.
- **Output**: Returns the input memory pointer if the deletion is successful, or NULL if the input is invalid or misaligned.
- **See also**: [`fd_exec_instr_ctx_delete`](fd_exec_instr_ctx.c.driver.md#fd_exec_instr_ctx_delete)  (Implementation)


---
### fd\_exec\_instr\_ctx\_find\_idx\_of\_instr\_account<!-- {{#callable_declaration:fd_exec_instr_ctx_find_idx_of_instr_account}} -->
Finds the index of an instruction account by its public key.
- **Description**: Use this function to locate the index of an instruction account within a given execution context by providing the account's public key. This is useful when you need to reference or manipulate a specific account within the context of an instruction. The function returns the index of the account if found, or -1 if the account is not present. Ensure that the context and public key provided are valid and initialized before calling this function.
- **Inputs**:
    - `ctx`: A pointer to a constant fd_exec_instr_ctx_t structure representing the execution context. Must not be null and should be properly initialized.
    - `pubkey`: A pointer to a constant fd_pubkey_t structure representing the public key of the account to find. Must not be null and should be properly initialized.
- **Output**: Returns the index of the instruction account if found, or -1 if the account is not present in the context.
- **See also**: [`fd_exec_instr_ctx_find_idx_of_instr_account`](fd_exec_instr_ctx.c.driver.md#fd_exec_instr_ctx_find_idx_of_instr_account)  (Implementation)


---
### fd\_exec\_instr\_ctx\_get\_key\_of\_account\_at\_index<!-- {{#callable_declaration:fd_exec_instr_ctx_get_key_of_account_at_index}} -->
Retrieve the public key of an account at a specified instruction index.
- **Description**: This function is used to obtain the public key of an account associated with a specific instruction index within an execution context. It should be called when you need to access the public key of an account that is part of the instruction's context. The function requires a valid instruction context and an index that is within the bounds of the instruction's account list. If the index is out of bounds, the function returns an error indicating insufficient account keys. The caller must ensure that the context and key pointer are valid and that the key pointer is not null.
- **Inputs**:
    - `ctx`: A pointer to a constant fd_exec_instr_ctx_t structure representing the execution context of the instruction. Must not be null.
    - `idx_in_instr`: An unsigned short representing the index of the account within the instruction's context. Must be within the range of available accounts in the instruction.
    - `key`: A pointer to a pointer to fd_pubkey_t where the address of the account's public key will be stored. Must not be null.
- **Output**: Returns an integer status code. Returns 0 on success, or an error code if the index is out of bounds or another error occurs.
- **See also**: [`fd_exec_instr_ctx_get_key_of_account_at_index`](fd_exec_instr_ctx.c.driver.md#fd_exec_instr_ctx_get_key_of_account_at_index)  (Implementation)


---
### fd\_exec\_instr\_ctx\_get\_last\_program\_key<!-- {{#callable_declaration:fd_exec_instr_ctx_get_last_program_key}} -->
Retrieves the public key of the last program in the instruction context.
- **Description**: Use this function to obtain the public key of the program associated with a given instruction context. This function is useful when you need to identify or verify the program being executed within a transaction. It is important to note that there is only one program per instruction, so this function will always retrieve the key of that single program. Ensure that the instruction context is valid and properly initialized before calling this function.
- **Inputs**:
    - `ctx`: A pointer to a constant fd_exec_instr_ctx_t structure representing the instruction context. This must not be null and should be a valid, initialized context.
    - `key`: A pointer to a location where the function will store the address of the program's public key. This must not be null, and the caller does not take ownership of the key.
- **Output**: Returns an integer status code indicating success or failure. A successful retrieval will result in a non-negative return value, while a failure will return a negative error code.
- **See also**: [`fd_exec_instr_ctx_get_last_program_key`](fd_exec_instr_ctx.c.driver.md#fd_exec_instr_ctx_get_last_program_key)  (Implementation)


---
### fd\_exec\_instr\_ctx\_try\_borrow\_instr\_account<!-- {{#callable_declaration:fd_exec_instr_ctx_try_borrow_instr_account}} -->
Attempts to borrow an account from the instruction context.
- **Description**: Use this function to borrow an account from the instruction context specified by its index. It is essential to ensure that the index is within the valid range of accounts in the instruction context. The function will return an error if the index is out of bounds or if the borrowing operation fails. This function is typically used when you need to access or modify account data during the execution of an instruction.
- **Inputs**:
    - `ctx`: A pointer to a constant `fd_exec_instr_ctx_t` structure representing the instruction context. This must not be null, and the context should be properly initialized before calling this function.
    - `idx`: An unsigned short integer representing the index of the account within the instruction context. It must be within the range of available accounts; otherwise, an error is returned.
    - `account`: A pointer to an `fd_borrowed_account_t` structure where the borrowed account information will be stored. This must not be null, and the caller is responsible for managing the memory of this structure.
- **Output**: Returns an integer indicating success or an error code. A non-zero return value indicates an error, such as an out-of-bounds index or a failure to borrow the account.
- **See also**: [`fd_exec_instr_ctx_try_borrow_instr_account`](fd_exec_instr_ctx.c.driver.md#fd_exec_instr_ctx_try_borrow_instr_account)  (Implementation)


---
### fd\_exec\_instr\_ctx\_try\_borrow\_instr\_account\_with\_key<!-- {{#callable_declaration:fd_exec_instr_ctx_try_borrow_instr_account_with_key}} -->
Borrows an account from the instruction context using a public key.
- **Description**: Use this function to borrow an account from the instruction context by specifying the account's public key. This is useful when you need to access account details without knowing its index in the instruction context. The function searches for the account associated with the given public key within the instruction's account list. If found, it attempts to borrow the account and returns a success code. If the account is not found, it returns an error indicating insufficient account keys. Ensure that the context and public key provided are valid and initialized before calling this function.
- **Inputs**:
    - `ctx`: A pointer to a constant fd_exec_instr_ctx_t structure representing the instruction context. Must not be null and should be properly initialized.
    - `pubkey`: A pointer to a constant fd_pubkey_t structure representing the public key of the account to borrow. Must not be null and should be a valid public key.
    - `account`: A pointer to an fd_borrowed_account_t structure where the borrowed account details will be stored. Must not be null and should be ready to receive account data.
- **Output**: Returns an integer status code: FD_EXECUTOR_INSTR_SUCCESS on success, or FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS if the account is not found.
- **See also**: [`fd_exec_instr_ctx_try_borrow_instr_account_with_key`](fd_exec_instr_ctx.c.driver.md#fd_exec_instr_ctx_try_borrow_instr_account_with_key)  (Implementation)


---
### fd\_exec\_instr\_ctx\_try\_borrow\_last\_program\_account<!-- {{#callable_declaration:fd_exec_instr_ctx_try_borrow_last_program_account}} -->
Borrows the instruction's program account.
- **Description**: This function is used to borrow the program account associated with a given instruction context. It should be called when you need to access the program account for the current instruction. The function assumes that there is only one program account per instruction, and it retrieves this account. Ensure that the `ctx` parameter is a valid and properly initialized instruction context before calling this function.
- **Inputs**:
    - `ctx`: A pointer to a constant `fd_exec_instr_ctx_t` structure representing the instruction context. It must not be null and should be properly initialized.
    - `account`: A pointer to an `fd_borrowed_account_t` structure where the borrowed account information will be stored. It must not be null.
- **Output**: Returns an integer status code indicating success or failure of the operation. The borrowed account information is written to the `account` parameter if successful.
- **See also**: [`fd_exec_instr_ctx_try_borrow_last_program_account`](fd_exec_instr_ctx.c.driver.md#fd_exec_instr_ctx_try_borrow_last_program_account)  (Implementation)


---
### fd\_exec\_instr\_ctx\_get\_signers<!-- {{#callable_declaration:fd_exec_instr_ctx_get_signers}} -->
Retrieves the public keys of signer accounts from an instruction context.
- **Description**: Use this function to obtain the public keys of all signer accounts associated with a given instruction context. It should be called when you need to verify or process the signers of a transaction instruction. The function expects a valid instruction context and an array to store the signer public keys. The array must have a capacity of at least `FD_TXN_SIG_MAX` elements. The function will populate the array with the public keys of the signers, up to the maximum specified by `FD_TXN_SIG_MAX`. If an error occurs while retrieving a signer, the function will return an error code.
- **Inputs**:
    - `ctx`: A pointer to a constant `fd_exec_instr_ctx_t` structure representing the instruction context. It must not be null and should be properly initialized before calling this function.
    - `signers`: An array of pointers to `fd_pubkey_t` where the function will store the public keys of the signer accounts. The array must have a size of at least `FD_TXN_SIG_MAX`. The caller retains ownership of the array.
- **Output**: Returns `FD_EXECUTOR_INSTR_SUCCESS` on success, or an error code if an error occurs while retrieving a signer.
- **See also**: [`fd_exec_instr_ctx_get_signers`](fd_exec_instr_ctx.c.driver.md#fd_exec_instr_ctx_get_signers)  (Implementation)


---
### fd\_exec\_instr\_ctx\_any\_signed<!-- {{#callable_declaration:fd_exec_instr_ctx_any_signed}} -->
Checks if any instruction account with the given public key is a signer.
- **Description**: Use this function to determine if any account associated with a given public key is marked as a signer within the context of a specific instruction. This is useful when verifying permissions or authorizations in transaction processing. The function returns a non-zero value if at least one account with the specified public key is a signer, and zero otherwise. It is important to ensure that the context and public key provided are valid and initialized before calling this function.
- **Inputs**:
    - `ctx`: A pointer to a constant `fd_exec_instr_ctx_t` structure representing the context of the instruction. It must not be null and should be properly initialized before use.
    - `pubkey`: A pointer to a constant `fd_pubkey_t` structure representing the public key to check against the instruction accounts. It must not be null and should be properly initialized before use.
- **Output**: Returns 1 if any instruction account with the given public key is a signer, and 0 otherwise.
- **See also**: [`fd_exec_instr_ctx_any_signed`](fd_exec_instr_ctx.c.driver.md#fd_exec_instr_ctx_any_signed)  (Implementation)


