# Purpose
This C header file defines the structure and functions for managing "borrowed accounts" within a Solana-based runtime environment, specifically in the context of the Flamenco runtime. The primary structure, `fd_borrowed_account_t`, encapsulates details about a borrowed account, including a magic number for validation, a pointer to the account, and context information related to execution instructions. The file provides a comprehensive API for interacting with these borrowed accounts, including constructors, destructors, getters, setters, and various utility functions. These functions facilitate operations such as initializing and destroying borrowed accounts, accessing and modifying account data, checking account properties (e.g., if an account is executable, writable, or owned by the current program), and ensuring compliance with constraints like maximum data length and rent exemption.

The header file is designed to be included in other C source files, providing a modular and reusable interface for handling borrowed accounts in a Solana transaction context. It mirrors several functions from the Agave library, which is part of the Solana SDK, ensuring compatibility and consistency with existing Solana transaction handling paradigms. The file also includes inline functions for performance optimization and uses macros to define constants and manage memory fences for thread safety. The presence of TODO comments indicates areas for future development, such as implementing additional API functions and enhancing rent-related checks. Overall, this header file is a critical component for developers working on Solana-based applications, providing essential tools for managing account state and behavior within the Flamenco runtime.
# Imports and Dependencies

---
- `fd_executor_err.h`
- `fd_system_ids.h`
- `fd_runtime.h`
- `context/fd_exec_epoch_ctx.h`
- `context/fd_exec_txn_ctx.h`
- `sysvar/fd_sysvar_rent.h`


# Data Structures

---
### fd\_borrowed\_account
- **Type**: `struct`
- **Members**:
    - `magic`: A unique identifier for the structure, used to verify its integrity.
    - `acct`: A pointer to an fd_txn_account_t structure, representing the account being borrowed.
    - `instr_ctx`: A constant pointer to an fd_exec_instr_ctx_t structure, providing context for the execution instruction.
    - `index_in_instruction`: An index indicating the position of the account in the instruction, set to USHORT_MAX for borrowed program accounts.
- **Description**: The `fd_borrowed_account` structure is designed to represent a borrowed account within a transaction context, particularly in the context of Solana's runtime environment. It includes a magic number for integrity checks, a pointer to the actual account being borrowed, and a pointer to the execution instruction context. The `index_in_instruction` field helps identify the account's position within the instruction, with a special value indicating borrowed program accounts. This structure is crucial for managing account borrowing and ensuring proper execution flow in a transaction.


---
### fd\_borrowed\_account\_t
- **Type**: `struct`
- **Members**:
    - `magic`: A unique identifier to ensure the integrity and validity of the borrowed account structure.
    - `acct`: A pointer to the transaction account associated with the borrowed account.
    - `instr_ctx`: A constant pointer to the instruction context related to the borrowed account.
    - `index_in_instruction`: An index indicating the position of the account in the instruction, set to USHORT_MAX for borrowed program accounts.
- **Description**: The `fd_borrowed_account_t` structure represents a borrowed account in the context of a Solana transaction, encapsulating details such as the account itself, its associated instruction context, and an index within the instruction. It includes a magic number for validation purposes and provides various methods for interacting with the account, such as getting and setting data, checking permissions, and ensuring the account's state is consistent with the transaction's requirements. This structure is integral to managing account data and permissions within the transaction execution environment.


# Functions

---
### fd\_borrowed\_account\_init<!-- {{#callable:fd_borrowed_account_init}} -->
The `fd_borrowed_account_init` function initializes a `fd_borrowed_account_t` structure with provided account, instruction context, and index, and sets a magic number to ensure validity.
- **Inputs**:
    - `borrowed_acct`: A pointer to a `fd_borrowed_account_t` structure that will be initialized.
    - `acct`: A pointer to a `fd_txn_account_t` structure representing the account to be borrowed.
    - `instr_ctx`: A constant pointer to a `fd_exec_instr_ctx_t` structure representing the instruction context.
    - `index_in_instruction`: An unsigned short integer representing the index of the account in the instruction.
- **Control Flow**:
    - Assigns the `acct` pointer to the `acct` field of `borrowed_acct`.
    - Assigns the `instr_ctx` pointer to the `instr_ctx` field of `borrowed_acct`.
    - Assigns the `index_in_instruction` value to the `index_in_instruction` field of `borrowed_acct`.
    - Calls `FD_COMPILER_MFENCE()` to ensure memory ordering before setting the magic number.
    - Sets the `magic` field of `borrowed_acct` to `FD_BORROWED_ACCOUNT_MAGIC`.
    - Calls `FD_COMPILER_MFENCE()` again to ensure memory ordering after setting the magic number.
- **Output**: The function does not return a value; it initializes the `fd_borrowed_account_t` structure pointed to by `borrowed_acct`.


---
### fd\_borrowed\_account\_drop<!-- {{#callable:fd_borrowed_account_drop}} -->
The `fd_borrowed_account_drop` function releases the acquired write on a borrowed account object by invoking the `drop` method of the account's virtual table.
- **Inputs**:
    - `borrowed_acct`: A pointer to an `fd_borrowed_account_t` structure representing the borrowed account to be dropped.
- **Control Flow**:
    - The function accesses the `acct` member of the `borrowed_acct` structure, which is a pointer to an `fd_txn_account_t`.
    - It then accesses the `vt` member of the `acct`, which is a pointer to a virtual table containing function pointers.
    - The `drop` function pointer from the virtual table is called with `acct` as its argument, effectively releasing the borrowed account.
- **Output**: This function does not return any value.


---
### fd\_borrowed\_account\_destroy<!-- {{#callable:fd_borrowed_account_destroy}} -->
The `fd_borrowed_account_destroy` function safely destroys a borrowed account by releasing its resources and resetting its state.
- **Inputs**:
    - `borrowed_acct`: A pointer to an `fd_borrowed_account_t` structure representing the borrowed account to be destroyed.
- **Control Flow**:
    - Check if the `magic` field of `borrowed_acct` matches `FD_BORROWED_ACCOUNT_MAGIC` to verify the account's validity.
    - If the account is valid, call [`fd_borrowed_account_drop`](#fd_borrowed_account_drop) to release the acquired write on the borrowed account object.
    - Use `FD_COMPILER_MFENCE()` to ensure memory ordering before and after setting the `magic` field to 0.
    - Set the `magic` field of `borrowed_acct` to 0 to mark it as destroyed.
    - Set the `borrowed_acct` pointer to `NULL` to prevent further use.
- **Output**: The function does not return a value; it modifies the state of the `borrowed_acct` to indicate it has been destroyed.
- **Functions called**:
    - [`fd_borrowed_account_drop`](#fd_borrowed_account_drop)


---
### fd\_borrowed\_account\_get\_data<!-- {{#callable:fd_borrowed_account_get_data}} -->
The function `fd_borrowed_account_get_data` retrieves a constant pointer to the data of a borrowed account.
- **Inputs**:
    - `borrowed_acct`: A pointer to a constant `fd_borrowed_account_t` structure representing the borrowed account from which data is to be retrieved.
- **Control Flow**:
    - The function accesses the `acct` member of the `borrowed_acct` structure, which is a pointer to an `fd_txn_account_t` structure.
    - It then calls the `get_data` function from the virtual table (`vt`) of the `acct` to retrieve the data pointer.
- **Output**: A constant pointer to an unsigned character (`uchar const *`) representing the data of the borrowed account.


---
### fd\_borrowed\_account\_get\_data\_len<!-- {{#callable:fd_borrowed_account_get_data_len}} -->
The function `fd_borrowed_account_get_data_len` retrieves the length of the data associated with a borrowed account.
- **Inputs**:
    - `borrowed_acct`: A pointer to a constant `fd_borrowed_account_t` structure representing the borrowed account from which the data length is to be retrieved.
- **Control Flow**:
    - The function accesses the `acct` member of the `borrowed_acct` structure, which is a pointer to an `fd_txn_account_t` structure.
    - It then calls the `get_data_len` function from the virtual table (`vt`) of the `acct` structure, passing the `acct` as an argument.
    - The `get_data_len` function returns the length of the data associated with the account.
- **Output**: The function returns an `ulong` representing the length of the data associated with the borrowed account.


---
### fd\_borrowed\_account\_get\_owner<!-- {{#callable:fd_borrowed_account_get_owner}} -->
The function `fd_borrowed_account_get_owner` retrieves the owner of a borrowed account.
- **Inputs**:
    - `borrowed_acct`: A pointer to a constant `fd_borrowed_account_t` structure representing the borrowed account whose owner is to be retrieved.
- **Control Flow**:
    - The function accesses the `acct` member of the `borrowed_acct` structure, which is a pointer to an `fd_txn_account_t` structure.
    - It then calls the `get_owner` function from the virtual table (`vt`) of the `acct` to retrieve the owner of the account.
- **Output**: A pointer to a constant `fd_pubkey_t` structure representing the owner of the borrowed account.


---
### fd\_borrowed\_account\_get\_lamports<!-- {{#callable:fd_borrowed_account_get_lamports}} -->
The function `fd_borrowed_account_get_lamports` retrieves the current number of lamports in a given borrowed account.
- **Inputs**:
    - `borrowed_acct`: A pointer to a constant `fd_borrowed_account_t` structure representing the borrowed account from which to retrieve the lamports.
- **Control Flow**:
    - The function accesses the `acct` member of the `borrowed_acct` structure, which is a pointer to an `fd_txn_account_t` structure.
    - It then calls the `get_lamports` function from the virtual table (`vt`) of the `acct` structure, passing the `acct` as an argument.
    - The `get_lamports` function returns the number of lamports, which is then returned by `fd_borrowed_account_get_lamports`.
- **Output**: The function returns an `ulong` representing the number of lamports in the borrowed account.


---
### fd\_borrowed\_account\_get\_rent\_epoch<!-- {{#callable:fd_borrowed_account_get_rent_epoch}} -->
The function `fd_borrowed_account_get_rent_epoch` retrieves the rent epoch of a borrowed account.
- **Inputs**:
    - `borrowed_acct`: A pointer to a constant `fd_borrowed_account_t` structure representing the borrowed account from which the rent epoch is to be retrieved.
- **Control Flow**:
    - The function accesses the `acct` member of the `borrowed_acct` structure, which is a pointer to an `fd_txn_account_t` structure.
    - It then calls the `get_rent_epoch` function from the virtual table (`vt`) of the `acct` structure, passing the `acct` as an argument.
    - The `get_rent_epoch` function returns the rent epoch of the account.
- **Output**: The function returns an `ulong` representing the rent epoch of the borrowed account.


---
### fd\_borrowed\_account\_get\_acc\_meta<!-- {{#callable:fd_borrowed_account_get_acc_meta}} -->
The function `fd_borrowed_account_get_acc_meta` retrieves the account metadata from a borrowed account structure.
- **Inputs**:
    - `borrowed_acct`: A pointer to a constant `fd_borrowed_account_t` structure representing the borrowed account from which metadata is to be retrieved.
- **Control Flow**:
    - The function accesses the `acct` member of the `borrowed_acct` structure, which is a pointer to an `fd_txn_account_t`.
    - It then calls the `get_meta` function from the virtual table (`vt`) of the `acct` to retrieve the account metadata.
- **Output**: A pointer to a constant `fd_account_meta_t` structure, representing the metadata of the account.


---
### fd\_borrowed\_account\_checked\_add\_lamports<!-- {{#callable:fd_borrowed_account_checked_add_lamports}} -->
The function `fd_borrowed_account_checked_add_lamports` safely adds a specified number of lamports to a borrowed account, ensuring no arithmetic overflow occurs.
- **Inputs**:
    - `borrowed_acct`: A pointer to an `fd_borrowed_account_t` structure representing the borrowed account to which lamports will be added.
    - `lamports`: An unsigned long integer representing the number of lamports to add to the account.
- **Control Flow**:
    - Initialize `balance_post` to 0UL to store the new balance after addition.
    - Call [`fd_ulong_checked_add`](program/fd_program_util.h.driver.md#fd_ulong_checked_add) to add the current lamports in the account and the specified `lamports`, storing the result in `balance_post`.
    - Check if [`fd_ulong_checked_add`](program/fd_program_util.h.driver.md#fd_ulong_checked_add) returned an error indicating arithmetic overflow; if so, return `FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW`.
    - If no overflow occurred, call [`fd_borrowed_account_set_lamports`](fd_borrowed_account.c.driver.md#fd_borrowed_account_set_lamports) to update the account's lamports to the new balance `balance_post`.
- **Output**: Returns 0 on success, or `FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW` if an arithmetic overflow occurs during the addition.
- **Functions called**:
    - [`fd_ulong_checked_add`](program/fd_program_util.h.driver.md#fd_ulong_checked_add)
    - [`fd_borrowed_account_set_lamports`](fd_borrowed_account.c.driver.md#fd_borrowed_account_set_lamports)


---
### fd\_borrowed\_account\_checked\_sub\_lamports<!-- {{#callable:fd_borrowed_account_checked_sub_lamports}} -->
The function `fd_borrowed_account_checked_sub_lamports` safely subtracts a specified number of lamports from a borrowed account, ensuring no arithmetic overflow occurs.
- **Inputs**:
    - `borrowed_acct`: A pointer to an `fd_borrowed_account_t` structure representing the borrowed account from which lamports will be subtracted.
    - `lamports`: An unsigned long integer representing the number of lamports to subtract from the account.
- **Control Flow**:
    - Initialize `balance_post` to 0UL to store the resulting balance after subtraction.
    - Call [`fd_ulong_checked_sub`](program/fd_program_util.h.driver.md#FD_FN_UNUSEDfd_ulong_checked_sub) to subtract `lamports` from the current lamports in `borrowed_acct`, storing the result in `balance_post`.
    - Check if [`fd_ulong_checked_sub`](program/fd_program_util.h.driver.md#FD_FN_UNUSEDfd_ulong_checked_sub) returned an error indicating arithmetic overflow; if so, return `FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW`.
    - If no error occurred, call [`fd_borrowed_account_set_lamports`](fd_borrowed_account.c.driver.md#fd_borrowed_account_set_lamports) to update the account's lamports to `balance_post`.
    - Return the result of [`fd_borrowed_account_set_lamports`](fd_borrowed_account.c.driver.md#fd_borrowed_account_set_lamports).
- **Output**: Returns 0 on success or an `FD_EXECUTOR_INSTR_ERR_{...}` code on failure, specifically `FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW` if an overflow occurs during subtraction.
- **Functions called**:
    - [`FD_FN_UNUSED::fd_ulong_checked_sub`](program/fd_program_util.h.driver.md#FD_FN_UNUSEDfd_ulong_checked_sub)
    - [`fd_borrowed_account_set_lamports`](fd_borrowed_account.c.driver.md#fd_borrowed_account_set_lamports)


---
### fd\_borrowed\_account\_is\_rent\_exempt\_at\_data\_length<!-- {{#callable:fd_borrowed_account_is_rent_exempt_at_data_length}} -->
The function `fd_borrowed_account_is_rent_exempt_at_data_length` checks if a borrowed account is rent-exempt based on its current data length and balance.
- **Inputs**:
    - `borrowed_acct`: A pointer to a constant `fd_borrowed_account_t` structure representing the borrowed account to be checked for rent exemption.
- **Control Flow**:
    - Retrieve the account from the `borrowed_acct` structure.
    - Check if the account's metadata is set up; if not, log an error and terminate.
    - Retrieve the rent information from the transaction context associated with the borrowed account.
    - Calculate the minimum balance required for rent exemption using the rent information and the account's data length.
    - Compare the account's current lamports (balance) with the calculated minimum balance.
    - Return 1 if the account's balance is greater than or equal to the minimum balance, indicating rent exemption; otherwise, return 0.
- **Output**: Returns an integer value: 1 if the account is rent-exempt at its current data length, or 0 if it is not.
- **Functions called**:
    - [`fd_rent_exempt_minimum_balance`](sysvar/fd_sysvar_rent1.c.driver.md#fd_rent_exempt_minimum_balance)


---
### fd\_borrowed\_account\_is\_executable<!-- {{#callable:fd_borrowed_account_is_executable}} -->
The function `fd_borrowed_account_is_executable` checks if a borrowed account is marked as executable.
- **Inputs**:
    - `borrowed_acct`: A pointer to a constant `fd_borrowed_account_t` structure representing the borrowed account to be checked.
- **Control Flow**:
    - The function accesses the `acct` member of the `borrowed_acct` structure, which is a pointer to an `fd_txn_account_t` structure.
    - It then calls the `is_executable` function from the virtual table (`vt`) of the `acct` to determine if the account is executable.
- **Output**: The function returns an integer, 1 if the account is executable, and 0 otherwise.


---
### fd\_borrowed\_account\_is\_executable\_internal<!-- {{#callable:fd_borrowed_account_is_executable_internal}} -->
The function `fd_borrowed_account_is_executable_internal` checks if a borrowed account is executable by considering both a feature flag and the account's executable status.
- **Inputs**:
    - `borrowed_acct`: A pointer to a constant `fd_borrowed_account_t` structure representing the borrowed account to be checked.
- **Control Flow**:
    - The function first checks if the feature `remove_accounts_executable_flag_checks` is inactive using `FD_FEATURE_ACTIVE` with the slot and features from the transaction context of the instruction context within the borrowed account.
    - If the feature is inactive, it proceeds to check if the account is executable by calling [`fd_borrowed_account_is_executable`](#fd_borrowed_account_is_executable) with the borrowed account.
    - The function returns the logical AND of the negation of the feature check and the result of the executable check.
- **Output**: The function returns an integer, 1 if the account is executable under the current conditions, and 0 otherwise.
- **Functions called**:
    - [`fd_borrowed_account_is_executable`](#fd_borrowed_account_is_executable)


---
### fd\_borrowed\_account\_is\_mutable<!-- {{#callable:fd_borrowed_account_is_mutable}} -->
The function `fd_borrowed_account_is_mutable` checks if a borrowed account is mutable by invoking the `is_mutable` method on the account's virtual table.
- **Inputs**:
    - `borrowed_acct`: A pointer to a constant `fd_borrowed_account_t` structure representing the borrowed account to be checked for mutability.
- **Control Flow**:
    - The function accesses the `acct` member of the `borrowed_acct` structure, which is a pointer to an `fd_txn_account_t` structure.
    - It then accesses the `vt` member of the `acct` structure, which is a pointer to a virtual table containing function pointers.
    - The function calls the `is_mutable` function from the virtual table, passing the `acct` pointer as an argument.
    - The result of the `is_mutable` function call is returned as the output of `fd_borrowed_account_is_mutable`.
- **Output**: An integer value indicating whether the account is mutable (non-zero) or not (zero).


---
### fd\_borrowed\_account\_is\_signer<!-- {{#callable:fd_borrowed_account_is_signer}} -->
The function `fd_borrowed_account_is_signer` checks if a borrowed account is a signer in the context of a specific instruction.
- **Inputs**:
    - `borrowed_acct`: A pointer to a constant `fd_borrowed_account_t` structure representing the borrowed account to be checked.
- **Control Flow**:
    - Retrieve the instruction context (`instr_ctx`) and instruction (`instr`) from the `borrowed_acct`.
    - Check if the `index_in_instruction` of `borrowed_acct` is greater than or equal to the account count (`acct_cnt`) in the instruction context; if so, return 0 indicating the account is not a signer.
    - Call [`fd_instr_acc_is_signer_idx`](info/fd_instr_info.h.driver.md#fd_instr_acc_is_signer_idx) with the instruction and `index_in_instruction` to determine if the account is a signer, and return the result.
- **Output**: Returns an integer, 1 if the account is a signer, and 0 otherwise.
- **Functions called**:
    - [`fd_instr_acc_is_signer_idx`](info/fd_instr_info.h.driver.md#fd_instr_acc_is_signer_idx)


---
### fd\_borrowed\_account\_is\_writable<!-- {{#callable:fd_borrowed_account_is_writable}} -->
The function `fd_borrowed_account_is_writable` checks if a borrowed account is writable based on its index in the instruction context.
- **Inputs**:
    - `borrowed_acct`: A pointer to a `fd_borrowed_account_t` structure representing the borrowed account to be checked for writability.
- **Control Flow**:
    - Retrieve the instruction context (`instr_ctx`) and instruction (`instr`) from the `borrowed_acct`.
    - Check if the `index_in_instruction` of `borrowed_acct` is greater than or equal to the account count (`acct_cnt`) in the instruction context; if so, return 0 indicating the account is not writable.
    - If the index is valid, call [`fd_instr_acc_is_writable_idx`](info/fd_instr_info.h.driver.md#fd_instr_acc_is_writable_idx) with the instruction and the index to determine if the account is writable, and return the result.
- **Output**: Returns an integer, 1 if the account is writable, and 0 if it is not writable or if the index is out of bounds.
- **Functions called**:
    - [`fd_instr_acc_is_writable_idx`](info/fd_instr_info.h.driver.md#fd_instr_acc_is_writable_idx)


---
### fd\_borrowed\_account\_is\_owned\_by\_current\_program<!-- {{#callable:fd_borrowed_account_is_owned_by_current_program}} -->
The function `fd_borrowed_account_is_owned_by_current_program` checks if a borrowed account is owned by the program invoked in the current instruction.
- **Inputs**:
    - `borrowed_acct`: A pointer to a constant `fd_borrowed_account_t` structure representing the borrowed account to be checked.
- **Control Flow**:
    - Initialize a pointer `program_id_pubkey` to NULL.
    - Call [`fd_exec_instr_ctx_get_last_program_key`](context/fd_exec_instr_ctx.c.driver.md#fd_exec_instr_ctx_get_last_program_key) with the instruction context from `borrowed_acct` to retrieve the last program's public key, storing it in `program_id_pubkey`.
    - If the call returns an error, return the error code.
    - Compare the public key from `program_id_pubkey` with the owner public key of the account in `borrowed_acct` using `memcmp`.
    - Return 1 if the keys match, indicating the account is owned by the current program, otherwise return 0.
- **Output**: Returns 1 if the account is owned by the current program, otherwise returns 0; if an error occurs during the retrieval of the program key, it returns the error code.
- **Functions called**:
    - [`fd_exec_instr_ctx_get_last_program_key`](context/fd_exec_instr_ctx.c.driver.md#fd_exec_instr_ctx_get_last_program_key)


---
### fd\_borrowed\_account\_can\_data\_be\_changed<!-- {{#callable:fd_borrowed_account_can_data_be_changed}} -->
The function `fd_borrowed_account_can_data_be_changed` checks if the data of a borrowed account can be modified based on its executability, writability, and ownership.
- **Inputs**:
    - `borrowed_acct`: A pointer to a constant `fd_borrowed_account_t` structure representing the borrowed account to be checked.
    - `err`: A pointer to an integer where the function will store an error code if the data cannot be changed.
- **Control Flow**:
    - Check if the account is executable using [`fd_borrowed_account_is_executable_internal`](#fd_borrowed_account_is_executable_internal); if true, set `err` to `FD_EXECUTOR_INSTR_ERR_EXECUTABLE_DATA_MODIFIED` and return 0.
    - Check if the account is writable using [`fd_borrowed_account_is_writable`](#fd_borrowed_account_is_writable); if false, set `err` to `FD_EXECUTOR_INSTR_ERR_READONLY_DATA_MODIFIED` and return 0.
    - Check if the account is owned by the current program using [`fd_borrowed_account_is_owned_by_current_program`](#fd_borrowed_account_is_owned_by_current_program); if false, set `err` to `FD_EXECUTOR_INSTR_ERR_EXTERNAL_DATA_MODIFIED` and return 0.
    - If all checks pass, set `err` to `FD_EXECUTOR_INSTR_SUCCESS` and return 1.
- **Output**: Returns 1 if the data can be changed, otherwise returns 0 and sets an appropriate error code in `err`.
- **Functions called**:
    - [`fd_borrowed_account_is_executable_internal`](#fd_borrowed_account_is_executable_internal)
    - [`fd_borrowed_account_is_writable`](#fd_borrowed_account_is_writable)
    - [`fd_borrowed_account_is_owned_by_current_program`](#fd_borrowed_account_is_owned_by_current_program)


---
### fd\_borrowed\_account\_can\_data\_be\_resized<!-- {{#callable:fd_borrowed_account_can_data_be_resized}} -->
The function `fd_borrowed_account_can_data_be_resized` checks if the data length of a borrowed account can be resized to a new specified length under certain conditions.
- **Inputs**:
    - `borrowed_acct`: A pointer to a constant `fd_borrowed_account_t` structure representing the borrowed account whose data length is to be checked for resizing.
    - `new_length`: An unsigned long integer representing the new desired length for the account data.
    - `err`: A pointer to an integer where the function will store an error code if resizing is not possible.
- **Control Flow**:
    - Retrieve the account from the `borrowed_acct` structure.
    - Check if the current data length is different from `new_length` and if the account is not owned by the current program; if so, set `err` to `FD_EXECUTOR_INSTR_ERR_ACC_DATA_SIZE_CHANGED` and return 0.
    - Check if `new_length` exceeds `MAX_PERMITTED_DATA_LENGTH`; if so, set `err` to `FD_EXECUTOR_INSTR_ERR_INVALID_REALLOC` and return 0.
    - Calculate the difference between `new_length` and the current data length, then add this to the current transaction's accounts resize delta.
    - Check if the new accounts resize delta exceeds `MAX_PERMITTED_ACCOUNT_DATA_ALLOCS_PER_TXN`; if so, set `err` to `FD_EXECUTOR_INSTR_ERR_MAX_ACCS_DATA_ALLOCS_EXCEEDED` and return 0.
    - If all checks pass, set `err` to `FD_EXECUTOR_INSTR_SUCCESS` and return 1.
- **Output**: Returns 1 if the data can be resized, otherwise returns 0 and sets an appropriate error code in `err`.
- **Functions called**:
    - [`fd_borrowed_account_is_owned_by_current_program`](#fd_borrowed_account_is_owned_by_current_program)


---
### fd\_borrowed\_account\_is\_zeroed<!-- {{#callable:fd_borrowed_account_is_zeroed}} -->
The function `fd_borrowed_account_is_zeroed` checks if all bytes in the data of a borrowed account are zero.
- **Inputs**:
    - `borrowed_acct`: A pointer to a constant `fd_borrowed_account_t` structure representing the borrowed account to be checked.
- **Control Flow**:
    - Retrieve the account data pointer from the `borrowed_acct` structure using the `get_data` method of the account's virtual table.
    - Iterate over each byte in the account data up to the length specified by the `get_data_len` method of the account's virtual table.
    - If any byte in the data is non-zero, return 0 immediately, indicating the account is not zeroed.
    - If all bytes are zero, return 1, indicating the account is zeroed.
- **Output**: Returns an integer: 1 if all bytes in the account data are zero, otherwise 0.


# Function Declarations (Public API)

---
### fd\_borrowed\_account\_get\_data\_mut<!-- {{#callable_declaration:fd_borrowed_account_get_data_mut}} -->
Provides mutable access to the data of a borrowed account.
- **Description**: This function is used to obtain a writable reference to the data of a borrowed account, assuming that the caller has already acquired exclusive write access to the account. It checks if the data can be changed and, if so, provides pointers to the data and its length. This function should be called when you need to modify the account data within a transaction. Ensure that the borrowed account is writable, non-executable, and owned by the current program before calling this function.
- **Inputs**:
    - `borrowed_acct`: A pointer to the fd_borrowed_account_t structure representing the borrowed account. Must not be null and should have exclusive write access.
    - `data_out`: A pointer to a uchar pointer where the address of the writable data will be stored. Can be null if the data pointer is not needed.
    - `dlen_out`: A pointer to a ulong where the length of the data will be stored. Can be null if the data length is not needed.
- **Output**: Returns FD_EXECUTOR_INSTR_SUCCESS on success or an error code if the data cannot be changed.
- **See also**: [`fd_borrowed_account_get_data_mut`](fd_borrowed_account.c.driver.md#fd_borrowed_account_get_data_mut)  (Implementation)


---
### fd\_borrowed\_account\_set\_owner<!-- {{#callable_declaration:fd_borrowed_account_set_owner}} -->
Sets the owner of a borrowed account.
- **Description**: This function assigns a new owner to a borrowed account, provided certain conditions are met. It should be used when you need to change the ownership of an account that is currently borrowed. The function requires that the account is owned by the current program, is writable, is not executable, and its data is zero-initialized or empty. If the new owner is the same as the current owner, the function returns success without making changes. It is important to ensure these preconditions are met before calling this function to avoid errors.
- **Inputs**:
    - `borrowed_acct`: A pointer to the borrowed account structure whose owner is to be set. Must not be null and must meet specific conditions (owned by current program, writable, non-executable, zero-initialized data).
    - `owner`: A pointer to the new owner's public key. Must not be null and should point to a valid fd_pubkey_t structure.
- **Output**: Returns FD_EXECUTOR_INSTR_SUCCESS on success or FD_EXECUTOR_INSTR_ERR_MODIFIED_PROGRAM_ID if any precondition is not met.
- **See also**: [`fd_borrowed_account_set_owner`](fd_borrowed_account.c.driver.md#fd_borrowed_account_set_owner)  (Implementation)


---
### fd\_borrowed\_account\_set\_lamports<!-- {{#callable_declaration:fd_borrowed_account_set_lamports}} -->
Sets the lamports balance of a borrowed account.
- **Description**: This function updates the lamports balance of a specified borrowed account, subject to several permission checks. It should be used when you need to modify the balance of an account that is part of a transaction context. The function ensures that the account is writable, not executable, and owned by the current program if the balance is to be decreased. It returns an error code if any of these conditions are not met, or if the account is read-only or executable. If the balance remains unchanged, the function returns success without modifying the account.
- **Inputs**:
    - `borrowed_acct`: A pointer to the fd_borrowed_account_t structure representing the account whose lamports balance is to be set. Must not be null and should be properly initialized.
    - `lamports`: The new lamports balance to set for the account. Must be a non-negative value. If the account is not owned by the current program, the new balance must not be less than the current balance.
- **Output**: Returns 0 (FD_EXECUTOR_INSTR_SUCCESS) on success, or an error code (FD_EXECUTOR_INSTR_ERR_{...}) if the operation fails due to permission checks or other constraints.
- **See also**: [`fd_borrowed_account_set_lamports`](fd_borrowed_account.c.driver.md#fd_borrowed_account_set_lamports)  (Implementation)


---
### fd\_borrowed\_account\_set\_data\_from\_slice<!-- {{#callable_declaration:fd_borrowed_account_set_data_from_slice}} -->
Sets the data of a borrowed account from a given data slice.
- **Description**: This function updates the data of a borrowed account with the provided data slice, ensuring that the account can be resized and modified as needed. It should be called when you need to replace the account's data with new content. The function performs necessary checks to ensure the account's data can be resized and modified, returning an error code if any conditions are not met. It is important to ensure that the borrowed account is writable and owned by the current program before calling this function.
- **Inputs**:
    - `borrowed_acct`: A pointer to the borrowed account structure whose data is to be set. Must not be null and should be properly initialized.
    - `data`: A pointer to the data slice to be copied into the account. Must not be null and should point to a valid memory region of at least 'data_sz' bytes.
    - `data_sz`: The size of the data slice in bytes. Must be within the permissible limits for account data size.
- **Output**: Returns an integer status code: 0 on success or an error code if the operation fails due to conditions such as non-writability or ownership issues.
- **See also**: [`fd_borrowed_account_set_data_from_slice`](fd_borrowed_account.c.driver.md#fd_borrowed_account_set_data_from_slice)  (Implementation)


---
### fd\_borrowed\_account\_set\_data\_length<!-- {{#callable_declaration:fd_borrowed_account_set_data_length}} -->
Sets the data length of a borrowed account.
- **Description**: This function adjusts the data length of a borrowed account, ensuring that the new length is permissible and that the account's data can be modified. It should be called when you need to resize the data associated with a borrowed account, provided the account is writable and owned by the current program. The function performs necessary checks to ensure the new length does not exceed predefined limits and that the account is in a state that allows resizing. It returns an error code if any conditions for resizing are not met.
- **Inputs**:
    - `borrowed_acct`: A pointer to the fd_borrowed_account_t structure representing the borrowed account. Must not be null and should be properly initialized with valid account data.
    - `new_len`: The desired new length for the account's data. Must be within the allowed range and not exceed MAX_PERMITTED_DATA_LENGTH. The function will return an error if the new length is invalid or if resizing is not permitted.
- **Output**: Returns an integer status code: 0 (FD_EXECUTOR_INSTR_SUCCESS) on success, or an error code if resizing is not possible.
- **See also**: [`fd_borrowed_account_set_data_length`](fd_borrowed_account.c.driver.md#fd_borrowed_account_set_data_length)  (Implementation)


---
### fd\_borrowed\_account\_set\_executable<!-- {{#callable_declaration:fd_borrowed_account_set_executable}} -->
Sets the executable flag of a borrowed account.
- **Description**: This function sets the executable flag of a borrowed account to the specified value. It should be used when you need to change the executable status of an account within a transaction context. The account must be rent exempt, owned by the current program, and writable for the operation to succeed. The function does not allow clearing the executable flag once set. It returns specific error codes if these conditions are not met, ensuring that only valid operations are performed.
- **Inputs**:
    - `borrowed_acct`: A pointer to the fd_borrowed_account_t structure representing the account to modify. Must not be null and must point to a valid borrowed account object.
    - `is_executable`: An integer indicating the desired executable status. A non-zero value sets the account as executable, while zero attempts to clear the flag, which is not allowed.
- **Output**: Returns FD_EXECUTOR_INSTR_SUCCESS on success, or an FD_EXECUTOR_INSTR_ERR_{...} code on failure, indicating the specific reason for the failure.
- **See also**: [`fd_borrowed_account_set_executable`](fd_borrowed_account.c.driver.md#fd_borrowed_account_set_executable)  (Implementation)


---
### fd\_borrowed\_account\_update\_accounts\_resize\_delta<!-- {{#callable_declaration:fd_borrowed_account_update_accounts_resize_delta}} -->
Updates the accounts resize delta for a borrowed account.
- **Description**: This function adjusts the accounts resize delta for a given borrowed account based on a new data length. It should be used when the size of the account data is expected to change, and the caller needs to update the transaction context accordingly. The function assumes that the borrowed account is valid and that the caller has already ensured the account can be resized. It sets an error code to indicate success or failure, which the caller should check to ensure the operation was successful.
- **Inputs**:
    - `borrowed_acct`: A pointer to a valid fd_borrowed_account_t structure representing the borrowed account. Must not be null.
    - `new_len`: The new desired length for the account data. Must be a valid length that the account can be resized to.
    - `err`: A pointer to an integer where the function will store the error code. Must not be null.
- **Output**: Returns 1 on success and sets *err to FD_EXECUTOR_INSTR_SUCCESS.
- **See also**: [`fd_borrowed_account_update_accounts_resize_delta`](fd_borrowed_account.c.driver.md#fd_borrowed_account_update_accounts_resize_delta)  (Implementation)


