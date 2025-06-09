# Purpose
This C header file, `fd_instr_info.h`, is part of a larger software system, likely related to transaction processing or execution within a virtual machine or blockchain environment. The file defines structures and functions for managing and interacting with instruction accounts within a transaction. The primary structure, `fd_instr_info_t`, encapsulates information about a transaction's instruction, including the program ID, data size, account count, and an array of `fd_instruction_account_t` structures that represent individual accounts involved in the instruction. The file enforces a maximum of 256 instruction accounts to maintain a low memory footprint, despite the possibility of transactions having more accounts.

The file provides several inline functions and prototypes for initializing and manipulating instruction accounts, such as [`fd_instruction_account_init`](#fd_instruction_account_tfd_instruction_account_init) and [`fd_instr_info_setup_instr_account`](#fd_instr_info_setup_instr_account). It also includes functions for accumulating starting lamports (a unit of currency or value in the system) and checking account properties like writability and signer status. The header file is designed to be included in other parts of the system, providing a consistent interface for handling instruction accounts and ensuring efficient memory usage and transaction processing.
# Imports and Dependencies

---
- `../../fd_flamenco_base.h`
- `../../types/fd_types.h`
- `../fd_txn_account.h`


# Data Structures

---
### fd\_instruction\_account
- **Type**: `struct`
- **Members**:
    - `index_in_transaction`: Stores the index of the account within the transaction.
    - `index_in_caller`: Stores the index of the account within the caller's context.
    - `index_in_callee`: Stores the index of the account within the callee's context.
    - `is_writable`: Indicates if the account is writable (1 if true, 0 if false).
    - `is_signer`: Indicates if the account is a signer (1 if true, 0 if false).
- **Description**: The `fd_instruction_account` structure is used to represent an account involved in a transaction instruction within a virtual machine execution context. It holds indices that map the account's position in different contexts (transaction, caller, and callee) and flags that specify whether the account is writable or a signer. This structure is crucial for managing account permissions and roles during the execution of instructions in a transaction.


---
### fd\_instruction\_account\_t
- **Type**: `struct`
- **Members**:
    - `index_in_transaction`: Stores the index of the account within the transaction.
    - `index_in_caller`: Stores the index of the account within the caller's context.
    - `index_in_callee`: Stores the index of the account within the callee's context.
    - `is_writable`: Indicates if the account is writable (1 if true, 0 if false).
    - `is_signer`: Indicates if the account is a signer (1 if true, 0 if false).
- **Description**: The `fd_instruction_account_t` structure is used to represent an account involved in a transaction instruction within a virtual machine execution context. It holds indices that map the account's position in different contexts (transaction, caller, and callee) and flags that indicate whether the account is writable or a signer. This structure is crucial for managing account permissions and roles during the execution of instructions in a transaction.


---
### fd\_instr\_info
- **Type**: `struct`
- **Members**:
    - `program_id`: An unsigned character representing the program identifier.
    - `data_sz`: An unsigned short indicating the size of the data.
    - `acct_cnt`: An unsigned short representing the count of accounts.
    - `data`: A pointer to an unsigned character array holding the instruction data.
    - `accounts`: An array of fd_instruction_account_t structures, each representing an account involved in the instruction.
    - `is_duplicate`: An array of unsigned characters indicating if an account is a duplicate.
    - `starting_lamports_h`: An unsigned long representing the high part of the starting lamports balance.
    - `starting_lamports_l`: An unsigned long representing the low part of the starting lamports balance.
- **Description**: The `fd_instr_info` structure is designed to encapsulate information about a specific instruction within a transaction, including the program ID, data size, and account count. It holds a pointer to the instruction data and an array of `fd_instruction_account_t` structures to manage up to 256 accounts, each with flags for writability and signer status. Additionally, it tracks duplicate accounts and maintains a split representation of starting lamports using two unsigned long fields, which are intended to be converted to a 128-bit representation in the future.


---
### fd\_instr\_info\_t
- **Type**: `struct`
- **Members**:
    - `program_id`: An unsigned character representing the program identifier.
    - `data_sz`: A ushort indicating the size of the data associated with the instruction.
    - `acct_cnt`: A ushort representing the count of accounts involved in the instruction.
    - `data`: A pointer to an unsigned character array holding the instruction data.
    - `accounts`: An array of fd_instruction_account_t structures, each representing an account involved in the instruction.
    - `is_duplicate`: An array of unsigned characters indicating if an account is a duplicate.
    - `starting_lamports_h`: An unsigned long representing the high part of the starting lamports balance.
    - `starting_lamports_l`: An unsigned long representing the low part of the starting lamports balance.
- **Description**: The `fd_instr_info_t` structure is designed to encapsulate information about a specific instruction within a transaction in a blockchain execution context. It includes details such as the program ID, the size of the instruction data, and the number of accounts involved. The structure also maintains an array of `fd_instruction_account_t` to represent each account, along with flags to indicate if an account is writable or a signer. Additionally, it tracks duplicate accounts and accumulates starting lamports balances, which are crucial for transaction execution and validation.


# Functions

---
### fd\_instruction\_account\_init<!-- {{#callable:fd_instruction_account_t::fd_instruction_account_init}} -->
The `fd_instruction_account_init` function initializes and returns a `fd_instruction_account_t` structure with specified indices and flags for writability and signer status.
- **Inputs**:
    - `idx_in_txn`: The index of the account in the transaction.
    - `idx_in_caller`: The index of the account in the caller.
    - `idx_in_callee`: The index of the account in the callee.
    - `is_writable`: A flag indicating if the account is writable (non-zero if true).
    - `is_signer`: A flag indicating if the account is a signer (non-zero if true).
- **Control Flow**:
    - A `fd_instruction_account_t` structure named `acc` is declared and initialized with the provided input values.
    - The structure fields `index_in_transaction`, `index_in_caller`, `index_in_callee`, `is_writable`, and `is_signer` are set to the corresponding input arguments.
    - The initialized `fd_instruction_account_t` structure is returned.
- **Output**: The function returns a `fd_instruction_account_t` structure initialized with the provided indices and flags.
- **See also**: [`fd_instruction_account_t`](#fd_instruction_account_t)  (Data Structure)


---
### fd\_instr\_info\_setup\_instr\_account<!-- {{#callable:fd_instr_info_setup_instr_account}} -->
The function `fd_instr_info_setup_instr_account` initializes an instruction account within an `fd_instr_info_t` structure and updates the account's duplicate status based on its presence in a transaction.
- **Inputs**:
    - `instr`: A pointer to an `fd_instr_info_t` structure where the instruction account will be set up.
    - `acc_idx_seen`: An array of `uchar` with a size of `FD_INSTR_ACCT_MAX` that tracks whether an account index has been seen in the transaction.
    - `idx_in_txn`: A `ushort` representing the index of the account in the transaction.
    - `idx_in_caller`: A `ushort` representing the index of the account in the caller.
    - `idx_in_callee`: A `ushort` representing the index of the account in the callee.
    - `is_writable`: A `uchar` indicating if the account is writable.
    - `is_signer`: A `uchar` indicating if the account is a signer.
- **Control Flow**:
    - Check if `idx_in_txn` is not equal to `USHORT_MAX` using `FD_LIKELY` macro for likely branch prediction.
    - If the account index in the transaction (`idx_in_txn`) is valid, set the `is_duplicate` status of the account at `idx_in_callee` in `instr` to the value in `acc_idx_seen` at `idx_in_txn`.
    - If the account index in the transaction has not been seen before (`!acc_idx_seen[idx_in_txn]`), mark it as seen by setting `acc_idx_seen[idx_in_txn]` to 1.
    - Initialize the account at `idx_in_callee` in `instr->accounts` using [`fd_instruction_account_init`](#fd_instruction_account_tfd_instruction_account_init) with the provided indices and flags (`is_writable`, `is_signer`).
- **Output**: The function does not return a value; it modifies the `instr` structure in place.
- **Functions called**:
    - [`fd_instruction_account_t::fd_instruction_account_init`](#fd_instruction_account_tfd_instruction_account_init)


---
### fd\_instr\_acc\_is\_writable\_idx<!-- {{#callable:fd_instr_acc_is_writable_idx}} -->
The function `fd_instr_acc_is_writable_idx` checks if a specified account in an instruction is writable.
- **Inputs**:
    - `instr`: A pointer to a constant `fd_instr_info_t` structure representing the instruction information.
    - `idx`: An unsigned short integer representing the index of the account to check within the instruction's accounts.
- **Control Flow**:
    - The function first checks if the provided index `idx` is greater than or equal to the number of accounts (`acct_cnt`) in the instruction `instr` using `FD_UNLIKELY` to optimize for the common case where this is false.
    - If the index is out of bounds, the function returns `FD_EXECUTOR_INSTR_ERR_MISSING_ACC`, indicating an error due to a missing account.
    - If the index is valid, the function returns a boolean value indicating whether the account at the specified index is writable by checking the `is_writable` field of the account.
- **Output**: The function returns an integer, which is either `FD_EXECUTOR_INSTR_ERR_MISSING_ACC` if the index is invalid, or a boolean value (0 or 1) indicating if the account is writable.


---
### fd\_instr\_acc\_is\_signer\_idx<!-- {{#callable:fd_instr_acc_is_signer_idx}} -->
The function `fd_instr_acc_is_signer_idx` checks if a specified account in an instruction is marked as a signer.
- **Inputs**:
    - `instr`: A pointer to a constant `fd_instr_info_t` structure representing the instruction information.
    - `idx`: An unsigned short integer representing the index of the account to check within the instruction's accounts.
- **Control Flow**:
    - The function first checks if the provided index `idx` is greater than or equal to the number of accounts (`acct_cnt`) in the instruction `instr` using `FD_UNLIKELY` for branch prediction optimization.
    - If the index is out of bounds, the function returns `FD_EXECUTOR_INSTR_ERR_MISSING_ACC`, indicating an error due to a missing account.
    - If the index is valid, the function returns a boolean value indicating whether the account at the specified index is marked as a signer by checking the `is_signer` field of the account.
- **Output**: The function returns an integer, which is either `FD_EXECUTOR_INSTR_ERR_MISSING_ACC` if the index is out of bounds, or a boolean value (0 or 1) indicating whether the account is a signer.


---
### fd\_instr\_get\_acc\_flags<!-- {{#callable:fd_instr_get_acc_flags}} -->
The `fd_instr_get_acc_flags` function retrieves the access flags for a specified account within an instruction, indicating whether the account is a signer or writable.
- **Inputs**:
    - `instr`: A pointer to a constant `fd_instr_info_t` structure representing the instruction information.
    - `idx`: An unsigned short integer representing the index of the account within the instruction's account list.
- **Control Flow**:
    - Check if the provided index `idx` is greater than or equal to the number of accounts (`acct_cnt`) in the instruction; if so, return 0.
    - Initialize a variable `flags` to 0 to store the access flags.
    - Check if the account at the given index is a signer; if true, set the `FD_INSTR_ACCT_FLAGS_IS_SIGNER` flag in `flags`.
    - Check if the account at the given index is writable; if true, set the `FD_INSTR_ACCT_FLAGS_IS_WRITABLE` flag in `flags`.
    - Return the `flags` variable containing the access flags for the account.
- **Output**: An unsigned char representing the access flags for the specified account, with bits set for signer and writable status.


# Function Declarations (Public API)

---
### fd\_instr\_info\_accumulate\_starting\_lamports<!-- {{#callable_declaration:fd_instr_info_accumulate_starting_lamports}} -->
Accumulates starting lamports for a transaction instruction.
- **Description**: Use this function to update the starting lamports fields of an `fd_instr_info_t` object during its setup. It should be called when you need to accumulate the lamports from a specific account in the transaction context, identified by its index. Ensure that the starting lamports fields in the `fd_instr_info_t` object are initialized to zero before calling this function. The function will only perform the accumulation if the account is not marked as a duplicate in the instruction context.
- **Inputs**:
    - `instr`: A pointer to an `fd_instr_info_t` structure where the starting lamports will be accumulated. The caller must ensure this is a valid, non-null pointer and that the starting lamports fields are zeroed out before calling.
    - `txn_ctx`: A pointer to a constant `fd_exec_txn_ctx_t` structure representing the transaction context. This must be a valid, non-null pointer.
    - `idx_in_callee`: An unsigned short representing the index of the account in the callee's context. It must be within the valid range of accounts in the instruction.
    - `idx_in_txn`: An unsigned short representing the index of the account in the transaction context. It must be within the valid range of accounts in the transaction.
- **Output**: None
- **See also**: [`fd_instr_info_accumulate_starting_lamports`](fd_instr_info.c.driver.md#fd_instr_info_accumulate_starting_lamports)  (Implementation)


---
### fd\_instr\_info\_init\_from\_txn\_instr<!-- {{#callable_declaration:fd_instr_info_init_from_txn_instr}} -->
Initialize an instruction information structure from a transaction instruction.
- **Description**: This function sets up an `fd_instr_info_t` structure based on the details provided in a transaction instruction and its context. It is used to prepare the instruction information for execution by populating fields such as program ID, account count, and data size. The function caps the number of instruction accounts at 256 to manage memory footprint effectively. It should be called when you need to convert transaction instruction data into a format suitable for execution, ensuring that the transaction context and instruction data are valid and properly initialized.
- **Inputs**:
    - `instr`: A pointer to an `fd_instr_info_t` structure that will be initialized. The caller must ensure this pointer is valid and points to allocated memory.
    - `txn_ctx`: A pointer to an `fd_exec_txn_ctx_t` structure containing the transaction context. This must be a valid, initialized context that provides necessary transaction details.
    - `txn_instr`: A pointer to a constant `fd_txn_instr_t` structure representing the transaction instruction. This must be valid and properly initialized, providing the instruction data to be used for initialization.
- **Output**: None
- **See also**: [`fd_instr_info_init_from_txn_instr`](fd_instr_info.c.driver.md#fd_instr_info_init_from_txn_instr)  (Implementation)


---
### fd\_instr\_info\_sum\_account\_lamports<!-- {{#callable_declaration:fd_instr_info_sum_account_lamports}} -->
Calculate the sum of lamport balances for all instruction accounts.
- **Description**: This function calculates the total sum of lamport balances for all accounts associated with a given instruction within a transaction context. It should be used when you need to determine the total lamport balance across all relevant accounts in an instruction. The function initializes the output parameters to zero and iterates over each account, summing their lamport balances unless the account is marked as a duplicate or has invalid metadata. It returns an error code if an arithmetic overflow occurs during the summation process.
- **Inputs**:
    - `instr`: A pointer to a constant `fd_instr_info_t` structure representing the instruction whose account lamports are to be summed. Must not be null.
    - `txn_ctx`: A pointer to an `fd_exec_txn_ctx_t` structure representing the transaction context containing account information. Must not be null.
    - `total_lamports_h`: A pointer to an `ulong` where the high part of the total lamports sum will be stored. Must not be null.
    - `total_lamports_l`: A pointer to an `ulong` where the low part of the total lamports sum will be stored. Must not be null.
- **Output**: Returns an integer status code: `FD_EXECUTOR_INSTR_SUCCESS` on success, or `FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW` if an overflow occurs during summation.
- **See also**: [`fd_instr_info_sum_account_lamports`](fd_instr_info.c.driver.md#fd_instr_info_sum_account_lamports)  (Implementation)


