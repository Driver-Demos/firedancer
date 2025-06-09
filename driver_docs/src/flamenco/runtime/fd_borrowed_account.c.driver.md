# Purpose
This C source code file provides a set of functions for managing and manipulating "borrowed accounts" within a transaction context, likely in a financial or blockchain-related application. The file defines several functions that operate on `fd_borrowed_account_t` structures, which appear to represent accounts that are temporarily accessed or modified during a transaction. The functions include operations to get and modify account data, set account ownership, adjust the number of lamports (a unit of currency), and manage account properties such as executability and data length. Each function includes checks to ensure that operations are valid, such as verifying account ownership, writability, and compliance with specific conditions like rent exemption for executability.

The code is structured to ensure that account modifications adhere to certain rules and constraints, as indicated by the frequent use of conditional checks and error handling. The functions rely on virtual table (vt) methods of the `fd_txn_account_t` structure to perform specific operations on the account, suggesting a design that supports polymorphism or interface-like behavior. The file does not define a main function, indicating that it is intended to be part of a larger codebase, likely as a library or module that provides account management functionality. The presence of references to external documentation and specific error codes suggests that this code is part of a well-defined API or system, possibly interacting with a blockchain or distributed ledger platform.
# Imports and Dependencies

---
- `fd_borrowed_account.h`


# Functions

---
### fd\_borrowed\_account\_get\_data\_mut<!-- {{#callable:fd_borrowed_account_get_data_mut}} -->
The function `fd_borrowed_account_get_data_mut` retrieves mutable data and its length from a borrowed account if the data can be changed.
- **Inputs**:
    - `borrowed_acct`: A pointer to an `fd_borrowed_account_t` structure representing the borrowed account from which data is to be retrieved.
    - `data_out`: A pointer to a pointer to `uchar` where the address of the mutable data will be stored if not NULL.
    - `dlen_out`: A pointer to `ulong` where the length of the data will be stored if not NULL.
- **Control Flow**:
    - Retrieve the `fd_txn_account_t` account from the `borrowed_acct` structure.
    - Call [`fd_borrowed_account_can_data_be_changed`](fd_borrowed_account.h.driver.md#fd_borrowed_account_can_data_be_changed) to check if the data can be changed, storing any error in `err`.
    - If `err` is set (indicating data cannot be changed), return the error code.
    - If `data_out` is not NULL, set `*data_out` to the result of `acct->vt->get_data_mut(acct)`, which retrieves the mutable data pointer.
    - If `dlen_out` is not NULL, set `*dlen_out` to the result of `acct->vt->get_data_len(acct)`, which retrieves the data length.
    - Return `FD_EXECUTOR_INSTR_SUCCESS` to indicate successful execution.
- **Output**: Returns an integer status code, `FD_EXECUTOR_INSTR_SUCCESS` on success or an error code if the data cannot be changed.
- **Functions called**:
    - [`fd_borrowed_account_can_data_be_changed`](fd_borrowed_account.h.driver.md#fd_borrowed_account_can_data_be_changed)


---
### fd\_borrowed\_account\_set\_owner<!-- {{#callable:fd_borrowed_account_set_owner}} -->
The function `fd_borrowed_account_set_owner` sets a new owner for a borrowed account if certain conditions are met.
- **Inputs**:
    - `borrowed_acct`: A pointer to an `fd_borrowed_account_t` structure representing the borrowed account whose owner is to be set.
    - `owner`: A constant pointer to an `fd_pubkey_t` structure representing the new owner's public key.
- **Control Flow**:
    - Retrieve the account from the `borrowed_acct` structure.
    - Check if the current program owns the account; if not, return an error code `FD_EXECUTOR_INSTR_ERR_MODIFIED_PROGRAM_ID`.
    - Check if the account is writable; if not, return the same error code.
    - Check if the account is executable; if it is, return the same error code.
    - Check if the account data is zero-initialized or empty; if not, return the same error code.
    - Compare the current owner with the new owner; if they are the same, return success without making changes.
    - Set the new owner for the account using the `set_owner` method of the account's virtual table.
    - Return success code `FD_EXECUTOR_INSTR_SUCCESS`.
- **Output**: The function returns an integer status code, either `FD_EXECUTOR_INSTR_SUCCESS` if the owner is successfully set or `FD_EXECUTOR_INSTR_ERR_MODIFIED_PROGRAM_ID` if any of the preconditions are not met.
- **Functions called**:
    - [`fd_borrowed_account_is_owned_by_current_program`](fd_borrowed_account.h.driver.md#fd_borrowed_account_is_owned_by_current_program)
    - [`fd_borrowed_account_is_writable`](fd_borrowed_account.h.driver.md#fd_borrowed_account_is_writable)
    - [`fd_borrowed_account_is_executable_internal`](fd_borrowed_account.h.driver.md#fd_borrowed_account_is_executable_internal)
    - [`fd_borrowed_account_is_zeroed`](fd_borrowed_account.h.driver.md#fd_borrowed_account_is_zeroed)


---
### fd\_borrowed\_account\_set\_lamports<!-- {{#callable:fd_borrowed_account_set_lamports}} -->
The function `fd_borrowed_account_set_lamports` sets the number of lamports for a borrowed account, ensuring compliance with ownership, writability, and executability constraints.
- **Inputs**:
    - `borrowed_acct`: A pointer to an `fd_borrowed_account_t` structure representing the borrowed account whose lamports are to be set.
    - `lamports`: An unsigned long integer representing the new number of lamports to set for the account.
- **Control Flow**:
    - Retrieve the account from the borrowed account structure.
    - Check if the account is not owned by the current program and if the new lamports value is less than the current balance; if so, return an error code for external account lamport spend.
    - Check if the account is not writable; if so, return an error code for read-only lamport change.
    - Check if the account is executable; if so, return an error code for executable lamport change.
    - Check if the current lamports value is equal to the new lamports value; if so, return success without making changes.
    - Set the new lamports value for the account.
    - Return success.
- **Output**: The function returns an integer status code indicating success or a specific error condition related to account ownership, writability, or executability.
- **Functions called**:
    - [`fd_borrowed_account_is_owned_by_current_program`](fd_borrowed_account.h.driver.md#fd_borrowed_account_is_owned_by_current_program)
    - [`fd_borrowed_account_is_writable`](fd_borrowed_account.h.driver.md#fd_borrowed_account_is_writable)
    - [`fd_borrowed_account_is_executable_internal`](fd_borrowed_account.h.driver.md#fd_borrowed_account_is_executable_internal)


---
### fd\_borrowed\_account\_set\_data\_from\_slice<!-- {{#callable:fd_borrowed_account_set_data_from_slice}} -->
The function `fd_borrowed_account_set_data_from_slice` sets the data of a borrowed account from a given data slice, ensuring that the account's data can be resized and changed before performing the operation.
- **Inputs**:
    - `borrowed_acct`: A pointer to an `fd_borrowed_account_t` structure representing the borrowed account whose data is to be set.
    - `data`: A constant pointer to an array of unsigned characters (`uchar`) representing the data slice to be set in the account.
    - `data_sz`: An unsigned long integer representing the size of the data slice to be set in the account.
- **Control Flow**:
    - Retrieve the account from the `borrowed_acct` structure.
    - Check if the account's data can be resized to `data_sz` using [`fd_borrowed_account_can_data_be_resized`](fd_borrowed_account.h.driver.md#fd_borrowed_account_can_data_be_resized); if not, return the error code.
    - Check if the account's data can be changed using [`fd_borrowed_account_can_data_be_changed`](fd_borrowed_account.h.driver.md#fd_borrowed_account_can_data_be_changed); if not, return the error code.
    - Call [`fd_borrowed_account_update_accounts_resize_delta`](#fd_borrowed_account_update_accounts_resize_delta) to update the account's resize delta; if it fails, return the error code.
    - Set the account's data using the `set_data` method of the account's virtual table (`vt`).
    - Return `FD_EXECUTOR_INSTR_SUCCESS` to indicate success.
- **Output**: The function returns an integer status code, `FD_EXECUTOR_INSTR_SUCCESS` on success, or an error code if any of the checks fail.
- **Functions called**:
    - [`fd_borrowed_account_can_data_be_resized`](fd_borrowed_account.h.driver.md#fd_borrowed_account_can_data_be_resized)
    - [`fd_borrowed_account_can_data_be_changed`](fd_borrowed_account.h.driver.md#fd_borrowed_account_can_data_be_changed)
    - [`fd_borrowed_account_update_accounts_resize_delta`](#fd_borrowed_account_update_accounts_resize_delta)


---
### fd\_borrowed\_account\_set\_data\_length<!-- {{#callable:fd_borrowed_account_set_data_length}} -->
The function `fd_borrowed_account_set_data_length` attempts to resize the data length of a borrowed account, ensuring that the operation is permissible and updating the account's data length if necessary.
- **Inputs**:
    - `borrowed_acct`: A pointer to an `fd_borrowed_account_t` structure representing the borrowed account whose data length is to be set.
    - `new_len`: An unsigned long integer representing the new desired length for the account's data.
- **Control Flow**:
    - Retrieve the account from the `borrowed_acct` structure.
    - Initialize an error variable `err` to `FD_EXECUTOR_INSTR_SUCCESS`.
    - Check if the account's data can be resized to `new_len` using [`fd_borrowed_account_can_data_be_resized`](fd_borrowed_account.h.driver.md#fd_borrowed_account_can_data_be_resized); if not, return the error code.
    - Check if the account's data can be changed using [`fd_borrowed_account_can_data_be_changed`](fd_borrowed_account.h.driver.md#fd_borrowed_account_can_data_be_changed); if not, return the error code.
    - Retrieve the current data length of the account using `acct->vt->get_data_len`.
    - If the current data length is equal to `new_len`, return `FD_EXECUTOR_INSTR_SUCCESS` without making changes.
    - Update the account's resize delta using [`fd_borrowed_account_update_accounts_resize_delta`](#fd_borrowed_account_update_accounts_resize_delta); if unsuccessful, return the error code.
    - Resize the account's data to `new_len` using `acct->vt->resize`.
    - Return `FD_EXECUTOR_INSTR_SUCCESS` to indicate successful completion.
- **Output**: The function returns an integer status code, `FD_EXECUTOR_INSTR_SUCCESS` on success or an error code if the operation fails at any validation step.
- **Functions called**:
    - [`fd_borrowed_account_can_data_be_resized`](fd_borrowed_account.h.driver.md#fd_borrowed_account_can_data_be_resized)
    - [`fd_borrowed_account_can_data_be_changed`](fd_borrowed_account.h.driver.md#fd_borrowed_account_can_data_be_changed)
    - [`fd_borrowed_account_update_accounts_resize_delta`](#fd_borrowed_account_update_accounts_resize_delta)


---
### fd\_borrowed\_account\_set\_executable<!-- {{#callable:fd_borrowed_account_set_executable}} -->
The function `fd_borrowed_account_set_executable` sets the executable flag of a borrowed account if certain conditions are met.
- **Inputs**:
    - `borrowed_acct`: A pointer to an `fd_borrowed_account_t` structure representing the borrowed account whose executable flag is to be set.
    - `is_executable`: An integer indicating whether the account should be set as executable (non-zero) or not (zero).
- **Control Flow**:
    - Retrieve the account from the `borrowed_acct` structure.
    - Check if the account is rent exempt by comparing its lamports to the minimum required for rent exemption; return an error if not.
    - Verify that the account is owned by the current program; return an error if not.
    - Ensure the account is writable; return an error if not.
    - Check if the executable flag is being cleared when it is already set; return an error if so.
    - If the executable flag is already in the desired state, return success without making changes.
    - Set the executable flag of the account using the provided `is_executable` value.
    - Return success after setting the executable flag.
- **Output**: Returns an integer status code indicating success or a specific error if any of the conditions for setting the executable flag are not met.
- **Functions called**:
    - [`fd_rent_exempt_minimum_balance`](sysvar/fd_sysvar_rent1.c.driver.md#fd_rent_exempt_minimum_balance)
    - [`fd_borrowed_account_is_owned_by_current_program`](fd_borrowed_account.h.driver.md#fd_borrowed_account_is_owned_by_current_program)
    - [`fd_borrowed_account_is_writable`](fd_borrowed_account.h.driver.md#fd_borrowed_account_is_writable)
    - [`fd_borrowed_account_is_executable_internal`](fd_borrowed_account.h.driver.md#fd_borrowed_account_is_executable_internal)
    - [`fd_borrowed_account_is_executable`](fd_borrowed_account.h.driver.md#fd_borrowed_account_is_executable)


---
### fd\_borrowed\_account\_update\_accounts\_resize\_delta<!-- {{#callable:fd_borrowed_account_update_accounts_resize_delta}} -->
The function `fd_borrowed_account_update_accounts_resize_delta` updates the accounts resize delta in the transaction context based on the new length of the account data.
- **Inputs**:
    - `borrowed_acct`: A pointer to an `fd_borrowed_account_t` structure representing the borrowed account whose data length is being updated.
    - `new_len`: An unsigned long integer representing the new length of the account data.
    - `err`: A pointer to an integer where the function will store the success or error code.
- **Control Flow**:
    - Retrieve the instruction context from the borrowed account structure.
    - Retrieve the account from the borrowed account structure.
    - Calculate the size delta by subtracting the current data length of the account from the new length using a saturated subtraction function `fd_ulong_sat_sub`.
    - Update the `accounts_resize_delta` in the transaction context by adding the calculated size delta using a saturated addition function `fd_ulong_sat_add`.
    - Set the error code to `FD_EXECUTOR_INSTR_SUCCESS`.
    - Return 1 to indicate success.
- **Output**: The function returns an integer value of 1 to indicate success and sets the error code to `FD_EXECUTOR_INSTR_SUCCESS`.


