# Purpose
The provided C code is part of a program loader system, specifically designed to manage the lifecycle of programs in a blockchain environment, likely Solana given the context and naming conventions. This file implements various functions to handle the state transitions and operations of a "loader v4" program, which includes deploying, retracting, writing, copying, setting program length, transferring authority, and finalizing programs. The code is structured to ensure that these operations are performed safely and correctly, with checks for account ownership, authority signatures, and program status. The functions are designed to interact with program accounts, manipulate their data, and enforce rules such as cooldown periods between deployments and retractions.

The file defines a set of functions that serve as the core logic for handling instructions related to program management. These functions include [`fd_loader_v4_program_instruction_write`](#fd_loader_v4_program_instruction_write), [`fd_loader_v4_program_instruction_copy`](#fd_loader_v4_program_instruction_copy), [`fd_loader_v4_program_instruction_set_program_length`](#fd_loader_v4_program_instruction_set_program_length), [`fd_loader_v4_program_instruction_deploy`](#fd_loader_v4_program_instruction_deploy), [`fd_loader_v4_program_instruction_retract`](#fd_loader_v4_program_instruction_retract), [`fd_loader_v4_program_instruction_transfer_authority`](#fd_loader_v4_program_instruction_transfer_authority), and [`fd_loader_v4_program_instruction_finalize`](#fd_loader_v4_program_instruction_finalize). Each function is responsible for a specific aspect of program management, such as writing data to a program account, copying data from one program to another, resizing program accounts, deploying programs, retracting them, transferring authority, and finalizing programs to make them immutable. The file also includes helper functions to check the status of a program and to get mutable or immutable references to program state. The main entry point for executing these instructions is [`fd_loader_v4_program_execute`](#fd_loader_v4_program_execute), which dispatches the appropriate function based on the instruction type. This code is intended to be part of a larger system that manages program execution and state transitions in a blockchain environment.
# Imports and Dependencies

---
- `fd_loader_v4_program.h`
- `../sysvar/fd_sysvar_clock.h`


# Functions

---
### fd\_loader\_v4\_status\_is\_deployed<!-- {{#callable:fd_loader_v4_status_is_deployed}} -->
The function `fd_loader_v4_status_is_deployed` checks if the status of a given loader v4 state is 'deployed'.
- **Inputs**:
    - `state`: A pointer to a constant `fd_loader_v4_state_t` structure representing the state of a loader v4 program.
- **Control Flow**:
    - The function accesses the `status` field of the `state` structure.
    - It compares the `status` field to the constant `FD_LOADER_V4_STATUS_ENUM_DELOYED`.
    - The function returns the result of this comparison.
- **Output**: The function returns an `uchar` (unsigned char) which is non-zero if the status is 'deployed' and zero otherwise.


---
### fd\_loader\_v4\_status\_is\_retracted<!-- {{#callable:fd_loader_v4_status_is_retracted}} -->
The function `fd_loader_v4_status_is_retracted` checks if the status of a given loader v4 state is 'retracted'.
- **Inputs**:
    - `state`: A pointer to a constant `fd_loader_v4_state_t` structure representing the state of a loader v4 program.
- **Control Flow**:
    - The function accesses the `status` field of the `state` structure.
    - It compares the `status` field to the constant `FD_LOADER_V4_STATUS_ENUM_RETRACTED`.
    - The function returns the result of this comparison.
- **Output**: The function returns an `uchar` (unsigned char) which is non-zero if the status is 'retracted' and zero otherwise.


---
### fd\_loader\_v4\_status\_is\_finalized<!-- {{#callable:fd_loader_v4_status_is_finalized}} -->
The function `fd_loader_v4_status_is_finalized` checks if the status of a given loader v4 state is finalized.
- **Inputs**:
    - `state`: A pointer to a constant `fd_loader_v4_state_t` structure representing the state of a loader v4 program.
- **Control Flow**:
    - The function accesses the `status` field of the `state` structure.
    - It compares the `status` field to the constant `FD_LOADER_V4_STATUS_ENUM_FINALIZED`.
    - The function returns the result of this comparison.
- **Output**: The function returns an `uchar` (unsigned char) that is non-zero if the status is finalized, and zero otherwise.


---
### fd\_loader\_v4\_get\_state\_mut<!-- {{#callable:fd_loader_v4_get_state_mut}} -->
The function `fd_loader_v4_get_state_mut` retrieves a mutable reference to a loader v4 state from a given data buffer, ensuring the buffer is large enough.
- **Inputs**:
    - `data`: A pointer to a mutable buffer containing the account's data.
    - `dlen`: The length of the data buffer.
    - `err`: A pointer to an integer where the function will store an error code.
- **Control Flow**:
    - Initialize the error code to `FD_EXECUTOR_INSTR_SUCCESS` indicating no error initially.
    - Check if the data length `dlen` is less than `LOADER_V4_PROGRAM_DATA_OFFSET`.
    - If the data length is insufficient, set the error code to `FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL` and return `NULL`.
    - If the data length is sufficient, return a pointer to the data cast as a `fd_loader_v4_state_t` type using `fd_type_pun`.
- **Output**: Returns a pointer to `fd_loader_v4_state_t` if the data length is sufficient, otherwise returns `NULL`.


---
### fd\_loader\_v4\_get\_state<!-- {{#callable:fd_loader_v4_get_state}} -->
The `fd_loader_v4_get_state` function retrieves the state of a program account as a constant pointer to a `fd_loader_v4_state_t` structure, checking if the account data is sufficiently large and setting an error code if not.
- **Inputs**:
    - `program`: A constant pointer to a `fd_txn_account_t` structure representing the program account whose state is to be retrieved.
    - `err`: A pointer to an integer where the function will store an error code indicating success or failure of the operation.
- **Control Flow**:
    - Initialize the error code pointed to by `err` to `FD_EXECUTOR_INSTR_SUCCESS` indicating success.
    - Check if the data length of the program account is less than `LOADER_V4_PROGRAM_DATA_OFFSET`.
    - If the data length is insufficient, set the error code to `FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL` and return `NULL`.
    - If the data length is sufficient, retrieve the data from the program account and return it as a constant pointer to `fd_loader_v4_state_t` using `fd_type_pun_const`.
- **Output**: A constant pointer to a `fd_loader_v4_state_t` structure representing the state of the program account, or `NULL` if the account data is too small.


---
### check\_program\_account<!-- {{#callable:check_program_account}} -->
The `check_program_account` function validates a program account's ownership, writability, authority signature, authority correctness, and non-finalized status, returning the program's state if all checks pass.
- **Inputs**:
    - `instr_ctx`: A pointer to the instruction execution context, which contains information about the current instruction being executed.
    - `program`: A constant pointer to a borrowed account structure representing the program account to be checked.
    - `authority_address`: A constant pointer to a public key structure representing the expected authority address for the program account.
    - `err`: A pointer to an integer where the function will store an error code if any validation checks fail.
- **Control Flow**:
    - Initialize the error code to `FD_EXECUTOR_INSTR_SUCCESS`.
    - Check if the program account is owned by the expected loader; if not, log an error and set the error code to `FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER`.
    - Retrieve the program's state using [`fd_loader_v4_get_state`](#fd_loader_v4_get_state); if an error occurs, return `NULL`.
    - Check if the program account is writable; if not, log an error and set the error code to `FD_EXECUTOR_INSTR_ERR_INVALID_ARG`.
    - Verify that the authority has signed the instruction; if not, log an error and set the error code to `FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE`.
    - Check if the provided authority address matches the one in the program's state; if not, log an error and set the error code to `FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY`.
    - Check if the program's status is finalized; if so, log an error and set the error code to `FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE`.
    - If all checks pass, return the program's state.
- **Output**: A constant pointer to the program's state if all checks pass, or `NULL` if any check fails.
- **Functions called**:
    - [`fd_loader_v4_get_state`](#fd_loader_v4_get_state)
    - [`fd_loader_v4_status_is_finalized`](#fd_loader_v4_status_is_finalized)


---
### fd\_loader\_v4\_program\_instruction\_write<!-- {{#callable:fd_loader_v4_program_instruction_write}} -->
The `fd_loader_v4_program_instruction_write` function writes a specified byte sequence to a program account at a given offset, ensuring the program is in a retracted state and the write operation is within bounds.
- **Inputs**:
    - `instr_ctx`: A pointer to the execution instruction context (`fd_exec_instr_ctx_t`), which provides the context for the instruction execution.
    - `write`: A pointer to a `fd_loader_v4_program_instruction_write_t` structure containing the offset, byte sequence, and length of bytes to be written to the program account.
- **Control Flow**:
    - Initialize variables for error handling, offset, bytes, and bytes length from the `write` structure.
    - Attempt to borrow the program account from the instruction context using `FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK`.
    - Retrieve the authority address from the instruction context using `fd_exec_instr_ctx_get_key_of_account_at_index`.
    - Check the program account's validity and state using [`check_program_account`](#check_program_account), ensuring it is owned by the loader and writable, and the authority is correct.
    - Verify that the program is in a retracted state using [`fd_loader_v4_status_is_retracted`](#fd_loader_v4_status_is_retracted).
    - Calculate the destination offset by adding the given offset to a predefined data offset constant.
    - Retrieve mutable data and its length from the program account using `fd_borrowed_account_get_data_mut`.
    - Check if the write operation would exceed the data length, logging an error and returning an error code if so.
    - If the byte length is greater than zero, perform the memory copy operation to write the bytes to the program account at the calculated destination offset.
    - Return success if all operations complete without errors.
- **Output**: Returns an integer status code, where `FD_EXECUTOR_INSTR_SUCCESS` indicates success, and various error codes indicate specific failure conditions.
- **Functions called**:
    - [`check_program_account`](#check_program_account)
    - [`fd_loader_v4_status_is_retracted`](#fd_loader_v4_status_is_retracted)


---
### fd\_loader\_v4\_program\_instruction\_copy<!-- {{#callable:fd_loader_v4_program_instruction_copy}} -->
The `fd_loader_v4_program_instruction_copy` function copies a specified length of data from a source program account to a destination program account, ensuring the program is in a retracted state and the source is a valid program.
- **Inputs**:
    - `instr_ctx`: A pointer to the execution instruction context (`fd_exec_instr_ctx_t`), which provides the context for the instruction execution.
    - `copy`: A pointer to a `fd_loader_v4_program_instruction_copy_t` structure containing the offsets and length for the data copy operation.
- **Control Flow**:
    - Initialize local variables for error handling and offsets from the `copy` structure.
    - Borrow the program account from the instruction context and check for errors.
    - Retrieve the authority address from the instruction context and check for errors.
    - Borrow the source program account from the instruction context and check for errors.
    - Check the program account's state to ensure it is retracted, returning an error if not.
    - Determine the source offset based on the source program's owner type, adjusting for specific program types.
    - Verify that the source data length is sufficient for the copy operation, returning an error if not.
    - Retrieve mutable data from the program account and check for errors.
    - Adjust the destination offset and verify that the destination data length is sufficient for the copy operation, returning an error if not.
    - Perform the memory copy from the source to the destination using `fd_memcpy`.
- **Output**: Returns an integer status code, `FD_EXECUTOR_INSTR_SUCCESS` on success, or an error code if any checks or operations fail.
- **Functions called**:
    - [`check_program_account`](#check_program_account)
    - [`fd_loader_v4_status_is_retracted`](#fd_loader_v4_status_is_retracted)


---
### fd\_loader\_v4\_program\_instruction\_set\_program\_length<!-- {{#callable:fd_loader_v4_program_instruction_set_program_length}} -->
The function `fd_loader_v4_program_instruction_set_program_length` resizes a program account to a specified size, handling initialization, lamport adjustments, and account closure if necessary.
- **Inputs**:
    - `instr_ctx`: A pointer to the execution instruction context (`fd_exec_instr_ctx_t`), which contains information about the current instruction execution environment.
    - `set_program_length`: A pointer to a structure (`fd_loader_v4_program_instruction_set_program_length_t`) containing the new size for the program account.
- **Control Flow**:
    - Retrieve the program account from the instruction context and check for errors.
    - Get the authority address from the instruction context and check for errors.
    - Determine if the operation is an initialization based on the new size and current data length of the program account.
    - If initialization is required, verify the program account's ownership, writability, and authority signature.
    - If not initialization, check the program account's state and ensure it is retracted.
    - Read the rent sysvar to calculate the required lamports for the new program size.
    - Check if the program account has sufficient lamports; if not, log an error and return.
    - If the program has excess lamports, attempt to transfer them to a recipient account, checking for writability and errors.
    - Set the program account's data length to the new size, handling errors.
    - If initializing, set the program as executable, retrieve and modify its state, and set the authority address.
- **Output**: Returns an integer status code, `FD_EXECUTOR_INSTR_SUCCESS` on success or an error code on failure.
- **Functions called**:
    - [`check_program_account`](#check_program_account)
    - [`fd_loader_v4_status_is_retracted`](#fd_loader_v4_status_is_retracted)
    - [`fd_loader_v4_get_state_mut`](#fd_loader_v4_get_state_mut)


---
### fd\_loader\_v4\_program\_instruction\_deploy<!-- {{#callable:fd_loader_v4_program_instruction_deploy}} -->
The `fd_loader_v4_program_instruction_deploy` function deploys a program account by verifying its state, checking cooldown periods, and updating its status to deployed.
- **Inputs**:
    - `instr_ctx`: A pointer to the `fd_exec_instr_ctx_t` structure, which contains the execution context for the instruction, including transaction context and other relevant data.
- **Control Flow**:
    - The function begins by attempting to borrow the program account from the instruction context using `FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK`.
    - It retrieves the authority address of the account at index 1 using `fd_exec_instr_ctx_get_key_of_account_at_index` and checks for errors.
    - The function calls [`check_program_account`](#check_program_account) to validate the program account's state and authority, returning an error if validation fails.
    - It reads the current slot from the system clock using `fd_sysvar_clock_read` and checks for errors.
    - The function checks if the program has been deployed recently by comparing the current slot with the program's last deployment slot plus a cooldown period, returning an error if the cooldown is still in effect.
    - It verifies that the program is in a retracted state using [`fd_loader_v4_status_is_retracted`](#fd_loader_v4_status_is_retracted), returning an error if not.
    - The function checks if the program data length is sufficient and retrieves the program data, returning an error if the data is too small.
    - It calls [`fd_deploy_program`](fd_bpf_loader_program.c.driver.md#fd_deploy_program) to deploy the program, returning an error if deployment fails.
    - The function retrieves mutable data from the program account and updates the program's state to reflect the current slot and deployed status.
    - Finally, it returns `FD_EXECUTOR_INSTR_SUCCESS` to indicate successful deployment.
- **Output**: The function returns an integer status code, `FD_EXECUTOR_INSTR_SUCCESS` on success, or an error code if any step in the deployment process fails.
- **Functions called**:
    - [`check_program_account`](#check_program_account)
    - [`fd_loader_v4_status_is_retracted`](#fd_loader_v4_status_is_retracted)
    - [`fd_deploy_program`](fd_bpf_loader_program.c.driver.md#fd_deploy_program)
    - [`fd_loader_v4_get_state_mut`](#fd_loader_v4_get_state_mut)


---
### fd\_loader\_v4\_program\_instruction\_retract<!-- {{#callable:fd_loader_v4_program_instruction_retract}} -->
The `fd_loader_v4_program_instruction_retract` function retracts a deployed program, making it writable and uninvokable, by updating its status to 'retracted' if certain conditions are met.
- **Inputs**:
    - `instr_ctx`: A pointer to the execution instruction context (`fd_exec_instr_ctx_t`) which contains the necessary context for executing the instruction.
- **Control Flow**:
    - Initialize a variable `err` to store error codes.
    - Borrow the program account from the instruction context using `FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK`.
    - Retrieve the authority address from the instruction context at index 1 using `fd_exec_instr_ctx_get_key_of_account_at_index`.
    - Check the program account's state and authority using [`check_program_account`](#check_program_account).
    - Read the current slot from the system clock using `fd_sysvar_clock_read`.
    - Check if the program was deployed recently and if the cooldown period is still in effect using `fd_ulong_sat_add`.
    - Verify if the program is currently deployed using [`fd_loader_v4_status_is_deployed`](#fd_loader_v4_status_is_deployed).
    - Retrieve mutable data of the program account using `fd_borrowed_account_get_data_mut`.
    - Get a mutable reference to the program's state using [`fd_loader_v4_get_state_mut`](#fd_loader_v4_get_state_mut).
    - Update the program's status to `FD_LOADER_V4_STATUS_ENUM_RETRACTED`.
    - Return `FD_EXECUTOR_INSTR_SUCCESS` if all operations are successful.
- **Output**: Returns an integer status code, `FD_EXECUTOR_INSTR_SUCCESS` on success, or an error code if any operation fails.
- **Functions called**:
    - [`check_program_account`](#check_program_account)
    - [`fd_loader_v4_status_is_deployed`](#fd_loader_v4_status_is_deployed)
    - [`fd_loader_v4_get_state_mut`](#fd_loader_v4_get_state_mut)


---
### fd\_loader\_v4\_program\_instruction\_transfer\_authority<!-- {{#callable:fd_loader_v4_program_instruction_transfer_authority}} -->
The function `fd_loader_v4_program_instruction_transfer_authority` transfers the authority of a program account to a new authority.
- **Inputs**:
    - `instr_ctx`: A pointer to the execution instruction context (`fd_exec_instr_ctx_t`), which contains information about the current instruction execution environment.
- **Control Flow**:
    - Borrow the program account from the instruction context using `FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK`.
    - Retrieve the current authority's public key from the instruction context at index 1 using `fd_exec_instr_ctx_get_key_of_account_at_index`.
    - Retrieve the new authority's public key from the instruction context at index 2 using `fd_exec_instr_ctx_get_key_of_account_at_index`.
    - Check the program account's state and validate the current authority using [`check_program_account`](#check_program_account).
    - Ensure the new authority has signed the transaction by checking if it is a signer in the instruction context.
    - Compare the current authority address with the new authority address to ensure they are different.
    - If all checks pass, retrieve the mutable data of the program account and update the authority address to the new authority's address.
    - Return `FD_EXECUTOR_INSTR_SUCCESS` if the operation is successful.
- **Output**: The function returns an integer status code, `FD_EXECUTOR_INSTR_SUCCESS` on success, or an error code if any validation or operation fails.
- **Functions called**:
    - [`check_program_account`](#check_program_account)
    - [`fd_loader_v4_get_state_mut`](#fd_loader_v4_get_state_mut)


---
### fd\_loader\_v4\_program\_instruction\_finalize<!-- {{#callable:fd_loader_v4_program_instruction_finalize}} -->
The `fd_loader_v4_program_instruction_finalize` function finalizes a program account, making it immutable, by verifying its deployment status and authority, and updating its state to finalized.
- **Inputs**:
    - `instr_ctx`: A pointer to the execution instruction context (`fd_exec_instr_ctx_t`) which contains the necessary context for executing the instruction, including account information and transaction details.
- **Control Flow**:
    - Borrow the program account at index 0 and check for errors.
    - Retrieve the authority address from the account at index 1 and check for errors.
    - Validate the program account using [`check_program_account`](#check_program_account) and ensure it is deployed; return an error if not.
    - Drop the borrowed program account to release resources.
    - Borrow the next version account at index 2 and check for errors.
    - Verify that the next version account is owned by the loader and has the same authority as the current program; return errors if checks fail.
    - Ensure the next version is not already finalized; return an error if it is.
    - Retrieve the public key of the next version account.
    - Drop the borrowed next version account to release resources.
    - Re-borrow the program account at index 0 and check for errors.
    - Get mutable access to the program account's data and update its state to finalized with the next version's address.
    - Return success if all operations complete without errors.
- **Output**: Returns an integer status code, `FD_EXECUTOR_INSTR_SUCCESS` on success, or an error code if any validation or operation fails.
- **Functions called**:
    - [`check_program_account`](#check_program_account)
    - [`fd_loader_v4_status_is_deployed`](#fd_loader_v4_status_is_deployed)
    - [`fd_loader_v4_get_state`](#fd_loader_v4_get_state)
    - [`fd_loader_v4_status_is_finalized`](#fd_loader_v4_status_is_finalized)
    - [`fd_loader_v4_get_state_mut`](#fd_loader_v4_get_state_mut)


---
### fd\_loader\_v4\_program\_execute<!-- {{#callable:fd_loader_v4_program_execute}} -->
The `fd_loader_v4_program_execute` function executes a program instruction in the context of a transaction, handling various program operations based on the instruction type and program state.
- **Inputs**:
    - `instr_ctx`: A pointer to an `fd_exec_instr_ctx_t` structure, which contains the execution context for the instruction, including transaction context, instruction data, and other relevant information.
- **Control Flow**:
    - Check if the loader v4 feature is active for the current transaction slot; if not, return an unsupported program ID error.
    - Begin a stack frame for the transaction context's scratchpad memory.
    - Retrieve the last program key from the instruction context and check if it matches the loader v4 program ID.
    - If it matches, decode the instruction data and execute the corresponding operation based on the instruction's discriminant (e.g., write, copy, deploy, retract, etc.).
    - If the program ID does not match, attempt to borrow the last program account and check if the program is cached and valid for execution.
    - Perform additional checks to ensure the program is not retracted or has delayed visibility, logging errors and returning appropriate error codes if checks fail.
    - Drop the borrowed program account and execute the program using the BPF executor if all checks pass.
    - Return the result code from the executed operation.
- **Output**: The function returns an integer status code indicating the success or failure of the program execution, with specific error codes for unsupported program IDs, invalid instruction data, and other execution errors.
- **Functions called**:
    - [`fd_loader_v4_program_instruction_write`](#fd_loader_v4_program_instruction_write)
    - [`fd_loader_v4_program_instruction_copy`](#fd_loader_v4_program_instruction_copy)
    - [`fd_loader_v4_program_instruction_set_program_length`](#fd_loader_v4_program_instruction_set_program_length)
    - [`fd_loader_v4_program_instruction_deploy`](#fd_loader_v4_program_instruction_deploy)
    - [`fd_loader_v4_program_instruction_retract`](#fd_loader_v4_program_instruction_retract)
    - [`fd_loader_v4_program_instruction_transfer_authority`](#fd_loader_v4_program_instruction_transfer_authority)
    - [`fd_loader_v4_program_instruction_finalize`](#fd_loader_v4_program_instruction_finalize)
    - [`fd_bpf_load_cache_entry`](fd_bpf_program_util.c.driver.md#fd_bpf_load_cache_entry)
    - [`fd_loader_v4_get_state`](#fd_loader_v4_get_state)
    - [`fd_loader_v4_status_is_retracted`](#fd_loader_v4_status_is_retracted)
    - [`fd_bpf_execute`](fd_bpf_loader_program.c.driver.md#fd_bpf_execute)


