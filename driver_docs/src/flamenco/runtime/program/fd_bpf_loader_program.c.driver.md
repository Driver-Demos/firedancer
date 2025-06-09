# Purpose
This C source file is part of a larger system that deals with the deployment, execution, and management of BPF (Berkeley Packet Filter) programs, specifically within the context of the Solana blockchain. The file provides a comprehensive set of functions to handle various operations related to BPF programs, such as deploying new programs, upgrading existing ones, setting authorities, and executing instructions. It includes error handling mechanisms to translate program errors into instruction errors, ensuring robust execution and management of BPF programs.

The file imports several headers and libraries that provide utilities for handling public keys, base58 encoding, system variables, and virtual machine operations. It defines functions for managing the lifecycle of BPF programs, including reading and writing program states, calculating heap costs, and executing BPF instructions. The code is structured to handle different types of instructions and program states, with specific functions dedicated to processing loader upgradeable instructions and executing BPF programs. Additionally, the file includes public APIs for directly invoking loader deployment functions, making it a critical component for managing BPF programs within the Solana ecosystem.
# Imports and Dependencies

---
- `fd_bpf_loader_program.h`
- `../fd_pubkey_utils.h`
- `../../../ballet/base58/fd_base58.h`
- `../../../ballet/sbpf/fd_sbpf_loader.h`
- `../sysvar/fd_sysvar_clock.h`
- `../sysvar/fd_sysvar_rent.h`
- `../../vm/syscall/fd_vm_syscall.h`
- `../../vm/fd_vm.h`
- `../fd_executor.h`
- `fd_bpf_loader_serialization.h`
- `fd_native_cpi.h`
- `stdlib.h`


# Global Variables

---
### trace\_buf
- **Type**: `char*`
- **Description**: `trace_buf` is a static global pointer to a character array, which is intended to be used as a buffer for tracing or logging purposes. It is allocated a memory size of 256 kilobytes during the program's initialization phase.
- **Use**: `trace_buf` is used to store trace or log data, with its memory being allocated at program startup and freed upon program termination.


# Functions

---
### make\_buf<!-- {{#callable:make_buf}} -->
The `make_buf` function allocates a buffer of 256 kilobytes and assigns it to the global pointer `trace_buf` during the program's initialization phase.
- **Inputs**: None
- **Control Flow**:
    - The function is marked with the `constructor` attribute, ensuring it is executed before `main()` when the program starts.
    - It calls `malloc` to allocate 256 kilobytes of memory.
    - The allocated memory is cast to a `char*` and assigned to the global variable `trace_buf`.
- **Output**: The function does not return any value; it modifies the global variable `trace_buf`.


---
### free\_buf<!-- {{#callable:free_buf}} -->
The `free_buf` function is a static destructor function that frees the memory allocated to the `trace_buf` pointer.
- **Inputs**: None
- **Control Flow**:
    - The function is marked with the `destructor` attribute, indicating it will be called automatically when the program exits or the shared library is unloaded.
    - It calls the `free` function to deallocate the memory pointed to by `trace_buf`.
- **Output**: The function does not return any value.


---
### program\_error\_to\_instr\_error<!-- {{#callable:program_error_to_instr_error}} -->
The function `program_error_to_instr_error` maps a program error code to an instruction error code, optionally setting a custom error code if applicable.
- **Inputs**:
    - `err`: An unsigned long integer representing the program error code to be converted.
    - `custom_err`: A pointer to an unsigned integer where a custom error code may be stored if applicable.
- **Control Flow**:
    - The function uses a switch statement to match the input error code `err` against predefined error cases.
    - For each case, it returns a corresponding instruction error code, and in some cases, it sets the `custom_err` to a specific value.
    - If the error code does not match any predefined cases, it checks if the error code is a custom error by shifting it right by `BUILTIN_BIT_SHIFT` and comparing it to zero.
    - If it is a custom error, it sets `custom_err` to the error code and returns `FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR`.
    - If none of the conditions are met, it returns `FD_EXECUTOR_INSTR_ERR_INVALID_ERR`.
- **Output**: The function returns an integer representing the mapped instruction error code.


---
### read\_bpf\_upgradeable\_loader\_state\_for\_program<!-- {{#callable:read_bpf_upgradeable_loader_state_for_program}} -->
The function `read_bpf_upgradeable_loader_state_for_program` retrieves and decodes the BPF upgradeable loader state for a specified program from a transaction context.
- **Inputs**:
    - `txn_ctx`: A pointer to the transaction context (`fd_exec_txn_ctx_t`) which contains information about the transaction and its accounts.
    - `program_id`: An unsigned short representing the index of the program within the transaction context's accounts.
    - `opt_err`: A pointer to an integer where any error code will be stored if an error occurs during the function execution.
- **Control Flow**:
    - Initialize a pointer `rec` to `NULL` to hold the account record.
    - Call `fd_exec_txn_ctx_get_account_at_index` to retrieve the account at the specified `program_id` index and check if it exists.
    - If an error occurs during account retrieval, set `*opt_err` to the error code and return `NULL`.
    - Decode the BPF upgradeable loader state using `fd_bincode_decode_spad` with the account's data and length.
    - If an error occurs during decoding, set `*opt_err` to `FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA` and return `NULL`.
    - Return the decoded BPF upgradeable loader state.
- **Output**: A pointer to `fd_bpf_upgradeable_loader_state_t`, representing the decoded BPF upgradeable loader state, or `NULL` if an error occurs.


---
### calculate\_heap\_cost<!-- {{#callable:calculate_heap_cost}} -->
The `calculate_heap_cost` function computes the cost of a heap based on its size and a given cost per unit, while handling potential errors.
- **Inputs**:
    - `heap_size`: The initial size of the heap in unsigned long format.
    - `heap_cost`: The cost per unit size of the heap in unsigned long format.
    - `err`: A pointer to an integer where error codes can be stored if an error occurs.
- **Control Flow**:
    - The function defines two constants, `KIBIBYTE_MUL_PAGES` and `KIBIBYTE_MUL_PAGES_SUB_1`, for internal calculations.
    - It adds `KIBIBYTE_MUL_PAGES_SUB_1` to `heap_size` using a saturated addition function `fd_ulong_sat_add`.
    - If the resulting `heap_size` is zero, it sets the error code to `FD_EXECUTOR_INSTR_ERR_GENERIC_ERR` and returns zero.
    - Otherwise, it calculates the final heap cost by dividing the adjusted `heap_size` by `KIBIBYTE_MUL_PAGES`, subtracting one, and then multiplying by `heap_cost` using saturated arithmetic functions.
    - The function returns the calculated heap cost.
- **Output**: The function returns the calculated heap cost as an unsigned long integer, or zero if an error occurs.


---
### fd\_deploy\_program<!-- {{#callable:fd_deploy_program}} -->
The `fd_deploy_program` function deploys a BPF program by setting up the necessary environment, loading, validating, and initializing the program in a virtual machine context.
- **Inputs**:
    - `instr_ctx`: A pointer to the instruction context (`fd_exec_instr_ctx_t`) which contains transaction context and other execution-related data.
    - `programdata`: A pointer to the program data (`uchar const *`) which contains the BPF program to be deployed.
    - `programdata_size`: The size of the program data (`ulong`) indicating the length of the BPF program.
    - `spad`: A pointer to the scratchpad (`fd_spad_t`) used for memory allocations during the deployment process.
- **Control Flow**:
    - Initialize deployment mode and check for direct mapping feature activation.
    - Allocate memory for syscalls and register them; return an error if allocation fails.
    - Peek into the ELF information of the program data to verify and load it; return an error if verification fails.
    - Allocate memory for the read-only data segment and the program buffer; return an error if allocation fails.
    - Create a new program instance and load the program data into it; return an error if loading fails.
    - Initialize a virtual machine (`fd_vm_t`) with the program and its context; return an error if initialization fails.
    - Validate the program within the virtual machine; return an error if validation fails.
    - Return success if all steps complete without errors.
- **Output**: Returns an integer status code indicating success (`FD_EXECUTOR_INSTR_SUCCESS`) or a specific error code if any step fails.
- **Functions called**:
    - [`fd_bpf_get_sbpf_versions`](fd_bpf_program_util.c.driver.md#fd_bpf_get_sbpf_versions)


---
### write\_program\_data<!-- {{#callable:write_program_data}} -->
The `write_program_data` function writes a specified number of bytes to a program's data at a given offset, ensuring that the write does not exceed the data's bounds.
- **Inputs**:
    - `instr_ctx`: A pointer to the instruction execution context (`fd_exec_instr_ctx_t`), which contains information about the current execution environment.
    - `instr_acc_idx`: An unsigned short integer representing the index of the instruction account within the context.
    - `program_data_offset`: An unsigned long integer specifying the offset within the program data where the bytes should be written.
    - `bytes`: A pointer to an array of unsigned characters (`uchar`) that contains the data to be written.
    - `bytes_len`: An unsigned long integer indicating the length of the data in bytes to be written.
- **Control Flow**:
    - Initialize a variable `err` to store error codes.
    - Attempt to borrow the instruction account using `FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK` and store it in `program`.
    - Retrieve mutable data and its length from the borrowed account using `fd_borrowed_account_get_data_mut`.
    - Check if the sum of `program_data_offset` and `bytes_len` exceeds the data length of the program; if so, log an error and return `FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL`.
    - Check if `program_data_offset` is greater than the data length; if so, return `FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL`.
    - If `bytes_len` is non-zero, copy the data from `bytes` to the program data at the specified offset using `fd_memcpy`.
    - Return `FD_EXECUTOR_INSTR_SUCCESS` to indicate successful execution.
- **Output**: Returns an integer status code, where `FD_EXECUTOR_INSTR_SUCCESS` indicates success, and other values indicate specific errors, such as data overflow or invalid offsets.


---
### fd\_bpf\_loader\_program\_get\_state<!-- {{#callable:fd_bpf_loader_program_get_state}} -->
The function `fd_bpf_loader_program_get_state` retrieves the state of a BPF loader program from a given account and shared program address data (spad), handling errors if the state retrieval fails.
- **Inputs**:
    - `acct`: A pointer to a `fd_txn_account_t` structure representing the account from which the BPF loader program state is to be retrieved.
    - `spad`: A pointer to a `fd_spad_t` structure used for shared program address data, which assists in decoding the program state.
    - `err`: A pointer to an integer where any error code encountered during the state retrieval process will be stored.
- **Control Flow**:
    - The function calls `fd_bincode_decode_spad` to decode the BPF loader program state from the account data using the provided spad and account data retrieval functions.
    - If an error occurs during decoding (indicated by a non-zero value in `*err`), the function sets `*err` to `FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA` and returns `NULL`.
    - If no error occurs, the function returns the decoded BPF loader program state.
- **Output**: A pointer to `fd_bpf_upgradeable_loader_state_t` representing the decoded state of the BPF loader program, or `NULL` if an error occurs.


---
### fd\_bpf\_loader\_v3\_program\_set\_state<!-- {{#callable:fd_bpf_loader_v3_program_set_state}} -->
The function `fd_bpf_loader_v3_program_set_state` sets the state of a BPF program in a borrowed account to a specified state.
- **Inputs**:
    - `borrowed_acct`: A pointer to a `fd_borrowed_account_t` structure representing the account whose state is to be set.
    - `state`: A pointer to a `fd_bpf_upgradeable_loader_state_t` structure representing the new state to be set for the program.
- **Control Flow**:
    - Calculate the size of the new state using `fd_bpf_upgradeable_loader_state_size` function.
    - Initialize pointers `data` and `dlen` to hold the mutable data and its length from the borrowed account.
    - Attempt to retrieve mutable data from the borrowed account using `fd_borrowed_account_get_data_mut`. If this fails, return the error code.
    - Check if the size of the new state exceeds the available data length in the account. If so, return `FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL`.
    - Initialize a `fd_bincode_encode_ctx_t` structure to encode the new state into the account's data.
    - Encode the new state into the account's data using `fd_bpf_upgradeable_loader_state_encode`. If encoding fails, return `FD_EXECUTOR_INSTR_ERR_GENERIC_ERR`.
    - Return `FD_BINCODE_SUCCESS` to indicate successful state setting.
- **Output**: The function returns an integer status code, `FD_BINCODE_SUCCESS` on success, or an error code if an error occurs during execution.


---
### common\_close\_account<!-- {{#callable:common_close_account}} -->
The `common_close_account` function closes a specified account by transferring its lamports to a recipient account and setting its state to uninitialized.
- **Inputs**:
    - `authority_address`: A pointer to the public key of the authority that is allowed to close the account.
    - `instr_ctx`: A pointer to the instruction context, which contains information about the current execution context.
    - `state`: A pointer to the state of the BPF upgradeable loader, which will be updated to reflect the account's new state.
- **Control Flow**:
    - Check if the `authority_address` is NULL and return an error if it is.
    - Retrieve the public key of the account at index 2 and check for errors.
    - Compare the `authority_address` with the retrieved account key and return an error if they do not match.
    - Verify that the account at index 2 is a signer and return an error if it is not.
    - Borrow the account to be closed and the recipient account using the instruction context.
    - Transfer the lamports from the account to be closed to the recipient account and check for errors.
    - Set the lamports of the account to be closed to zero and check for errors.
    - Set the state of the account to be closed to uninitialized and check for errors.
    - Return success if all operations are completed without errors.
- **Output**: The function returns an integer status code indicating success or the type of error encountered during execution.
- **Functions called**:
    - [`fd_bpf_loader_v3_program_set_state`](#fd_bpf_loader_v3_program_set_state)


---
### fd\_bpf\_execute<!-- {{#callable:fd_bpf_execute}} -->
The `fd_bpf_execute` function executes a BPF program within a virtual machine context, handling input serialization, VM initialization, execution, and error handling.
- **Inputs**:
    - `instr_ctx`: A pointer to the instruction context (`fd_exec_instr_ctx_t`) which contains transaction context and other execution-related data.
    - `prog`: A pointer to the validated BPF program (`fd_sbpf_validated_program_t`) to be executed.
    - `is_deprecated`: A flag (`uchar`) indicating whether the program is deprecated.
- **Control Flow**:
    - Initialize error code and create a new syscall context for the VM.
    - Register the syscall slot with the VM using the transaction context.
    - Serialize input parameters for the BPF program execution, checking for errors and null input.
    - Initialize SHA256 and VM contexts, joining them to their respective new instances.
    - Set up the VM with the provided program and context parameters, checking for initialization errors.
    - Calculate heap cost and adjust compute units, returning an error if the cost exceeds available units.
    - Execute the BPF program within the VM, updating the compute meter with remaining compute units.
    - If tracing is enabled, attempt to print the trace and log any errors encountered.
    - Log the consumed compute units and return data if available.
    - Handle execution errors, including specific cases for syscall errors and access violations, returning appropriate error codes.
    - Deserialize input parameters post-execution, returning any errors encountered.
    - Return success if execution completes without errors.
- **Output**: Returns an integer status code indicating success (`FD_EXECUTOR_INSTR_SUCCESS`) or a specific error code if execution fails.
- **Functions called**:
    - [`fd_bpf_loader_input_serialize_parameters`](fd_bpf_loader_serialization.c.driver.md#fd_bpf_loader_input_serialize_parameters)
    - [`calculate_heap_cost`](#calculate_heap_cost)
    - [`program_error_to_instr_error`](#program_error_to_instr_error)
    - [`fd_bpf_loader_input_deserialize_parameters`](fd_bpf_loader_serialization.c.driver.md#fd_bpf_loader_input_deserialize_parameters)


---
### process\_loader\_upgradeable\_instruction<!-- {{#callable:process_loader_upgradeable_instruction}} -->
The `process_loader_upgradeable_instruction` function processes various instructions related to upgradeable BPF loader programs, handling tasks such as initialization, writing, deployment, upgrading, setting authority, closing, extending, and migrating programs.
- **Inputs**:
    - `instr_ctx`: A pointer to the `fd_exec_instr_ctx_t` structure, which contains the context for the execution of the instruction, including transaction context and instruction data.
- **Control Flow**:
    - Decode the instruction data from the transaction context using `fd_bincode_decode_spad` and check for errors.
    - Retrieve the last program key using `fd_exec_instr_ctx_get_last_program_key` and handle any errors.
    - Use a switch statement to handle different instruction types based on the `discriminant` field of the decoded instruction.
    - For each case in the switch statement, perform specific operations such as checking account numbers, borrowing accounts, verifying states, setting states, and handling errors appropriately.
    - Return specific error codes or success based on the outcome of each operation.
- **Output**: The function returns an integer status code indicating success (`FD_EXECUTOR_INSTR_SUCCESS`) or a specific error code if an error occurs during processing.
- **Functions called**:
    - [`fd_bpf_loader_program_get_state`](#fd_bpf_loader_program_get_state)
    - [`fd_bpf_loader_v3_program_set_state`](#fd_bpf_loader_v3_program_set_state)
    - [`write_program_data`](#write_program_data)
    - [`fd_native_cpi_create_account_meta`](fd_native_cpi.c.driver.md#fd_native_cpi_create_account_meta)
    - [`fd_native_cpi_native_invoke`](fd_native_cpi.c.driver.md#fd_native_cpi_native_invoke)
    - [`fd_deploy_program`](#fd_deploy_program)
    - [`common_close_account`](#common_close_account)


---
### fd\_bpf\_loader\_program\_execute<!-- {{#callable:fd_bpf_loader_program_execute}} -->
The `fd_bpf_loader_program_execute` function manages and executes BPF programs by validating program accounts, checking program states, and executing the program if valid.
- **Inputs**:
    - `ctx`: A pointer to an `fd_exec_instr_ctx_t` structure, which contains the execution context for the instruction, including transaction context and other necessary data for program execution.
- **Control Flow**:
    - Begin a scoped frame using `FD_SPAD_FRAME_BEGIN` with the shared program address data (spad) from the transaction context.
    - Attempt to borrow the last program account using `fd_exec_instr_ctx_try_borrow_last_program_account`. If unsuccessful, return the error code.
    - Retrieve the last program key using `fd_exec_instr_ctx_get_last_program_key`. If unsuccessful, return the error code.
    - Check if the program is a management instruction by comparing the program account owner with `fd_solana_native_loader_id`. If it matches, drop the program account and handle specific program IDs for upgradeable, deprecated, or unsupported loaders, returning appropriate error codes or processing instructions.
    - If the program is not a management instruction, check if the program account is executable. If not, log an error and return `FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID`.
    - Retrieve the program account metadata and check if the program is deprecated by comparing the owner with `fd_solana_bpf_loader_deprecated_program_id`.
    - If the program is upgradeable, retrieve its state and validate it. If the state is invalid or the program is not deployed, log an error and return `FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA`.
    - Check if the program is cached using [`fd_bpf_load_cache_entry`](fd_bpf_program_util.c.driver.md#fd_bpf_load_cache_entry). If not cached, log an error and return `FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA`.
    - Drop the program account and execute the program using [`fd_bpf_execute`](#fd_bpf_execute), passing the execution context, validated program, and deprecation status.
    - End the scoped frame using `FD_SPAD_FRAME_END`.
- **Output**: Returns an integer status code indicating success or specific error conditions encountered during the execution process.
- **Functions called**:
    - [`process_loader_upgradeable_instruction`](#process_loader_upgradeable_instruction)
    - [`fd_bpf_loader_program_get_state`](#fd_bpf_loader_program_get_state)
    - [`fd_bpf_load_cache_entry`](fd_bpf_program_util.c.driver.md#fd_bpf_load_cache_entry)
    - [`fd_bpf_execute`](#fd_bpf_execute)


---
### fd\_directly\_invoke\_loader\_v3\_deploy<!-- {{#callable:fd_directly_invoke_loader_v3_deploy}} -->
The function `fd_directly_invoke_loader_v3_deploy` sets up a transaction context and instruction context to deploy a BPF program using the provided ELF data.
- **Inputs**:
    - `slot_ctx`: A pointer to an `fd_exec_slot_ctx_t` structure representing the execution slot context.
    - `elf`: A constant pointer to an array of unsigned characters representing the ELF data of the program to be deployed.
    - `elf_sz`: An unsigned long integer representing the size of the ELF data.
    - `runtime_spad`: A pointer to an `fd_spad_t` structure used for runtime scratchpad memory allocations.
- **Control Flow**:
    - Allocate and join a new transaction context using the provided runtime scratchpad memory.
    - Retrieve the workspace and transaction global addresses from the slot context and funk structure.
    - Initialize the transaction context with the execution slot context and set up basic transaction context settings.
    - Create an instruction context on the transaction context's instruction stack.
    - Call [`fd_deploy_program`](#fd_deploy_program) with the instruction context, ELF data, ELF size, and runtime scratchpad memory.
- **Output**: Returns an integer status code from the [`fd_deploy_program`](#fd_deploy_program) function, indicating success or failure of the program deployment.
- **Functions called**:
    - [`fd_deploy_program`](#fd_deploy_program)


