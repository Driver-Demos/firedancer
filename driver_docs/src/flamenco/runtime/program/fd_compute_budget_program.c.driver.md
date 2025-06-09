# Purpose
The provided C source code file is part of a larger system that manages compute budgets for executing programs, likely within a blockchain or distributed ledger environment. This file defines functions that handle the execution of compute budget instructions, which are used to manage and allocate computational resources for different types of programs, including built-in, migrating, and non-built-in programs. The code includes functions to determine the kind of program being executed, check if an instruction is related to compute budgets, and calculate default compute unit limits based on the type and number of instructions. It also includes logic to update execution contexts with new compute unit limits, heap sizes, and other parameters based on the instructions provided.

The file is structured to provide specific functionality related to compute budget management, with a focus on ensuring that programs adhere to predefined limits and constraints. It includes several static inline functions for efficient execution and a main function, [`fd_executor_compute_budget_program_execute_instructions`](#fd_executor_compute_budget_program_execute_instructions), which processes a series of instructions to update the execution context accordingly. The code references external components and libraries, such as `fd_runtime_err.h` and `fd_vm.h`, indicating that it is part of a modular system. The file does not define public APIs or external interfaces directly but rather implements internal logic for compute budget management, which is likely invoked by other parts of the system.
# Imports and Dependencies

---
- `fd_compute_budget_program.h`
- `../fd_runtime_err.h`
- `../fd_system_ids.h`
- `../fd_executor.h`
- `../context/fd_exec_instr_ctx.h`
- `../context/fd_exec_txn_ctx.h`
- `../context/fd_exec_slot_ctx.h`
- `../context/fd_exec_epoch_ctx.h`
- `../../vm/fd_vm.h`
- `fd_builtin_programs.h`


# Functions

---
### get\_program\_kind<!-- {{#callable:get_program_kind}} -->
The `get_program_kind` function determines the type of a program based on its migration status and whether it is a built-in program.
- **Inputs**:
    - `ctx`: A pointer to a `fd_exec_txn_ctx_t` structure containing transaction context, including account keys.
    - `instr`: A pointer to a `fd_txn_instr_t` structure representing a transaction instruction, which includes the program ID.
- **Control Flow**:
    - Retrieve the program's public key from the transaction context using the program ID from the instruction.
    - Check if the program is a non-migrating built-in program using [`fd_is_non_migrating_builtin_program`](fd_builtin_programs.c.driver.md#fd_is_non_migrating_builtin_program); if true, return `FD_PROGRAM_KIND_BUILTIN`.
    - Determine if the program is a migrating built-in program using [`fd_is_migrating_builtin_program`](fd_builtin_programs.c.driver.md#fd_is_migrating_builtin_program), which also sets the `migrated_yet` flag.
    - If the program is migrating but not yet migrated, return `FD_PROGRAM_KIND_BUILTIN`.
    - If the program is migrating and has been migrated, return `FD_PROGRAM_KIND_MIGRATING_BUILTIN`.
    - If none of the above conditions are met, return `FD_PROGRAM_KIND_NOT_BUILTIN`.
- **Output**: The function returns an `uchar` indicating the program kind: `FD_PROGRAM_KIND_BUILTIN`, `FD_PROGRAM_KIND_MIGRATING_BUILTIN`, or `FD_PROGRAM_KIND_NOT_BUILTIN`.
- **Functions called**:
    - [`fd_is_non_migrating_builtin_program`](fd_builtin_programs.c.driver.md#fd_is_non_migrating_builtin_program)
    - [`fd_is_migrating_builtin_program`](fd_builtin_programs.c.driver.md#fd_is_migrating_builtin_program)


---
### is\_compute\_budget\_instruction<!-- {{#callable:is_compute_budget_instruction}} -->
The function `is_compute_budget_instruction` checks if a given transaction instruction is associated with the Solana compute budget program.
- **Inputs**:
    - `ctx`: A pointer to a `fd_exec_txn_ctx_t` structure containing the transaction context, including account keys.
    - `instr`: A pointer to a `fd_txn_instr_t` structure representing the transaction instruction to be checked.
- **Control Flow**:
    - Retrieve the array of account keys from the transaction context `ctx`.
    - Determine the program public key by accessing the account key at the index specified by `instr->program_id`.
    - Compare the program public key with the known Solana compute budget program ID using `memcmp`.
    - Return the result of the comparison, which is 0 if the keys match, indicating the instruction is a compute budget instruction.
- **Output**: The function returns an integer, which is 0 if the instruction is a compute budget instruction (i.e., the program public key matches the Solana compute budget program ID), and non-zero otherwise.


---
### calculate\_default\_compute\_unit\_limit<!-- {{#callable:calculate_default_compute_unit_limit}} -->
The function `calculate_default_compute_unit_limit` computes the default compute unit limit based on the number of different types of instructions and a feature flag in the execution context.
- **Inputs**:
    - `ctx`: A pointer to a constant `fd_exec_txn_ctx_t` structure representing the transaction execution context, which includes information about the current slot and active features.
    - `num_builtin_instrs`: An unsigned long integer representing the number of builtin instructions in the transaction.
    - `num_non_builtin_instrs`: An unsigned long integer representing the number of non-builtin instructions in the transaction.
    - `num_non_compute_budget_instrs`: An unsigned long integer representing the number of instructions that are not part of the compute budget.
- **Control Flow**:
    - Check if the feature `reserve_minimal_cus_for_builtin_instructions` is active using `FD_FEATURE_ACTIVE` macro with the context's slot and features.
    - If the feature is active, calculate the compute unit limit by adding the product of `num_builtin_instrs` and `MAX_BUILTIN_ALLOCATION_COMPUTE_UNIT_LIMIT` to the product of `num_non_builtin_instrs` and `DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT`, using saturated arithmetic functions `fd_ulong_sat_add` and `fd_ulong_sat_mul`.
    - If the feature is not active, calculate the compute unit limit by multiplying `num_non_compute_budget_instrs` with `DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT` using the saturated multiplication function `fd_ulong_sat_mul`.
- **Output**: The function returns an unsigned long integer representing the calculated default compute unit limit based on the provided instruction counts and the active feature flag.


---
### sanitize\_requested\_heap\_size<!-- {{#callable:sanitize_requested_heap_size}} -->
The `sanitize_requested_heap_size` function checks if a given heap size in bytes is within defined limits and aligned to a specific granularity.
- **Inputs**:
    - `bytes`: An unsigned long integer representing the requested heap size in bytes.
- **Control Flow**:
    - The function checks if the input `bytes` is greater than `FD_MAX_HEAP_FRAME_BYTES`, less than `FD_MIN_HEAP_FRAME_BYTES`, or not a multiple of `FD_HEAP_FRAME_BYTES_GRANULARITY`.
    - It returns the negation of the logical OR of these conditions, effectively returning 1 if the size is valid and 0 if it is not.
- **Output**: An integer value, 1 if the requested heap size is valid, and 0 if it is invalid.


---
### fd\_executor\_compute\_budget\_program\_execute\_instructions<!-- {{#callable:fd_executor_compute_budget_program_execute_instructions}} -->
The function `fd_executor_compute_budget_program_execute_instructions` processes and executes compute budget instructions within a transaction context, updating various execution parameters based on the instructions provided.
- **Inputs**:
    - `ctx`: A pointer to the transaction execution context (`fd_exec_txn_ctx_t`), which contains information about the transaction and its execution environment.
    - `txn_raw`: A pointer to the raw transaction data (`fd_rawtxn_b_t`), which includes the serialized instructions to be executed.
- **Control Flow**:
    - Initialize flags and variables to track updates to compute units, heap size, and account data size limits.
    - Iterate over each instruction in the transaction context's descriptor.
    - For each instruction, determine if it is a compute budget instruction; if not, increment the non-compute budget instruction counter and continue.
    - If SIMD-170 feature is active, classify instructions as built-in or non-built-in and update respective counters.
    - Deserialize compute budget instructions and handle errors in deserialization.
    - Switch on the instruction type to update the corresponding execution parameters (heap size, compute unit limit, compute unit price, or loaded accounts data size limit).
    - Check for duplicate instructions and return an error if found.
    - After processing all instructions, update the transaction context with the new execution parameters, applying any necessary sanitization and limits.
    - Return success if all instructions are processed without errors.
- **Output**: Returns an integer status code indicating success (`FD_RUNTIME_EXECUTE_SUCCESS`) or an error code if an invalid or duplicate instruction is encountered.
- **Functions called**:
    - [`get_program_kind`](#get_program_kind)
    - [`is_compute_budget_instruction`](#is_compute_budget_instruction)
    - [`sanitize_requested_heap_size`](#sanitize_requested_heap_size)
    - [`calculate_default_compute_unit_limit`](#calculate_default_compute_unit_limit)


---
### fd\_compute\_budget\_program\_execute<!-- {{#callable:fd_compute_budget_program_execute}} -->
The `fd_compute_budget_program_execute` function updates the compute units in the execution context and returns a success status.
- **Inputs**:
    - `ctx`: A pointer to an `fd_exec_instr_ctx_t` structure, which represents the execution instruction context.
- **Control Flow**:
    - The function calls `FD_EXEC_CU_UPDATE` macro with `ctx` and `DEFAULT_COMPUTE_UNITS` to update the compute units in the context.
    - The function returns `FD_EXECUTOR_INSTR_SUCCESS` to indicate successful execution.
- **Output**: The function returns an integer value `FD_EXECUTOR_INSTR_SUCCESS`, indicating successful execution.


