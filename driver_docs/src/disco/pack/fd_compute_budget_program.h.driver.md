# Purpose
This C header file provides utility functions for parsing and managing compute budget program instructions within a transaction. It is designed to handle the compute budget limits and associated fees for transactions, which are critical for ensuring that transactions adhere to specified resource constraints. The file defines a set of constants and flags that are used to track the state of compute budget instructions within a transaction, such as setting compute unit limits, heap sizes, and prioritization fees. The header is intended for high-performance use, focusing on parsing and processing transaction data efficiently while performing minimal error checking.

The file includes a structure, `fd_compute_budget_program_state_t`, which maintains the state of compute budget instructions parsed from a transaction. It provides functions to initialize this state, parse individual instructions, and finalize the state to compute the total priority rewards and maximum compute units for a transaction. The header defines several consensus-critical constants that cannot be changed without coordination, ensuring compatibility with the broader system. This file is a specialized component of a larger system, likely part of a blockchain or distributed ledger technology, where managing compute resources and transaction fees is essential for maintaining network performance and fairness.
# Imports and Dependencies

---
- `../../ballet/fd_ballet_base.h`
- `../../ballet/txn/fd_txn.h`


# Global Variables

---
### FD\_COMPUTE\_BUDGET\_PROGRAM\_ID
- **Type**: ``uchar[FD_TXN_ACCT_ADDR_SZ]``
- **Description**: `FD_COMPUTE_BUDGET_PROGRAM_ID` is a static constant array of unsigned characters representing a unique identifier for the compute budget program. It is derived from the base58 decoding of the string 'ComputeBudget111111111111111111111111111111'. This identifier is used to recognize and validate compute budget program instructions within a transaction.
- **Use**: This variable is used to identify and validate compute budget program instructions in transactions.


# Data Structures

---
### fd\_compute\_budget\_program\_private\_state
- **Type**: `struct`
- **Members**:
    - `flags`: Indicates which instructions have been parsed so far in the transaction.
    - `compute_budget_instr_cnt`: Counts the number of compute budget instructions parsed so far, ranging from 0 to 4.
    - `compute_units`: Stores the total requested compute units for the transaction if SET_CU is in flags, otherwise 0.
    - `loaded_acct_data_sz`: Stores the maximum total data in bytes that the transaction will load from referenced accounts if SET_LOADED_DATA_SZ is in flags, otherwise 0.
    - `heap_size`: Stores the size in bytes of the BPF heap used for executing the transaction if SET_HEAP is in flags, otherwise 0.
    - `micro_lamports_per_cu`: Stores the requested prioritization fee in micro-lamports per compute unit if SET_FEE is in flags, otherwise 0.
- **Description**: The `fd_compute_budget_program_private_state` structure is used to maintain the state of a transaction's compute budget program, tracking various parameters such as the number of instructions parsed, compute units requested, data size loaded from accounts, heap size, and prioritization fee. It uses flags to determine which parameters have been set, allowing for efficient parsing and processing of compute budget instructions within a transaction. This structure is crucial for managing the compute resources and fees associated with executing transactions in a high-performance environment.


---
### fd\_compute\_budget\_program\_state\_t
- **Type**: `struct`
- **Members**:
    - `flags`: Tracks which compute budget instructions have been parsed in the transaction.
    - `compute_budget_instr_cnt`: Counts the number of compute budget instructions parsed so far, ranging from 0 to 4.
    - `compute_units`: Stores the total requested compute units for the transaction if the SET_CU flag is set, otherwise 0.
    - `loaded_acct_data_sz`: Stores the maximum total data in bytes that the transaction will load from referenced accounts if the SET_LOADED_DATA_SZ flag is set, otherwise 0.
    - `heap_size`: Stores the size in bytes of the BPF heap used for executing the transaction if the SET_HEAP flag is set, otherwise 0.
    - `micro_lamports_per_cu`: Stores the requested prioritization fee in micro-lamports per compute unit if the SET_FEE flag is set, otherwise 0.
- **Description**: The `fd_compute_budget_program_state_t` is a structure used to maintain the state of compute budget program instructions within a transaction. It tracks which instructions have been parsed, the number of instructions, and various parameters such as compute units, loaded account data size, heap size, and prioritization fee. This state is crucial for determining the compute budget limits and rewards associated with a transaction, ensuring that the transaction adheres to the specified compute budget constraints.


# Functions

---
### fd\_compute\_budget\_program\_init<!-- {{#callable:fd_compute_budget_program_init}} -->
The `fd_compute_budget_program_init` function initializes a `fd_compute_budget_program_state_t` structure to zero, preparing it for parsing a transaction.
- **Inputs**:
    - `state`: A pointer to a `fd_compute_budget_program_state_t` structure that will be initialized to zero.
- **Control Flow**:
    - The function takes a pointer to a `fd_compute_budget_program_state_t` structure as input.
    - It sets all fields of the structure to zero by assigning it a zero-initialized instance of `fd_compute_budget_program_state_t`.
- **Output**: The function does not return any value; it modifies the state structure in place.


---
### fd\_compute\_budget\_program\_parse<!-- {{#callable:fd_compute_budget_program_parse}} -->
The `fd_compute_budget_program_parse` function parses a single compute budget program instruction from transaction data and updates the state accordingly, returning 0 if the instruction is invalid.
- **Inputs**:
    - `instr_data`: A pointer to the instruction data from the transaction, which is an array of unsigned characters.
    - `data_sz`: The size of the instruction data, indicating the number of bytes available in `instr_data`.
    - `state`: A pointer to a `fd_compute_budget_program_state_t` structure that holds the current state of the compute budget program parsing process.
- **Control Flow**:
    - Check if `data_sz` is less than 5; if so, return 0 indicating an invalid instruction.
    - Use a switch statement on the first byte of `instr_data` to determine the type of instruction.
    - For case 0, return 0 as the instruction is deprecated and invalid.
    - For case 1, parse a RequestHeapFrame instruction, checking for size constraints and flag conditions, and update the state accordingly.
    - For case 2, parse a SetComputeUnitLimit instruction, checking for size constraints and flag conditions, and update the state accordingly.
    - For case 3, parse a SetComputeUnitPrice instruction, checking for size constraints and flag conditions, and update the state accordingly.
    - For case 4, parse a SetLoadedAccountsDataSizeLimit instruction, checking for size constraints and flag conditions, and update the state accordingly.
    - Return 1 if the instruction is valid and successfully parsed, otherwise return 0.
- **Output**: Returns an integer, 1 if the instruction is valid and successfully parsed, or 0 if the instruction is invalid.


---
### fd\_compute\_budget\_program\_finalize<!-- {{#callable:fd_compute_budget_program_finalize}} -->
The `fd_compute_budget_program_finalize` function calculates the total priority rewards and compute unit limits for a transaction based on its compute budget program state and instruction count.
- **Inputs**:
    - `state`: A pointer to a `fd_compute_budget_program_state_t` structure containing the state of the compute budget program for the transaction.
    - `instr_cnt`: The total number of instructions in the transaction, including compute budget program instructions.
    - `out_rewards`: A pointer to a `ulong` where the function will store the calculated total priority rewards for the transaction.
    - `out_compute`: A pointer to a `uint` where the function will store the maximum number of compute units the transaction can consume.
    - `out_loaded_account_data_cost`: A pointer to a `ulong` where the function will store the cost associated with the loaded account data size.
- **Control Flow**:
    - Initialize `cu_limit` to 0 and determine the compute unit limit based on the state flags; use default if not set.
    - Clamp `cu_limit` to the maximum allowed compute unit limit and store it in `out_compute`.
    - Determine the loaded account data size based on the state flags; use default if not set.
    - Calculate the loaded account data cost and store it in `out_loaded_account_data_cost`.
    - Calculate the total fee using a careful arithmetic approach to avoid overflow, considering the compute unit limit and micro lamports per compute unit.
    - Store the calculated total fee in `out_rewards`.
- **Output**: The function outputs the total priority rewards in `out_rewards`, the maximum compute units in `out_compute`, and the loaded account data cost in `out_loaded_account_data_cost`.


