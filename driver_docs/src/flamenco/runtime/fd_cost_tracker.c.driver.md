# Purpose
This C source code file is part of a cost-tracking system for transactions, likely within a blockchain or distributed ledger context. The file provides a set of functions to calculate and manage the costs associated with executing transactions. It includes functions to compute various cost components such as loaded accounts data size, instruction data cost, signature verification cost, and write lock cost. These calculations are used to determine the overall cost of a transaction, which is then used to ensure that transactions do not exceed predefined limits for block, vote, and account costs. The code also includes mechanisms to track and update these costs as transactions are processed.

The file defines several static inline functions, indicating that these are utility functions intended for use within this file or module, rather than being part of a public API. The functions are designed to be efficient, using inline assembly and saturation arithmetic to handle potential overflows. The code also includes a public function, [`fd_cost_tracker_init`](#fd_cost_tracker_init), which initializes the cost tracker with appropriate limits and prepares it for tracking transaction costs. Additionally, the file provides functionality to add transaction costs to the tracker and check if a transaction would fit within the current cost limits. This code is a critical component of a broader system that ensures the efficient and fair processing of transactions by managing resource usage and preventing any single transaction from overwhelming the system's capacity.
# Imports and Dependencies

---
- `fd_cost_tracker.h`


# Functions

---
### calculate\_loaded\_accounts\_data\_size\_cost<!-- {{#callable:calculate_loaded_accounts_data_size_cost}} -->
The function `calculate_loaded_accounts_data_size_cost` computes the cost associated with the loaded accounts' data size in a transaction context.
- **Inputs**:
    - `txn_ctx`: A pointer to a `fd_exec_txn_ctx_t` structure that contains the transaction context, including the loaded accounts' data size.
- **Control Flow**:
    - Add `FD_ACCOUNT_DATA_COST_PAGE_SIZE` to `txn_ctx->loaded_accounts_data_size` and subtract 1, using saturated arithmetic.
    - Divide the result by `FD_ACCOUNT_DATA_COST_PAGE_SIZE`.
    - Multiply the quotient by `FD_VM_HEAP_COST` using saturated multiplication.
    - Return the final computed cost.
- **Output**: The function returns an `ulong` representing the calculated cost of the loaded accounts' data size.


---
### get\_instructions\_data\_cost<!-- {{#callable:get_instructions_data_cost}} -->
The `get_instructions_data_cost` function calculates the total cost of instruction data in a transaction context by summing the sizes of all instruction data and dividing by a predefined cost per byte.
- **Inputs**:
    - `txn_ctx`: A pointer to a `fd_exec_txn_ctx_t` structure representing the transaction context, which contains details about the transaction and its instructions.
- **Control Flow**:
    - Initialize `total_instr_data_sz` to 0.
    - Iterate over each instruction in the transaction context using a loop that runs from 0 to `instr_cnt` (the number of instructions).
    - For each instruction, add its `data_sz` (data size) to `total_instr_data_sz`.
    - After the loop, divide `total_instr_data_sz` by `FD_PACK_INV_COST_PER_INSTR_DATA_BYTE` to calculate the cost.
- **Output**: Returns an `ulong` representing the total cost of the instruction data in the transaction context.


---
### get\_signature\_cost<!-- {{#callable:get_signature_cost}} -->
The `get_signature_cost` function calculates the total cost of transaction signatures, including specific costs for different cryptographic signature types, based on the transaction context.
- **Inputs**:
    - `txn_ctx`: A pointer to a `fd_exec_txn_ctx_t` structure containing the transaction context, which includes the transaction descriptor and raw transaction data.
- **Control Flow**:
    - Retrieve the transaction descriptor and raw payload from the transaction context.
    - Get the account addresses associated with the transaction using `fd_txn_get_acct_addrs`.
    - Initialize variables to count different types of cryptographic instruction signatures (secp256k1, ed25519, secp256r1).
    - Iterate over each instruction in the transaction to determine the number of each type of cryptographic signature instruction present.
    - For each instruction, check if the program ID matches known cryptographic signature verification programs and increment the corresponding signature count based on the instruction data.
    - Calculate the cost for secp256k1 signature verifications using `fd_ulong_sat_mul`.
    - Determine the cost for ed25519 signature verifications, using a different cost if the `ed25519_precompile_verify_strict` feature is active.
    - Calculate the cost for secp256r1 signature verifications if the `enable_secp256r1_precompile` feature is active.
    - Sum the base signature cost with the calculated costs for each type of cryptographic signature verification and return the total.
- **Output**: The function returns an `ulong` representing the total cost of the transaction's signatures, including costs for specific cryptographic signature verifications.


---
### get\_write\_lock\_cost<!-- {{#callable:get_write_lock_cost}} -->
The `get_write_lock_cost` function calculates the cost associated with a given number of write locks by multiplying it with a predefined unit cost.
- **Inputs**:
    - `num_write_locks`: The number of write locks for which the cost needs to be calculated.
- **Control Flow**:
    - The function takes a single input, `num_write_locks`.
    - It calls the `fd_ulong_sat_mul` function to multiply `num_write_locks` by `FD_WRITE_LOCK_UNITS`, which is a constant representing the cost per write lock.
- **Output**: The function returns an unsigned long integer representing the total cost of the specified number of write locks.


---
### calculate\_allocated\_accounts\_data\_size<!-- {{#callable:calculate_allocated_accounts_data_size}} -->
The function `calculate_allocated_accounts_data_size` computes the total size of allocated account data for a transaction by analyzing its instructions and checking for system program allocations.
- **Inputs**:
    - `txn_ctx`: A pointer to a `fd_exec_txn_ctx_t` structure that contains the transaction context, including the transaction descriptor and raw transaction data.
    - `spad`: A pointer to a `fd_spad_t` structure used for temporary storage during the function's execution.
- **Control Flow**:
    - Begin a frame for the `spad` structure using `FD_SPAD_FRAME_BEGIN` macro.
    - Retrieve the transaction descriptor and raw payload from `txn_ctx`.
    - Initialize `allocated_accounts_data_size` to zero.
    - Iterate over each instruction in the transaction using a loop.
    - For each instruction, retrieve the associated account addresses and program ID.
    - Check if the instruction has data and if the program ID matches the Solana system program ID; if not, continue to the next instruction.
    - Decode the instruction data using `fd_bincode_decode_spad` and check for decoding errors; if an error occurs, continue to the next instruction.
    - Determine the space required for the instruction based on its type (e.g., create account, allocate) using a switch statement.
    - If the space exceeds `FD_ACC_SZ_MAX`, return zero immediately.
    - Add the space to `allocated_accounts_data_size` using `fd_ulong_sat_add`.
    - After processing all instructions, return the minimum of `2UL*FD_ACC_SZ_MAX` and `allocated_accounts_data_size` using `fd_ulong_min`.
    - End the frame for the `spad` structure using `FD_SPAD_FRAME_END` macro.
- **Output**: The function returns an `ulong` representing the total size of allocated account data, constrained by a maximum limit.


---
### FD\_SPAD\_FRAME\_BEGIN<!-- {{#callable:calculate_allocated_accounts_data_size::FD_SPAD_FRAME_BEGIN}} -->
The `FD_SPAD_FRAME_BEGIN` function calculates the total allocated account data size for a transaction by iterating over its instructions and decoding system program instructions to determine space allocations.
- **Inputs**:
    - `spad`: A pointer to an `fd_spad_t` structure used for temporary storage during the function's execution.
- **Control Flow**:
    - Retrieve the transaction descriptor and raw payload from the transaction context.
    - Initialize `allocated_accounts_data_size` to zero.
    - Iterate over each instruction in the transaction.
    - For each instruction, retrieve the account addresses and program ID, and get the instruction data.
    - Check if the instruction data size is zero or if the program ID does not match the Solana system program ID; if so, skip the instruction.
    - Decode the instruction data into a `fd_system_program_instruction_t` structure and check for decoding errors; if an error occurs, skip the instruction.
    - Determine the space required by the instruction based on its discriminant (e.g., create account, allocate, etc.).
    - If the space required exceeds `FD_ACC_SZ_MAX`, return zero.
    - Add the space required by the instruction to `allocated_accounts_data_size`.
    - Return the minimum of `2 * FD_ACC_SZ_MAX` and `allocated_accounts_data_size`.
- **Output**: The function returns the total allocated account data size, constrained by a maximum limit, as an unsigned long integer.


---
### calculate\_non\_vote\_transaction\_cost<!-- {{#callable:calculate_non_vote_transaction_cost}} -->
The `calculate_non_vote_transaction_cost` function computes the cost of executing a non-vote transaction by aggregating various cost components such as signature, write lock, data bytes, and account data sizes.
- **Inputs**:
    - `txn_ctx`: A pointer to a `fd_exec_txn_ctx_t` structure containing the transaction context, which includes details about the transaction and its execution environment.
    - `loaded_accounts_data_size_cost`: An unsigned long integer representing the cost associated with the size of loaded account data.
    - `data_bytes_cost`: An unsigned long integer representing the cost associated with the data bytes involved in the transaction.
    - `spad`: A pointer to an `fd_spad_t` structure used for temporary storage and processing during the calculation.
- **Control Flow**:
    - Retrieve the signature cost by calling [`get_signature_cost`](#get_signature_cost) with `txn_ctx` as the argument.
    - Calculate the write lock cost by calling [`get_write_lock_cost`](#get_write_lock_cost) with the number of writable accounts obtained from `fd_txn_account_cnt`.
    - Determine the allocated accounts data size by invoking [`calculate_allocated_accounts_data_size`](#calculate_allocated_accounts_data_size) with `txn_ctx` and `spad`.
    - Construct and return a `fd_transaction_cost_t` structure with the calculated costs, including signature, write lock, data bytes, programs execution, loaded accounts data size, and allocated accounts data size.
- **Output**: The function returns a `fd_transaction_cost_t` structure containing the calculated costs for the non-vote transaction, encapsulated within a `transaction` field of the `inner` union.
- **Functions called**:
    - [`get_signature_cost`](#get_signature_cost)
    - [`get_write_lock_cost`](#get_write_lock_cost)
    - [`calculate_allocated_accounts_data_size`](#calculate_allocated_accounts_data_size)


---
### transaction\_cost\_sum<!-- {{#callable:transaction_cost_sum}} -->
The `transaction_cost_sum` function calculates the total cost of a transaction based on its type and associated cost details.
- **Inputs**:
    - `self`: A pointer to a `fd_transaction_cost_t` structure representing the transaction cost details.
- **Control Flow**:
    - The function checks the `discriminant` field of the `self` structure to determine the type of transaction.
    - If the transaction is a simple vote (`fd_transaction_cost_enum_simple_vote`), it returns a predefined constant `FD_PACK_SIMPLE_VOTE_COST`.
    - If the transaction is a regular transaction (`fd_transaction_cost_enum_transaction`), it retrieves the cost details from the `inner.transaction` field.
    - It initializes a `cost` variable to zero and adds various cost components (signature, write lock, data bytes, programs execution, and loaded accounts data size) using the `fd_ulong_sat_add` function to ensure saturation arithmetic.
    - If the `discriminant` does not match any known type, the function calls `__builtin_unreachable()` indicating an unexpected code path.
- **Output**: The function returns an `ulong` representing the total calculated cost of the transaction.


---
### get\_allocated\_accounts\_data\_size<!-- {{#callable:get_allocated_accounts_data_size}} -->
The `get_allocated_accounts_data_size` function retrieves the allocated accounts data size from a transaction cost structure based on its discriminant type.
- **Inputs**:
    - `self`: A pointer to a constant `fd_transaction_cost_t` structure, which contains information about the transaction cost and its type.
- **Control Flow**:
    - The function uses a switch statement to check the `discriminant` field of the `self` structure.
    - If the `discriminant` is `fd_transaction_cost_enum_simple_vote`, the function returns 0.
    - If the `discriminant` is `fd_transaction_cost_enum_transaction`, the function returns the `allocated_accounts_data_size` from the `inner.transaction` field of the `self` structure.
    - If the `discriminant` is neither of the above, the function calls `__builtin_unreachable()`, indicating that this code path should not be possible.
- **Output**: The function returns an unsigned long integer (`ulong`) representing the allocated accounts data size for the transaction, or 0 if the transaction is a simple vote.


---
### would\_fit<!-- {{#callable:would_fit}} -->
The `would_fit` function checks if a transaction's cost would exceed various predefined limits within a cost tracker system.
- **Inputs**:
    - `self`: A pointer to an `fd_cost_tracker_t` structure representing the current state of the cost tracker.
    - `txn_ctx`: A pointer to an `fd_exec_txn_ctx_t` structure containing the context of the transaction being evaluated.
    - `tx_cost`: A pointer to an `fd_transaction_cost_t` structure representing the cost details of the transaction.
- **Control Flow**:
    - Calculate the total cost of the transaction using [`transaction_cost_sum`](#transaction_cost_sum) function.
    - Check if the transaction is a simple vote and if adding its cost would exceed the vote cost limit; return an error code if it does.
    - Check if adding the transaction cost would exceed the block cost limit; return an error code if it does.
    - Check if the transaction cost exceeds the account cost limit; return an error code if it does.
    - Calculate the new allocated accounts data size and check if it exceeds the maximum allowed; return an error code if it does.
    - Iterate over writable accounts in the transaction context, checking if adding the transaction cost to each account would exceed the account cost limit; return an error code if any do.
    - Return success if none of the limits are exceeded.
- **Output**: Returns an integer indicating success or a specific error code if any cost limit is exceeded.
- **Functions called**:
    - [`transaction_cost_sum`](#transaction_cost_sum)
    - [`get_allocated_accounts_data_size`](#get_allocated_accounts_data_size)
    - [`fd_exec_txn_ctx_account_is_writable_idx`](context/fd_exec_txn_ctx.c.driver.md#fd_exec_txn_ctx_account_is_writable_idx)


---
### add\_transaction\_execution\_cost<!-- {{#callable:add_transaction_execution_cost}} -->
The `add_transaction_execution_cost` function updates the cost tracker with the execution cost of a transaction, adjusting costs for writable accounts and overall block and vote costs.
- **Inputs**:
    - `self`: A pointer to an `fd_cost_tracker_t` structure that tracks costs associated with transactions.
    - `txn_ctx`: A constant pointer to an `fd_exec_txn_ctx_t` structure representing the execution context of the transaction, including account information.
    - `tx_cost`: A constant pointer to an `fd_transaction_cost_t` structure representing the cost details of the transaction.
    - `adjustment`: An unsigned long integer representing the cost adjustment to be applied to the transaction execution.
- **Control Flow**:
    - Initialize pointers to the account costs pool and root from the cost tracker structure.
    - Iterate over each account in the transaction context.
    - Check if the account is writable; if not, continue to the next account.
    - For writable accounts, attempt to find the account cost in the map using the account's public key.
    - If the account cost is not found, acquire a new map node, set its key and cost, and insert it into the map.
    - If the account cost is found, add the adjustment to the existing cost using a saturating addition function.
    - Update the block cost in the cost tracker by adding the adjustment using a saturating addition function.
    - If the transaction is a simple vote, update the vote cost in the cost tracker by adding the adjustment using a saturating addition function.
- **Output**: The function does not return a value; it modifies the `fd_cost_tracker_t` structure in place to reflect the updated costs.
- **Functions called**:
    - [`fd_exec_txn_ctx_account_is_writable_idx`](context/fd_exec_txn_ctx.c.driver.md#fd_exec_txn_ctx_account_is_writable_idx)


---
### add\_transaction\_cost<!-- {{#callable:add_transaction_cost}} -->
The `add_transaction_cost` function updates a cost tracker with the allocated accounts data size and transaction count, and adds the transaction execution cost to the tracker's total costs.
- **Inputs**:
    - `self`: A pointer to an `fd_cost_tracker_t` structure that maintains the state of the cost tracking.
    - `txn_ctx`: A constant pointer to an `fd_exec_txn_ctx_t` structure that provides context about the transaction being processed.
    - `tx_cost`: A constant pointer to an `fd_transaction_cost_t` structure that contains the cost details of the transaction.
- **Control Flow**:
    - The function begins by updating the `allocated_accounts_data_size` of the `self` cost tracker by adding the allocated accounts data size obtained from `tx_cost`.
    - It increments the `transaction_count` of the `self` cost tracker by one.
    - The function then calls [`add_transaction_execution_cost`](#add_transaction_execution_cost), passing `self`, `txn_ctx`, `tx_cost`, and the total transaction cost calculated by `transaction_cost_sum(tx_cost)` to update the execution costs in the cost tracker.
- **Output**: The function does not return any value; it modifies the state of the `fd_cost_tracker_t` structure pointed to by `self`.
- **Functions called**:
    - [`get_allocated_accounts_data_size`](#get_allocated_accounts_data_size)
    - [`add_transaction_execution_cost`](#add_transaction_execution_cost)
    - [`transaction_cost_sum`](#transaction_cost_sum)


---
### fd\_cost\_tracker\_init<!-- {{#callable:fd_cost_tracker_init}} -->
The `fd_cost_tracker_init` function initializes a cost tracker structure with predefined limits and resets its aggregated statistics for a new block.
- **Inputs**:
    - `self`: A pointer to an `fd_cost_tracker_t` structure that will be initialized.
    - `slot_ctx`: A constant pointer to an `fd_exec_slot_ctx_t` structure containing context about the execution slot, including features and slot bank information.
    - `spad`: A pointer to an `fd_spad_t` structure used for memory allocation.
- **Control Flow**:
    - Set the `account_cost_limit` to `FD_MAX_WRITABLE_ACCOUNT_UNITS`.
    - Determine the `block_cost_limit` based on the active feature `raise_block_limits_to_50m` and set it to either `FD_MAX_BLOCK_UNITS_SIMD_0207` or `FD_MAX_BLOCK_UNITS`.
    - Set the `vote_cost_limit` to `FD_MAX_VOTE_UNITS`.
    - Initialize the `cost_by_writable_accounts` map with a memory pool allocated using `fd_spad_alloc` and join it using `fd_account_costs_pair_t_map_join`.
    - Check if the memory allocation for `account_costs_pool` failed and log an error if it did.
    - Reset various aggregated statistics in the `self` structure to zero, including `block_cost`, `vote_cost`, `transaction_count`, and several signature counts.
- **Output**: The function does not return a value; it initializes the `fd_cost_tracker_t` structure pointed to by `self`.


---
### fd\_calculate\_cost\_for\_executed\_transaction<!-- {{#callable:fd_calculate_cost_for_executed_transaction}} -->
The function `fd_calculate_cost_for_executed_transaction` calculates the cost of executing a transaction based on its type and associated data.
- **Inputs**:
    - `txn_ctx`: A pointer to a `fd_exec_txn_ctx_t` structure containing the context of the transaction to be evaluated.
    - `spad`: A pointer to a `fd_spad_t` structure used for temporary storage during cost calculation.
- **Control Flow**:
    - Check if the transaction is a simple vote transaction using `fd_txn_is_simple_vote_transaction`; if true, return a cost structure with a simple vote discriminant.
    - Calculate the cost associated with the size of loaded accounts data using [`calculate_loaded_accounts_data_size_cost`](#calculate_loaded_accounts_data_size_cost).
    - Calculate the cost associated with the instructions data using [`get_instructions_data_cost`](#get_instructions_data_cost).
    - Calculate the cost for non-vote transactions using [`calculate_non_vote_transaction_cost`](#calculate_non_vote_transaction_cost) with the previously calculated costs and return the result.
- **Output**: Returns a `fd_transaction_cost_t` structure representing the calculated cost of the transaction, with different fields populated based on whether the transaction is a simple vote or a non-vote transaction.
- **Functions called**:
    - [`calculate_loaded_accounts_data_size_cost`](#calculate_loaded_accounts_data_size_cost)
    - [`get_instructions_data_cost`](#get_instructions_data_cost)
    - [`calculate_non_vote_transaction_cost`](#calculate_non_vote_transaction_cost)


---
### fd\_cost\_tracker\_try\_add<!-- {{#callable:fd_cost_tracker_try_add}} -->
The `fd_cost_tracker_try_add` function attempts to add a transaction cost to a cost tracker, ensuring it fits within predefined limits before doing so.
- **Inputs**:
    - `self`: A pointer to an `fd_cost_tracker_t` structure that tracks the costs of transactions.
    - `txn_ctx`: A constant pointer to an `fd_exec_txn_ctx_t` structure representing the execution context of the transaction.
    - `tx_cost`: A constant pointer to an `fd_transaction_cost_t` structure representing the cost of the transaction to be added.
- **Control Flow**:
    - Call the [`would_fit`](#would_fit) function to check if the transaction cost can be added without exceeding limits.
    - If [`would_fit`](#would_fit) returns an error, return the error code immediately.
    - If the transaction cost fits, call [`add_transaction_cost`](#add_transaction_cost) to add the transaction cost to the tracker.
    - Return `FD_COST_TRACKER_SUCCESS` to indicate successful addition of the transaction cost.
- **Output**: Returns an integer indicating success (`FD_COST_TRACKER_SUCCESS`) or an error code if the transaction cost cannot be added due to exceeding limits.
- **Functions called**:
    - [`would_fit`](#would_fit)
    - [`add_transaction_cost`](#add_transaction_cost)


