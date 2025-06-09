# Purpose
This C header file, `fd_cost_tracker.h`, is part of a larger system that integrates logic from Agave's Rust-based cost model and cost tracker modules to manage and validate block limits during transaction replays. It defines several constants that represent various block and account limits, such as maximum block units and writable accounts per block, which are crucial for ensuring that transactions do not exceed predefined resource constraints. The file also declares function prototypes for initializing a cost tracker, calculating transaction costs, and attempting to add transaction costs to a block, providing a C interface for these operations. The inclusion of external headers and the use of constants linked to specific lines in Agave's source code suggest a close integration with Agave's cost management logic, ensuring consistency and correctness in transaction cost handling.
# Imports and Dependencies

---
- `../vm/fd_vm_base.h`
- `fd_system_ids.h`
- `fd_executor.h`
- `../../disco/pack/fd_pack.h`
- `../../disco/pack/fd_pack_cost.h`


# Function Declarations (Public API)

---
### fd\_cost\_tracker\_init<!-- {{#callable_declaration:fd_cost_tracker_init}} -->
Initialize the cost tracker and allocate memory for account cost tracking.
- **Description**: This function sets up a cost tracker by initializing its limits and allocating necessary memory for tracking account costs. It should be called before using the cost tracker to ensure that all limits are set and memory is allocated properly. The function requires a valid execution slot context and a shared memory allocator to function correctly. It prepares the cost tracker for use in monitoring and validating block limits during transaction processing.
- **Inputs**:
    - `self`: A pointer to an fd_cost_tracker_t structure that will be initialized. The caller must ensure this pointer is valid and points to allocated memory.
    - `slot_ctx`: A pointer to a constant fd_exec_slot_ctx_t structure providing context about the execution slot. This must not be null and should be properly initialized before calling the function.
    - `spad`: A pointer to an fd_spad_t structure used for memory allocation. This must not be null and should be properly initialized to allocate memory for the cost tracker.
- **Output**: None
- **See also**: [`fd_cost_tracker_init`](fd_cost_tracker.c.driver.md#fd_cost_tracker_init)  (Implementation)


---
### fd\_calculate\_cost\_for\_executed\_transaction<!-- {{#callable_declaration:fd_calculate_cost_for_executed_transaction}} -->
Calculates the cost of an executed transaction.
- **Description**: This function computes the cost associated with an executed transaction, which is essential for validating block limits during replay. It should be used when you need to determine the cost of a transaction based on its context and characteristics. The function distinguishes between simple vote transactions and other types, applying different cost calculations accordingly. It is important to ensure that the transaction context is properly initialized and valid before calling this function.
- **Inputs**:
    - `txn_ctx`: A pointer to a constant `fd_exec_txn_ctx_t` structure representing the transaction context. It must not be null and should be properly initialized with valid transaction data.
    - `spad`: A pointer to an `fd_spad_t` structure used for temporary storage during cost calculation. It must not be null and should be allocated before calling this function.
- **Output**: Returns an `fd_transaction_cost_t` structure containing the calculated cost of the transaction. The cost is determined based on the transaction type and its associated data.
- **See also**: [`fd_calculate_cost_for_executed_transaction`](fd_cost_tracker.c.driver.md#fd_calculate_cost_for_executed_transaction)  (Implementation)


---
### fd\_cost\_tracker\_try\_add<!-- {{#callable_declaration:fd_cost_tracker_try_add}} -->
Attempts to add a transaction cost to the cost tracker if it fits within block limits.
- **Description**: Use this function to check if a transaction's cost can be added to the current block without exceeding predefined limits. It should be called when you need to validate whether a transaction can be included in a block based on its cost. The function returns an error code if adding the transaction would exceed any block limits, allowing the caller to handle such cases appropriately. Ensure that the cost tracker has been initialized before calling this function.
- **Inputs**:
    - `self`: A pointer to an initialized `fd_cost_tracker_t` structure. The caller retains ownership and must ensure it is not null.
    - `txn_ctx`: A pointer to a constant `fd_exec_txn_ctx_t` structure representing the transaction context. The caller retains ownership and must ensure it is not null.
    - `tx_cost`: A pointer to a constant `fd_transaction_cost_t` structure representing the transaction cost. The caller retains ownership and must ensure it is not null.
- **Output**: Returns `FD_COST_TRACKER_SUCCESS` if the transaction cost is successfully added. Returns an error code if the transaction cost would exceed block limits, indicating the specific limit that would be exceeded.
- **See also**: [`fd_cost_tracker_try_add`](fd_cost_tracker.c.driver.md#fd_cost_tracker_try_add)  (Implementation)


