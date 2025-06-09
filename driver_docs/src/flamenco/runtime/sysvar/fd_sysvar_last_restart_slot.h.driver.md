# Purpose
This C header file defines the interface for managing a system variable (sysvar) related to the "last restart slot" within a runtime environment, likely part of a larger system dealing with transaction processing or state management. It includes function prototypes for initializing, updating, and reading this sysvar, which is crucial for maintaining state consistency across restarts or updates in a distributed system. The file includes necessary dependencies and context structures, such as `fd_exec_slot_ctx_t`, to facilitate these operations. The functions are designed to interact with a "funk" (possibly a data structure or database abstraction) to ensure the sysvar is correctly managed, although the update function is noted as not fully implemented, indicating ongoing development.
# Imports and Dependencies

---
- `../../fd_flamenco_base.h`
- `../../types/fd_types.h`
- `../context/fd_exec_slot_ctx.h`


# Global Variables

---
### fd\_sysvar\_last\_restart\_slot\_read
- **Type**: `function pointer`
- **Description**: The `fd_sysvar_last_restart_slot_read` is a function that returns a pointer to a `fd_sol_sysvar_last_restart_slot_t` structure. It is used to query the 'last restart slot' system variable from a given 'funk' context. If the account does not exist or has zero lamports, the function returns NULL.
- **Use**: This function is used to read the 'last restart slot' system variable from a specified context, returning a pointer to the relevant data structure or NULL if unavailable.


# Function Declarations (Public API)

---
### fd\_sysvar\_last\_restart\_slot\_init<!-- {{#callable_declaration:fd_sysvar_last_restart_slot_init}} -->
Create or update the "last restart slot" sysvar account.
- **Description**: This function initializes or updates the "last restart slot" system variable account using the state information from the provided execution slot context. It should be called when the "last restart slot" sysvar is supported by the current ledger version, as indicated by the feature set in the execution context. If the sysvar is not supported, the function logs an informational message and returns without making any changes. This function must be called with a valid execution slot context that reflects the current state of the bank.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the execution slot context. This parameter must not be null and should contain valid state information for the current bank. The function checks if the "last restart slot" sysvar is supported by the ledger version specified in this context.
- **Output**: None
- **See also**: [`fd_sysvar_last_restart_slot_init`](fd_sysvar_last_restart_slot.c.driver.md#fd_sysvar_last_restart_slot_init)  (Implementation)


---
### fd\_sysvar\_last\_restart\_slot\_update<!-- {{#callable_declaration:fd_sysvar_last_restart_slot_update}} -->
Updates the 'last restart slot' sysvar account before transaction processing.
- **Description**: This function updates the 'last restart slot' sysvar account using the current state of the bank, specifically before transaction processing occurs. It should be called to ensure that the sysvar reflects the latest restart slot information. The function checks if the feature is active for the current slot and updates the sysvar only if necessary, based on the current and previous restart slot values. It is important to call this function in the appropriate context where the slot context and runtime scratchpad are valid and properly initialized.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the execution context for the current slot. Must not be null and should be properly initialized with valid slot and epoch context information.
    - `runtime_spad`: A pointer to an fd_spad_t structure used as a runtime scratchpad. Must not be null and should be initialized before calling this function.
- **Output**: None
- **See also**: [`fd_sysvar_last_restart_slot_update`](fd_sysvar_last_restart_slot.c.driver.md#fd_sysvar_last_restart_slot_update)  (Implementation)


---
### fd\_sysvar\_last\_restart\_slot\_read<!-- {{#callable_declaration:fd_sysvar_last_restart_slot_read}} -->
Queries the last restart slot sysvar from the given funk.
- **Description**: This function retrieves the last restart slot sysvar from the specified funk. It should be used when you need to access the last restart slot information stored in the sysvar account. The function requires a valid funk and transaction context, and it will return NULL if the sysvar account does not exist or has zero lamports, indicating non-existence in this context. Ensure that the funk and transaction contexts are properly initialized before calling this function.
- **Inputs**:
    - `funk`: A pointer to an fd_funk_t structure representing the funk from which the sysvar is queried. Must not be null.
    - `funk_txn`: A pointer to an fd_funk_txn_t structure representing the transaction context. Must not be null.
    - `spad`: A pointer to an fd_spad_t structure used for decoding the sysvar data. Must not be null.
- **Output**: Returns a pointer to an fd_sol_sysvar_last_restart_slot_t structure containing the last restart slot information, or NULL if the account does not exist or has zero lamports.
- **See also**: [`fd_sysvar_last_restart_slot_read`](fd_sysvar_last_restart_slot.c.driver.md#fd_sysvar_last_restart_slot_read)  (Implementation)


