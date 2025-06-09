# Purpose
This C header file defines the interface for managing a "slot history" system variable within a runtime environment, likely part of a larger system called "Flamenco." The file includes function declarations for initializing, updating, and reading the slot history, which is represented as a bit-vector indicating processed slots within a current epoch. It also defines constants representing different states of slot history, such as found, future, not found, and too old. The functions interact with various context structures and shared memory spaces, suggesting that this code is part of a concurrent or distributed system where tracking the execution state across different slots is crucial. The header file is designed to be included in other source files that need to manipulate or query the slot history as part of their execution logic.
# Imports and Dependencies

---
- `../../fd_flamenco_base.h`
- `../../types/fd_types.h`
- `../context/fd_exec_slot_ctx.h`
- `../context/fd_exec_epoch_ctx.h`


# Global Variables

---
### fd\_sysvar\_slot\_history\_read
- **Type**: `fd_slot_history_global_t *`
- **Description**: The `fd_sysvar_slot_history_read` is a function that returns a pointer to a `fd_slot_history_global_t` structure. This function is used to read the slot history sysvar from a given `funk` context. If the account does not exist or has zero lamports, it returns NULL.
- **Use**: This function is used to access the slot history sysvar, which tracks processed slots in the current epoch, from a `funk` context.


# Function Declarations (Public API)

---
### fd\_sysvar\_slot\_history\_init<!-- {{#callable_declaration:fd_sysvar_slot_history_init}} -->
Initialize the slot history sysvar account.
- **Description**: This function initializes the slot history sysvar account, which is used to track processed slots within the current epoch. It should be called to set up the slot history before any slot processing begins. The function requires a valid execution slot context and a runtime scratchpad memory area to allocate necessary resources. It is important to ensure that the provided context and memory area are properly initialized and valid before calling this function.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the execution slot context. This must be a valid, non-null pointer, and the context should be properly initialized before calling this function.
    - `runtime_spad`: A pointer to an fd_spad_t structure representing the runtime scratchpad memory area. This must be a valid, non-null pointer, and the memory area should be properly initialized and have sufficient space for allocation.
- **Output**: None
- **See also**: [`fd_sysvar_slot_history_init`](fd_sysvar_slot_history.c.driver.md#fd_sysvar_slot_history_init)  (Implementation)


---
### fd\_sysvar\_slot\_history\_update<!-- {{#callable_declaration:fd_sysvar_slot_history_update}} -->
Update the slot history sysvar account.
- **Description**: This function updates the slot history sysvar account and should be called at the end of every slot, after execution has concluded. It ensures that the current slot is recorded and prepares the account for the next slot. The function requires a valid execution slot context and a runtime scratchpad for memory allocation. It handles memory allocation and updates the sysvar account with the current slot information.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the execution slot context. Must not be null and should be properly initialized before calling this function.
    - `runtime_spad`: A pointer to an fd_spad_t structure used for runtime memory allocation. Must not be null and should be properly initialized.
- **Output**: Returns 0 on success. On failure, it logs an error and may return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR.
- **See also**: [`fd_sysvar_slot_history_update`](fd_sysvar_slot_history.c.driver.md#fd_sysvar_slot_history_update)  (Implementation)


---
### fd\_sysvar\_slot\_history\_read<!-- {{#callable_declaration:fd_sysvar_slot_history_read}} -->
Reads the slot history sysvar from the specified funk.
- **Description**: This function retrieves the slot history sysvar from the provided funk and transaction context. It should be used when you need to access the slot history data for the current epoch. The function returns NULL if the sysvar account does not exist in the funk or if it has zero lamports, indicating a non-existent account in this context. Ensure that the funk and transaction contexts are properly initialized before calling this function, and that the spad has sufficient space for allocation.
- **Inputs**:
    - `funk`: A pointer to an fd_funk_t structure representing the funk from which the slot history sysvar is to be read. Must not be null.
    - `funk_txn`: A pointer to an fd_funk_txn_t structure representing the transaction context within the funk. Must not be null.
    - `spad`: A pointer to an fd_spad_t structure used for memory allocation during the read operation. Must not be null and should have sufficient space for allocation.
- **Output**: Returns a pointer to an fd_slot_history_global_t structure containing the slot history data, or NULL if the account does not exist or has zero lamports.
- **See also**: [`fd_sysvar_slot_history_read`](fd_sysvar_slot_history.c.driver.md#fd_sysvar_slot_history_read)  (Implementation)


---
### fd\_sysvar\_slot\_history\_find\_slot<!-- {{#callable_declaration:fd_sysvar_slot_history_find_slot}} -->
Finds the status of a specific slot in the slot history.
- **Description**: This function checks the status of a given slot within the slot history sysvar, which is represented as a bit-vector. It is used to determine if a slot has been processed, is too old, or is in the future relative to the current epoch. The function should be called with a valid slot history object and a slot number to check. The workspace parameter is currently unused and can be ignored. The function returns different status codes based on whether the slot is found, too old, or in the future.
- **Inputs**:
    - `history`: A pointer to a constant fd_slot_history_global_t structure representing the slot history. Must not be null.
    - `slot`: An unsigned long integer representing the slot number to check. Must be within the valid range of slots managed by the history.
    - `wksp`: A pointer to an fd_wksp_t structure. This parameter is currently unused and can be ignored.
- **Output**: Returns an integer status code: FD_SLOT_HISTORY_SLOT_FOUND if the slot is found, FD_SLOT_HISTORY_SLOT_FUTURE if the slot is in the future, FD_SLOT_HISTORY_SLOT_NOT_FOUND if the slot is not found, or FD_SLOT_HISTORY_SLOT_TOO_OLD if the slot is too old.
- **See also**: [`fd_sysvar_slot_history_find_slot`](fd_sysvar_slot_history.c.driver.md#fd_sysvar_slot_history_find_slot)  (Implementation)


