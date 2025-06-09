# Purpose
This C header file defines the interface for managing a "stake history" system variable (sysvar) within a blockchain or distributed ledger system, specifically in the context of the Flamenco runtime. It includes function prototypes for initializing, reading, and updating the stake history sysvar, which tracks the history of cluster-wide stake activations and deactivations on a per-epoch basis. The file sets a maximum capacity for the stake history entries using a preprocessor macro, `FD_SYSVAR_STAKE_HISTORY_CAP`, which is defined as 512 entries. The functions interact with a data structure called `fd_funk_t` and utilize transaction and runtime context structures to manage the stake history data, ensuring that updates occur at epoch boundaries. This header file is part of a larger system that likely involves complex interactions with blockchain state and transaction processing.
# Imports and Dependencies

---
- `../../fd_flamenco_base.h`
- `../../types/fd_types.h`
- `../../../funk/fd_funk.h`


# Global Variables

---
### fd\_sysvar\_stake\_history\_read
- **Type**: `fd_stake_history_t *`
- **Description**: The `fd_sysvar_stake_history_read` is a function that returns a pointer to an `fd_stake_history_t` structure. This function is responsible for reading the stake history system variable from a data structure referred to as 'funk'. If the account does not exist or has zero lamports, it returns NULL.
- **Use**: This function is used to access the stake history system variable, which records the history of cluster-wide activations and deactivations per epoch.


# Function Declarations (Public API)

---
### fd\_sysvar\_stake\_history\_init<!-- {{#callable_declaration:fd_sysvar_stake_history_init}} -->
Initialize the stake history sysvar account.
- **Description**: This function initializes the stake history sysvar account, which is used to track the history of cluster-wide activations and de-activations per epoch. It should be called at the start of each epoch to ensure that the stake history is properly set up for the current epoch. This function must be called with a valid execution slot context, and it prepares the stake history for further operations.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the execution slot context. This parameter must not be null, and the caller retains ownership of the context. It is used to write the initialized stake history.
- **Output**: None
- **See also**: [`fd_sysvar_stake_history_init`](fd_sysvar_stake_history.c.driver.md#fd_sysvar_stake_history_init)  (Implementation)


---
### fd\_sysvar\_stake\_history\_read<!-- {{#callable_declaration:fd_sysvar_stake_history_read}} -->
Reads the stake history sysvar from the funk database.
- **Description**: This function retrieves the stake history sysvar from the specified funk database, which contains the history of cluster-wide activations and deactivations per epoch. It should be called when you need to access the stake history data. The function returns NULL if the account does not exist in the funk database or if the account has zero lamports, indicating that the account is effectively non-existent. Ensure that the funk and funk_txn parameters are properly initialized before calling this function.
- **Inputs**:
    - `funk`: A pointer to an fd_funk_t structure representing the funk database from which the stake history sysvar is to be read. Must not be null.
    - `funk_txn`: A pointer to an fd_funk_txn_t structure representing the transaction context within the funk database. Must not be null.
    - `spad`: A pointer to an fd_spad_t structure used for decoding the stake history data. Must not be null.
- **Output**: Returns a pointer to an fd_stake_history_t structure containing the stake history data if successful, or NULL if the account does not exist or has zero lamports.
- **See also**: [`fd_sysvar_stake_history_read`](fd_sysvar_stake_history.c.driver.md#fd_sysvar_stake_history_read)  (Implementation)


---
### fd\_sysvar\_stake\_history\_update<!-- {{#callable_declaration:fd_sysvar_stake_history_update}} -->
Update the stake history sysvar account at the epoch boundary.
- **Description**: This function updates the stake history sysvar account with new epoch data, typically called at the start of each epoch. It modifies the stake history to include the latest activation and deactivation information for the epoch, ensuring that the history is maintained up to the maximum capacity defined by FD_SYSVAR_STAKE_HISTORY_CAP. The function should be called with valid context and data structures, and it assumes that the stake history sysvar has been initialized and is accessible.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the execution slot context. Must not be null and should be properly initialized before calling this function.
    - `pair`: A pointer to an fd_epoch_stake_history_entry_pair_t structure containing the epoch and its corresponding stake history entry data. Must not be null and should contain valid epoch data.
    - `runtime_spad`: A pointer to an fd_spad_t structure used for runtime operations. Must not be null and should be properly initialized.
- **Output**: None
- **See also**: [`fd_sysvar_stake_history_update`](fd_sysvar_stake_history.c.driver.md#fd_sysvar_stake_history_update)  (Implementation)


