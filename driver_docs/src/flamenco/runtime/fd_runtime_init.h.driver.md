# Purpose
This C header file, `fd_runtime_init.h`, is part of a larger system designed to manage and manipulate a Solana runtime environment, specifically focusing on backup and restoration functionalities. It defines constants for encoding types and provides inline functions and prototypes for operations related to the management of "epoch" and "slot" banks, which are likely data structures used within the Solana runtime. The file includes functions for saving, restoring, recovering, and deleting these banks, indicating its role in maintaining the state of the runtime environment. The header is designed to be independent of `fd_executor.h`, suggesting modularity in the system's architecture. Additionally, it includes references to external dependencies and constants, such as `fd_flamenco_base.h` and `fd_funk_rec.h`, which are likely part of the broader framework supporting these operations.
# Imports and Dependencies

---
- `../fd_flamenco_base.h`
- `../../funk/fd_funk_rec.h`


# Functions

---
### fd\_runtime\_epoch\_bank\_key<!-- {{#callable:fd_funk_rec_key_t::fd_runtime_epoch_bank_key}} -->
The `fd_runtime_epoch_bank_key` function initializes and returns a record key for identifying an epoch bank in the runtime environment.
- **Inputs**: None
- **Control Flow**:
    - Declare a variable `id` of type `fd_funk_rec_key_t`.
    - Use `fd_memset` to set all bytes of `id` to 1, effectively initializing it.
    - Set the last byte of `id.uc` to `FD_FUNK_KEY_EPOCH_BANK`, marking it as an epoch bank key.
    - Return the initialized `id`.
- **Output**: The function returns an `fd_funk_rec_key_t` structure representing the key for an epoch bank.
- **See also**: [`fd_funk_rec_key_t`](../../funk/fd_funk_base.h.driver.md#fd_funk_rec_key_t)  (Data Structure)


---
### fd\_runtime\_slot\_bank\_key<!-- {{#callable:fd_runtime_slot_bank_key}} -->
The function `fd_runtime_slot_bank_key` initializes and returns a `fd_funk_rec_key_t` structure with a specific key value for identifying a slot bank.
- **Inputs**: None
- **Control Flow**:
    - Declare a variable `id` of type `fd_funk_rec_key_t`.
    - Use `fd_memset` to set all bytes of `id` to 1, effectively initializing it.
    - Set the last byte of `id.uc` to `FD_FUNK_KEY_SLOT_BANK`, which is a predefined constant.
    - Return the initialized `id` structure.
- **Output**: The function returns a `fd_funk_rec_key_t` structure with its last byte set to `FD_FUNK_KEY_SLOT_BANK`, representing a slot bank key.


# Function Declarations (Public API)

---
### fd\_runtime\_save\_slot\_bank<!-- {{#callable_declaration:fd_runtime_save_slot_bank}} -->
Saves the current slot bank state to persistent storage.
- **Description**: This function is used to save the current state of a slot bank to persistent storage, ensuring that the state can be restored later if needed. It should be called when the current state of the slot bank needs to be preserved, such as during a checkpoint or before a shutdown. The function requires a valid execution slot context and will log warnings or errors if the operation fails. It is important to ensure that the slot context is properly initialized and that the function is called in a context where saving the state is appropriate.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the execution slot context. This must not be null and should be properly initialized before calling the function. The function assumes ownership of the context for the duration of the call.
- **Output**: Returns an integer status code indicating success or failure. A return value of FD_RUNTIME_EXECUTE_SUCCESS indicates success, while other values indicate an error occurred during the save operation.
- **See also**: [`fd_runtime_save_slot_bank`](fd_runtime_init.c.driver.md#fd_runtime_save_slot_bank)  (Implementation)


---
### fd\_runtime\_save\_epoch\_bank<!-- {{#callable_declaration:fd_runtime_save_epoch_bank}} -->
Saves the current epoch bank state to persistent storage.
- **Description**: This function is used to save the current state of the epoch bank associated with a given execution slot context to persistent storage. It should be called when the epoch bank needs to be backed up, typically as part of a checkpointing or state-saving operation. The function prepares a record for the epoch bank, encodes its state, and publishes it to the storage system. It is important to ensure that the `slot_ctx` is properly initialized and contains valid data before calling this function. If the operation fails, an error code is returned, and the function logs a warning message.
- **Inputs**:
    - `slot_ctx`: A pointer to an `fd_exec_slot_ctx_t` structure representing the execution slot context. Must not be null and should be properly initialized with valid epoch bank data. The caller retains ownership.
- **Output**: Returns an integer status code. A return value of `FD_RUNTIME_EXECUTE_SUCCESS` indicates success, while any other value indicates an error occurred during the operation.
- **See also**: [`fd_runtime_save_epoch_bank`](fd_runtime_init.c.driver.md#fd_runtime_save_epoch_bank)  (Implementation)


---
### fd\_features\_restore<!-- {{#callable_declaration:fd_features_restore}} -->
Restores all known feature accounts from the accounts database.
- **Description**: Use this function to load all known feature accounts into the execution slot context when initializing a bank from a snapshot. It is typically called during the setup phase of a Solana runtime environment to ensure that all feature accounts are correctly restored. This function must be called with a valid execution slot context and runtime scratchpad, and it assumes that the accounts database is accessible and contains the necessary feature data.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the execution slot context. Must not be null, and the caller retains ownership.
    - `runtime_spad`: A pointer to an fd_spad_t structure used as a runtime scratchpad. Must not be null, and the caller retains ownership.
- **Output**: None
- **See also**: [`fd_features_restore`](fd_runtime_init.c.driver.md#fd_features_restore)  (Implementation)


---
### fd\_runtime\_recover\_banks<!-- {{#callable_declaration:fd_runtime_recover_banks}} -->
Recover slot_bank and epoch_bank from funk.
- **Description**: This function is used to recover the `slot_bank` and `epoch_bank` from the `funk` data structure associated with the provided execution slot context. It should be called when there is a need to restore these banks, typically during the initialization or recovery phase of a runtime environment. The function can optionally clear the existing `epoch_bank` and `slot_bank` data before recovery, based on the `clear_first` and `delete_first` flags, respectively. It is important to ensure that the `slot_ctx` and `runtime_spad` are properly initialized before calling this function. The function logs errors if it encounters issues during the recovery process, such as missing records or invalid data.
- **Inputs**:
    - `slot_ctx`: A pointer to an `fd_exec_slot_ctx_t` structure that contains the execution slot context. This must be a valid, non-null pointer, and the caller retains ownership.
    - `delete_first`: An integer flag indicating whether to clear the existing `slot_bank` data before recovery. A non-zero value means the data will be cleared.
    - `clear_first`: An integer flag indicating whether to clear the existing `epoch_bank` data before recovery. A non-zero value means the data will be cleared.
    - `runtime_spad`: A pointer to an `fd_spad_t` structure used for decoding operations. This must be a valid, non-null pointer, and the caller retains ownership.
- **Output**: None
- **See also**: [`fd_runtime_recover_banks`](fd_runtime_init.c.driver.md#fd_runtime_recover_banks)  (Implementation)


---
### fd\_runtime\_delete\_banks<!-- {{#callable_declaration:fd_runtime_delete_banks}} -->
Deletes the epoch bank and clears the slot bank in the execution slot context.
- **Description**: Use this function to delete the epoch bank and reset the slot bank within the provided execution slot context. This function is typically called when the banks need to be cleared or reset as part of a larger operation, such as cleaning up resources or preparing for a new execution cycle. It is important to ensure that the `slot_ctx` is properly initialized and valid before calling this function to avoid undefined behavior.
- **Inputs**:
    - `slot_ctx`: A pointer to an `fd_exec_slot_ctx_t` structure representing the execution slot context. This parameter must not be null and should be properly initialized before calling the function. The function will modify the contents of this structure by deleting the epoch bank and clearing the slot bank.
- **Output**: None
- **See also**: [`fd_runtime_delete_banks`](fd_runtime_init.c.driver.md#fd_runtime_delete_banks)  (Implementation)


