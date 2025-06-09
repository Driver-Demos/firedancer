# Purpose
This C source file is part of a larger system that manages the state of "banks" within an execution context, likely in a blockchain or distributed ledger environment. The file provides functions to save, recover, and delete the state of epoch and slot banks, as well as to restore features from an accounts database. The primary functions include [`fd_runtime_save_epoch_bank`](#fd_runtime_save_epoch_bank) and [`fd_runtime_save_slot_bank`](#fd_runtime_save_slot_bank), which handle the serialization and storage of bank states, and [`fd_runtime_recover_banks`](#fd_runtime_recover_banks), which retrieves and deserializes these states. The file also includes [`fd_runtime_delete_banks`](#fd_runtime_delete_banks) for clearing bank states and [`fd_features_restore`](#fd_features_restore) for updating the feature activation state based on account data.

The code is structured to interact with a transactional system, using a "funk" object to manage records and transactions. It employs a binary encoding scheme for data serialization and deserialization, ensuring data integrity through checks like magic numbers. The file does not depend on `fd_executor.h`, indicating a modular design where this file's functionality is self-contained and focused on bank state management. The use of logging and error handling throughout the code suggests a robust approach to managing potential issues during execution. This file is likely part of a library or module that is integrated into a larger application, providing specific functionality related to state management and feature activation within an execution context.
# Imports and Dependencies

---
- `fd_runtime_init.h`
- `fd_runtime_err.h`
- `stdio.h`
- `../types/fd_types.h`
- `context/fd_exec_epoch_ctx.h`
- `context/fd_exec_slot_ctx.h`
- `../../ballet/lthash/fd_lthash.h`
- `fd_system_ids.h`


# Functions

---
### fd\_runtime\_save\_epoch\_bank<!-- {{#callable:fd_runtime_save_epoch_bank}} -->
The `fd_runtime_save_epoch_bank` function saves the current state of an epoch bank to persistent storage using a transactional record system.
- **Inputs**:
    - `slot_ctx`: A pointer to an `fd_exec_slot_ctx_t` structure, which contains context information for the current execution slot, including the epoch context and transaction information.
- **Control Flow**:
    - Retrieve the epoch bank from the epoch context within the provided slot context.
    - Calculate the size required to store the epoch bank data, including a header for encoding.
    - Generate a unique key for the epoch bank record and prepare a transactional record for saving the bank data.
    - If the record preparation fails, log a warning and return the error code.
    - Allocate a buffer for the record's value and truncate it to the calculated size, logging an error if this fails.
    - Store a binary encoding header in the buffer and set up an encoding context for the epoch bank data.
    - Encode the epoch bank data into the buffer; if encoding fails, log a warning, cancel the record preparation, and return an error code.
    - Ensure the encoding context's data pointer matches the end of the buffer to verify successful encoding.
    - Publish the prepared record to make the changes persistent.
    - Log a debug message indicating the epoch has been frozen with relevant slot and hash information.
    - Return a success code indicating the operation completed successfully.
- **Output**: Returns an integer status code, where `FD_RUNTIME_EXECUTE_SUCCESS` indicates success, and other values indicate specific errors encountered during the process.
- **Functions called**:
    - [`fd_funk_rec_key_t::fd_runtime_epoch_bank_key`](fd_runtime_init.h.driver.md#fd_funk_rec_key_tfd_runtime_epoch_bank_key)


---
### fd\_runtime\_save\_slot\_bank<!-- {{#callable:fd_runtime_save_slot_bank}} -->
The `fd_runtime_save_slot_bank` function saves the current state of a slot bank into a persistent storage using a transaction context.
- **Inputs**:
    - `slot_ctx`: A pointer to an `fd_exec_slot_ctx_t` structure, which contains the context for the current execution slot, including the slot bank and transaction information.
- **Control Flow**:
    - Calculate the size needed to store the slot bank data, including a header size for encoding.
    - Generate a unique key for the slot bank record using `fd_runtime_slot_bank_key()`.
    - Remove any existing record for the slot bank in the persistent storage using `fd_funk_rec_hard_remove()`.
    - Prepare a new record for the slot bank using `fd_funk_rec_prepare()`, handling any errors that occur.
    - Allocate and truncate a buffer for the slot bank data using `fd_funk_val_truncate()`, logging an error if it fails.
    - Store a magic number in the buffer to indicate the encoding format.
    - Initialize a binary encoding context for the slot bank data.
    - Encode the slot bank data into the buffer using `fd_slot_bank_encode()`, canceling the record preparation if encoding fails.
    - Check that the encoding filled the buffer exactly, logging an error if it did not.
    - Publish the prepared record to make the changes permanent.
    - Log a debug message indicating the slot bank has been frozen and saved.
- **Output**: Returns an integer status code, `FD_RUNTIME_EXECUTE_SUCCESS` on success, or an error code if an error occurs during the process.
- **Functions called**:
    - [`fd_runtime_slot_bank_key`](fd_runtime_init.h.driver.md#fd_runtime_slot_bank_key)


---
### fd\_runtime\_recover\_banks<!-- {{#callable:fd_runtime_recover_banks}} -->
The `fd_runtime_recover_banks` function recovers and initializes the epoch and slot banks from persistent storage, optionally clearing or deleting existing data first.
- **Inputs**:
    - `slot_ctx`: A pointer to the `fd_exec_slot_ctx_t` structure, which contains context information for the execution slot, including pointers to the funk and transaction.
    - `delete_first`: An integer flag indicating whether to delete the existing slot bank data before recovery.
    - `clear_first`: An integer flag indicating whether to clear the existing epoch bank memory before recovery.
    - `runtime_spad`: A pointer to the `fd_spad_t` structure used for temporary storage during decoding operations.
- **Control Flow**:
    - Initialize pointers to the funk, transaction, and epoch context from the slot context.
    - Enter a loop to recover the epoch bank:
    -   - Retrieve the epoch bank record key and query the global funk record.
    -   - Check if the record is missing or empty, logging an error if so.
    -   - Verify the magic number in the record value to ensure it is valid.
    -   - If `clear_first` is true, clear the epoch bank memory.
    -   - Decode the epoch bank from the record value using the runtime spad, logging a warning and returning on error.
    -   - Assign the decoded epoch bank to the epoch context and log a notice.
    -   - Break the loop if the query test fails.
    - Enter a loop to recover the slot bank:
    -   - If `delete_first` is true, clear the slot bank data in the slot context.
    -   - Retrieve the slot bank record key and query the global funk record.
    -   - Check if the record is missing or empty, logging an error if so.
    -   - Verify the magic number in the record value to ensure it is valid.
    -   - Decode the slot bank from the record value using the runtime spad, logging an error on failure.
    -   - Assign the decoded slot bank to the slot context (with a note that this should be improved).
    -   - If the query test passes, set `delete_first` to true and continue the loop.
    -   - Log a notice with details of the recovered slot bank.
    -   - Reset various counters in the slot bank and break the loop.
- **Output**: The function does not return a value; it modifies the `slot_ctx` to reflect the recovered epoch and slot banks.
- **Functions called**:
    - [`fd_funk_rec_key_t::fd_runtime_epoch_bank_key`](fd_runtime_init.h.driver.md#fd_funk_rec_key_tfd_runtime_epoch_bank_key)
    - [`fd_exec_epoch_ctx_bank_mem_clear`](context/fd_exec_epoch_ctx.c.driver.md#fd_exec_epoch_ctx_bank_mem_clear)
    - [`fd_runtime_slot_bank_key`](fd_runtime_init.h.driver.md#fd_runtime_slot_bank_key)


---
### fd\_runtime\_delete\_banks<!-- {{#callable:fd_runtime_delete_banks}} -->
The `fd_runtime_delete_banks` function deletes the epoch bank and clears the slot bank in the given execution slot context.
- **Inputs**:
    - `slot_ctx`: A pointer to an `fd_exec_slot_ctx_t` structure, which contains the execution slot context including the epoch and slot banks to be deleted and cleared.
- **Control Flow**:
    - Call [`fd_exec_epoch_ctx_epoch_bank_delete`](context/fd_exec_epoch_ctx.c.driver.md#fd_exec_epoch_ctx_epoch_bank_delete) with `slot_ctx->epoch_ctx` to delete the epoch bank associated with the execution context.
    - Use `memset` to clear the memory of `slot_ctx->slot_bank` by setting it to zero, effectively clearing the slot bank.
- **Output**: This function does not return any value; it performs operations directly on the provided `slot_ctx` structure.
- **Functions called**:
    - [`fd_exec_epoch_ctx_epoch_bank_delete`](context/fd_exec_epoch_ctx.c.driver.md#fd_exec_epoch_ctx_epoch_bank_delete)


---
### fd\_feature\_restore<!-- {{#callable:fd_feature_restore}} -->
The `fd_feature_restore` function restores a feature from the accounts database and updates the bank's feature activation state based on a given feature account address.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context (`fd_exec_slot_ctx_t`) which contains information about the current execution slot.
    - `id`: A constant pointer to the feature ID (`fd_feature_id_t`) that identifies the feature to be restored.
    - `acct`: A constant array of 32 unsigned characters representing the account address associated with the feature.
    - `runtime_spad`: A pointer to the runtime scratchpad (`fd_spad_t`) used for temporary storage during the function execution.
- **Control Flow**:
    - Check if the feature ID is marked as reverted and return immediately if true.
    - Initialize a transaction account record from the account address in a read-only mode; return if initialization fails.
    - Verify if the account is owned by the feature program; return if it is not.
    - Check if the account data size is at least 9 bytes (FD_FEATURE_SIZEOF); return if it is not.
    - Begin a scratchpad frame to deserialize the feature account data into a `fd_feature_t` structure.
    - If deserialization fails, return immediately.
    - If the feature has an activation timestamp, log the activation and update the feature set in the epoch context.
    - If the feature does not have an activation timestamp, log that it is not activated.
    - End the scratchpad frame, automatically cleaning up temporary allocations.
- **Output**: The function does not return a value; it updates the feature activation state in the execution slot context if applicable.


---
### FD\_SPAD\_FRAME\_BEGIN<!-- {{#callable:fd_feature_restore::FD_SPAD_FRAME_BEGIN}} -->
The `FD_SPAD_FRAME_BEGIN` function decodes a feature from account data and logs its activation status, updating the feature set if activated.
- **Inputs**:
    - `runtime_spad`: A pointer to a shared memory allocator used for decoding the feature data.
- **Control Flow**:
    - Initialize a variable `decode_err` to track decoding errors.
    - Call `fd_bincode_decode_spad` to decode the feature data from the account record using the `runtime_spad` allocator.
    - Check if `decode_err` is set, and return immediately if a decoding error occurred.
    - If the feature has an activation timestamp (`has_activated_at` is true), log the activation and update the feature set in the epoch context with the activation time.
    - If the feature is not activated, log a debug message indicating the feature is not activated.
    - The function does not call a destroy function for the feature, as it uses the `fd_spad` allocator.
- **Output**: The function does not return any value; it performs logging and updates the feature set if applicable.


---
### fd\_features\_restore<!-- {{#callable:fd_features_restore}} -->
The `fd_features_restore` function iterates over all feature IDs and restores each feature's state using the [`fd_feature_restore`](#fd_feature_restore) function.
- **Inputs**:
    - `slot_ctx`: A pointer to an `fd_exec_slot_ctx_t` structure, which contains the execution context for a slot.
    - `runtime_spad`: A pointer to an `fd_spad_t` structure, which is used for temporary storage during the restoration process.
- **Control Flow**:
    - Initialize an iterator for feature IDs using `fd_feature_iter_init()`.
    - Loop through each feature ID until `fd_feature_iter_done(id)` returns true.
    - For each feature ID, call [`fd_feature_restore`](#fd_feature_restore) with the current `slot_ctx`, feature ID, feature account key, and `runtime_spad`.
- **Output**: The function does not return a value; it performs operations to restore feature states within the provided execution context.
- **Functions called**:
    - [`fd_feature_restore`](#fd_feature_restore)


