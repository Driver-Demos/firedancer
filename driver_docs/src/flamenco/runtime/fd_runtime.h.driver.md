# Purpose
The provided C header file, `fd_runtime.h`, is part of a larger software system, likely related to a blockchain or distributed ledger technology, given the terminology and structures used. This file serves as a comprehensive interface for the runtime environment of a system named "Flamenco." It includes a wide array of functionalities, constants, and data structures that are essential for managing and executing transactions, verifying data integrity, and handling various runtime operations. The file is structured to provide both macro definitions for constants and memory management, as well as function prototypes for transaction processing, block verification, and epoch management.

Key components of this header file include definitions for constants related to transaction execution and memory footprint management, which are crucial for optimizing performance and ensuring the system's scalability. The file also defines several data structures, such as `fd_execute_txn_task_info_t`, `fd_raw_block_txn_iter_t`, and `fd_poh_verifier_t`, which are used to manage transaction execution tasks, iterate over raw block transactions, and verify proof-of-history hashes, respectively. Additionally, the file provides a set of function prototypes that facilitate various runtime operations, such as transaction preparation, execution, and finalization, as well as block and microblock verification. This header file is intended to be included in other parts of the system, providing a public API for interacting with the runtime environment and ensuring consistent and efficient transaction processing across the system.
# Imports and Dependencies

---
- `stdarg.h`
- `../fd_flamenco_base.h`
- `fd_runtime_err.h`
- `fd_runtime_init.h`
- `fd_rocksdb.h`
- `fd_acc_mgr.h`
- `fd_hashes.h`
- `../features/fd_features.h`
- `fd_rent_lists.h`
- `../../ballet/poh/fd_poh.h`
- `../leaders/fd_leaders.h`
- `context/fd_exec_epoch_ctx.h`
- `context/fd_exec_slot_ctx.h`
- `context/fd_capture_ctx.h`
- `context/fd_exec_txn_ctx.h`
- `info/fd_runtime_block_info.h`
- `info/fd_instr_info.h`
- `../gossip/fd_gossip.h`
- `../repair/fd_repair.h`
- `../../disco/pack/fd_microblock.h`
- `info/fd_microblock_info.h`
- `../../ballet/bmtree/fd_wbmtree.h`
- `../../ballet/sbpf/fd_sbpf_loader.h`
- `fd_runtime_public.h`
- `../../util/tmpl/fd_map_dynamic.c`


# Global Variables

---
### fd\_acct\_addr\_null
- **Type**: `fd_acct_addr_t`
- **Description**: The `fd_acct_addr_null` is a constant of type `fd_acct_addr_t` that represents a null or invalid account address. It is initialized with a byte array of 32 bytes, all set to 0xFF, which is typically used to signify an uninitialized or invalid state in memory.
- **Use**: This variable is used as a sentinel value to represent an invalid or null account address in the system, often for comparison or initialization purposes.


# Data Structures

---
### fd\_execute\_txn\_task\_info
- **Type**: `struct`
- **Members**:
    - `spads`: A pointer to an array of fd_spad_t pointers, representing multiple shared memory pads.
    - `spad`: A pointer to a single fd_spad_t, representing a shared memory pad.
    - `txn_ctx`: A pointer to an fd_exec_txn_ctx_t, representing the execution context for a transaction.
    - `txn`: A pointer to an fd_txn_p_t, representing a transaction.
    - `exec_res`: An integer representing the execution result of the transaction.
- **Description**: The `fd_execute_txn_task_info` structure is designed to encapsulate all necessary information for executing a transaction task within a runtime environment. It includes pointers to shared memory pads (`spads` and `spad`), which are used for managing shared data during execution, a transaction context (`txn_ctx`) that provides the necessary execution environment, and a transaction (`txn`) that is to be executed. The `exec_res` field stores the result of the transaction execution, indicating success or failure. This structure is crucial for managing transaction execution tasks in a concurrent and shared memory environment.


---
### fd\_execute\_txn\_task\_info\_t
- **Type**: `struct`
- **Members**:
    - `spads`: A pointer to an array of fd_spad_t pointers, representing shared memory pads used in transaction execution.
    - `spad`: A pointer to a single fd_spad_t, representing a shared memory pad for transaction execution.
    - `txn_ctx`: A pointer to an fd_exec_txn_ctx_t, representing the context for executing a transaction.
    - `txn`: A pointer to an fd_txn_p_t, representing the transaction to be executed.
    - `exec_res`: An integer representing the result of the transaction execution.
- **Description**: The `fd_execute_txn_task_info_t` structure is designed to encapsulate all necessary information for executing a transaction task within the runtime environment. It includes pointers to shared memory pads (`spads` and `spad`) for managing memory during execution, a transaction context (`txn_ctx`) for maintaining execution state, a transaction pointer (`txn`) for the transaction being processed, and an execution result (`exec_res`) to store the outcome of the transaction execution. This structure is crucial for managing and executing transactions efficiently in a concurrent processing environment.


---
### fd\_raw\_block\_txn\_iter
- **Type**: `struct`
- **Members**:
    - `curr_batch`: A pointer to the current batch of block entries being processed.
    - `orig_data`: A pointer to the original data of the block.
    - `remaining_batches`: The number of batches left to process.
    - `remaining_microblocks`: The number of microblocks left to process.
    - `remaining_txns`: The number of transactions left to process.
    - `curr_offset`: The current offset within the data being processed.
    - `curr_txn_sz`: The size of the current transaction being processed.
- **Description**: The `fd_raw_block_txn_iter` structure is designed to facilitate the iteration over transactions within a raw block of data. It maintains pointers to the current batch and original data, and tracks the number of remaining batches, microblocks, and transactions to be processed. Additionally, it keeps track of the current offset within the data and the size of the current transaction, enabling efficient traversal and processing of block transactions.


---
### fd\_raw\_block\_txn\_iter\_t
- **Type**: `struct`
- **Members**:
    - `curr_batch`: A pointer to the current batch of block entries being processed.
    - `orig_data`: A pointer to the original data of the block.
    - `remaining_batches`: The number of batches left to process.
    - `remaining_microblocks`: The number of microblocks left to process.
    - `remaining_txns`: The number of transactions left to process.
    - `curr_offset`: The current offset within the data being processed.
    - `curr_txn_sz`: The size of the current transaction being processed.
- **Description**: The `fd_raw_block_txn_iter_t` structure is designed to facilitate the iteration over transactions within a raw block of data. It maintains pointers to the current batch and original data, and tracks the number of remaining batches, microblocks, and transactions to be processed. Additionally, it keeps track of the current offset and the size of the current transaction, enabling efficient traversal and processing of block data.


---
### fd\_poh\_verifier
- **Type**: `struct`
- **Members**:
    - `microblock`: A union that can hold either a pointer to a `fd_microblock_hdr_t` or a pointer to a raw `uchar` data.
    - `in_poh_hash`: A constant pointer to a `fd_hash_t` representing the hash in the Proof of History (PoH).
    - `microblk_max_sz`: An unsigned long representing the maximum size of the microblock.
    - `spad`: A pointer to an `fd_spad_t` structure, likely used for scratchpad memory.
    - `success`: An integer indicating the success status of the verification process.
- **Description**: The `fd_poh_verifier` structure is designed to facilitate the verification of microblocks in a Proof of History (PoH) system. It contains a union for handling microblock data either as a header or raw data, a hash pointer for PoH verification, a maximum size constraint for microblocks, a scratchpad pointer for auxiliary operations, and a success flag to indicate the outcome of the verification process.


---
### fd\_poh\_verifier\_t
- **Type**: `struct`
- **Members**:
    - `microblock`: A union containing either a pointer to a constant microblock header or a raw uchar pointer.
    - `in_poh_hash`: A pointer to a constant hash used in the Proof of History (PoH) verification.
    - `microblk_max_sz`: An unsigned long representing the maximum size of a microblock.
    - `spad`: A pointer to a shared page data structure used during verification.
    - `success`: An integer indicating the success status of the verification process.
- **Description**: The `fd_poh_verifier_t` structure is designed to facilitate the verification of microblocks in a Proof of History (PoH) system. It contains a union for accessing microblock data either as a header or raw data, a hash for PoH verification, and a maximum size constraint for microblocks. Additionally, it includes a shared page pointer for managing shared data during the verification process and a success flag to indicate the outcome of the verification.


---
### fd\_account\_rec
- **Type**: `struct`
- **Members**:
    - `meta`: A field of type `fd_account_meta_t` that stores metadata related to the account.
    - `data`: A flexible array member of type `uchar[]` that holds the account's data.
- **Description**: The `fd_account_rec` structure is a packed data structure that represents an account record, consisting of metadata and associated data. The `meta` field contains metadata about the account, while the `data` field is a flexible array member that can store variable-length data associated with the account. This structure is designed to ensure that the alignment requirements of its components are satisfied, and it is used to encode the layout of an account's metadata followed by its data in memory.


---
### fd\_account\_rec\_t
- **Type**: `struct`
- **Members**:
    - `meta`: Holds metadata about the account.
    - `data`: A flexible array member to store the account's data.
- **Description**: The `fd_account_rec_t` structure is a packed data structure that represents an account record in the runtime system. It consists of a metadata component (`meta`) and a flexible array member (`data`) that holds the account's data. The structure is designed to ensure that the alignment requirements of its components are satisfied, with a specified alignment of 8 bytes. This layout is used to manage the memory footprint during transaction execution, with the metadata followed by the account's data, ensuring efficient access and storage.


---
### fd\_runtime\_spad\_verify\_handle\_private
- **Type**: `struct`
- **Members**:
    - `spad`: A pointer to an fd_spad_t structure, representing a shared memory space for transaction execution.
    - `txn_ctx`: A pointer to an fd_exec_txn_ctx_t structure, representing the context for executing a transaction.
- **Description**: The `fd_runtime_spad_verify_handle_private` structure is a private data structure used within the runtime to manage the verification of shared memory spaces (spads) during transaction execution. It contains pointers to a shared memory space (`spad`) and a transaction execution context (`txn_ctx`), which are essential for managing and verifying the integrity of memory allocations and transaction execution states. This structure is typically used internally to ensure that memory operations are correctly handled and verified, preventing issues such as memory overflows or unbalanced memory operations.


---
### fd\_runtime\_spad\_verify\_handle\_private\_t
- **Type**: `struct`
- **Members**:
    - `spad`: A pointer to an fd_spad_t structure, representing a shared memory space for transaction execution.
    - `txn_ctx`: A pointer to an fd_exec_txn_ctx_t structure, representing the context for executing a transaction.
- **Description**: The `fd_runtime_spad_verify_handle_private_t` structure is a private data structure used within the runtime to manage and verify shared memory allocations (spads) during transaction execution. It contains pointers to a shared memory space (`spad`) and a transaction execution context (`txn_ctx`). This structure is primarily used to ensure that memory allocations are correctly managed and verified, preventing out-of-bounds errors and ensuring that the transaction execution context is properly maintained.


---
### fd\_conflict\_detect\_ele
- **Type**: `struct`
- **Members**:
    - `key`: A unique identifier of type `fd_acct_addr_t` for the account involved in the conflict detection.
    - `writable`: A `uchar` indicating if the account is writable (1 for writable, 0 for read-only).
- **Description**: The `fd_conflict_detect_ele` structure is used to represent an element in a conflict detection map for transactions. It contains a key, which is an account address, and a writable flag to indicate if the account is writable. This structure is part of a mechanism to detect read-write and write-write conflicts in transactions, ensuring that no two transactions attempt to modify the same account simultaneously, which is crucial for maintaining data integrity in concurrent transaction processing.


---
### fd\_conflict\_detect\_ele\_t
- **Type**: `struct`
- **Members**:
    - `key`: Represents the account address used as a key in conflict detection.
    - `writable`: Indicates if the account is writable (1) or read-only (0).
- **Description**: The `fd_conflict_detect_ele_t` structure is used to represent an element in a conflict detection map for transaction processing. It consists of a key, which is an account address, and a writable flag that indicates whether the account is writable or not. This structure is part of a mechanism to detect read-write or write-write conflicts among transactions, ensuring that transactions do not interfere with each other by accessing the same accounts in incompatible ways.


# Functions

---
### fd\_runtime\_spad\_private\_frame\_end<!-- {{#callable:fd_runtime_spad_private_frame_end}} -->
The function `fd_runtime_spad_private_frame_end` verifies the integrity of a shared private allocation descriptor (spad) and logs an error if corruption or overflow is detected, then pops the spad frame.
- **Inputs**:
    - `_spad_handle`: A pointer to a `fd_runtime_spad_verify_handle_private_t` structure containing the spad and transaction context to be verified and managed.
- **Control Flow**:
    - The function checks if the instruction stack size in the transaction context is at or above the maximum allowed depth minus one.
    - If the above condition is true, it calls `fd_spad_verify` to check the integrity of the spad.
    - If `fd_spad_verify` returns a non-zero value, indicating an error, it retrieves the transaction signature and logs an error message indicating spad corruption or overflow.
    - Finally, it calls `fd_spad_pop` to pop the spad frame.
- **Output**: The function does not return a value; it performs verification and logging as side effects.


# Function Declarations (Public API)

---
### block\_finalize\_tpool\_wrapper<!-- {{#callable_declaration:block_finalize_tpool_wrapper}} -->
Distributes and synchronizes tasks across a thread pool for block finalization.
- **Description**: This function is used to distribute tasks related to block finalization across multiple workers in a thread pool. It should be called when you need to execute tasks in parallel using a thread pool, particularly for operations that can be divided among multiple workers. The function ensures that each worker processes a portion of the task data and waits for all workers to complete their tasks before returning. It is important to ensure that the thread pool and task data are properly initialized before calling this function.
- **Inputs**:
    - `para_arg_1`: Pointer to the thread pool (fd_tpool_t *) used for executing tasks. Must not be null.
    - `para_arg_2`: Unused parameter. Can be null or any value.
    - `arg_1`: Pointer to the task data (fd_accounts_hash_task_data_t *) containing information about the tasks to be executed. Must not be null.
    - `arg_2`: Pointer to an unsigned long representing the number of workers. Must be a valid pointer and the value should be greater than zero.
    - `arg_3`: Pointer to the execution slot context (fd_exec_slot_ctx_t *) used during task execution. Must not be null.
    - `arg_4`: Unused parameter. Can be null or any value.
- **Output**: None
- **See also**: [`block_finalize_tpool_wrapper`](fd_runtime.c.driver.md#block_finalize_tpool_wrapper)  (Implementation)


---
### fd\_runtime\_compute\_max\_tick\_height<!-- {{#callable_declaration:fd_runtime_compute_max_tick_height}} -->
Compute the maximum tick height for a given slot and ticks per slot.
- **Description**: This function calculates the maximum tick height for a specified slot based on the number of ticks per slot. It should be used when you need to determine the upper limit of tick height for a given slot in a runtime environment. The function requires valid input values for ticks per slot and slot, and it will return an error if these values cause arithmetic overflow. The result is stored in the provided output parameter.
- **Inputs**:
    - `ticks_per_slot`: The number of ticks per slot, must be greater than 0 to avoid undefined behavior.
    - `slot`: The current slot number, used to calculate the next slot and determine the maximum tick height.
    - `out_max_tick_height`: A pointer to a ulong where the computed maximum tick height will be stored. Must not be null.
- **Output**: Returns 0 on success, indicating the maximum tick height was successfully computed and stored in out_max_tick_height. Returns a non-zero error code if an overflow occurs during computation.
- **See also**: [`fd_runtime_compute_max_tick_height`](fd_runtime.c.driver.md#fd_runtime_compute_max_tick_height)  (Implementation)


---
### fd\_runtime\_update\_leaders<!-- {{#callable_declaration:fd_runtime_update_leaders}} -->
Updates the leader schedule for a given slot.
- **Description**: This function is used to update the leader schedule for a specific slot within the execution context. It should be called when the leader schedule needs to be refreshed, typically during slot processing. The function requires a valid execution slot context and a runtime scratchpad for temporary data storage. It is important to ensure that the provided slot is within the valid range for the current epoch, as determined by the epoch schedule. The function does not return a value but may log errors if it encounters issues such as exceeding maximum allowed counts for stake weights or slots.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the execution context for the slot. Must not be null and should be properly initialized before calling this function.
    - `slot`: An unsigned long integer representing the slot number for which the leader schedule is to be updated. It should be within the valid range for the current epoch.
    - `runtime_spad`: A pointer to an fd_spad_t structure used as a scratchpad for temporary data storage during the update process. Must not be null and should have sufficient space for the operation.
- **Output**: None
- **See also**: [`fd_runtime_update_leaders`](fd_runtime.c.driver.md#fd_runtime_update_leaders)  (Implementation)


---
### fd\_runtime\_collect\_rent\_from\_account<!-- {{#callable_declaration:fd_runtime_collect_rent_from_account}} -->
Collects rent from an account if applicable.
- **Description**: This function is used to collect rent from a specified account based on the current slot, epoch, and rent schedule. It should be called when rent collection is required, typically during account maintenance operations. The function checks if rent collection is disabled via features and only collects rent if it is enabled. If the account is rent-exempt, it updates the rent epoch accordingly. This function assumes that the account and other parameters are properly initialized and valid.
- **Inputs**:
    - `slot`: The current slot number, which determines the timing of rent collection. Must be a valid slot number.
    - `schedule`: A pointer to the epoch schedule, which defines the timing and duration of epochs. Must not be null.
    - `rent`: A pointer to the rent configuration, which includes rent rates and exemptions. Must not be null.
    - `slots_per_year`: The number of slots in a year, used to calculate rent over time. Must be a positive double value.
    - `features`: A pointer to the features structure, which indicates if rent collection is disabled. Must not be null.
    - `acc`: A pointer to the account from which rent is to be collected. Must not be null and should be a valid account structure.
    - `epoch`: The current epoch number, used to determine rent exemptions and calculations. Must be a valid epoch number.
- **Output**: Returns the amount of rent collected as an unsigned long integer. Returns 0 if rent collection is disabled or if the account is rent-exempt.
- **See also**: [`fd_runtime_collect_rent_from_account`](fd_runtime.c.driver.md#fd_runtime_collect_rent_from_account)  (Implementation)


---
### fd\_runtime\_update\_slots\_per\_epoch<!-- {{#callable_declaration:fd_runtime_update_slots_per_epoch}} -->
Update the number of slots per epoch in the execution context.
- **Description**: This function updates the number of slots per epoch in the provided execution context. It should be called whenever the slots per epoch value changes to ensure the execution context is up-to-date. The function will adjust the partition width accordingly and trigger a repartitioning of fresh account partitions. It is important to ensure that the execution context is properly initialized before calling this function.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the execution context. Must not be null, and the context should be properly initialized before use.
    - `slots_per_epoch`: The new number of slots per epoch to be set in the execution context. It should be a valid unsigned long value.
- **Output**: None
- **See also**: [`fd_runtime_update_slots_per_epoch`](fd_runtime.c.driver.md#fd_runtime_update_slots_per_epoch)  (Implementation)


---
### fd\_runtime\_register\_new\_fresh\_account<!-- {{#callable_declaration:fd_runtime_register_new_fresh_account}} -->
Registers a new fresh account in the runtime context.
- **Description**: This function is used to register a new fresh account within the execution slot context, associating it with a given public key. It should be called when a new account needs to be added to the runtime's fresh account list. The function expects that there is available space in the fresh account list; otherwise, it will log an error and terminate the process. This function must be called with a valid execution slot context and a non-null public key.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the execution slot context. Must not be null. The caller retains ownership.
    - `pubkey`: A pointer to a constant fd_pubkey_t structure representing the public key of the new account. Must not be null. The caller retains ownership.
- **Output**: None
- **See also**: [`fd_runtime_register_new_fresh_account`](fd_runtime.c.driver.md#fd_runtime_register_new_fresh_account)  (Implementation)


---
### fd\_runtime\_block\_verify\_ticks<!-- {{#callable_declaration:fd_runtime_block_verify_ticks}} -->
Verifies the tick count and alignment in a block of data.
- **Description**: This function is used to verify the number of ticks and their alignment within a block of data in a blockstore. It should be called after epoch processing to ensure the block is complete and the ticks align with the expected hashes per tick. The function checks if the number of ticks matches the expected range and if the last entry is a tick. It returns specific error codes if the tick count is too high, too low, or if there are alignment issues. The function assumes the block is full and requires scratch memory for processing.
- **Inputs**:
    - `blockstore`: A pointer to an fd_blockstore_t structure representing the blockstore. Must not be null.
    - `slot`: An unsigned long representing the slot number to verify. Must be a valid slot in the blockstore.
    - `block_data_mem`: A pointer to a memory buffer where block data is stored. Must not be null and should have sufficient size for the block data.
    - `block_data_sz`: An unsigned long indicating the size of the block data in bytes. Must be greater than zero.
    - `tick_height`: An unsigned long representing the current tick height. Used to calculate the next tick height.
    - `max_tick_height`: An unsigned long representing the maximum allowable tick height. Used to ensure the tick count does not exceed this value.
    - `hashes_per_tick`: An unsigned long indicating the number of hashes expected per tick. Must be greater than zero.
- **Output**: Returns an unsigned long indicating the result of the verification. Returns FD_BLOCK_OK on success or specific error codes on failure, such as FD_BLOCK_ERR_TOO_MANY_TICKS, FD_BLOCK_ERR_TOO_FEW_TICKS, or FD_BLOCK_ERR_TRAILING_ENTRY.
- **See also**: [`fd_runtime_block_verify_ticks`](fd_runtime.c.driver.md#fd_runtime_block_verify_ticks)  (Implementation)


---
### fd\_runtime\_microblock\_verify\_ticks<!-- {{#callable_declaration:fd_runtime_microblock_verify_ticks}} -->
Verifies the tick count and transaction count in a microblock against expected values.
- **Description**: This function is used to verify that the tick count and transaction count in a microblock are consistent with the expected values for a given slot. It should be called during the processing of microblocks to ensure that the number of ticks and transactions align with the specified parameters. The function checks for various conditions such as too many or too few ticks, invalid tick hash counts, and trailing entries. It returns specific error codes if any of these conditions are violated, allowing the caller to handle these errors appropriately.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context, which must be valid and initialized before calling this function. The caller retains ownership.
    - `slot`: The slot number being verified. It should be a valid slot identifier within the context of the execution environment.
    - `hdr`: A pointer to the microblock header, which contains information about the transactions and hashes. This must not be null, and the caller retains ownership.
    - `slot_complete`: A boolean indicating whether the slot is complete. If true, additional checks are performed to ensure the slot ends correctly.
    - `tick_height`: The current tick height, which should be a non-negative value representing the number of ticks processed so far.
    - `max_tick_height`: The maximum allowed tick height for the slot, which should be a non-negative value. The function checks that the tick height does not exceed this value.
    - `hashes_per_tick`: The expected number of hashes per tick, which should be greater than zero. This value is used to verify the hash count in the microblock.
- **Output**: Returns an integer status code: 0 (FD_BLOCK_OK) on success, or a non-zero error code indicating the type of verification failure.
- **See also**: [`fd_runtime_microblock_verify_ticks`](fd_runtime.c.driver.md#fd_runtime_microblock_verify_ticks)  (Implementation)


---
### fd\_runtime\_microblock\_verify\_read\_write\_conflicts<!-- {{#callable_declaration:fd_runtime_microblock_verify_read_write_conflicts}} -->
Verifies read-write and write-write conflicts among transactions.
- **Description**: This function checks a list of transactions for read-write and write-write conflicts, which is essential for ensuring data consistency in concurrent transaction processing. It should be used when processing a batch of transactions to detect any conflicts that might prevent successful execution. The function requires a pre-allocated account map and account array for conflict detection and clearing purposes. It returns a runtime error if an error occurs during execution, or a specific conflict error if conflicts are detected. The function also provides detailed conflict information through output parameters.
- **Inputs**:
    - `txns`: An array of transactions to be verified for conflicts. The array must contain 'txn_cnt' transactions.
    - `txn_cnt`: The number of transactions in the 'txns' array. Must be a non-negative integer.
    - `acct_map`: A map used to detect conflicts among transactions. Must be pre-allocated and large enough to handle the expected number of accounts.
    - `acct_arr`: An array used to clear the account map before the function returns. Must be pre-allocated and large enough to handle the expected number of accounts.
    - `funk`: A pointer to a structure used for reading Solana accounts for address lookup tables. Must be valid and properly initialized.
    - `funk_txn`: A pointer to a structure used in conjunction with 'funk' for address lookup table operations. Must be valid and properly initialized.
    - `slot`: The slot number used for checking certain bounds in the address lookup table system program. Must be a valid slot number.
    - `slot_hashes`: An array of slot hashes used in address lookup table operations. Must be valid and properly initialized.
    - `features`: A pointer to a structure containing feature flags used to determine account writability. Must be valid and properly initialized.
    - `out_conflict_detected`: A pointer to an integer where the function will store the conflict detection result. Must not be null.
    - `out_conflict_addr_opt`: An optional pointer to store the address of the account causing the conflict, if any. Can be null if the address is not needed.
- **Output**: Returns a runtime error code if an error occurs, FD_RUNTIME_EXECUTE_SUCCESS if no conflict is detected, or FD_RUNTIME_TXN_ERR_ACCOUNT_IN_USE if a conflict is detected. The 'out_conflict_detected' parameter is set to indicate the type of conflict, and 'out_conflict_addr_opt' is set to the conflicting account address if provided.
- **See also**: [`fd_runtime_microblock_verify_read_write_conflicts`](fd_runtime.c.driver.md#fd_runtime_microblock_verify_read_write_conflicts)  (Implementation)


---
### fd\_runtime\_load\_txn\_address\_lookup\_tables<!-- {{#callable_declaration:fd_runtime_load_txn_address_lookup_tables}} -->
Load accounts from transaction address lookup tables into an output array.
- **Description**: This function is used to load accounts specified in the address lookup tables of a transaction into a provided output array. It should be called when processing transactions that may include address lookup tables, particularly for transactions with a version other than FD_TXN_V0. The function requires valid transaction and payload data, and it interacts with the provided funk and funk_txn structures to access account information. It returns specific error codes if any issues are encountered, such as missing or invalid address lookup tables.
- **Inputs**:
    - `txn`: A pointer to a constant fd_txn_t structure representing the transaction. It must not be null and should contain valid transaction data.
    - `payload`: A pointer to a constant uchar array representing the transaction payload. It must not be null and should contain the necessary data for address lookup.
    - `funk`: A pointer to an fd_funk_t structure used for accessing account information. It must not be null.
    - `funk_txn`: A pointer to an fd_funk_txn_t structure used in conjunction with funk for transaction-specific account access. It must not be null.
    - `slot`: An unsigned long representing the current slot number. It should be a valid slot value within the expected range.
    - `hashes`: A pointer to an fd_slot_hash_t structure used for hash-related operations. It must not be null.
    - `out_accts_alt`: A pointer to an fd_acct_addr_t array where the loaded accounts will be stored. It must be large enough to hold the accounts specified by the transaction's address lookup tables.
- **Output**: Returns an integer indicating success or a specific error code if an issue occurs during account loading.
- **See also**: [`fd_runtime_load_txn_address_lookup_tables`](fd_runtime.c.driver.md#fd_runtime_load_txn_address_lookup_tables)  (Implementation)


---
### fd\_runtime\_poh\_verify<!-- {{#callable_declaration:fd_runtime_poh_verify}} -->
Verifies the Proof of History (PoH) hashes for a given microblock.
- **Description**: This function is used to verify the integrity of PoH hashes while processing microblocks in a streaming manner. It should be called with a properly initialized `fd_poh_verifier_t` structure that contains the necessary microblock data and hash information. The function checks the consistency of the PoH hash against the expected hash in the microblock header. If a mismatch is detected, it logs a warning and sets the `success` field of the verifier structure to indicate failure. This function is typically used in environments where microblocks are processed sequentially, and hash verification is critical for maintaining data integrity.
- **Inputs**:
    - `poh_info`: A pointer to an `fd_poh_verifier_t` structure containing the microblock header, initial PoH hash, maximum microblock size, and a scratchpad for temporary data. The structure must be properly initialized before calling this function. The caller retains ownership and must ensure it is not null.
- **Output**: None
- **See also**: [`fd_runtime_poh_verify`](fd_runtime.c.driver.md#fd_runtime_poh_verify)  (Implementation)


---
### fd\_runtime\_block\_execute\_prepare<!-- {{#callable_declaration:fd_runtime_block_execute_prepare}} -->
Prepares the execution context for a runtime block.
- **Description**: This function is used to prepare the execution context for processing a runtime block. It should be called before executing transactions within a block to ensure that the execution context is properly initialized. The function resets various counters and fees in the slot context to zero and updates the block height if a blockstore is present. It also updates system variables using the provided scratchpad. This function must be called before any transaction execution to ensure the context is correctly set up.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the execution context for the slot. Must not be null. The function will reset various fields within this context.
    - `runtime_spad`: A pointer to an fd_spad_t structure used for runtime operations. Must not be null. It is used to update system variables before execution.
- **Output**: Returns an integer indicating success or failure. A return value of 0 indicates success, while a non-zero value indicates an error occurred during system variable updates.
- **See also**: [`fd_runtime_block_execute_prepare`](fd_runtime.c.driver.md#fd_runtime_block_execute_prepare)  (Implementation)


---
### fd\_runtime\_block\_execute\_finalize\_start<!-- {{#callable_declaration:fd_runtime_block_execute_finalize_start}} -->
Finalize the start of block execution by freezing the slot and preparing account hash data.
- **Description**: This function is used to finalize the start of block execution by freezing the current slot, updating the BPF program cache, and preparing the task data for account hash collection. It should be called when a slot is ready to be finalized and no further changes are expected. The function allocates memory for task data and initializes it for collecting modified account information. It is important to ensure that the slot context and runtime scratchpad are properly initialized before calling this function.
- **Inputs**:
    - `slot_ctx`: A pointer to the slot context, which must be valid and properly initialized. The caller retains ownership.
    - `runtime_spad`: A pointer to the runtime scratchpad, which must be valid and properly initialized. The caller retains ownership.
    - `task_data`: A pointer to a pointer where the function will allocate and store the task data for account hash collection. The caller must ensure this is a valid pointer and will take ownership of the allocated memory.
    - `lt_hash_cnt`: The number of hash values to allocate for the task data. It must be a non-negative value.
- **Output**: None
- **See also**: [`fd_runtime_block_execute_finalize_start`](fd_runtime.c.driver.md#fd_runtime_block_execute_finalize_start)  (Implementation)


---
### fd\_runtime\_block\_execute\_finalize\_finish<!-- {{#callable_declaration:fd_runtime_block_execute_finalize_finish}} -->
Finalize the execution of a runtime block.
- **Description**: This function is used to finalize the execution of a runtime block by updating the hash bank and saving the slot bank. It should be called after the block execution is complete and before the next block execution begins. The function ensures that the hash bank is updated with the latest transaction hashes and attempts to save the slot bank. If the slot bank cannot be saved, a warning is logged, and an error code is returned. The function resets the total compute units requested in the slot context to zero as a side effect.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context. Must not be null. The caller retains ownership.
    - `capture_ctx`: A pointer to the capture context. Must not be null. The caller retains ownership.
    - `block_info`: A pointer to the block information structure. Must not be null. The caller retains ownership.
    - `runtime_spad`: A pointer to the runtime scratchpad. Must not be null. The caller retains ownership.
    - `task_data`: A pointer to the accounts hash task data. Must not be null. The caller retains ownership.
    - `lt_hash_cnt`: The number of long-term hashes to process. Must be a valid unsigned long value.
- **Output**: Returns 0 on success, or a non-zero error code if an error occurs during hash bank update or slot bank saving.
- **See also**: [`fd_runtime_block_execute_finalize_finish`](fd_runtime.c.driver.md#fd_runtime_block_execute_finalize_finish)  (Implementation)


---
### fd\_runtime\_block\_execute\_finalize\_para<!-- {{#callable_declaration:fd_runtime_block_execute_finalize_para}} -->
Finalizes the execution of a runtime block in parallel.
- **Description**: This function is used to finalize the execution of a runtime block in a parallelized manner. It should be called after the block execution has been prepared and executed. The function sets up the necessary context for parallel execution and invokes a callback function to complete the finalization process. It is important to ensure that all input contexts and structures are properly initialized and valid before calling this function. The function assumes that the block execution is complete and ready for finalization.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the execution slot context. Must not be null.
    - `capture_ctx`: A pointer to an fd_capture_ctx_t structure used for capturing execution context. Must not be null.
    - `block_info`: A pointer to a constant fd_runtime_block_info_t structure containing information about the block. Must not be null.
    - `worker_cnt`: An unsigned long representing the number of workers to be used for parallel execution. Must be a positive number.
    - `runtime_spad`: A pointer to an fd_spad_t structure used for runtime scratchpad memory. Must not be null.
    - `exec_para_ctx`: A pointer to an fd_exec_para_cb_ctx_t structure used for setting up the parallel execution callback context. Must not be null.
- **Output**: Returns 0 on successful finalization.
- **See also**: [`fd_runtime_block_execute_finalize_para`](fd_runtime.c.driver.md#fd_runtime_block_execute_finalize_para)  (Implementation)


---
### fd\_runtime\_prepare\_txns\_start<!-- {{#callable_declaration:fd_runtime_prepare_txns_start}} -->
Prepares transaction contexts and task information for execution.
- **Description**: This function initializes the transaction contexts and task information for a given set of transactions, preparing them for execution. It should be called before executing transactions to ensure that all necessary contexts and resources are allocated and set up correctly. The function processes each transaction, setting up its context and checking for any errors during preparation. If an error occurs, it is recorded in the task information, and the function returns a non-zero result indicating failure. This function is typically used in transaction processing pipelines where transactions need to be prepared before execution.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context, which must be valid and properly initialized. The caller retains ownership.
    - `task_info`: An array of task information structures, one for each transaction, which will be populated by the function. Must not be null and must have at least txn_cnt elements.
    - `txns`: An array of transactions to be prepared, with each transaction represented by a pointer. Must not be null and must have at least txn_cnt elements.
    - `txn_cnt`: The number of transactions to prepare. Must be a non-negative integer.
    - `runtime_spad`: A pointer to the runtime scratchpad used for allocating transaction contexts. Must be valid and properly initialized. The caller retains ownership.
- **Output**: Returns 0 on success, or a non-zero error code if any transaction preparation fails. The task_info array is updated with the preparation results for each transaction.
- **See also**: [`fd_runtime_prepare_txns_start`](fd_runtime.c.driver.md#fd_runtime_prepare_txns_start)  (Implementation)


---
### fd\_runtime\_pre\_execute\_check<!-- {{#callable_declaration:fd_runtime_pre_execute_check}} -->
Performs pre-execution checks on a transaction task.
- **Description**: This function is used to perform a series of pre-execution checks on a transaction task, ensuring that the transaction is ready for execution. It should be called before executing a transaction to verify that all necessary conditions are met. The function checks if the transaction has been sanitized successfully, sets up accounts, optionally dumps the transaction to protobuf, and performs various validation checks. If any check fails, it updates the task information with the error and halts further processing of the transaction.
- **Inputs**:
    - `task_info`: A pointer to a fd_execute_txn_task_info_t structure containing information about the transaction task. Must not be null. The function updates this structure with execution results and error flags if any checks fail.
    - `dump_txn`: An unsigned character flag indicating whether to dump the transaction to protobuf. A non-zero value enables dumping.
- **Output**: None
- **See also**: [`fd_runtime_pre_execute_check`](fd_runtime.c.driver.md#fd_runtime_pre_execute_check)  (Implementation)


---
### fd\_runtime\_process\_txns\_in\_microblock\_stream<!-- {{#callable_declaration:fd_runtime_process_txns_in_microblock_stream}} -->
Processes transactions in a microblock stream using multiple execution contexts.
- **Description**: This function is used to process a list of transactions in a microblock stream, leveraging multiple execution contexts for parallel processing. It is suitable for scenarios where transactions are known to be conflict-free and can be executed concurrently. The function requires a valid execution slot context, a capture context, and a transaction pool for task management. It also optionally uses a cost tracker to monitor transaction costs, which is particularly relevant during offline replay. The function returns an error code if any issues occur during processing, such as exceeding cost limits.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the execution slot context. Must not be null.
    - `capture_ctx`: A pointer to an fd_capture_ctx_t structure used for capturing execution data. Must not be null.
    - `txns`: An array of fd_txn_p_t structures representing the transactions to be processed. The array must contain at least txn_cnt elements.
    - `txn_cnt`: The number of transactions in the txns array. Must be greater than zero.
    - `tpool`: A pointer to an fd_tpool_t structure representing the thread pool used for executing tasks. Must not be null.
    - `exec_spads`: An array of pointers to fd_spad_t structures representing the execution scratchpads. The array must contain at least exec_spad_cnt elements.
    - `exec_spad_cnt`: The number of execution scratchpads available in the exec_spads array. Must be greater than zero.
    - `runtime_spad`: A pointer to an fd_spad_t structure used as the runtime scratchpad. Must not be null.
    - `cost_tracker_opt`: An optional pointer to an fd_cost_tracker_t structure used for tracking transaction costs. Can be null if cost tracking is not required.
- **Output**: Returns 0 on success or a non-zero error code if a failure occurs, such as exceeding cost limits.
- **See also**: [`fd_runtime_process_txns_in_microblock_stream`](fd_runtime.c.driver.md#fd_runtime_process_txns_in_microblock_stream)  (Implementation)


---
### fd\_runtime\_finalize\_txn<!-- {{#callable_declaration:fd_runtime_finalize_txn}} -->
Finalize a transaction by updating slot context and handling transaction status.
- **Description**: This function is used to finalize a transaction by updating the slot context with transaction fees, signature counts, and compute units used. It also handles transaction status logging if a capture context is provided and meets certain conditions. The function should be called after a transaction has been executed to ensure that all relevant transaction data is properly recorded and any necessary rollbacks are performed in case of errors. It is important to ensure that all input contexts are properly initialized and valid before calling this function.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the execution slot context. Must not be null and should be properly initialized before calling this function.
    - `capture_ctx`: A pointer to an fd_capture_ctx_t structure used for capturing transaction status. Can be null if capturing is not required.
    - `task_info`: A pointer to an fd_execute_txn_task_info_t structure containing information about the transaction task. Must not be null and should be properly initialized.
    - `finalize_spad`: A pointer to an fd_spad_t structure used for finalization operations. Must not be null and should be properly initialized.
- **Output**: None
- **See also**: [`fd_runtime_finalize_txn`](fd_runtime.c.driver.md#fd_runtime_finalize_txn)  (Implementation)


---
### fd\_runtime\_is\_epoch\_boundary<!-- {{#callable_declaration:fd_runtime_is_epoch_boundary}} -->
Determine if a slot transition marks an epoch boundary.
- **Description**: Use this function to check if the transition from a previous slot to a current slot signifies the start of a new epoch. This is useful in scenarios where epoch-specific processing is required. The function should be called with valid slot numbers and an initialized epoch bank. It returns a non-zero value if the transition is an epoch boundary, otherwise it returns zero.
- **Inputs**:
    - `epoch_bank`: A pointer to an fd_epoch_bank_t structure that contains the epoch schedule. Must not be null.
    - `curr_slot`: The current slot number as an unsigned long. Should be a valid slot number within the expected range.
    - `prev_slot`: The previous slot number as an unsigned long. Should be a valid slot number within the expected range.
- **Output**: Returns a non-zero value if the transition from prev_slot to curr_slot is an epoch boundary, otherwise returns zero.
- **See also**: [`fd_runtime_is_epoch_boundary`](fd_runtime.c.driver.md#fd_runtime_is_epoch_boundary)  (Implementation)


---
### fd\_runtime\_block\_pre\_execute\_process\_new\_epoch<!-- {{#callable_declaration:fd_runtime_block_pre_execute_process_new_epoch}} -->
Processes a new epoch during block pre-execution.
- **Description**: This function is used to handle the transition to a new epoch during the pre-execution phase of a block. It updates the block height and checks if the current slot marks an epoch boundary. If an epoch boundary is detected, it processes the new epoch and sets the `is_epoch_boundary` flag accordingly. This function should be called as part of the block pre-execution process to ensure proper epoch handling and reward distribution.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context, which must not be null. It contains information about the current slot and block.
    - `tpool`: A pointer to the thread pool used for parallel processing, which must not be null.
    - `exec_spads`: An array of pointers to execution scratchpads, which must not be null. The array should have at least `exec_spad_cnt` elements.
    - `exec_spad_cnt`: The number of execution scratchpads in the `exec_spads` array. It should be a positive number.
    - `runtime_spad`: A pointer to the runtime scratchpad, which must not be null. It is used for temporary storage during execution.
    - `is_epoch_boundary`: A pointer to an integer that will be set to 1 if the current slot is an epoch boundary, or 0 otherwise. It must not be null.
- **Output**: None
- **See also**: [`fd_runtime_block_pre_execute_process_new_epoch`](fd_runtime.c.driver.md#fd_runtime_block_pre_execute_process_new_epoch)  (Implementation)


---
### fd\_runtime\_checkpt<!-- {{#callable_declaration:fd_runtime_checkpt}} -->
Performs a checkpoint operation based on the current slot and capture context.
- **Description**: This function is used to perform a checkpoint operation during runtime execution, which is triggered based on the current slot number and the checkpoint frequency specified in the capture context. It should be called during the execution process to ensure that the state is saved at regular intervals or when an abort condition is met. The function will log the checkpointing action and attempt to save the current state to a specified file path. If the checkpoint path is not set, the function will not perform any file operations. It is important to ensure that the capture context and slot context are properly initialized before calling this function.
- **Inputs**:
    - `capture_ctx`: A pointer to an fd_capture_ctx_t structure that contains the checkpoint frequency and path. Must not be null if checkpointing is desired. If null, the function will not perform any checkpointing.
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the current execution slot context. Must be valid and properly initialized.
    - `slot`: An unsigned long integer representing the current slot number. If this is equal to ULONG_MAX, an abort checkpoint is triggered.
- **Output**: None
- **See also**: [`fd_runtime_checkpt`](fd_runtime.c.driver.md#fd_runtime_checkpt)  (Implementation)


---
### fd\_raw\_block\_txn\_iter\_init<!-- {{#callable_declaration:fd_raw_block_txn_iter_init}} -->
Initializes a transaction iterator for a raw block.
- **Description**: Use this function to initialize an iterator for processing transactions within a raw block of data. It sets up the iterator to traverse through the transactions based on the provided batches and batch count. This function is typically called at the beginning of transaction processing to prepare the iterator for subsequent operations. Ensure that the input data and batches are valid and properly formatted before calling this function.
- **Inputs**:
    - `orig_data`: A pointer to the original data buffer containing the raw block. Must not be null and should point to a valid memory region.
    - `batches`: A pointer to an array of fd_block_entry_batch_t structures representing the batches in the block. Must not be null and should point to a valid array of batch structures.
    - `batch_cnt`: The number of batches in the block. Must be a non-negative integer representing the count of batches in the array.
- **Output**: Returns an initialized fd_raw_block_txn_iter_t structure for iterating over transactions in the raw block.
- **See also**: [`fd_raw_block_txn_iter_init`](fd_runtime.c.driver.md#fd_raw_block_txn_iter_init)  (Implementation)


---
### fd\_raw\_block\_txn\_iter\_done<!-- {{#callable_declaration:fd_raw_block_txn_iter_done}} -->
Checks if a transaction iterator has completed all transactions.
- **Description**: Use this function to determine if a transaction iterator has processed all its transactions, microblocks, and batches. It is typically called in a loop to check for completion of transaction processing. Ensure that the iterator is properly initialized before calling this function.
- **Inputs**:
    - `iter`: A transaction iterator of type `fd_raw_block_txn_iter_t`. It must be initialized and valid. The function checks the iterator's internal counters to determine if all transactions have been processed.
- **Output**: Returns a non-zero value if the iterator has completed all transactions, microblocks, and batches; otherwise, it returns zero.
- **See also**: [`fd_raw_block_txn_iter_done`](fd_runtime.c.driver.md#fd_raw_block_txn_iter_done)  (Implementation)


---
### fd\_raw\_block\_txn\_iter\_next<!-- {{#callable_declaration:fd_raw_block_txn_iter_next}} -->
Advances the transaction iterator to the next transaction.
- **Description**: Use this function to move the transaction iterator to the next transaction within a raw block. It should be called repeatedly to iterate over all transactions in a block. The function updates the iterator's current offset and transaction size, and it handles parsing of transactions. It must be called with a valid iterator that has been initialized using `fd_raw_block_txn_iter_init`. The function will return an updated iterator, and if there are no more transactions, it will attempt to find the next transaction in the raw block.
- **Inputs**:
    - `iter`: A transaction iterator of type `fd_raw_block_txn_iter_t`. It must be initialized and valid. The iterator is updated to point to the next transaction.
- **Output**: Returns an updated `fd_raw_block_txn_iter_t` pointing to the next transaction, or attempts to find the next transaction if the current batch is exhausted.
- **See also**: [`fd_raw_block_txn_iter_next`](fd_runtime.c.driver.md#fd_raw_block_txn_iter_next)  (Implementation)


---
### fd\_raw\_block\_txn\_iter\_ele<!-- {{#callable_declaration:fd_raw_block_txn_iter_ele}} -->
Extracts a transaction from the current position of the iterator.
- **Description**: Use this function to extract a transaction from the current position of a transaction iterator. It is expected that the iterator is properly initialized and points to a valid transaction within a batch. The function will parse the transaction data and populate the provided transaction structure. Ensure that the iterator is not at the end of the batch to avoid errors. This function should be called in a context where transaction parsing errors can be handled appropriately.
- **Inputs**:
    - `iter`: A transaction iterator that must be initialized and point to a valid transaction within a batch. The iterator should not be at the end of the batch.
    - `out_txn`: A pointer to a transaction structure where the parsed transaction data will be stored. The caller must ensure this pointer is valid and points to a writable memory location.
- **Output**: None
- **See also**: [`fd_raw_block_txn_iter_ele`](fd_runtime.c.driver.md#fd_raw_block_txn_iter_ele)  (Implementation)


---
### fd\_runtime\_block\_eval\_tpool<!-- {{#callable_declaration:fd_runtime_block_eval_tpool}} -->
Evaluates a block using a thread pool and updates transaction count.
- **Description**: This function is used to evaluate a block in the context of a given execution slot, utilizing a thread pool for parallel processing. It should be called when a block needs to be processed and verified, and it updates the transaction count based on the block's contents. The function requires a valid execution slot context, block, capture context, and thread pool. It also requires scratchpad memory for execution and runtime operations. The function returns an error code if the evaluation fails, otherwise it returns 0 on success.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the execution slot context. Must not be null.
    - `block`: A pointer to an fd_block_t structure representing the block to be evaluated. Must not be null.
    - `capture_ctx`: A pointer to an fd_capture_ctx_t structure for capturing context during execution. Can be null if capturing is not required.
    - `tpool`: A pointer to an fd_tpool_t structure representing the thread pool to be used for execution. Must not be null.
    - `scheduler`: An unsigned long integer representing the scheduler identifier. This parameter is currently unused.
    - `txn_cnt`: A pointer to an unsigned long where the transaction count will be stored. Must not be null.
    - `exec_spads`: A pointer to an array of fd_spad_t pointers used for execution scratchpad memory. Must not be null.
    - `exec_spad_cnt`: An unsigned long indicating the number of execution scratchpads available. Must be greater than zero.
    - `runtime_spad`: A pointer to an fd_spad_t structure used for runtime scratchpad memory. Must not be null.
- **Output**: Returns 0 on success, or an error code if the block evaluation fails.
- **See also**: [`fd_runtime_block_eval_tpool`](fd_runtime.c.driver.md#fd_runtime_block_eval_tpool)  (Implementation)


---
### fd\_runtime\_block\_execute\_tpool<!-- {{#callable_declaration:fd_runtime_block_execute_tpool}} -->
Executes a block of transactions using a thread pool.
- **Description**: This function is used to execute a block of transactions in a parallelized manner using a thread pool. It should be called when a block of transactions needs to be processed efficiently, leveraging multiple threads for execution. The function requires a valid execution slot context, block information, and a thread pool to manage the execution. It also supports optional transaction capture for debugging or analysis purposes. The function handles transaction preparation, execution, and finalization, and returns a status code indicating success or the type of error encountered.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the execution slot context. Must not be null.
    - `capture_ctx`: A pointer to an fd_capture_ctx_t structure for capturing transaction execution details. Can be null if capture is not needed.
    - `block_info`: A pointer to a constant fd_runtime_block_info_t structure containing information about the block to be executed. Must not be null.
    - `tpool`: A pointer to an fd_tpool_t structure representing the thread pool to be used for execution. Must not be null.
    - `exec_spads`: An array of pointers to fd_spad_t structures used for execution. Must not be null and should have at least exec_spad_cnt elements.
    - `exec_spad_cnt`: The number of execution spads available in the exec_spads array. Must be greater than zero.
    - `runtime_spad`: A pointer to an fd_spad_t structure used for runtime operations. Must not be null.
- **Output**: Returns an integer status code indicating success (FD_RUNTIME_EXECUTE_SUCCESS) or an error code if execution fails.
- **See also**: [`fd_runtime_block_execute_tpool`](fd_runtime.c.driver.md#fd_runtime_block_execute_tpool)  (Implementation)


---
### fd\_runtime\_read\_genesis<!-- {{#callable_declaration:fd_runtime_read_genesis}} -->
Reads and processes the genesis block from a specified file.
- **Description**: This function is used to read and process the genesis block from a file specified by the given file path. It initializes various runtime structures based on the genesis data. This function should be called during the initialization phase of the runtime, before any transactions are processed. The function handles errors related to file access and decoding, logging them appropriately. It is important to ensure that the file path is valid and points to a readable genesis file. The function does not perform any operations if the file path is an empty string.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure, which provides context for the execution slot. Must not be null.
    - `genesis_filepath`: A constant character pointer representing the file path to the genesis file. Must not be an empty string, and the file must be accessible and readable.
    - `is_snapshot`: An unsigned character flag indicating whether the genesis block is a snapshot. A non-zero value indicates a snapshot, while zero indicates a full genesis block.
    - `capture_ctx`: A pointer to an fd_capture_ctx_t structure used for capturing execution context. Must not be null.
    - `runtime_spad`: A pointer to an fd_spad_t structure used for runtime memory allocation. Must not be null.
- **Output**: None
- **See also**: [`fd_runtime_read_genesis`](fd_runtime.c.driver.md#fd_runtime_read_genesis)  (Implementation)


