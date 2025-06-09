# Purpose
This C header file defines the interface for managing a system variable related to recent block hashes within a runtime environment, likely part of a blockchain or distributed ledger system. It includes necessary type definitions and dependencies from other modules, such as `fd_types.h`, `fd_flamenco_base.h`, and `fd_funk.h`. The file sets a constant, `FD_SYSVAR_RECENT_HASHES_CAP`, which limits the number of block hash entries to 150. It declares three functions: [`fd_sysvar_recent_hashes_init`](#fd_sysvar_recent_hashes_init) for initializing the recent hashes system variable account, [`fd_sysvar_recent_hashes_update`](#fd_sysvar_recent_hashes_update) for updating this account at the start of each slot, and [`fd_sysvar_recent_hashes_read`](#fd_sysvar_recent_hashes_read) for reading the recent hashes from a data structure called "funk," returning a pointer to the global recent block hashes if available. This header is crucial for maintaining and accessing recent block hash data efficiently within the system.
# Imports and Dependencies

---
- `../../types/fd_types.h`
- `../../fd_flamenco_base.h`
- `../../../funk/fd_funk.h`


# Global Variables

---
### fd\_sysvar\_recent\_hashes\_read
- **Type**: `fd_recent_block_hashes_global_t *`
- **Description**: The `fd_sysvar_recent_hashes_read` is a function that returns a pointer to a `fd_recent_block_hashes_global_t` structure. This function is used to read the recent block hashes system variable from a given data structure referred to as 'funk'. If the account does not exist or has zero lamports, it returns NULL.
- **Use**: This function is used to access the recent block hashes system variable, providing a mechanism to retrieve the latest block hash entries from the 'funk' data structure.


# Function Declarations (Public API)

---
### fd\_sysvar\_recent\_hashes\_init<!-- {{#callable_declaration:fd_sysvar_recent_hashes_init}} -->
Initialize the recent hashes sysvar account.
- **Description**: This function initializes the recent hashes sysvar account, which is a necessary step before any operations involving recent block hashes can be performed. It should be called when setting up the execution context for a slot, specifically when the slot number is zero. The function prepares the sysvar by allocating memory in the provided scratchpad and encoding the recent block hashes from the slot context. It is important to ensure that the slot context and runtime scratchpad are properly initialized before calling this function.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the execution context for a slot. The slot number within this context must be zero for the function to proceed with initialization. The caller retains ownership and must ensure it is valid and properly initialized.
    - `runtime_spad`: A pointer to an fd_spad_t structure used as a scratchpad for runtime operations. The function will allocate memory within this scratchpad, so it must be valid and have sufficient space for allocation. The caller retains ownership and must ensure it is properly initialized.
- **Output**: None
- **See also**: [`fd_sysvar_recent_hashes_init`](fd_sysvar_recent_hashes.c.driver.md#fd_sysvar_recent_hashes_init)  (Implementation)


---
### fd\_sysvar\_recent\_hashes\_update<!-- {{#callable_declaration:fd_sysvar_recent_hashes_update}} -->
Update the recent hashes sysvar account.
- **Description**: This function updates the recent hashes sysvar account and should be called at the start of every slot, before any execution commences. It processes the current blockhash queue and encodes the recent blockhashes into the sysvar account. This ensures that the sysvar reflects the most recent blockhashes, which is crucial for maintaining the integrity and consistency of the system's state.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the execution slot context. It must be valid and properly initialized before calling this function. The caller retains ownership.
    - `runtime_spad`: A pointer to an fd_spad_t structure used for runtime scratchpad memory. It must be valid and properly initialized. The caller retains ownership.
- **Output**: None
- **See also**: [`fd_sysvar_recent_hashes_update`](fd_sysvar_recent_hashes.c.driver.md#fd_sysvar_recent_hashes_update)  (Implementation)


---
### fd\_sysvar\_recent\_hashes\_read<!-- {{#callable_declaration:fd_sysvar_recent_hashes_read}} -->
Reads the recent hashes sysvar from the funk database.
- **Description**: This function retrieves the recent block hashes sysvar from the specified funk database and transaction context. It should be used when you need to access the recent block hashes for processing or validation purposes. The function returns NULL if the sysvar account does not exist or has zero lamports, indicating that the account is not valid or funded. Ensure that the `spad` provided has sufficient space for allocation, as the function will attempt to allocate memory for the decoded data.
- **Inputs**:
    - `funk`: A pointer to an `fd_funk_t` structure representing the funk database from which to read the recent hashes sysvar. Must not be null.
    - `funk_txn`: A pointer to an `fd_funk_txn_t` structure representing the transaction context within the funk database. Must not be null.
    - `spad`: A pointer to an `fd_spad_t` structure used for memory allocation during the read operation. Must not be null and should have sufficient space for allocation.
- **Output**: Returns a pointer to an `fd_recent_block_hashes_global_t` structure containing the recent block hashes if successful, or NULL if the account does not exist or has zero lamports.
- **See also**: [`fd_sysvar_recent_hashes_read`](fd_sysvar_recent_hashes.c.driver.md#fd_sysvar_recent_hashes_read)  (Implementation)


