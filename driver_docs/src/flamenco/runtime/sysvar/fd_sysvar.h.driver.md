# Purpose
This C header file, `fd_sysvar.h`, is part of the Flamenco runtime system and serves as a configuration and function declaration file for handling system variables (sysvars) within the runtime. It defines two macros, `FD_SYSVAR_RENT_UNADJUSTED_INITIAL_BALANCE` and `FD_SYSVAR_INITIAL_RENT_EPOCH`, which are likely used to set initial conditions or parameters related to system rent or epoch management, as indicated by the linked references to a Rust source file. The file also declares two functions, [`fd_sysvar_set`](#fd_sysvar_set) and [`fd_sysvar_instr_acct_check`](#fd_sysvar_instr_acct_check), which are presumably used to set system variables and check instruction account contexts, respectively. Additionally, there is a note suggesting future refactoring to include common functions for reading and writing sysvar accounts, indicating ongoing development and modularization efforts.
# Imports and Dependencies

---
- `../../fd_flamenco_base.h`


# Function Declarations (Public API)

---
### fd\_sysvar\_set<!-- {{#callable_declaration:fd_sysvar_set}} -->
Sets the system variable account data and updates its metadata.
- **Description**: This function updates the data and metadata of a system variable account identified by a public key. It should be used when you need to modify the contents of a sysvar account, including its data, owner, and slot information. The function also ensures that the account's lamports are adjusted to meet the minimum rent-exempt balance requirements. It is important to ensure that the `fd_exec_slot_ctx_t` context is properly initialized and that the provided public keys and data are valid. The function returns an error code if it fails to read the account data.
- **Inputs**:
    - `slot_ctx`: A pointer to an `fd_exec_slot_ctx_t` structure representing the execution context. Must be properly initialized and not null.
    - `owner`: A pointer to a constant `fd_pubkey_t` representing the new owner of the account. Must not be null.
    - `pubkey`: A pointer to a constant `fd_pubkey_t` representing the public key of the account to be updated. Must not be null.
    - `data`: A pointer to the data to be set in the account. The data should be valid and the size should match the `sz` parameter. Must not be null.
    - `sz`: An unsigned long representing the size of the data to be set in the account. Should be a valid size for the account data.
    - `slot`: An unsigned long representing the slot number to be set for the account. Should be a valid slot number.
- **Output**: Returns 0 on success or an error code if the account data could not be read or updated.
- **See also**: [`fd_sysvar_set`](fd_sysvar.c.driver.md#fd_sysvar_set)  (Implementation)


---
### fd\_sysvar\_instr\_acct\_check<!-- {{#callable_declaration:fd_sysvar_instr_acct_check}} -->
Verify the account key at a specified index in the instruction context.
- **Description**: This function checks if the account key at the given index within the instruction context matches the expected public key. It is used to ensure that the account key in the transaction matches the expected key for the operation. The function should be called when there is a need to validate account keys in a transaction context. It returns specific error codes if the index is out of bounds or if the keys do not match, ensuring robust error handling.
- **Inputs**:
    - `ctx`: A pointer to a constant `fd_exec_instr_ctx_t` structure representing the execution instruction context. Must not be null.
    - `idx`: An unsigned long representing the index of the account to check within the instruction context. Must be less than the number of accounts in the instruction context; otherwise, an error code is returned.
    - `addr_want`: A pointer to a constant `fd_pubkey_t` representing the expected public key. Must not be null.
- **Output**: Returns an integer status code: `FD_EXECUTOR_INSTR_SUCCESS` on success, `FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS` if the index is out of bounds, or `FD_EXECUTOR_INSTR_ERR_INVALID_ARG` if the keys do not match.
- **See also**: [`fd_sysvar_instr_acct_check`](fd_sysvar.c.driver.md#fd_sysvar_instr_acct_check)  (Implementation)


