# Purpose
This C header file defines function prototypes for facilitating cross-program invocations (CPI) within a native program runtime environment, specifically in the context of the Flamenco runtime. It includes necessary dependencies from other parts of the Flamenco system, such as base types and system call interfaces. The primary function, [`fd_native_cpi_native_invoke`](#fd_native_cpi_native_invoke), is designed to allow a native program to invoke another native program, similar to the `native_invoke()` function in Agave's runtime. Additionally, the file provides a utility function, [`fd_native_cpi_create_account_meta`](#fd_native_cpi_create_account_meta), to create account metadata, which is essential for managing program interactions and permissions. This header is crucial for enabling modular and secure program execution within the Flamenco runtime.
# Imports and Dependencies

---
- `../../fd_flamenco_base.h`
- `../../types/fd_types.h`
- `../../vm/syscall/fd_vm_syscall.h`


# Function Declarations (Public API)

---
### fd\_native\_cpi\_native\_invoke<!-- {{#callable_declaration:fd_native_cpi_native_invoke}} -->
Invoke a native program with specified instruction data and account metadata.
- **Description**: This function is used to perform a cross-program invocation (CPI) from one native program to another within the execution context. It should be called when a native program needs to execute another program with specific instruction data and account metadata. The function requires a valid execution instruction context and a valid native program ID. It prepares the instruction with the provided data and account metadata, and then executes it. The function returns an error code if the preparation or execution of the instruction fails.
- **Inputs**:
    - `ctx`: A pointer to the execution instruction context. Must not be null and should be properly initialized before calling this function.
    - `native_program_id`: A pointer to the public key of the native program to be invoked. Must not be null and should point to a valid program ID.
    - `instr_data`: A pointer to the instruction data to be passed to the invoked program. Must not be null and should contain valid data for the program.
    - `instr_data_len`: The length of the instruction data. Must accurately reflect the size of the data pointed to by instr_data.
    - `acct_metas`: A pointer to an array of account metadata structures. Must not be null and should contain valid metadata for each account involved in the invocation.
    - `acct_metas_len`: The number of account metadata entries in the acct_metas array. Must match the actual number of entries provided.
    - `signers`: A pointer to an array of public keys representing the signers of the transaction. Can be null if there are no signers.
    - `signers_cnt`: The number of signers in the signers array. Should be zero if signers is null.
- **Output**: Returns an integer error code indicating success or failure of the invocation process.
- **See also**: [`fd_native_cpi_native_invoke`](fd_native_cpi.c.driver.md#fd_native_cpi_native_invoke)  (Implementation)


---
### fd\_native\_cpi\_create\_account\_meta<!-- {{#callable_declaration:fd_native_cpi_create_account_meta}} -->
Populate an account metadata structure for use in native program calls.
- **Description**: This function is used to set up an account metadata structure, which is necessary for invoking native programs. It assigns the provided public key, signer status, and writable status to the metadata structure. This function should be called when preparing to make a cross-program invocation (CPI) and requires a valid public key and a pre-allocated metadata structure. The function does not perform any validation on the input parameters, so it is the caller's responsibility to ensure that the inputs are valid.
- **Inputs**:
    - `key`: A pointer to a constant fd_pubkey_t structure representing the public key to be associated with the account metadata. Must not be null.
    - `is_signer`: An unsigned character indicating whether the account is a signer. Non-zero values indicate true, while zero indicates false.
    - `is_writable`: An unsigned character indicating whether the account is writable. Non-zero values indicate true, while zero indicates false.
    - `meta`: A pointer to an fd_vm_rust_account_meta_t structure where the account metadata will be stored. Must be pre-allocated and not null.
- **Output**: None
- **See also**: [`fd_native_cpi_create_account_meta`](fd_native_cpi.c.driver.md#fd_native_cpi_create_account_meta)  (Implementation)


