# Purpose
This C header file defines function prototypes for cryptographic verification routines used in a runtime environment, specifically for the Ed25519, Secp256k1, and Secp256r1 cryptographic algorithms. The file includes necessary dependencies from other parts of the project, such as `fd_runtime.h` and `fd_exec_instr_ctx.h`, which likely provide runtime support and context structures needed for instruction execution. Each function, prefixed with `fd_precompile_`, serves as an entry point for processing instructions related to its respective cryptographic algorithm, indicating that these functions are likely used to verify digital signatures or perform similar cryptographic operations. The use of include guards ensures that the header is only included once during compilation, preventing redefinition errors.
# Imports and Dependencies

---
- `../fd_runtime.h`
- `../context/fd_exec_instr_ctx.h`


# Function Declarations (Public API)

---
### fd\_precompile\_ed25519\_verify<!-- {{#callable_declaration:fd_precompile_ed25519_verify}} -->
Processes Ed25519 signature verification instructions.
- **Description**: This function serves as the entry point for processing Ed25519 signature verification instructions within a given execution context. It should be called when there is a need to verify Ed25519 signatures as part of the instruction set. The function expects the context to contain valid instruction data, including the number of signatures and their respective offsets. It handles edge cases where the data size is insufficient or the signature count is zero, returning specific error codes in such scenarios. Successful execution results in a success code, while any errors encountered during data retrieval or signature verification result in a custom error code being set in the transaction context.
- **Inputs**:
    - `ctx`: A pointer to an fd_exec_instr_ctx_t structure containing the execution context for the instruction. This context must be properly initialized and contain valid instruction data. The caller retains ownership and must ensure it is not null.
- **Output**: Returns an integer status code: FD_EXECUTOR_INSTR_SUCCESS on success, or FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR on failure, with a specific error code set in ctx->txn_ctx->custom_err.
- **See also**: [`fd_precompile_ed25519_verify`](fd_precompiles.c.driver.md#fd_precompile_ed25519_verify)  (Implementation)


---
### fd\_precompile\_secp256k1\_verify<!-- {{#callable_declaration:fd_precompile_secp256k1_verify}} -->
Processes Secp256k1 verification instructions.
- **Description**: This function serves as the entry point for processing Secp256k1 verification instructions within a given execution context. It should be called when a Secp256k1 verification operation is required as part of the instruction set being executed. The function expects the context to contain valid instruction data, and it performs various checks to ensure the data's integrity and correctness. If the data is valid and the verification succeeds, the function returns a success code; otherwise, it sets an appropriate error code in the context and returns an error code. This function must be called with a properly initialized execution context.
- **Inputs**:
    - `ctx`: A pointer to an fd_exec_instr_ctx_t structure that contains the execution context for the instruction. This context must be properly initialized and must not be null. The function uses this context to access instruction data and to set error codes if necessary.
- **Output**: Returns an integer status code: FD_EXECUTOR_INSTR_SUCCESS on success, or FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR on failure, with the specific error code set in ctx->txn_ctx->custom_err.
- **See also**: [`fd_precompile_secp256k1_verify`](fd_precompiles.c.driver.md#fd_precompile_secp256k1_verify)  (Implementation)


