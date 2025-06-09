# Purpose
This C header file defines utility functions and structures for generating and managing transaction templates, specifically for a system that appears to involve blockchain or distributed ledger technology. It includes a structure, `fd_txn_accounts_t`, which organizes account information, including the number of signers and writable accounts, essential for transaction validation and execution. The file provides function prototypes for creating transaction templates ([`fd_txn_base_generate`](#fd_txn_base_generate)), adding instructions to transactions ([`fd_txn_add_instr`](#fd_txn_add_instr)), and resetting transaction instructions ([`fd_txn_reset_instrs`](#fd_txn_reset_instrs)). These functions facilitate the construction and manipulation of transactions by allowing pre-staging, re-use, and dynamic modification of transaction data, which is crucial for efficient transaction processing in systems requiring high throughput and reliability.
# Imports and Dependencies

---
- `../../ballet/txn/fd_txn.h`
- `../../ballet/txn/fd_compact_u16.h`
- `../../flamenco/types/fd_types_custom.h`
- `../../flamenco/types/fd_types.h`


# Data Structures

---
### fd\_txn\_accounts
- **Type**: `struct`
- **Members**:
    - `signature_cnt`: Stores the count of signatures, with a maximum of 128.
    - `readonly_signed_cnt`: Counts the number of readonly signed accounts, with a maximum of 128.
    - `readonly_unsigned_cnt`: Counts the number of readonly unsigned accounts, with a maximum of 128.
    - `acct_cnt`: Holds the total number of accounts.
    - `signers_w`: Pointer to an array of writable signer public keys.
    - `signers_r`: Pointer to an array of readonly signer public keys.
    - `non_signers_w`: Pointer to an array of writable non-signer public keys.
    - `non_signers_r`: Pointer to an array of readonly non-signer public keys.
- **Description**: The `fd_txn_accounts` structure is designed to manage and organize account information within a transaction, specifically focusing on the number and types of accounts involved, such as signers and non-signers, and whether they are writable or readonly. It includes fields to track the count of signatures and accounts, and pointers to arrays of public keys for different categories of accounts, facilitating the construction and management of transaction templates.


---
### fd\_txn\_accounts\_t
- **Type**: `struct`
- **Members**:
    - `signature_cnt`: Stores the count of signatures, with a maximum of 128.
    - `readonly_signed_cnt`: Stores the count of readonly signed accounts, with a maximum of 128.
    - `readonly_unsigned_cnt`: Stores the count of readonly unsigned accounts, with a maximum of 128.
    - `acct_cnt`: Stores the total count of accounts.
    - `signers_w`: Pointer to an array of writable signer public keys.
    - `signers_r`: Pointer to an array of readonly signer public keys.
    - `non_signers_w`: Pointer to an array of writable non-signer public keys.
    - `non_signers_r`: Pointer to an array of readonly non-signer public keys.
- **Description**: The `fd_txn_accounts_t` structure is designed to manage a list of accounts involved in a transaction, providing details on the number of signers and writable accounts. It includes fields to track the count of signatures, readonly signed and unsigned accounts, and the total number of accounts. Additionally, it maintains pointers to arrays of public keys for both signers and non-signers, categorized into writable and readonly groups. This structure is crucial for organizing account information in transaction generation and management.


# Function Declarations (Public API)

---
### fd\_txn\_base\_generate<!-- {{#callable_declaration:fd_txn_base_generate}} -->
Generates a transaction template with metadata and payload.
- **Description**: This function is used to create a transaction template, which is useful for pre-staging and re-use in transaction processing. It initializes the transaction metadata and payload based on the provided account information and optional recent blockhash. The function must be called with a valid number of signatures, which cannot exceed 127, and a properly initialized accounts structure. The function returns the offset to the start of the instructions in the transaction payload, allowing further customization of the transaction. It is important to ensure that the output buffers are sufficiently large to accommodate the transaction data.
- **Inputs**:
    - `out_txn_meta`: A buffer to store the transaction metadata. It must be at least FD_TXN_MAX_SZ bytes in size. The caller retains ownership.
    - `out_txn_payload`: A buffer to store the transaction payload. It must be at least FD_TXN_MTU bytes in size. The caller retains ownership.
    - `num_signatures`: The number of signatures required for the transaction. It must be less than or equal to 127. If this condition is not met, the function will not proceed.
    - `accounts`: A pointer to an fd_txn_accounts_t structure containing account information for the transaction. This includes the number of signers and read-only accounts. The structure must be properly initialized before calling the function.
    - `opt_recent_blockhash`: An optional pointer to a recent blockhash. If provided, it will be included in the transaction payload; otherwise, a default value will be used. The pointer can be null.
- **Output**: Returns the offset to the start of the instructions in the transaction payload as an unsigned long integer.
- **See also**: [`fd_txn_base_generate`](fd_txn_generate.c.driver.md#fd_txn_base_generate)  (Implementation)


---
### fd\_txn\_add\_instr<!-- {{#callable_declaration:fd_txn_add_instr}} -->
Adds an instruction to a transaction being generated.
- **Description**: This function is used to append a new instruction to an existing transaction that is being constructed. It should be called after initializing the transaction metadata and before finalizing the transaction. The function updates the transaction payload with the new instruction and returns the offset to the start of this instruction within the payload. It is important to ensure that the transaction metadata has been properly initialized and that the number of instructions does not exceed the maximum allowed. The function assumes that the transaction metadata and payload are correctly set up and that the recent blockhash offset is valid.
- **Inputs**:
    - `txn_meta_ptr`: Pointer to the transaction metadata. Must not be null and should point to a valid transaction metadata structure.
    - `out_txn_payload`: Buffer where the transaction payload is stored. Must have a size of at least FD_TXN_MTU and be properly initialized.
    - `program_id`: Identifier of the program to which the instruction belongs. Must be a valid program ID.
    - `accounts`: Array of indices representing accounts involved in the instruction. Must not be null and should contain valid indices.
    - `accounts_sz`: Number of accounts in the 'accounts' array. Must be a valid size that fits within the transaction constraints.
    - `instr_buf`: Buffer containing the instruction data to be added. Must not be null and should contain valid instruction data.
    - `instr_buf_sz`: Size of the instruction data in 'instr_buf'. Must be a valid size that fits within the transaction constraints.
- **Output**: Returns the offset to the start of the instruction added in the transaction buffer.
- **See also**: [`fd_txn_add_instr`](fd_txn_generate.c.driver.md#fd_txn_add_instr)  (Implementation)


---
### fd\_txn\_reset\_instrs<!-- {{#callable_declaration:fd_txn_reset_instrs}} -->
Resets the list of instructions in the transaction metadata and clears the instructions from the transaction payload.
- **Description**: This function is used to reset the instruction count in the transaction metadata and clear the corresponding instructions from the transaction payload. It should be called when you need to remove all instructions from a transaction, effectively resetting it to a state where no instructions are present. This function does nothing if the instruction count is already zero, ensuring that it is safe to call even on an already reset transaction. It is important to ensure that the transaction metadata and payload are properly initialized before calling this function.
- **Inputs**:
    - `txn_meta_ptr`: A pointer to the transaction metadata structure. This must not be null and should point to a valid transaction metadata object. The caller retains ownership of this pointer.
    - `out_txn_payload`: An array of unsigned characters with a size of at least FD_TXN_MTU. This array represents the transaction payload, and the function will modify it to clear the instructions. The caller retains ownership of this array.
- **Output**: None
- **See also**: [`fd_txn_reset_instrs`](fd_txn_generate.c.driver.md#fd_txn_reset_instrs)  (Implementation)


