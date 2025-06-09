# Purpose
This C source code file provides functionality for creating and managing public keys, specifically focusing on operations related to Program Derived Addresses (PDAs) within a cryptographic context. The file includes functions that utilize SHA-256 hashing to derive public keys based on input seeds and other parameters, ensuring that the derived keys meet specific criteria. The primary functions in this file are [`fd_pubkey_create_with_seed`](#fd_pubkey_create_with_seed), [`fd_pubkey_derive_pda`](#fd_pubkey_derive_pda), and [`fd_pubkey_find_program_address`](#fd_pubkey_find_program_address). These functions are responsible for creating a public key from a seed, deriving a PDA from a set of seeds, and finding a valid program address, respectively. The code includes error handling to manage conditions such as exceeding maximum seed lengths and invalid seed combinations, which are critical for maintaining the integrity and security of the key derivation process.

The file is part of a larger system, as indicated by the inclusion of headers from different directories, suggesting it is a component of a cryptographic library or application. The functions defined here are likely intended to be used by other parts of the system, as they provide essential operations for key management and validation. The code references external libraries and functions, such as SHA-256 hashing and Ed25519 point validation, indicating its reliance on established cryptographic standards. The presence of detailed comments and references to external documentation suggests that this file is well-documented, providing clear guidance on the implementation and expected behavior of the functions.
# Imports and Dependencies

---
- `fd_pubkey_utils.h`
- `fd_executor_err.h`
- `../vm/syscall/fd_vm_syscall.h`
- `../../ballet/ed25519/fd_curve25519.h`


# Functions

---
### fd\_pubkey\_create\_with\_seed<!-- {{#callable:fd_pubkey_create_with_seed}} -->
The `fd_pubkey_create_with_seed` function generates a public key by hashing a base, seed, and owner using SHA-256, with error handling for seed length and owner validity.
- **Inputs**:
    - `ctx`: A pointer to a `fd_exec_instr_ctx_t` structure, which contains context information for the execution, including error handling.
    - `base`: A 32-byte array representing the base input for the public key generation.
    - `seed`: A pointer to a character array representing the seed used in the public key generation.
    - `seed_sz`: An unsigned long integer representing the size of the seed.
    - `owner`: A 32-byte array representing the owner input for the public key generation.
    - `out`: A 32-byte array where the resulting public key will be stored.
- **Control Flow**:
    - Check if the seed size exceeds `MAX_SEED_LEN`; if so, set a custom error and return an error code.
    - Check if the owner contains the string 'ProgramDerivedAddress' starting from the 12th byte; if so, set a custom error and return an error code.
    - Initialize a SHA-256 context for hashing.
    - Append the base, seed, and owner to the SHA-256 context in sequence.
    - Finalize the SHA-256 hash and store the result in the `out` array.
    - Return a success code indicating the public key was generated successfully.
- **Output**: The function returns an integer status code: `FD_EXECUTOR_INSTR_SUCCESS` on success, or `FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR` on error, with specific error details set in `ctx->txn_ctx->custom_err`.


---
### fd\_pubkey\_derive\_pda<!-- {{#callable:fd_pubkey_derive_pda}} -->
The `fd_pubkey_derive_pda` function derives a Program Derived Address (PDA) using a set of seeds, a bump seed, and a program ID, ensuring the result is not a valid ed25519 curve point.
- **Inputs**:
    - `program_id`: A pointer to a `fd_pubkey_t` structure representing the program ID used in the derivation process.
    - `seeds_cnt`: An unsigned long integer representing the number of seed elements in the `seeds` array.
    - `seeds`: A pointer to an array of unsigned char pointers, each pointing to a seed used in the derivation process.
    - `seed_szs`: A pointer to an array of unsigned long integers representing the sizes of each seed in the `seeds` array.
    - `bump_seed`: A pointer to an unsigned char representing an optional bump seed used in the derivation process.
    - `out`: A pointer to a `fd_pubkey_t` structure where the derived PDA will be stored.
    - `custom_err`: A pointer to an unsigned integer where any custom error codes will be stored.
- **Control Flow**:
    - Check if the total number of seeds, including the bump seed if present, exceeds `MAX_SEEDS`; if so, set `custom_err` to `FD_PUBKEY_ERR_MAX_SEED_LEN_EXCEEDED` and return `FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR`.
    - Initialize a SHA-256 context and iterate over each seed, appending it to the SHA-256 context.
    - If a bump seed is provided, append it to the SHA-256 context.
    - Append the program ID and the string "ProgramDerivedAddress" to the SHA-256 context.
    - Finalize the SHA-256 hash and store the result in `out`.
    - Validate the derived PDA by checking if it is a valid ed25519 curve point; if it is, set `custom_err` to `FD_PUBKEY_ERR_INVALID_SEEDS` and return `FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR`.
    - Return `FD_PUBKEY_SUCCESS` if the PDA is valid.
- **Output**: The function returns an integer status code: `FD_PUBKEY_SUCCESS` if the PDA is successfully derived and valid, or `FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR` if an error occurs, with `custom_err` set to the specific error code.


---
### fd\_pubkey\_find\_program\_address<!-- {{#callable:fd_pubkey_find_program_address}} -->
The `fd_pubkey_find_program_address` function attempts to find a valid program-derived address (PDA) by iterating over possible bump seeds and using them to derive the PDA.
- **Inputs**:
    - `program_id`: A pointer to the program's public key identifier used in deriving the PDA.
    - `seeds_cnt`: The number of seed elements provided for PDA derivation.
    - `seeds`: An array of pointers to seed data used in the PDA derivation process.
    - `seed_szs`: An array of sizes corresponding to each seed in the seeds array.
    - `out`: A pointer to a `fd_pubkey_t` structure where the resulting valid PDA will be stored.
    - `out_bump_seed`: A pointer to a uchar where the bump seed used to derive the valid PDA will be stored.
    - `custom_err`: A pointer to a uint where any custom error codes will be stored.
- **Control Flow**:
    - Initialize a bump seed array with a single element.
    - Iterate over possible bump seed values from 255 down to 0.
    - For each bump seed, call [`fd_pubkey_derive_pda`](#fd_pubkey_derive_pda) to attempt to derive a PDA.
    - If [`fd_pubkey_derive_pda`](#fd_pubkey_derive_pda) returns success, copy the derived PDA and bump seed to the output parameters and break the loop.
    - If a custom error occurs that is not `FD_PUBKEY_ERR_INVALID_SEEDS`, return the error.
    - Set `custom_err` to `UINT_MAX` after the loop.
    - Return `FD_PUBKEY_SUCCESS` indicating a valid PDA was found or all possibilities were exhausted.
- **Output**: The function returns an integer status code, `FD_PUBKEY_SUCCESS` if a valid PDA is found or all possibilities are exhausted, otherwise it returns an error code from [`fd_pubkey_derive_pda`](#fd_pubkey_derive_pda).
- **Functions called**:
    - [`fd_pubkey_derive_pda`](#fd_pubkey_derive_pda)


