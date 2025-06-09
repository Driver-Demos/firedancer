# Purpose
This C header file, `fd_pubkey_utils.h`, is part of a larger codebase, likely related to cryptographic operations involving public keys, specifically within the context of a system named "firedancer." It defines constants and function prototypes for operations related to public key creation and manipulation, such as creating a public key with a seed, deriving a program-derived address (PDA), and finding a valid program address. The file includes error codes for handling specific conditions like exceeding maximum seed length or encountering illegal owners. The functions appear to be designed for use in a virtual machine or runtime environment, as indicated by the references to "vm helper" and "syscall" functions, suggesting that these utilities are part of a system that involves program execution and address derivation on elliptic curves, specifically the ed25519 curve. The presence of TODO comments indicates ongoing development and potential integration with other shared functions in the system.
# Imports and Dependencies

---
- `context/fd_exec_instr_ctx.h`
- `context/fd_exec_txn_ctx.h`


# Function Declarations (Public API)

---
### fd\_pubkey\_create\_with\_seed<!-- {{#callable_declaration:fd_pubkey_create_with_seed}} -->
Generates a public key using a base, seed, and owner.
- **Description**: This function is used to create a public key by hashing together a base key, a seed, and an owner key. It is typically called when a unique key needs to be derived from these components. The function requires that the seed size does not exceed a predefined maximum length and that the owner key does not contain a specific marker indicating an illegal owner. If these conditions are not met, the function will return an error code and set a custom error in the context. The resulting public key is stored in the provided output buffer.
- **Inputs**:
    - `ctx`: A pointer to a constant fd_exec_instr_ctx_t structure, which provides context for the execution. It must not be null and is used to set custom error codes if necessary.
    - `base`: A pointer to an array of 32 unsigned characters representing the base key. This array must be exactly 32 bytes long and must not be null.
    - `seed`: A pointer to a character array representing the seed. The seed can be of any length up to MAX_SEED_LEN, and the pointer must not be null.
    - `seed_sz`: An unsigned long representing the size of the seed. It must not exceed MAX_SEED_LEN, otherwise an error is returned.
    - `owner`: A pointer to an array of 32 unsigned characters representing the owner key. This array must be exactly 32 bytes long and must not be null. The function checks for an illegal owner marker within this key.
    - `out`: A pointer to an array of 32 unsigned characters where the resulting public key will be stored. This array must be exactly 32 bytes long and must not be null.
- **Output**: Returns an integer status code: FD_EXECUTOR_INSTR_SUCCESS on success, or FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR on failure, with a specific custom error set in the context.
- **See also**: [`fd_pubkey_create_with_seed`](fd_pubkey_utils.c.driver.md#fd_pubkey_create_with_seed)  (Implementation)


---
### fd\_pubkey\_derive\_pda<!-- {{#callable_declaration:fd_pubkey_derive_pda}} -->
Derives a program-derived address (PDA) from given seeds and a program ID.
- **Description**: Use this function to derive a program-derived address (PDA) that is not a valid ed25519 curve point, based on a given program ID and a set of seed values. This function is useful when you need to generate a PDA for cryptographic operations or address derivation in a blockchain context. Ensure that the total number of seeds, including the optional bump seed, does not exceed the maximum allowed limit. The function will return a custom error code if the seeds are invalid or exceed the maximum length.
- **Inputs**:
    - `program_id`: A pointer to a constant fd_pubkey_t structure representing the program ID. Must not be null.
    - `seeds_cnt`: The number of seed pointers provided in the seeds array. Must be non-negative and, when combined with bump_seed, not exceed MAX_SEEDS.
    - `seeds`: An array of pointers to seed data, each of which is a byte array. The array must contain seeds_cnt elements. Each seed must not be null.
    - `seed_szs`: An array of unsigned long integers representing the size of each seed in the seeds array. Must contain seeds_cnt elements.
    - `bump_seed`: An optional pointer to a single byte used as a bump seed. Can be null if no bump seed is used.
    - `out`: A pointer to an fd_pubkey_t structure where the derived PDA will be stored. Must not be null.
    - `custom_err`: A pointer to an unsigned integer where a custom error code will be stored if the function fails. Must not be null.
- **Output**: Returns FD_PUBKEY_SUCCESS on success. On failure, returns FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR and sets custom_err to an appropriate error code.
- **See also**: [`fd_pubkey_derive_pda`](fd_pubkey_utils.c.driver.md#fd_pubkey_derive_pda)  (Implementation)


---
### fd\_pubkey\_find\_program\_address<!-- {{#callable_declaration:fd_pubkey_find_program_address}} -->
Finds a valid program-derived address (PDA) and its corresponding bump seed.
- **Description**: This function attempts to find a valid program-derived address (PDA) by iterating through possible bump seeds until a valid address is found. It should be used when a PDA is required for a given program ID and set of seed values. The function will return the first valid PDA found, along with the bump seed used to derive it. It is important to ensure that the number of seeds does not exceed the maximum allowed, and that each seed's size is within the permissible limit. The function will set a custom error code if an error occurs during the derivation process.
- **Inputs**:
    - `program_id`: A pointer to the program ID used in deriving the PDA. Must not be null.
    - `seeds_cnt`: The number of seed values provided. Must not exceed MAX_SEEDS.
    - `seeds`: An array of pointers to seed values. Each seed must be a valid pointer and the total number of seeds must match seeds_cnt.
    - `seed_szs`: An array of sizes corresponding to each seed. Each size must not exceed MAX_SEED_LEN.
    - `out`: A pointer to where the derived PDA will be stored. Must not be null.
    - `out_bump_seed`: A pointer to where the bump seed used to derive the PDA will be stored. Must not be null.
    - `custom_err`: A pointer to a variable where a custom error code will be stored if an error occurs. Must not be null.
- **Output**: Returns FD_PUBKEY_SUCCESS on success, or an error code if a valid PDA cannot be found. The derived PDA and bump seed are written to the provided output pointers.
- **See also**: [`fd_pubkey_find_program_address`](fd_pubkey_utils.c.driver.md#fd_pubkey_find_program_address)  (Implementation)


