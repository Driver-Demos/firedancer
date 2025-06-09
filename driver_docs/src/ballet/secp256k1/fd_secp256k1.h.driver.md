# Purpose
This C header file defines an interface for working with secp256k1 cryptographic signatures, specifically focusing on the recovery of public keys from recoverable signatures. It includes a single function prototype, [`fd_secp256k1_recover`](#fd_secp256k1_recover), which is designed to extract a public key from a given message hash and its corresponding recoverable signature, using a specified recovery ID. The function is part of a library that wraps around `libsecp256k1`, indicating that it leverages existing cryptographic functionality to perform its operations. The header file is structured to ensure that the function is available for use in other parts of the program, while also providing a brief description of the function's parameters and expected behavior. The file includes necessary preprocessor directives to prevent multiple inclusions and relies on a base header file, `fd_ballet_base.h`, for foundational definitions or configurations.
# Imports and Dependencies

---
- `../fd_ballet_base.h`


# Global Variables

---
### fd\_secp256k1\_recover
- **Type**: `function`
- **Description**: The `fd_secp256k1_recover` function is designed to recover a public key from a recoverable SECP256K1 signature. It requires a message hash, a signature, and a recovery ID as inputs, and it outputs the recovered public key. The function does not perform input argument checking and returns the public key on success or NULL on failure.
- **Use**: This function is used to derive a public key from a given SECP256K1 signature and message hash, utilizing the recovery ID.


# Function Declarations (Public API)

---
### fd\_secp256k1\_recover<!-- {{#callable_declaration:fd_secp256k1_recover}} -->
Recovers a public key from a recoverable SECP256K1 signature.
- **Description**: Use this function to recover a public key from a given SECP256K1 signature and message hash. It requires a valid recovery ID, which must be between 0 and 3 inclusive. The function assumes that the provided pointers to the message hash, signature, and public key are valid and point to memory regions of appropriate sizes (32 bytes for the message hash, 64 bytes for the signature, and 64 bytes for the public key). The function does not perform input validation on these pointers, so it is the caller's responsibility to ensure they are correct. On success, the public key is written to the provided memory region and returned; on failure, the function returns NULL.
- **Inputs**:
    - `public_key`: A pointer to a 64-byte memory region where the recovered public key will be stored. The caller must ensure this memory is allocated and writable.
    - `msg_hash`: A pointer to a 32-byte memory region containing the hash of the message. The caller must ensure this memory is allocated and readable.
    - `sig`: A pointer to a 64-byte memory region containing the recoverable signature. The caller must ensure this memory is allocated and readable.
    - `recovery_id`: An integer representing the recovery ID used during the signing process. It must be between 0 and 3 inclusive. If the value is outside this range, the function will return NULL.
- **Output**: Returns the pointer to the public_key on success, or NULL on failure.
- **See also**: [`fd_secp256k1_recover`](fd_secp256k1.c.driver.md#fd_secp256k1_recover)  (Implementation)


