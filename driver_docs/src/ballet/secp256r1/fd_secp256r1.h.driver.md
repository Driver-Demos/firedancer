# Purpose
This code is a C header file that defines an interface for verifying digital signatures using the SECP256r1 elliptic curve. It includes necessary dependencies, such as a base header and a SHA-256 hashing module, which are likely used in the signature verification process. The file defines two macros, `FD_SECP256R1_SUCCESS` and `FD_SECP256R1_FAILURE`, to indicate the outcome of the verification process. The primary function declared is [`fd_secp256r1_verify`](#fd_secp256r1_verify), which takes a message, its size, a signature, a public key, and a SHA-256 context as parameters, and returns an integer indicating success or failure. This header is part of a larger cryptographic library, providing a specific API for SECP256r1 signature verification.
# Imports and Dependencies

---
- `../fd_ballet_base.h`
- `../sha256/fd_sha256.h`


# Function Declarations (Public API)

---
### fd\_secp256r1\_verify<!-- {{#callable_declaration:fd_secp256r1_verify}} -->
Verify a SECP256r1 signature for a given message.
- **Description**: Use this function to verify the authenticity of a message using the SECP256r1 elliptic curve digital signature algorithm. It requires the message, its size, the signature, the public key, and a SHA-256 context. The function checks the validity of the signature against the provided public key and message, returning a success or failure code. Ensure that the signature and public key are correctly formatted and that the SHA-256 context is properly initialized before calling this function.
- **Inputs**:
    - `msg`: A pointer to the message data to be verified. The caller retains ownership and it must not be null.
    - `msg_sz`: The size of the message in bytes. It must accurately reflect the length of the message data.
    - `sig`: A 64-byte array containing the signature to verify. It must be a valid signature for the message and public key.
    - `public_key`: A 33-byte array containing the public key used for verification. It must be a valid SECP256r1 public key.
    - `sha`: A pointer to an fd_sha256_t structure used for SHA-256 operations. It must be initialized before calling this function.
- **Output**: Returns FD_SECP256R1_SUCCESS (1) if the signature is valid, or FD_SECP256R1_FAILURE (0) if it is not.
- **See also**: [`fd_secp256r1_verify`](fd_secp256r1.c.driver.md#fd_secp256r1_verify)  (Implementation)


