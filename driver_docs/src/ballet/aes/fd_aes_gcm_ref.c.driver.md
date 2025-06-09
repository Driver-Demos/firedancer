# Purpose
The provided C source code file, `fd_aes_ref.c`, is a reference implementation of the AES-GCM (Advanced Encryption Standard - Galois/Counter Mode) encryption and decryption algorithm. This file is part of a cryptographic library, likely intended for use in secure communications or data protection applications. The code is derived from the OpenSSL project, specifically from the files `crypto/evp/e_aes.c` and `crypto/modes/gcm128.c`, indicating that it leverages well-established cryptographic techniques and standards. The primary functionality of this file is to provide a reference implementation for initializing, encrypting, and decrypting data using the AES-GCM mode, which combines the AES block cipher with Galois field multiplication for authentication.

The file defines several key functions, including [`fd_aes_128_gcm_init_ref`](#fd_aes_128_gcm_init_ref), [`fd_aes_gcm_encrypt_ref`](#fd_aes_gcm_encrypt_ref), and [`fd_aes_gcm_decrypt_ref`](#fd_aes_gcm_decrypt_ref), which handle the initialization of the AES-GCM context, encryption, and decryption processes, respectively. It also includes internal functions for handling additional authenticated data (AAD) and finalizing the encryption or decryption process. The code is structured to ensure that the encryption and decryption operations are performed securely, with checks on input sizes and careful management of cryptographic state. The use of macros and static functions suggests that this implementation is designed for internal use within a larger cryptographic library, rather than as a standalone application. The file does not define public APIs or external interfaces directly, but rather provides the core cryptographic operations that can be integrated into higher-level functions or applications.
# Imports and Dependencies

---
- `fd_aes_gcm.h`
- `assert.h`


# Functions

---
### fd\_aes\_gcm\_setiv<!-- {{#callable:fd_aes_gcm_setiv}} -->
The `fd_aes_gcm_setiv` function initializes the GCM context with a given initialization vector (IV) and prepares it for encryption or decryption.
- **Inputs**:
    - `gcm`: A pointer to an `fd_aes_gcm_ref_t` structure that holds the GCM context to be initialized.
    - `iv`: A 12-byte array representing the initialization vector to be used for the GCM operation.
- **Control Flow**:
    - Initialize the AAD length and message length in the GCM context to zero.
    - Set the AAD and message residuals to zero.
    - Copy the 12-byte IV into the first 12 bytes of the `Yi` field in the GCM context.
    - Set the 13th, 14th, and 15th bytes of `Yi` to zero and the 16th byte to one, initializing the counter to one.
    - Set the `Xi` field in the GCM context to zero.
    - Encrypt the `Yi` field using the AES key stored in the GCM context, storing the result in `EK0`.
    - Increment the counter and store its byte-swapped value in the last four bytes of `Yi`.
- **Output**: The function does not return a value; it modifies the GCM context in place.
- **Functions called**:
    - [`fd_aes_encrypt`](fd_aes_base.h.driver.md#fd_aes_encrypt)


---
### fd\_aes\_128\_gcm\_init\_ref<!-- {{#callable:fd_aes_128_gcm_init_ref}} -->
The `fd_aes_128_gcm_init_ref` function initializes an AES-GCM context with a 128-bit key and a 96-bit IV for encryption or decryption operations.
- **Inputs**:
    - `gcm`: A pointer to an `fd_aes_gcm_ref_t` structure that will be initialized.
    - `key`: A 16-byte array representing the 128-bit AES encryption key.
    - `iv`: A 12-byte array representing the 96-bit initialization vector (IV).
- **Control Flow**:
    - The function begins by zeroing out the memory of the `gcm` structure using `memset`.
    - A pointer to the key schedule (`ks`) is set to the `key` field of the `gcm` structure.
    - The AES encryption key is set using [`fd_aes_set_encrypt_key`](fd_aes_base.h.driver.md#fd_aes_set_encrypt_key), which initializes the key schedule with the provided 128-bit key.
    - The function encrypts the zeroed-out `gcm->H.c` using the key schedule, storing the result back in `gcm->H.c`.
    - The two 64-bit halves of `gcm->H` are byte-swapped using `fd_ulong_bswap`.
    - The GCM hash table is initialized with `fd_gcm_init` using the byte-swapped `gcm->H.u`.
    - The initialization vector (IV) is set in the `gcm` structure using [`fd_aes_gcm_setiv`](#fd_aes_gcm_setiv).
- **Output**: The function does not return a value; it initializes the `gcm` structure for subsequent AES-GCM operations.
- **Functions called**:
    - [`fd_aes_set_encrypt_key`](fd_aes_base.h.driver.md#fd_aes_set_encrypt_key)
    - [`fd_aes_encrypt`](fd_aes_base.h.driver.md#fd_aes_encrypt)
    - [`fd_aes_gcm_setiv`](#fd_aes_gcm_setiv)


---
### fd\_gcm128\_aad<!-- {{#callable:fd_gcm128_aad}} -->
The `fd_gcm128_aad` function processes additional authenticated data (AAD) for AES-GCM encryption, updating the internal state of the AES-GCM context.
- **Inputs**:
    - `aes_gcm`: A pointer to an `fd_aes_gcm_ref_t` structure representing the AES-GCM context, which holds the state and parameters for the encryption process.
    - `aad`: A pointer to an array of unsigned characters representing the additional authenticated data to be processed.
    - `aad_sz`: An unsigned long integer representing the size of the additional authenticated data in bytes.
- **Control Flow**:
    - Initialize `alen` with the current AAD length from `aes_gcm->len.u[0]`.
    - Check if `aes_gcm->len.u[1]` is non-zero, indicating an error state, and return -2 if true.
    - Add `aad_sz` to `alen` and check if it exceeds the maximum allowed size or if there's an overflow, returning -1 if either condition is met.
    - Update `aes_gcm->len.u[0]` with the new `alen`.
    - If `aes_gcm->ares` is non-zero, process any remaining AAD bytes from a previous call, updating `aes_gcm->Xi.c` and `aes_gcm->ares`.
    - If `n` becomes zero after processing, call `fd_gcm_gmult` to finalize the GHASH for the current block.
    - Process full 16-byte blocks of AAD using `fd_gcm_ghash`, updating `aad` and `aad_sz` accordingly.
    - Process any remaining AAD bytes less than 16, updating `aes_gcm->Xi.c`.
    - Update `aes_gcm->ares` with the number of remaining bytes and return 0.
- **Output**: Returns 0 on success, -1 if the AAD size exceeds the maximum allowed or causes an overflow, and -2 if the message length is non-zero, indicating an error state.


---
### fd\_gcm128\_encrypt<!-- {{#callable:fd_gcm128_encrypt}} -->
The `fd_gcm128_encrypt` function performs AES-GCM encryption on a given input data buffer, updating the encryption context and producing an encrypted output buffer.
- **Inputs**:
    - `ctx`: A pointer to the AES-GCM context (`fd_aes_gcm_ref_t`) which holds the encryption state and parameters.
    - `in`: A pointer to the input data buffer that needs to be encrypted.
    - `out`: A pointer to the output buffer where the encrypted data will be stored.
    - `len`: The length of the input data buffer to be encrypted.
- **Control Flow**:
    - Initialize local variables for message length (`mlen`), counter (`ctr`), and message residue (`mres`).
    - Check if the total message length exceeds the maximum allowed size; if so, return -1.
    - Update the message length in the context with the new length.
    - If there is any additional authenticated data (AAD) residue (`ares`), finalize the GHASH for AAD and reset `ares`.
    - Swap the byte order of the counter value from the context and store it in `ctr`.
    - Iterate over each byte of the input data buffer, performing encryption using AES and updating the counter and GHASH as needed.
    - For each block of 16 bytes, perform AES encryption on the counter block and XOR the result with the input data to produce the encrypted output.
    - Update the GHASH with the encrypted data block when a full block is processed.
    - Store the updated message residue (`mres`) back in the context.
    - Return 0 to indicate successful encryption.
- **Output**: Returns 0 on successful encryption, or -1 if the message length exceeds the allowed limit.
- **Functions called**:
    - [`fd_aes_encrypt`](fd_aes_base.h.driver.md#fd_aes_encrypt)


---
### fd\_gcm128\_decrypt<!-- {{#callable:fd_gcm128_decrypt}} -->
The `fd_gcm128_decrypt` function decrypts a given input buffer using AES-GCM mode and updates the context with the decrypted data.
- **Inputs**:
    - `ctx`: A pointer to the AES-GCM context (`fd_aes_gcm_ref_t`) which holds encryption state and parameters.
    - `in`: A pointer to the input buffer containing the encrypted data to be decrypted.
    - `out`: A pointer to the output buffer where the decrypted data will be stored.
    - `len`: The length of the input data to be decrypted.
- **Control Flow**:
    - Initialize local variables for message length (`mlen`), counter (`ctr`), and message residue (`mres`).
    - Check if the total message length exceeds the maximum allowed size and return -1 if it does.
    - If `ctx->ares` is set, finalize the GHASH for the Additional Authenticated Data (AAD) and reset `ctx->ares`.
    - Swap the byte order of the counter value from the context and store it in `ctr`.
    - Iterate over the input data, processing each byte:
    - If `n` (the current position in the block) is 0, encrypt the counter block and increment the counter.
    - Decrypt each byte by XORing it with the corresponding byte from the encrypted counter block and store it in the output buffer.
    - Update the GHASH with the decrypted data when a block is completed.
    - Update the context's message residue (`ctx->mres`) with the current residue value.
    - Return 0 to indicate successful decryption.
- **Output**: Returns 0 on successful decryption, or -1 if the message length exceeds the allowed limit.
- **Functions called**:
    - [`fd_aes_encrypt`](fd_aes_base.h.driver.md#fd_aes_encrypt)


---
### fd\_gcm128\_finish<!-- {{#callable:fd_gcm128_finish}} -->
The `fd_gcm128_finish` function finalizes the GCM (Galois/Counter Mode) encryption or decryption process by processing any remaining data and computing the final authentication tag.
- **Inputs**:
    - `ctx`: A pointer to an `fd_aes_gcm_ref_t` structure that holds the context for the GCM operation, including lengths, intermediate values, and keys.
- **Control Flow**:
    - Calculate the bit lengths of the additional authenticated data (AAD) and ciphertext by left-shifting the stored lengths by 3 bits.
    - Check if there is any remaining message data (`mres`) to process; if so, pad it to a multiple of 16 bytes and update the hash state using `fd_gcm_ghash`.
    - If there is no remaining message data but there is remaining AAD (`ares`), update the hash state using `fd_gcm_gmult`.
    - Swap the byte order of the AAD and ciphertext lengths to big-endian format.
    - Store the swapped lengths in a temporary structure and append it to the current hash state.
    - Update the hash state with the final block containing the lengths using `fd_gcm_ghash`.
    - XOR the final hash state with the pre-computed encryption of the initial counter block (`EK0`) to produce the final authentication tag.
- **Output**: The function does not return a value but updates the `ctx` structure with the final authentication tag in `ctx->Xi`.


---
### fd\_aes\_gcm\_encrypt\_ref<!-- {{#callable:fd_aes_gcm_encrypt_ref}} -->
The `fd_aes_gcm_encrypt_ref` function performs AES-GCM encryption on a plaintext input, producing a ciphertext and an authentication tag.
- **Inputs**:
    - `aes_gcm`: A pointer to an `fd_aes_gcm_ref_t` structure that holds the AES-GCM context and state.
    - `c`: A pointer to the output buffer where the ciphertext will be stored.
    - `p`: A pointer to the input buffer containing the plaintext to be encrypted.
    - `sz`: The size of the plaintext in bytes.
    - `aad`: A pointer to the additional authenticated data (AAD) to be included in the encryption process.
    - `aad_sz`: The size of the AAD in bytes.
    - `tag`: A 16-byte array where the authentication tag will be stored.
- **Control Flow**:
    - The function begins by processing the additional authenticated data (AAD) using [`fd_gcm128_aad`](#fd_gcm128_aad), which updates the AES-GCM context with the AAD.
    - It then initializes a `bulk` variable to zero and calls [`fd_gcm128_encrypt`](#fd_gcm128_encrypt) to encrypt the plaintext `p` into the ciphertext `c`, ensuring the operation is successful with an assertion.
    - After encryption, [`fd_gcm128_finish`](#fd_gcm128_finish) is called to finalize the GCM operation, which computes the authentication tag.
    - The computed tag is copied from the AES-GCM context to the provided `tag` array using `fd_memcpy`.
- **Output**: The function does not return a value, but it outputs the encrypted ciphertext in `c` and the authentication tag in `tag`.
- **Functions called**:
    - [`fd_gcm128_aad`](#fd_gcm128_aad)
    - [`fd_gcm128_encrypt`](#fd_gcm128_encrypt)
    - [`fd_gcm128_finish`](#fd_gcm128_finish)


---
### fd\_aes\_gcm\_decrypt\_ref<!-- {{#callable:fd_aes_gcm_decrypt_ref}} -->
The `fd_aes_gcm_decrypt_ref` function performs AES-GCM decryption on a given ciphertext and verifies the integrity of the decrypted data using a provided authentication tag.
- **Inputs**:
    - `aes_gcm`: A pointer to an `fd_aes_gcm_ref_t` structure that holds the AES-GCM context and state information.
    - `c`: A pointer to the input ciphertext data to be decrypted.
    - `p`: A pointer to the output buffer where the decrypted plaintext will be stored.
    - `sz`: The size of the ciphertext data in bytes.
    - `aad`: A pointer to the additional authenticated data (AAD) that was used during encryption.
    - `aad_sz`: The size of the additional authenticated data in bytes.
    - `tag`: A 16-byte array containing the authentication tag to verify the integrity of the decrypted data.
- **Control Flow**:
    - The function begins by processing the additional authenticated data (AAD) using [`fd_gcm128_aad`](#fd_gcm128_aad) to update the AES-GCM context.
    - It then decrypts the ciphertext `c` into the plaintext buffer `p` using [`fd_gcm128_decrypt`](#fd_gcm128_decrypt), ensuring the size `sz` is processed.
    - After decryption, [`fd_gcm128_finish`](#fd_gcm128_finish) is called to finalize the GCM operation and compute the authentication tag.
    - Finally, the function compares the computed tag with the provided `tag` using `memcmp` to verify data integrity, returning the result of this comparison.
- **Output**: The function returns an integer indicating whether the computed authentication tag matches the provided tag (1 for match, 0 for mismatch).
- **Functions called**:
    - [`fd_gcm128_aad`](#fd_gcm128_aad)
    - [`fd_gcm128_decrypt`](#fd_gcm128_decrypt)
    - [`fd_gcm128_finish`](#fd_gcm128_finish)


