# Purpose
The `fd_aes_gcm_x86.c` file is a C source file that provides functionality for AES-GCM (Galois/Counter Mode) encryption and decryption optimized for x86 architectures with support for various SIMD (Single Instruction, Multiple Data) instruction sets, including AES-NI, AVX, and AVX-512. The file includes key expansion routines and defines several functions for initializing, encrypting, and decrypting data using AES-GCM. It leverages hardware acceleration features available in modern processors to perform cryptographic operations efficiently. The file is structured to conditionally compile different sections of code based on the availability of specific instruction sets, ensuring that the most efficient implementation is used depending on the hardware capabilities.

The file defines a series of functions that serve as wrappers around assembly routines (`fd_aes_gcm_{aesni,avx10}.S`) for performing AES-GCM operations. These functions include [`fd_aes_128_gcm_init_aesni`](#fd_aes_128_gcm_init_aesni), [`fd_aes_gcm_encrypt_aesni`](#fd_aes_gcm_encrypt_aesni), and [`fd_aes_gcm_decrypt_aesni`](#fd_aes_gcm_decrypt_aesni), among others, which handle the initialization, encryption, and decryption processes, respectively. The code also includes functions for handling additional authenticated data (AAD) and finalizing encryption and decryption operations. The use of macros and inline assembly instructions allows for efficient key expansion and cryptographic transformations, making this file a critical component for applications requiring high-performance encryption and decryption on x86 platforms.
# Imports and Dependencies

---
- `fd_aes_gcm.h`
- `../../util/simd/fd_sse.h`


# Functions

---
### expand\_aes\_key<!-- {{#callable:expand_aes_key}} -->
The `expand_aes_key` function expands a given AES key into encryption and decryption keys for AES-GCM operations using AES-NI instructions.
- **Inputs**:
    - `out`: A pointer to an `fd_aes_gcm_aesni_key_t` structure where the expanded encryption and decryption keys will be stored.
    - `keyp`: A pointer to a constant unsigned character array representing the original AES key to be expanded.
- **Control Flow**:
    - Load the original AES key from `keyp` into a vector `v0`.
    - Initialize a zero vector `v1` and an array `enc` to store the expanded encryption keys.
    - Define a macro `ASSIST` to assist in generating the next round key using AES key generation assist instructions and vector operations.
    - Iteratively apply the `ASSIST` macro to generate 10 additional round keys, storing them in the `enc` array.
    - Store the expanded encryption keys from the `enc` array into the `out->key_enc` array.
    - Derive the decryption keys by storing the last encryption key directly and applying the AES inverse mix columns operation to the other keys, storing them in the `out->key_dec` array.
    - Set the `key_sz` field of the `out` structure to 16, indicating the key size.
- **Output**: The function does not return a value but populates the `out` structure with the expanded encryption and decryption keys and sets the key size.


---
### fd\_aes\_128\_gcm\_init\_aesni<!-- {{#callable:fd_aes_128_gcm_init_aesni}} -->
The `fd_aes_128_gcm_init_aesni` function initializes an AES-GCM context for AES-NI by expanding the AES key, precomputing necessary values, and setting the initialization vector.
- **Inputs**:
    - `aes_gcm`: A pointer to an `fd_aes_gcm_aesni_t` structure that will be initialized.
    - `key`: A 16-byte array representing the AES key.
    - `iv`: A 12-byte array representing the initialization vector.
- **Control Flow**:
    - The function calls [`expand_aes_key`](#expand_aes_key) to expand the provided AES key and store it in the `aes_gcm->key` field.
    - It then calls `aes_gcm_precompute_aesni` to perform precomputations necessary for AES-GCM operations using AES-NI.
    - Finally, it copies the provided initialization vector into the `aes_gcm->iv` field using `memcpy`.
- **Output**: The function does not return a value; it initializes the provided `fd_aes_gcm_aesni_t` structure with the expanded key and initialization vector.
- **Functions called**:
    - [`expand_aes_key`](#expand_aes_key)


---
### load\_le\_ctr<!-- {{#callable:load_le_ctr}} -->
The `load_le_ctr` function initializes a 4-element array with a fixed value and three 32-bit little-endian integers derived from a 12-byte initialization vector.
- **Inputs**:
    - `le_ctr`: A 4-element array of unsigned integers where the counter values will be stored.
    - `iv`: A 12-byte array representing the initialization vector from which the counter values are derived.
- **Control Flow**:
    - Set the first element of `le_ctr` to 2.
    - Load a 32-bit integer from the last 4 bytes of `iv`, byte-swap it to convert from big-endian to little-endian, and store it in `le_ctr[1]`.
    - Load a 32-bit integer from the middle 4 bytes of `iv`, byte-swap it, and store it in `le_ctr[2]`.
    - Load a 32-bit integer from the first 4 bytes of `iv`, byte-swap it, and store it in `le_ctr[3]`.
- **Output**: The function does not return a value; it modifies the `le_ctr` array in place.


---
### fd\_aes\_gcm\_encrypt\_aesni<!-- {{#callable:fd_aes_gcm_encrypt_aesni}} -->
The `fd_aes_gcm_encrypt_aesni` function performs AES-GCM encryption using AES-NI instructions, updating the GHASH accumulator and generating an authentication tag.
- **Inputs**:
    - `aes_gcm`: A pointer to an `fd_aes_gcm_aesni_t` structure containing the AES-GCM context and precomputed keys.
    - `c`: A pointer to the output buffer where the ciphertext will be stored.
    - `p`: A pointer to the input buffer containing the plaintext to be encrypted.
    - `sz`: The size of the plaintext in bytes.
    - `aad`: A pointer to the additional authenticated data (AAD) buffer.
    - `aad_sz`: The size of the AAD in bytes.
    - `tag`: A 16-byte buffer where the authentication tag will be stored.
- **Control Flow**:
    - Initialize a 4-element array `le_ctr` with the little-endian counter derived from the IV in `aes_gcm`.
    - Initialize a 16-byte `ghash_acc` array to zero, which will accumulate the GHASH value.
    - Call `aes_gcm_aad_update_aesni` to update the GHASH accumulator with the AAD.
    - Call `aes_gcm_enc_update_aesni` to encrypt the plaintext `p` into ciphertext `c` and update the GHASH accumulator.
    - Call `aes_gcm_enc_final_aesni` to finalize the encryption process, updating the GHASH accumulator with the total AAD and data lengths.
    - Copy the final GHASH accumulator value into the `tag` buffer.
- **Output**: The function outputs the encrypted ciphertext in the buffer `c` and the authentication tag in the buffer `tag`.
- **Functions called**:
    - [`load_le_ctr`](#load_le_ctr)


---
### fd\_aes\_gcm\_decrypt\_aesni<!-- {{#callable:fd_aes_gcm_decrypt_aesni}} -->
The `fd_aes_gcm_decrypt_aesni` function decrypts data using AES-GCM with AES-NI instructions, verifying the integrity of the data with a provided authentication tag.
- **Inputs**:
    - `aes_gcm`: A pointer to an `fd_aes_gcm_aesni_t` structure containing the AES-GCM context and precomputed keys.
    - `c`: A pointer to the ciphertext data to be decrypted.
    - `p`: A pointer to the buffer where the decrypted plaintext will be stored.
    - `sz`: The size of the ciphertext data in bytes.
    - `aad`: A pointer to the additional authenticated data (AAD) used in the decryption process.
    - `aad_sz`: The size of the additional authenticated data in bytes.
    - `tag`: A 16-byte array containing the authentication tag to verify the integrity of the decrypted data.
- **Control Flow**:
    - Initialize a 4-element array `le_ctr` and load it with a little-endian counter derived from the initialization vector (IV) stored in `aes_gcm`.
    - Initialize a 16-byte array `ghash_acc` to zero, which will accumulate the GHASH value during decryption.
    - Call `aes_gcm_aad_update_aesni` to update the GHASH accumulator with the additional authenticated data (AAD).
    - Call `aes_gcm_dec_update_aesni` to decrypt the ciphertext `c` into plaintext `p` while updating the GHASH accumulator with the decrypted data.
    - Call `aes_gcm_dec_final_aesni` to finalize the decryption process, verify the authentication tag, and return the result.
- **Output**: Returns an integer indicating the success or failure of the decryption and authentication process, typically 0 for success and non-zero for failure.
- **Functions called**:
    - [`load_le_ctr`](#load_le_ctr)


---
### fd\_aes\_128\_gcm\_init\_avx2<!-- {{#callable:fd_aes_128_gcm_init_avx2}} -->
The `fd_aes_128_gcm_init_avx2` function initializes an AES-GCM context for 128-bit encryption using AVX2 instructions by expanding the AES key, precomputing necessary values, and storing the initialization vector.
- **Inputs**:
    - `aes_gcm`: A pointer to an `fd_aes_gcm_aesni_t` structure where the AES-GCM context will be initialized.
    - `key`: A 16-byte array representing the 128-bit AES encryption key.
    - `iv`: A 12-byte array representing the initialization vector for the AES-GCM encryption.
- **Control Flow**:
    - The function begins by expanding the AES key using the [`expand_aes_key`](#expand_aes_key) function, which is called with a type-punned pointer to the `key` field of the `aes_gcm` structure and the provided `key` array.
    - Next, the function calls `aes_gcm_precompute_aesni_avx` to precompute values necessary for AES-GCM encryption using AVX2 instructions, passing the `aes_gcm` structure.
    - Finally, the function copies the 12-byte initialization vector from the `iv` array into the `iv` field of the `aes_gcm` structure using `memcpy`.
- **Output**: The function does not return a value; it initializes the provided `aes_gcm` structure for subsequent AES-GCM operations.
- **Functions called**:
    - [`expand_aes_key`](#expand_aes_key)


---
### fd\_aes\_gcm\_encrypt\_avx2<!-- {{#callable:fd_aes_gcm_encrypt_avx2}} -->
The `fd_aes_gcm_encrypt_avx2` function performs AES-GCM encryption using AVX2 and AES-NI instructions, updating the ciphertext and generating an authentication tag.
- **Inputs**:
    - `aes_gcm`: A pointer to an `fd_aes_gcm_aesni_t` structure containing the AES-GCM context and precomputed keys.
    - `c`: A pointer to the output buffer where the ciphertext will be stored.
    - `p`: A pointer to the input buffer containing the plaintext to be encrypted.
    - `sz`: The size of the plaintext in bytes.
    - `aad`: A pointer to the additional authenticated data (AAD) buffer.
    - `aad_sz`: The size of the AAD in bytes.
    - `tag`: A 16-byte buffer where the authentication tag will be stored.
- **Control Flow**:
    - Initialize a 4-element array `le_ctr` with the little-endian counter derived from the initialization vector (IV) in `aes_gcm` using [`load_le_ctr`](#load_le_ctr) function.
    - Initialize a 16-byte buffer `ghash_acc` to zero, which will accumulate the GHASH value.
    - Call `aes_gcm_aad_update_aesni_avx` to update the GHASH accumulator with the AAD.
    - Call `aes_gcm_enc_update_aesni_avx` to encrypt the plaintext `p` into ciphertext `c` and update the GHASH accumulator with the ciphertext.
    - Call `aes_gcm_enc_final_aesni_avx` to finalize the encryption process, updating the GHASH accumulator with the total AAD and plaintext sizes.
    - Copy the final GHASH accumulator value into the `tag` buffer as the authentication tag.
- **Output**: The function outputs the encrypted ciphertext in the buffer `c` and the authentication tag in the buffer `tag`.
- **Functions called**:
    - [`load_le_ctr`](#load_le_ctr)


---
### fd\_aes\_gcm\_decrypt\_avx2<!-- {{#callable:fd_aes_gcm_decrypt_avx2}} -->
The `fd_aes_gcm_decrypt_avx2` function performs AES-GCM decryption using AVX2 and AES-NI instructions, processing ciphertext and additional authenticated data to produce plaintext and verify the authentication tag.
- **Inputs**:
    - `aes_gcm`: A pointer to an `fd_aes_gcm_aesni_t` structure containing precomputed AES-GCM keys and initialization vector.
    - `c`: A pointer to the ciphertext data to be decrypted.
    - `p`: A pointer to the buffer where the decrypted plaintext will be stored.
    - `sz`: The size of the ciphertext data in bytes.
    - `aad`: A pointer to the additional authenticated data (AAD) used in the decryption process.
    - `aad_sz`: The size of the additional authenticated data in bytes.
    - `tag`: A 16-byte array containing the authentication tag to be verified.
- **Control Flow**:
    - Initialize a 4-element array `le_ctr` and load it with a little-endian counter derived from the initialization vector in `aes_gcm`.
    - Initialize a 16-byte array `ghash_acc` to zero, which will accumulate the GHASH value during decryption.
    - Call `aes_gcm_aad_update_aesni_avx` to update the GHASH accumulator with the additional authenticated data (AAD).
    - Call `aes_gcm_dec_update_aesni_avx` to decrypt the ciphertext `c` into plaintext `p` while updating the GHASH accumulator.
    - Call `aes_gcm_dec_final_aesni_avx` to finalize the decryption, verify the authentication tag, and return the result.
- **Output**: Returns an integer indicating the success or failure of the decryption and authentication tag verification; typically, 0 indicates success, and a non-zero value indicates failure.
- **Functions called**:
    - [`load_le_ctr`](#load_le_ctr)


---
### fd\_aes\_128\_gcm\_init\_avx10<!-- {{#callable:fd_aes_128_gcm_init_avx10}} -->
The `fd_aes_128_gcm_init_avx10` function initializes an AES-GCM context for 128-bit encryption using AVX-512 instructions.
- **Inputs**:
    - `aes_gcm`: A pointer to an `fd_aes_gcm_avx10_t` structure that will be initialized.
    - `key`: A 16-byte array representing the AES encryption key.
    - `iv`: A 12-byte array representing the initialization vector.
- **Control Flow**:
    - The function begins by expanding the AES key using the [`expand_aes_key`](#expand_aes_key) function, storing the result in the `key` field of the `aes_gcm` structure.
    - It then calls `aes_gcm_precompute_vaes_avx10_512` to precompute necessary values for the AES-GCM encryption using AVX-512 instructions.
    - Finally, it copies the 12-byte initialization vector into the `iv` field of the `aes_gcm` structure.
- **Output**: The function does not return a value; it initializes the provided `fd_aes_gcm_avx10_t` structure for subsequent AES-GCM operations.
- **Functions called**:
    - [`expand_aes_key`](#expand_aes_key)


---
### fd\_aes\_128\_gcm\_init\_avx10\_512<!-- {{#callable:fd_aes_128_gcm_init_avx10_512}} -->
The function `fd_aes_128_gcm_init_avx10_512` initializes an AES-GCM context for 128-bit encryption using AVX-512 instructions.
- **Inputs**:
    - `aes_gcm`: A pointer to an `fd_aes_gcm_avx10_t` structure that will be initialized.
    - `key`: A 16-byte array representing the AES encryption key.
    - `iv`: A 12-byte array representing the initialization vector.
- **Control Flow**:
    - The function calls [`expand_aes_key`](#expand_aes_key) to expand the provided 128-bit AES key and store it in the `aes_gcm` structure.
    - It then calls `aes_gcm_precompute_vaes_avx10_512` to precompute necessary values for the AES-GCM encryption using AVX-512 instructions.
    - Finally, it copies the 12-byte initialization vector into the `iv` field of the `aes_gcm` structure.
- **Output**: The function does not return a value; it initializes the `aes_gcm` structure in place.
- **Functions called**:
    - [`expand_aes_key`](#expand_aes_key)


---
### fd\_aes\_gcm\_encrypt\_avx10\_512<!-- {{#callable:fd_aes_gcm_encrypt_avx10_512}} -->
The `fd_aes_gcm_encrypt_avx10_512` function performs AES-GCM encryption using AVX-512 instructions, updating the GCM state with additional authenticated data and plaintext, and producing a ciphertext and authentication tag.
- **Inputs**:
    - `aes_gcm`: A pointer to an `fd_aes_gcm_avx10_t` structure that holds the AES-GCM context, including the encryption key and initialization vector.
    - `c`: A pointer to a buffer where the resulting ciphertext will be stored.
    - `p`: A pointer to the plaintext data that will be encrypted.
    - `sz`: The size of the plaintext data in bytes.
    - `aad`: A pointer to additional authenticated data (AAD) that will be included in the GCM authentication process.
    - `aad_sz`: The size of the additional authenticated data in bytes.
    - `tag`: A buffer of 16 bytes where the resulting authentication tag will be stored.
- **Control Flow**:
    - Initialize a local counter `le_ctr` using the initialization vector from `aes_gcm` by calling [`load_le_ctr`](#load_le_ctr).
    - Initialize a 16-byte buffer `ghash_acc` to zero, which will accumulate the GCM hash state.
    - Update the GCM state with the additional authenticated data (AAD) by calling `aes_gcm_aad_update_vaes_avx10`.
    - Encrypt the plaintext `p` into ciphertext `c` while updating the GCM hash state by calling `aes_gcm_enc_update_vaes_avx10_512`.
    - Finalize the encryption process by calling `aes_gcm_enc_final_vaes_avx10`, which completes the GCM hash state update.
    - Copy the final GCM hash state from `ghash_acc` into the `tag` buffer.
- **Output**: The function outputs the encrypted ciphertext in the buffer pointed to by `c` and the authentication tag in the `tag` buffer.
- **Functions called**:
    - [`load_le_ctr`](#load_le_ctr)


---
### fd\_aes\_gcm\_decrypt\_avx10\_512<!-- {{#callable:fd_aes_gcm_decrypt_avx10_512}} -->
The `fd_aes_gcm_decrypt_avx10_512` function performs AES-GCM decryption using AVX-512 instructions, processing ciphertext to produce plaintext and verifying the integrity with a tag.
- **Inputs**:
    - `aes_gcm`: A pointer to an `fd_aes_gcm_avx10_t` structure containing the AES-GCM context and precomputed keys.
    - `c`: A pointer to the ciphertext data to be decrypted.
    - `p`: A pointer to the buffer where the resulting plaintext will be stored.
    - `sz`: The size of the ciphertext data in bytes.
    - `aad`: A pointer to the additional authenticated data (AAD) used in the decryption process.
    - `aad_sz`: The size of the additional authenticated data in bytes.
    - `tag`: A 16-byte array containing the authentication tag to verify the integrity of the decrypted data.
- **Control Flow**:
    - Initialize a 4-element array `le_ctr` with a counter value derived from the initialization vector (IV) stored in `aes_gcm` using [`load_le_ctr`](#load_le_ctr) function.
    - Initialize a 16-byte array `ghash_acc` to zero, which will accumulate the GHASH value during decryption.
    - Update the GHASH accumulator with the additional authenticated data (AAD) using `aes_gcm_aad_update_vaes_avx10`.
    - Decrypt the ciphertext `c` into plaintext `p` while updating the GHASH accumulator using `aes_gcm_dec_update_vaes_avx10_512`.
    - Finalize the decryption process by verifying the tag and returning the result using `aes_gcm_dec_final_vaes_avx10`.
- **Output**: Returns an integer indicating the success or failure of the decryption and authentication process, typically 0 for success and non-zero for failure.
- **Functions called**:
    - [`load_le_ctr`](#load_le_ctr)


