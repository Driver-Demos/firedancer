# Purpose
This C source code file is part of a QUIC (Quick UDP Internet Connections) implementation, specifically focusing on cryptographic operations necessary for secure communication. The file provides functions to generate initial secrets, derive keys, and perform encryption and decryption of QUIC packets. It includes cryptographic operations such as HKDF (HMAC-based Key Derivation Function) extraction and expansion, AES-GCM (Advanced Encryption Standard in Galois/Counter Mode) encryption, and header protection, which are essential for maintaining the confidentiality and integrity of data transmitted over a QUIC connection.

The code is structured around several key functions that handle different aspects of QUIC cryptography. [`fd_quic_gen_initial_secrets`](#fd_quic_gen_initial_secrets) and [`fd_quic_key_update_derive`](#fd_quic_key_update_derive) are responsible for generating and updating cryptographic secrets used in the QUIC protocol. [`fd_quic_crypto_encrypt`](#fd_quic_crypto_encrypt) and [`fd_quic_crypto_decrypt`](#fd_quic_crypto_decrypt) manage the encryption and decryption of packet payloads, ensuring data security during transmission. Additionally, [`fd_quic_crypto_decrypt_hdr`](#fd_quic_crypto_decrypt_hdr) deals with decrypting packet headers, which is crucial for processing incoming packets correctly. The file imports several headers related to cryptographic algorithms and utilities, indicating its reliance on external libraries for low-level cryptographic operations. Overall, this file is a specialized component of a larger QUIC implementation, providing essential cryptographic functionality to support secure data exchange.
# Imports and Dependencies

---
- `fd_quic_crypto_suites.h`
- `../fd_quic.h`
- `../../../ballet/aes/fd_aes_base.h`
- `../../../ballet/aes/fd_aes_gcm.h`
- `../../../ballet/hmac/fd_hmac.h`
- `../templ/fd_quic_parse_util.h`


# Global Variables

---
### FD\_QUIC\_CRYPTO\_V1\_INITIAL\_SALT
- **Type**: ``uchar const[20]``
- **Description**: `FD_QUIC_CRYPTO_V1_INITIAL_SALT` is a static constant array of 20 unsigned characters. It represents the initial salt used in the key derivation process for QUIC version 1, as specified in the QUIC protocol RFC.
- **Use**: This variable is used as the initial salt in the HKDF (HMAC-based Extract-and-Expand Key Derivation Function) to derive initial secrets for QUIC connections.


# Functions

---
### fd\_quic\_hkdf\_extract<!-- {{#callable:fd_quic_hkdf_extract}} -->
The `fd_quic_hkdf_extract` function performs an HMAC-SHA256 operation to derive a key from a given connection ID and salt.
- **Inputs**:
    - `output`: A pointer to the memory location where the derived key will be stored.
    - `salt`: A pointer to the salt value used in the HMAC operation.
    - `salt_sz`: The size of the salt in bytes.
    - `conn_id`: A pointer to the connection ID used in the HMAC operation.
    - `conn_id_sz`: The size of the connection ID in bytes.
- **Control Flow**:
    - The function calls `fd_hmac_sha256` with the connection ID, its size, the salt, its size, and the output buffer.
    - The `fd_hmac_sha256` function computes the HMAC-SHA256 of the connection ID using the salt and stores the result in the output buffer.
- **Output**: The function does not return a value; it writes the derived key to the memory location pointed to by `output`.


---
### fd\_quic\_hkdf\_expand\_label<!-- {{#callable:fd_quic_hkdf_expand_label}} -->
The `fd_quic_hkdf_expand_label` function is a wrapper that calls `fd_tls_hkdf_expand_label` to expand a given secret using a specified label and output size.
- **Inputs**:
    - `out`: A pointer to the output buffer where the expanded key will be stored.
    - `out_sz`: The size of the output buffer, indicating how many bytes should be written.
    - `secret`: A 32-byte array representing the secret key to be expanded.
    - `label`: A pointer to a character array representing the label used in the expansion process.
    - `label_sz`: The size of the label in bytes.
- **Control Flow**:
    - The function directly calls `fd_tls_hkdf_expand_label` with the provided arguments, passing `NULL` and `0UL` for the context and context size parameters, respectively.
- **Output**: The function does not return a value; it writes the expanded key to the provided output buffer.


---
### fd\_quic\_gen\_initial\_secrets<!-- {{#callable:fd_quic_gen_initial_secrets}} -->
The `fd_quic_gen_initial_secrets` function generates initial cryptographic secrets for QUIC connections based on the connection ID and whether the endpoint is a server or client.
- **Inputs**:
    - `secrets`: A pointer to an `fd_quic_crypto_secrets_t` structure where the generated secrets will be stored.
    - `conn_id`: A constant pointer to an array of unsigned characters representing the connection ID.
    - `conn_id_sz`: An unsigned long representing the size of the connection ID.
    - `is_server`: An integer indicating whether the endpoint is a server (non-zero) or a client (zero).
- **Control Flow**:
    - Retrieve the initial salt value from a predefined constant `FD_QUIC_CRYPTO_V1_INITIAL_SALT`.
    - Calculate the size of the initial salt using `sizeof` on the constant.
    - Call [`fd_quic_hkdf_extract`](#fd_quic_hkdf_extract) to derive the initial secret using the initial salt and the connection ID.
    - Determine the read and write secrets based on whether the endpoint is a server or client.
    - Use [`fd_quic_hkdf_expand_label`](#fd_quic_hkdf_expand_label) to expand the initial secret into client and server secrets using predefined labels for client and server input.
- **Output**: The function does not return a value; it modifies the `secrets` structure in place to store the generated initial secrets.
- **Functions called**:
    - [`fd_quic_hkdf_extract`](#fd_quic_hkdf_extract)
    - [`fd_quic_hkdf_expand_label`](#fd_quic_hkdf_expand_label)


---
### fd\_quic\_key\_update\_derive<!-- {{#callable:fd_quic_key_update_derive}} -->
The `fd_quic_key_update_derive` function derives new cryptographic keys for QUIC key updates using HKDF expansion.
- **Inputs**:
    - `secrets`: A pointer to an `fd_quic_crypto_secrets_t` structure containing the current cryptographic secrets.
    - `new_keys`: An array of two `fd_quic_crypto_keys_t` structures where the newly derived keys will be stored.
- **Control Flow**:
    - Retrieve the encryption level identifier for application data.
    - Iterate over two elements (j=0 and j=1) to derive new secrets using [`fd_quic_hkdf_expand_label`](#fd_quic_hkdf_expand_label) with the current secrets and a key update label.
    - For each new secret, derive a new packet key and IV using [`fd_quic_hkdf_expand_label`](#fd_quic_hkdf_expand_label) with appropriate labels for QUIC key and IV.
- **Output**: The function does not return a value; it updates the `new_keys` array with newly derived cryptographic keys.
- **Functions called**:
    - [`fd_quic_hkdf_expand_label`](#fd_quic_hkdf_expand_label)


---
### fd\_quic\_gen\_keys<!-- {{#callable:fd_quic_gen_keys}} -->
The `fd_quic_gen_keys` function generates cryptographic keys for QUIC protocol operations using a given secret.
- **Inputs**:
    - `keys`: A pointer to an `fd_quic_crypto_keys_t` structure where the generated keys will be stored.
    - `secret`: A 32-byte array containing the secret used to derive the keys.
- **Control Flow**:
    - The function calls [`fd_quic_hkdf_expand_label`](#fd_quic_hkdf_expand_label) to generate the packet key (`pkt_key`) using the provided secret and the label `FD_QUIC_CRYPTO_LABEL_QUIC_KEY`.
    - It then calls [`fd_quic_hkdf_expand_label`](#fd_quic_hkdf_expand_label) again to generate the header protection key (`hp_key`) using the same secret and the label `FD_QUIC_CRYPTO_LABEL_QUIC_HP`.
    - Finally, it calls [`fd_quic_hkdf_expand_label`](#fd_quic_hkdf_expand_label) to generate the initialization vector (`iv`) using the secret and the label `FD_QUIC_CRYPTO_LABEL_QUIC_IV`.
- **Output**: The function does not return a value; it populates the `keys` structure with the derived cryptographic keys.
- **Functions called**:
    - [`fd_quic_hkdf_expand_label`](#fd_quic_hkdf_expand_label)


---
### fd\_quic\_crypto\_encrypt<!-- {{#callable:fd_quic_crypto_encrypt}} -->
The `fd_quic_crypto_encrypt` function encrypts a QUIC packet using AEAD_AES_128_GCM and applies header protection.
- **Inputs**:
    - `out`: A pointer to the output buffer where the encrypted packet will be stored.
    - `out_sz`: A pointer to the size of the output buffer, which will be updated to the size of the encrypted data.
    - `hdr`: A pointer to the packet header data to be encrypted.
    - `hdr_sz`: The size of the packet header in bytes.
    - `pkt`: A pointer to the packet data to be encrypted.
    - `pkt_sz`: The size of the packet data in bytes.
    - `pkt_keys`: A pointer to the cryptographic keys used for packet encryption.
    - `hp_keys`: A pointer to the cryptographic keys used for header protection.
    - `pkt_number`: The packet number used to derive the nonce for encryption.
- **Control Flow**:
    - Calculate the required buffer size for the encrypted output and check if the provided buffer is sufficient.
    - Check if the header size is within valid bounds and if the packet size is not too large.
    - Copy the header data into the output buffer.
    - Determine the packet number size and its position in the header.
    - Generate a nonce using the packet number and the IV from `pkt_keys`.
    - Initialize the AEAD_AES_128_GCM cipher with the packet key and nonce.
    - Encrypt the packet data and append the authentication tag to the output buffer.
    - Update the output size to reflect the total size of the encrypted data.
    - Calculate the sample position for header protection based on the packet number size.
    - Initialize the AES encryption key for header protection using `hp_keys`.
    - Encrypt the sample to generate a mask for header protection.
    - Apply the mask to the first byte of the header and the packet number to protect the header.
    - Return success status.
- **Output**: Returns `FD_QUIC_SUCCESS` on successful encryption or `FD_QUIC_FAILED` if an error occurs, such as insufficient buffer size.
- **Functions called**:
    - [`fd_quic_get_nonce`](fd_quic_crypto_suites.h.driver.md#fd_quic_get_nonce)


---
### fd\_quic\_crypto\_decrypt<!-- {{#callable:fd_quic_crypto_decrypt}} -->
The `fd_quic_crypto_decrypt` function decrypts a QUIC packet using AES-GCM with the provided cryptographic keys and packet number.
- **Inputs**:
    - `buf`: A pointer to the buffer containing the encrypted packet data.
    - `buf_sz`: The size of the buffer in bytes.
    - `pkt_number_off`: The offset in the buffer where the packet number starts.
    - `pkt_number`: The packet number used to derive the nonce for decryption.
    - `keys`: A pointer to the cryptographic keys used for decryption.
- **Control Flow**:
    - Check if the packet number offset is within the buffer size and if the buffer size is at least the minimum required for a QUIC packet; return failure if not.
    - Derive the header size using the first byte of the buffer to determine the packet number length.
    - Calculate the nonce by XORing the QUIC IV with the reconstructed packet number.
    - Check if the buffer size is sufficient for the header and the GCM tag; return failure if not.
    - Calculate the offsets for the header, payload, and GCM tag within the buffer.
    - Initialize the AES-GCM cipher with the packet key and nonce.
    - Attempt to decrypt the payload using the AES-GCM cipher; return failure if decryption fails.
    - Return success if decryption is successful.
- **Output**: Returns `FD_QUIC_SUCCESS` on successful decryption or `FD_QUIC_FAILED` if any checks fail or decryption is unsuccessful.
- **Functions called**:
    - [`fd_quic_get_nonce`](fd_quic_crypto_suites.h.driver.md#fd_quic_get_nonce)


---
### fd\_quic\_crypto\_decrypt\_hdr<!-- {{#callable:fd_quic_crypto_decrypt_hdr}} -->
The `fd_quic_crypto_decrypt_hdr` function decrypts the header of a QUIC packet using header protection keys.
- **Inputs**:
    - `buf`: A pointer to the buffer containing the encrypted packet header.
    - `buf_sz`: The size of the buffer in bytes.
    - `pkt_number_off`: The offset in the buffer where the packet number starts.
    - `keys`: A pointer to the `fd_quic_crypto_keys_t` structure containing the header protection keys.
- **Control Flow**:
    - Check if the buffer size is less than the crypto tag size or if the packet number offset is out of bounds; if so, log a warning and return failure.
    - Extract the first byte of the buffer to determine if it is a long header and calculate the sample offset.
    - Check if there are enough bytes for a sample; if not, log a warning and return failure.
    - Set up AES-128 encryption using the header protection key and encrypt the sample to get the mask.
    - Use the mask to decrypt the first byte of the buffer.
    - Calculate the packet number size based on the decrypted first byte and check if it fits within the buffer; if not, log a warning and return failure.
    - Decrypt the packet number using the mask.
- **Output**: Returns `FD_QUIC_SUCCESS` on successful decryption of the header, or `FD_QUIC_FAILED` if any checks fail.


