# Purpose
This C header file defines the cryptographic components and operations necessary for implementing QUIC (Quick UDP Internet Connections) protocol version 1, focusing on the cryptographic suites and key management. The file specifies the supported cryptographic suites, such as TLS_AES_128_GCM_SHA256 and TLS_AES_256_GCM_SHA384, which are used for secure communication in QUIC. It provides structures and functions for managing cryptographic keys and secrets, including the generation of initial secrets and keys, key updates, and encryption and decryption of QUIC packets. The file also defines constants and macros related to encryption levels and cryptographic labels, which are essential for the QUIC protocol's security operations.

The header file is a crucial part of a larger QUIC implementation, providing the necessary cryptographic functionality to ensure secure data transmission. It includes functions for generating initial secrets based on connection IDs, deriving keys for packet protection, and handling key updates. Additionally, it offers functions for encrypting and decrypting QUIC packets and headers, adhering to the specifications outlined in RFC 9001. The file is designed to be included in other C source files, allowing them to utilize the defined cryptographic operations and structures, making it a foundational component for secure QUIC communication.
# Imports and Dependencies

---
- `../fd_quic_enum.h`
- `../../../ballet/aes/fd_aes_gcm.h`


# Data Structures

---
### fd\_quic\_crypto\_keys\_t
- **Type**: `struct`
- **Members**:
    - `pkt_key`: An array of unsigned characters used as the packet protection key.
    - `iv`: An array of unsigned characters used as the initialization vector for AES-GCM encryption.
    - `hp_key`: An array of unsigned characters used as the header protection key.
- **Description**: The `fd_quic_crypto_keys_t` structure is designed to hold cryptographic keys necessary for securing QUIC packets. It includes keys for packet protection, header protection, and an initialization vector, all of which are essential for encrypting and decrypting data in compliance with the QUIC protocol's security requirements.


---
### fd\_quic\_crypto\_secrets\_t
- **Type**: `struct`
- **Members**:
    - `initial_secret`: An array storing the initial secret used for QUIC encryption.
    - `secret`: A 3D array storing secrets for each encryption level and direction (incoming or outgoing).
    - `new_secret`: A 2D array storing new secrets for key updates during encryption.
- **Description**: The `fd_quic_crypto_secrets_t` structure is designed to manage cryptographic secrets used in the QUIC protocol for secure communication. It includes an initial secret for establishing the initial encryption context, a set of secrets for different encryption levels and directions (incoming and outgoing), and new secrets for handling key updates. This structure is crucial for maintaining the confidentiality and integrity of data transmitted over a QUIC connection by facilitating the generation and management of cryptographic keys.


---
### fd\_quic\_crypto\_keys
- **Type**: `struct`
- **Members**:
    - `pkt_key`: An array of unsigned characters used as the packet protection key.
    - `iv`: An array of unsigned characters used as the initialization vector for encryption.
    - `hp_key`: An array of unsigned characters used as the header protection key.
- **Description**: The `fd_quic_crypto_keys` structure is designed to hold cryptographic keys necessary for packet protection in the QUIC protocol. It includes a packet protection key (`pkt_key`), an initialization vector (`iv`), and a header protection key (`hp_key`), all of which are essential for ensuring the confidentiality and integrity of QUIC packets during transmission.


---
### fd\_quic\_crypto\_secrets
- **Type**: `struct`
- **Members**:
    - `initial_secret`: An array storing the initial secret used for QUIC encryption.
    - `secret`: A 3D array storing secrets for each encryption level and direction (incoming or outgoing).
    - `new_secret`: An array storing new secrets for key updates during encryption.
- **Description**: The `fd_quic_crypto_secrets` structure is designed to manage cryptographic secrets used in the QUIC protocol for secure communication. It includes an initial secret for establishing the initial encryption context, a multi-dimensional array to hold secrets for different encryption levels and directions (incoming and outgoing), and a provision for new secrets to facilitate key updates. This structure is crucial for maintaining the confidentiality and integrity of data transmitted over a QUIC connection by managing the cryptographic keys and secrets necessary for encryption and decryption processes.


# Functions

---
### fd\_quic\_get\_nonce<!-- {{#callable:fd_quic_get_nonce}} -->
The `fd_quic_get_nonce` function generates a nonce by XORing a given initialization vector (IV) with a 62-bit packet number, after swapping its byte order.
- **Inputs**:
    - `nonce`: A pointer to a buffer where the resulting nonce will be stored.
    - `iv`: A constant pointer to the initialization vector (IV) used in the nonce generation.
    - `pkt_number`: An unsigned long integer representing the packet number to be used in the nonce generation.
- **Control Flow**:
    - Define a mask constant `MASK_LOWER_62` to isolate the lower 62 bits of the packet number.
    - Copy the first 4 bytes of the IV into the nonce buffer using `memcpy`.
    - Load an unsigned long integer from the IV starting at the 5th byte using `FD_LOAD`.
    - Swap the byte order of the packet number masked with `MASK_LOWER_62` using `fd_ulong_bswap`.
    - XOR the loaded IV value with the byte-swapped packet number and store the result in the nonce buffer starting at the 5th byte using `FD_STORE`.
    - Undefine the `MASK_LOWER_62` constant.
- **Output**: The function does not return a value; it modifies the `nonce` buffer in place to contain the generated nonce.


# Function Declarations (Public API)

---
### fd\_quic\_gen\_initial\_secrets<!-- {{#callable_declaration:fd_quic_gen_initial_secrets}} -->
Generate initial cryptographic secrets for a QUIC connection.
- **Description**: This function is used to generate the initial cryptographic secrets required for a QUIC connection based on the provided connection ID. It must be called to set up the initial secrets before any secure communication can occur. The function differentiates between client and server roles, setting the appropriate secrets for each. It does not generate keys but prepares the secrets necessary for further cryptographic operations. This function should be called during the initial setup phase of a QUIC connection.
- **Inputs**:
    - `secrets`: A pointer to an fd_quic_crypto_secrets_t structure where the generated secrets will be stored. The caller must ensure this pointer is valid and points to a properly allocated structure.
    - `conn_id`: A pointer to a buffer containing the connection ID. This buffer must not be null and should contain the connection ID data used to derive the initial secrets.
    - `conn_id_sz`: The size of the connection ID buffer. It must accurately reflect the length of the data pointed to by conn_id.
    - `is_server`: An integer indicating the role of the current QUIC instance. A value of 1 indicates the server role, while 0 indicates the client role. This affects which secrets are set as incoming or outgoing.
- **Output**: None
- **See also**: [`fd_quic_gen_initial_secrets`](fd_quic_crypto_suites.c.driver.md#fd_quic_gen_initial_secrets)  (Implementation)


---
### fd\_quic\_gen\_keys<!-- {{#callable_declaration:fd_quic_gen_keys}} -->
Derives cryptographic keys for QUIC packet protection from a given secret.
- **Description**: This function is used to derive a set of cryptographic keys necessary for QUIC packet protection, including a packet protection key, a header protection key, and an initialization vector (IV). It must be called with a valid secret of 32 bytes, and the keys structure must be provided to store the derived keys. This function is typically called twice per encryption level, once for incoming keys and once for outgoing keys, ensuring that the keys structure is fully initialized for secure communication.
- **Inputs**:
    - `keys`: A pointer to an fd_quic_crypto_keys_t structure where the derived keys will be stored. The caller must ensure this pointer is valid and points to a properly allocated structure.
    - `secret`: A constant array of 32 unsigned characters representing the secret from which the keys will be derived. This array must be exactly 32 bytes long, and the caller retains ownership of the data.
- **Output**: None
- **See also**: [`fd_quic_gen_keys`](fd_quic_crypto_suites.c.driver.md#fd_quic_gen_keys)  (Implementation)


---
### fd\_quic\_key\_update\_derive<!-- {{#callable_declaration:fd_quic_key_update_derive}} -->
Derives new IVs and packet protection keys for the next QUIC key update.
- **Description**: This function is used to derive the next set of IVs and packet protection keys for QUIC key updates, which are periodic key rotations performed for security reasons. It should be called when a key update is required, using the current secrets to generate new keys. The function does not update header protection keys, only the IVs and packet protection keys. It is important to ensure that the `secrets` parameter is properly initialized with the current encryption secrets before calling this function.
- **Inputs**:
    - `secrets`: A pointer to an `fd_quic_crypto_secrets_t` structure containing the current encryption secrets. Must not be null and should be properly initialized with the current secrets.
    - `new_keys`: An array of two `fd_quic_crypto_keys_t` structures where the derived new keys will be stored. The caller must ensure this array is allocated and has space for two key structures.
- **Output**: None
- **See also**: [`fd_quic_key_update_derive`](fd_quic_crypto_suites.c.driver.md#fd_quic_key_update_derive)  (Implementation)


---
### fd\_quic\_crypto\_encrypt<!-- {{#callable_declaration:fd_quic_crypto_encrypt}} -->
Encrypts a QUIC packet with header and packet protection.
- **Description**: This function encrypts a QUIC packet according to RFC 9001, applying both packet protection and header protection. It should be used when preparing a packet for secure transmission over a QUIC connection. The function requires pre-allocated output buffer space, which must be large enough to accommodate the encrypted data and authentication tag. The function will fail if the output buffer is too small or if the header size is out of bounds. It is essential to provide valid encryption keys for both packet and header protection.
- **Inputs**:
    - `out`: A pointer to the buffer where the encrypted packet will be stored. The buffer must be pre-allocated and large enough to hold the encrypted data and authentication tag.
    - `out_sz`: A pointer to a variable that initially contains the size of the output buffer. On successful encryption, it will be updated to reflect the size of the encrypted data. The initial size must be at least hdr_sz + pkt_sz + FD_QUIC_CRYPTO_TAG_SZ.
    - `hdr`: A pointer to the plaintext header of the packet. This must not be null and should contain at least 4 bytes.
    - `hdr_sz`: The size of the header in bytes. It must be at least 4 and no more than INT_MAX.
    - `pkt`: A pointer to the plaintext payload of the packet. This must not be null.
    - `pkt_sz`: The size of the payload in bytes. It must not exceed INT_MAX.
    - `pkt_keys`: A pointer to the fd_quic_crypto_keys_t structure containing the keys for packet protection. This must not be null.
    - `hp_keys`: A pointer to the fd_quic_crypto_keys_t structure containing the keys for header protection. This must not be null.
    - `pkt_number`: The packet number, which is used in nonce generation for encryption.
- **Output**: Returns FD_QUIC_SUCCESS on successful encryption, or FD_QUIC_FAILED if an error occurs, such as insufficient output buffer size or invalid header size.
- **See also**: [`fd_quic_crypto_encrypt`](fd_quic_crypto_suites.c.driver.md#fd_quic_crypto_encrypt)  (Implementation)


---
### fd\_quic\_crypto\_decrypt<!-- {{#callable_declaration:fd_quic_crypto_decrypt}} -->
Decrypts a QUIC protected packet.
- **Description**: This function is used to decrypt a QUIC packet that contains a decrypted header, an encrypted payload, and an authentication tag. It should be called when you need to access the plaintext payload of a QUIC packet. The function requires a buffer containing the packet, the size of the packet, the offset of the packet number, the packet number itself, and the decryption keys. It returns a success or failure status based on whether the decryption was successful. Ensure that the buffer is large enough to contain the packet and that the packet number offset is correctly determined from the unprotected header data.
- **Inputs**:
    - `buf`: A buffer containing the QUIC packet with a decrypted header, encrypted payload, and authentication tag. The buffer must be large enough to hold the entire packet, including the authentication tag.
    - `buf_sz`: The size of the QUIC packet in the buffer. It must be at least the size of the shortest possible QUIC packet.
    - `pkt_number_off`: The offset of the packet number within the ciphertext. This must be determined from the unprotected header data.
    - `pkt_number`: The packet number used in the decryption process. It is used to derive the nonce for decryption.
    - `keys`: A pointer to the fd_quic_crypto_keys_t structure containing the keys needed for decryption. The caller retains ownership of this structure.
- **Output**: Returns FD_QUIC_SUCCESS if the decryption is successful, or FD_QUIC_FAILED if it fails due to issues like buffer size being too small or decryption errors.
- **See also**: [`fd_quic_crypto_decrypt`](fd_quic_crypto_suites.c.driver.md#fd_quic_crypto_decrypt)  (Implementation)


---
### fd\_quic\_crypto\_decrypt\_hdr<!-- {{#callable_declaration:fd_quic_crypto_decrypt_hdr}} -->
Decrypts the header of a QUIC packet by removing header protection.
- **Description**: Use this function to decrypt the header of a QUIC packet, which involves removing the header protection. This function should be called when you have a buffer containing an encrypted QUIC packet and you need to access the unprotected header information. Ensure that the buffer size is sufficient and that the packet number offset is correctly determined from the unprotected header data. The function requires a set of cryptographic keys to perform the decryption. It returns a success or failure status, indicating whether the header was successfully decrypted.
- **Inputs**:
    - `buf`: A pointer to a buffer containing an encrypted QUIC packet. The buffer must be large enough to hold the packet, and on return, the header will be decrypted while the rest remains encrypted. The caller retains ownership and the buffer must not be null.
    - `buf_sz`: The size of the buffer in bytes. It must be at least as large as the QUIC packet, including the header and any encrypted payload.
    - `pkt_number_off`: The offset within the buffer where the packet number is located. This offset must be determined from the unprotected header data and must be within the bounds of the buffer.
    - `keys`: A pointer to a constant fd_quic_crypto_keys_t structure containing the cryptographic keys needed for decryption. The caller retains ownership and the pointer must not be null.
- **Output**: Returns FD_QUIC_SUCCESS if the header was successfully decrypted, or FD_QUIC_FAILED if an error occurred, such as insufficient buffer size or invalid input parameters.
- **See also**: [`fd_quic_crypto_decrypt_hdr`](fd_quic_crypto_suites.c.driver.md#fd_quic_crypto_decrypt_hdr)  (Implementation)


