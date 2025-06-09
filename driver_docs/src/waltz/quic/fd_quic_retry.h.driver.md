# Purpose
The provided C header file, `fd_quic_retry.h`, defines a set of APIs and data structures for implementing the QUIC (Quick UDP Internet Connections) protocol's Retry mechanism, as specified in RFC 9000 and RFC 9001. This file is part of a larger QUIC implementation and focuses on handling the Retry process, which is a critical part of the QUIC handshake designed to mitigate denial-of-service attacks by verifying client addresses. The file includes functions for creating and verifying Retry Integrity Tags and tokens, which are essential for ensuring the integrity and authenticity of Retry packets exchanged between clients and servers.

Key components of this file include the implementation of the Retry Integrity Tag using AES-128-GCM, which is a cryptographic scheme for ensuring that Retry packets have not been tampered with. The file also defines structures such as `fd_quic_retry_data_t` and `fd_quic_retry_token_t` to encapsulate data within the QUIC Retry token, including client claims and connection identifiers. Functions like [`fd_quic_retry_integrity_tag_sign`](#fd_quic_retry_integrity_tag_sign) and [`fd_quic_retry_integrity_tag_verify`](#fd_quic_retry_integrity_tag_verify) are provided for signing and verifying these tags, while [`fd_quic_retry_token_sign`](#fd_quic_retry_token_sign) and [`fd_quic_retry_token_verify`](#fd_quic_retry_token_verify) handle the authentication of Retry tokens. This header file is intended to be included in other parts of the QUIC implementation, providing a specialized and secure mechanism for handling Retry operations in QUIC connections.
# Imports and Dependencies

---
- `fd_quic_conn_id.h`
- `fd_quic_enum.h`
- `fd_quic_proto_structs.h`
- `crypto/fd_quic_crypto_suites.h`
- `../../ballet/aes/fd_aes_gcm.h`


# Global Variables

---
### struct
- **Type**: `struct`
- **Description**: The `fd_quic_retry_data` structure is a packed data structure used to encode data within the QUIC Retry token. It contains various fields that hold claims about the client, such as a magic number, a pseudorandom token ID, the client's IP address, UDP port, expiration time, and connection IDs.
- **Use**: This structure is used to store and manage client-related data necessary for the QUIC Retry token authentication process.


---
### FD\_PROTOTYPES\_BEGIN
- **Type**: `Macro`
- **Description**: `FD_PROTOTYPES_BEGIN` is a macro used to mark the beginning of a section in the code where function prototypes are declared. It is typically used to ensure that the function prototypes are properly encapsulated and can be conditionally included or excluded based on compilation settings.
- **Use**: This macro is used to delineate the start of a block of function prototypes, aiding in code organization and conditional compilation.


# Data Structures

---
### fd\_quic\_retry\_data\_t
- **Type**: `struct`
- **Members**:
    - `magic`: A magic number used to identify the structure, set to 0xdaa5.
    - `token_id`: A 12-byte pseudorandom identifier for the token, which is guessable.
    - `ip6_addr`: A 16-byte array representing the source IPv6 or IPv4-mapped IPv6 address in network byte order.
    - `udp_port`: The source UDP port in host byte order.
    - `expire_comp`: A compressed expiration time represented as Unix nanoseconds shifted right by 22 bits.
    - `rscid`: The Retry Source Connection ID.
    - `odcid`: A 20-byte array representing the Original Destination Connection ID.
    - `odcid_sz`: The size of the Original Destination Connection ID, ranging from 1 to 20.
- **Description**: The `fd_quic_retry_data_t` structure is used to encode data within the QUIC Retry token, containing claims about the client. It includes fields for a magic number, a pseudorandom token identifier, the client's IP address and UDP port, a compressed expiration timestamp, and connection identifiers for both the retry source and original destination. This structure is packed to ensure a specific memory layout, which is crucial for the integrity and verification processes in the QUIC protocol's retry mechanism.


---
### fd\_quic\_retry\_token
- **Type**: `struct`
- **Members**:
    - `data`: A union member that holds the retry data in a structured format.
    - `data_opaque`: A union member that holds the retry data in an opaque byte array format.
    - `mac_tag`: An array of bytes used as a Message Authentication Code (MAC) tag for integrity verification.
- **Description**: The `fd_quic_retry_token` structure is designed to encapsulate a QUIC retry token, which is used in the QUIC protocol to handle retry mechanisms securely. It contains a union that can store the retry data either as a structured `fd_quic_retry_data_t` or as an opaque byte array, allowing for flexible data handling. Additionally, it includes a `mac_tag` field, which is used to store a cryptographic tag for verifying the integrity of the retry token using AES-GCM encryption. This structure is part of a non-standard implementation to authenticate QUIC retry tokens, ensuring secure and stateless handling of retries.


---
### fd\_quic\_retry\_token\_t
- **Type**: `struct`
- **Members**:
    - `data`: A union member that holds the retry data in a structured format.
    - `data_opaque`: A union member that holds the retry data in an opaque byte array format.
    - `mac_tag`: An array that stores the message authentication code (MAC) tag for the retry token.
- **Description**: The `fd_quic_retry_token_t` structure is designed to encapsulate a QUIC Retry token, which is used in the QUIC protocol to handle connection retries securely. This structure contains a union that allows the retry data to be accessed either as a structured `fd_quic_retry_data_t` or as a raw byte array `data_opaque`. Additionally, it includes a `mac_tag` field, which is used to store the authentication tag generated by the AES-GCM encryption process, ensuring the integrity and authenticity of the retry token. This structure is crucial for implementing secure and stateless retry mechanisms in QUIC connections.


# Functions

---
### fd\_quic\_retry\_integrity\_tag\_sign<!-- {{#callable:fd_quic_retry_integrity_tag_sign}} -->
The `fd_quic_retry_integrity_tag_sign` function generates a retry integrity tag for a given pseudo-packet using AES-128-GCM encryption.
- **Inputs**:
    - `aes_gcm`: A pointer to an `fd_aes_gcm_t` structure, which is used to perform AES-GCM encryption.
    - `retry_pseudo_pkt`: A pointer to the byte array representing the pseudo-packet for which the integrity tag is to be generated.
    - `retry_pseudo_pkt_len`: The length of the pseudo-packet in bytes.
    - `retry_integrity_tag`: An array of bytes where the generated integrity tag will be stored; it must be of size `FD_QUIC_RETRY_INTEGRITY_TAG_SZ`.
- **Control Flow**:
    - Initialize the AES-GCM context using the hardcoded key `FD_QUIC_RETRY_INTEGRITY_TAG_KEY` and nonce `FD_QUIC_RETRY_INTEGRITY_TAG_NONCE` by calling `fd_aes_128_gcm_init`.
    - Encrypt the pseudo-packet using `fd_aes_gcm_encrypt`, which writes the resulting integrity tag into `retry_integrity_tag`.
- **Output**: The function does not return a value; it outputs the integrity tag directly into the `retry_integrity_tag` array.


---
### fd\_quic\_retry\_integrity\_tag\_verify<!-- {{#callable:fd_quic_retry_integrity_tag_verify}} -->
The `fd_quic_retry_integrity_tag_verify` function verifies the integrity of a QUIC retry packet using AES-128-GCM decryption.
- **Inputs**:
    - `aes_gcm`: A pointer to an `fd_aes_gcm_t` structure used for AES-GCM encryption/decryption operations.
    - `retry_pseudo_pkt`: A pointer to the retry pseudo packet data that needs to be verified.
    - `retry_pseudo_pkt_len`: The length of the retry pseudo packet data.
    - `retry_integrity_tag`: A 16-byte array containing the retry integrity tag to be verified.
- **Control Flow**:
    - Initialize the AES-GCM context using the provided `aes_gcm` pointer, with a predefined key and nonce for the retry integrity tag.
    - Attempt to decrypt the `retry_pseudo_pkt` using the AES-GCM context and the provided `retry_integrity_tag`.
    - Check the result of the decryption; if successful, return `FD_QUIC_SUCCESS`, otherwise return `FD_QUIC_FAILED`.
- **Output**: Returns `FD_QUIC_SUCCESS` if the integrity tag is valid, otherwise returns `FD_QUIC_FAILED`.


---
### fd\_quic\_retry\_data\_set\_ip4<!-- {{#callable:fd_quic_retry_data_set_ip4}} -->
The `fd_quic_retry_data_set_ip4` function sets the IPv4 address in a `fd_quic_retry_data_t` structure as an IPv4-mapped IPv6 address.
- **Inputs**:
    - `data`: A pointer to a `fd_quic_retry_data_t` structure where the IPv4 address will be set.
    - `ip4_addr`: A 32-bit unsigned integer representing the IPv4 address in big-endian order.
- **Control Flow**:
    - The function begins by zeroing out the first 10 bytes of the `ip6_addr` field in the `fd_quic_retry_data_t` structure to prepare it for an IPv4-mapped IPv6 address.
    - It then sets the next 2 bytes of the `ip6_addr` field to 0xFF, which is part of the standard format for IPv4-mapped IPv6 addresses.
    - Finally, it stores the provided `ip4_addr` into the last 4 bytes of the `ip6_addr` field using the `FD_STORE` macro, completing the conversion to an IPv4-mapped IPv6 address.
- **Output**: The function returns a pointer to the modified `fd_quic_retry_data_t` structure.


---
### fd\_quic\_retry\_token\_sign<!-- {{#callable:fd_quic_retry_token_sign}} -->
The `fd_quic_retry_token_sign` function generates a MAC tag for a QUIC retry token using AES-GCM encryption with a derived initialization vector.
- **Inputs**:
    - `token`: A pointer to an `fd_quic_retry_token_t` structure that contains the data to be signed and where the resulting MAC tag will be stored.
    - `aes_gcm`: A pointer to an `fd_aes_gcm_t` structure used for AES-GCM encryption operations.
    - `aes_key`: A constant pointer to an array of unsigned characters representing the AES encryption key.
    - `aes_iv`: A constant pointer to an array of unsigned characters representing the AES initialization vector.
- **Control Flow**:
    - Initialize a 12-byte array `iv` to store the derived initialization vector.
    - Iterate over 12 bytes to compute the derived IV by XORing each byte of `aes_iv` with the corresponding byte of `token->data.token_id`.
    - Initialize the AES-GCM context using `fd_aes_128_gcm_init` with the derived IV and the provided AES key.
    - Set the additional authenticated data (AAD) to `token->data_opaque` and its size to the size of `fd_quic_retry_data_t`.
    - Encrypt the AAD using `fd_aes_gcm_encrypt` to generate the MAC tag, which is stored in `token->mac_tag`.
- **Output**: The function does not return a value; it modifies the `mac_tag` field of the `token` structure to contain the generated MAC tag.


---
### fd\_quic\_retry\_token\_verify<!-- {{#callable:fd_quic_retry_token_verify}} -->
The `fd_quic_retry_token_verify` function verifies the validity of a QUIC retry token using AES-GCM decryption.
- **Inputs**:
    - `token`: A pointer to a `fd_quic_retry_token_t` structure containing the token data and MAC tag to be verified.
    - `aes_gcm`: A pointer to an `fd_aes_gcm_t` structure used for AES-GCM operations.
    - `aes_key`: A pointer to an array of unsigned characters representing the AES key used for decryption.
    - `aes_iv`: A pointer to an array of unsigned characters representing the AES initialization vector used for decryption.
- **Control Flow**:
    - Initialize a 12-byte array `iv` by XORing each byte of `aes_iv` with the corresponding byte of `token->data.token_id`.
    - Initialize the AES-GCM context `aes_gcm` with the provided `aes_key` and the computed `iv`.
    - Set `aad` to point to `token->data_opaque` and `aad_sz` to the size of `fd_quic_retry_data_t`.
    - Call `fd_aes_gcm_decrypt` to attempt decryption of the token's MAC tag using the AES-GCM context, with `aad` as the additional authenticated data.
    - Return `FD_QUIC_SUCCESS` if decryption is successful, otherwise return `FD_QUIC_FAILED`.
- **Output**: Returns `FD_QUIC_SUCCESS` if the token's MAC tag is valid, otherwise returns `FD_QUIC_FAILED`.


# Function Declarations (Public API)

---
### fd\_quic\_retry\_create<!-- {{#callable_declaration:fd_quic_retry_create}} -->
Generates a QUIC Retry packet with integrity and authentication tokens.
- **Description**: This function is used to create a QUIC Retry packet, which is part of the QUIC protocol's mechanism to handle connection retries. It should be called on the server side when a Retry packet needs to be sent to a client, typically in response to an initial connection attempt that requires validation. The function requires several parameters, including connection identifiers and cryptographic keys, to generate a packet that includes both a retry token and an integrity tag. The generated packet is written to the provided buffer, and the function returns the size of the created packet. It is important to ensure that the buffer provided is of sufficient size to hold the packet, as defined by FD_QUIC_RETRY_LOCAL_SZ.
- **Inputs**:
    - `retry`: A buffer where the generated Retry packet will be stored. It must be at least FD_QUIC_RETRY_LOCAL_SZ bytes in size.
    - `pkt`: A pointer to the fd_quic_pkt_t structure representing the original packet that triggered the Retry. This must not be null.
    - `rng`: A pointer to an fd_rng_t structure used for generating random values. This must not be null.
    - `retry_secret`: A constant array of bytes used as the secret key for generating the retry token's integrity tag. It must be FD_QUIC_RETRY_SECRET_SZ bytes long.
    - `retry_iv`: A constant array of bytes used as the initialization vector for the retry token's integrity tag. It must be FD_QUIC_RETRY_IV_SZ bytes long.
    - `orig_dst_conn_id`: A pointer to the fd_quic_conn_id_t structure representing the original destination connection ID chosen by the client. This must not be null.
    - `src_conn_id`: A pointer to the fd_quic_conn_id_t structure representing the source connection ID chosen by the server. This must not be null.
    - `new_conn_id`: An unsigned long representing the new connection ID to be used in the Retry packet.
    - `expire_at`: An unsigned long representing the expiration time for the retry token, in nanoseconds since the Unix epoch.
- **Output**: Returns the size of the generated Retry packet in bytes.
- **See also**: [`fd_quic_retry_create`](fd_quic_retry.c.driver.md#fd_quic_retry_create)  (Implementation)


---
### fd\_quic\_retry\_server\_verify<!-- {{#callable_declaration:fd_quic_retry_server_verify}} -->
Verifies a QUIC retry token on the server side.
- **Description**: This function is used to verify the authenticity and validity of a QUIC retry token received by a server. It should be called when a server receives a retry packet from a client to ensure that the token is valid and was issued by the server. The function checks the token's integrity, expiration, and matches it against the client's IP and port. It requires the original destination connection ID and the retry source connection ID to be provided as output parameters. The function must be called with valid retry secret and IV values, and the current time and token time-to-live must be specified. If the token is invalid or expired, the function returns a failure code.
- **Inputs**:
    - `pkt`: A pointer to a constant fd_quic_pkt_t structure representing the received packet. Must not be null.
    - `initial`: A pointer to a constant fd_quic_initial_t structure representing the initial packet data. Must not be null and must have a destination connection ID length equal to FD_QUIC_CONN_ID_SZ.
    - `orig_dst_conn_id`: A pointer to an fd_quic_conn_id_t structure where the original destination connection ID will be stored. Must not be null.
    - `retry_src_conn_id`: A pointer to an unsigned long where the retry source connection ID will be stored. Must not be null.
    - `retry_secret`: An array of unsigned characters of size FD_QUIC_RETRY_SECRET_SZ representing the retry secret. Must not be null.
    - `retry_iv`: An array of unsigned characters of size FD_QUIC_RETRY_IV_SZ representing the retry initialization vector. Must not be null.
    - `now`: An unsigned long representing the current time in nanoseconds.
    - `ttl`: An unsigned long representing the time-to-live for the token in nanoseconds.
- **Output**: Returns FD_QUIC_SUCCESS if the token is valid and matches the expected criteria, otherwise returns FD_QUIC_FAILED.
- **See also**: [`fd_quic_retry_server_verify`](fd_quic_retry.c.driver.md#fd_quic_retry_server_verify)  (Implementation)


---
### fd\_quic\_retry\_client\_verify<!-- {{#callable_declaration:fd_quic_retry_client_verify}} -->
Verifies a QUIC Retry packet on the client side.
- **Description**: This function is used to verify the integrity and validity of a QUIC Retry packet received by a client. It should be called when a client receives a Retry packet in response to its Initial packet. The function checks the Retry Integrity Tag and extracts the source connection ID and token from the packet. It requires the original destination connection ID used in the Initial packet for verification. The function will return a failure code if the packet is invalid or the integrity tag cannot be verified.
- **Inputs**:
    - `retry_ptr`: Pointer to the buffer containing the Retry packet data. Must not be null.
    - `retry_sz`: Size of the Retry packet data in bytes. Must be greater than the size of the Retry Integrity Tag.
    - `orig_dst_conn_id`: Pointer to the original destination connection ID used in the Initial packet. Must not be null.
    - `src_conn_id`: Pointer to a fd_quic_conn_id_t structure where the source connection ID from the Retry packet will be stored. Must not be null.
    - `token`: Pointer to a location where the address of the token in the Retry packet will be stored. Must not be null.
    - `token_sz`: Pointer to a location where the size of the token will be stored. Must not be null.
- **Output**: Returns FD_QUIC_SUCCESS if the Retry packet is valid and the integrity tag is verified, otherwise returns FD_QUIC_FAILED.
- **See also**: [`fd_quic_retry_client_verify`](fd_quic_retry.c.driver.md#fd_quic_retry_client_verify)  (Implementation)


