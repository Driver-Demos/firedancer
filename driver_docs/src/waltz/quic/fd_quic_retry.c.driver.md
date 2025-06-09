# Purpose
This C source code file is part of a QUIC (Quick UDP Internet Connections) protocol implementation, specifically focusing on handling QUIC Retry packets. The file provides functions to create, verify, and process Retry packets, which are used in the QUIC protocol to help manage connection establishment and mitigate certain types of network attacks. The key functions include [`fd_quic_retry_pseudo`](#fd_quic_retry_pseudo), which constructs a pseudo-packet for integrity verification, [`fd_quic_retry_create`](#fd_quic_retry_create), which crafts a new Retry packet with a token and integrity tags, and [`fd_quic_retry_server_verify`](#fd_quic_retry_server_verify) and [`fd_quic_retry_client_verify`](#fd_quic_retry_client_verify), which verify the validity of Retry packets on the server and client sides, respectively.

The code is structured to ensure the integrity and authenticity of Retry packets using cryptographic techniques, such as AES-GCM for creating and verifying integrity tags. It includes various checks to validate packet sizes, connection IDs, and tokens, ensuring compliance with the QUIC protocol specifications. The file is not an executable on its own but is intended to be part of a larger QUIC library, providing specific functionality related to Retry packets. It includes both public APIs for use by other components of the QUIC implementation and internal logic for handling the cryptographic and protocol-specific details of Retry packet processing.
# Imports and Dependencies

---
- `fd_quic_common.h`
- `fd_quic_retry_private.h`
- `crypto/fd_quic_crypto_suites.h`
- `fd_quic_conn_id.h`
- `fd_quic_enum.h`
- `fd_quic_private.h`
- `../../ballet/aes/fd_aes_gcm.h`
- `assert.h`


# Functions

---
### fd\_quic\_retry\_pseudo<!-- {{#callable:fd_quic_retry_pseudo}} -->
The `fd_quic_retry_pseudo` function constructs a QUIC retry pseudo-packet by combining the original destination connection ID and a stripped version of the retry packet, and returns the size of the constructed pseudo-packet.
- **Inputs**:
    - `out`: An array of unsigned characters where the constructed pseudo-packet will be stored.
    - `retry_pkt`: A pointer to the retry packet data that needs to be included in the pseudo-packet.
    - `retry_pkt_sz`: The size of the retry packet in bytes.
    - `orig_dst_conn_id`: A pointer to the original destination connection ID structure, which contains the size and the actual connection ID.
- **Control Flow**:
    - Check if the retry packet size is less than or equal to the crypto tag size or greater than the maximum allowed size; if so, return a parse failure code.
    - Initialize a pointer to the start of the output buffer.
    - Store the size of the original destination connection ID in the output buffer and advance the pointer.
    - Copy the original destination connection ID into the output buffer and advance the pointer by the size of the connection ID.
    - Calculate the size of the retry packet without the crypto tag and copy this stripped retry packet into the output buffer.
    - Return the total size of the constructed pseudo-packet by calculating the difference between the current pointer position and the start of the output buffer.
- **Output**: The function returns the size of the constructed pseudo-packet as an unsigned long integer, or a parse failure code if the input retry packet size is invalid.


---
### fd\_quic\_retry\_create<!-- {{#callable:fd_quic_retry_create}} -->
The `fd_quic_retry_create` function constructs a QUIC Retry packet with a header, token, and integrity tags, returning the size of the created packet.
- **Inputs**:
    - `retry`: An output buffer to store the created Retry packet, with a size of FD_QUIC_RETRY_LOCAL_SZ.
    - `pkt`: A pointer to the original QUIC packet structure containing source IP and UDP port information.
    - `rng`: A pointer to a random number generator used for creating new retry data.
    - `retry_secret`: A constant array of bytes used as a secret key for signing the retry token.
    - `retry_iv`: A constant array of bytes used as an initialization vector for signing the retry token.
    - `orig_dst_conn_id`: A pointer to the original destination connection ID structure.
    - `src_conn_id`: A pointer to the source connection ID structure.
    - `new_conn_id`: A new connection ID to be used in the Retry packet.
    - `expire_at`: A timestamp indicating when the retry token should expire.
- **Control Flow**:
    - Initialize pointers and available space for the output buffer.
    - Create a Retry packet header with specified connection IDs and version, then encode it into the output buffer.
    - Create a retry token with source IP, UDP port, and expiration data, and copy the original destination connection ID into it.
    - Sign the retry token using AES-GCM with the provided secret and IV, then clear the AES-GCM context.
    - If crypto is not disabled, calculate the pseudo header for the retry packet and sign the outer integrity tag using AES-GCM.
    - Ensure the total size of the created packet does not exceed the buffer size and return the size of the created packet.
- **Output**: The function returns the size of the created Retry packet as an unsigned long integer.
- **Functions called**:
    - [`fd_quic_retry_data_set_ip4`](fd_quic_retry.h.driver.md#fd_quic_retry_data_set_ip4)
    - [`fd_quic_retry_token_sign`](fd_quic_retry.h.driver.md#fd_quic_retry_token_sign)
    - [`fd_quic_retry_pseudo`](#fd_quic_retry_pseudo)
    - [`fd_quic_retry_integrity_tag_sign`](fd_quic_retry.h.driver.md#fd_quic_retry_integrity_tag_sign)


---
### fd\_quic\_retry\_server\_verify<!-- {{#callable:fd_quic_retry_server_verify}} -->
The `fd_quic_retry_server_verify` function verifies a QUIC retry token and checks if it matches the expected parameters, updating connection IDs if successful.
- **Inputs**:
    - `pkt`: A pointer to a `fd_quic_pkt_t` structure representing the QUIC packet to be verified.
    - `initial`: A pointer to a `fd_quic_initial_t` structure containing the initial packet data, including the destination connection ID and token.
    - `orig_dst_conn_id`: A pointer to a `fd_quic_conn_id_t` structure where the original destination connection ID will be stored if verification is successful.
    - `retry_src_conn_id`: A pointer to an `ulong` where the retry source connection ID will be stored if verification is successful.
    - `retry_secret`: An array of `uchar` of size `FD_QUIC_RETRY_SECRET_SZ` used as the secret key for token verification.
    - `retry_iv`: An array of `uchar` of size `FD_QUIC_RETRY_IV_SZ` used as the initialization vector for token verification.
    - `now`: An `ulong` representing the current time, used to check token expiration.
    - `ttl`: An `ulong` representing the time-to-live for the token, used to determine the expiration window.
- **Control Flow**:
    - Check if the destination connection ID length in the initial packet matches the expected size; if not, log a debug message and return failure.
    - Check if the token length in the initial packet matches the expected size; if not, log a debug message and return failure.
    - Retrieve the retry token from the initial packet and check if the original destination connection ID size is valid; if not, log a debug message and return failure.
    - Verify the retry token using AES-GCM with the provided secret and IV; clear the AES-GCM context after use.
    - Extract the IPv4 address and port from the packet and retry token, and check if they match, along with the token's expiration time being valid.
    - Log debug messages for various failure conditions, such as invalid token, expired token, or mismatched token.
    - If verification is successful, update the original destination connection ID and retry source connection ID with values from the retry token.
    - Return success if all checks pass, otherwise return failure.
- **Output**: Returns `FD_QUIC_SUCCESS` if the retry token is valid and matches the expected parameters, otherwise returns `FD_QUIC_FAILED`.
- **Functions called**:
    - [`fd_quic_retry_token_verify`](fd_quic_retry.h.driver.md#fd_quic_retry_token_verify)


---
### fd\_quic\_retry\_client\_verify<!-- {{#callable:fd_quic_retry_client_verify}} -->
The `fd_quic_retry_client_verify` function verifies the integrity and validity of a QUIC Retry packet received by a client.
- **Inputs**:
    - `retry_ptr`: A pointer to the start of the Retry packet data.
    - `retry_sz`: The size of the Retry packet data.
    - `orig_dst_conn_id`: A pointer to the original destination connection ID structure.
    - `src_conn_id`: A pointer to the source connection ID structure to be filled as output.
    - `token`: A pointer to a location where the address of the retry token will be stored as output.
    - `token_sz`: A pointer to a location where the size of the retry token will be stored as output.
- **Control Flow**:
    - Initialize pointers and sizes for processing the Retry packet.
    - Decode the Retry header using `fd_quic_decode_retry_hdr` and check for parsing failure.
    - Verify that the source connection ID length is non-zero to ensure packet validity.
    - Check that the remaining packet size is sufficient for a valid Retry token and integrity tag.
    - Extract the Retry token and verify its size is within acceptable limits.
    - Extract the Retry integrity tag and ensure the remaining size matches the expected tag size.
    - Construct a pseudo header for integrity verification using [`fd_quic_retry_pseudo`](#fd_quic_retry_pseudo).
    - If cryptographic verification is enabled, verify the integrity tag using [`fd_quic_retry_integrity_tag_verify`](fd_quic_retry.h.driver.md#fd_quic_retry_integrity_tag_verify).
    - If all checks pass, set the output parameters for source connection ID, token, and token size.
    - Return success or failure based on the verification results.
- **Output**: Returns `FD_QUIC_SUCCESS` if the Retry packet is valid and verified, otherwise returns `FD_QUIC_FAILED`.
- **Functions called**:
    - [`fd_quic_retry_pseudo`](#fd_quic_retry_pseudo)
    - [`fd_quic_retry_integrity_tag_verify`](fd_quic_retry.h.driver.md#fd_quic_retry_integrity_tag_verify)


