# Purpose
This C source code file is part of a library that implements the Transport Layer Security (TLS) protocol, specifically focusing on the TLS 1.3 version. The file provides a comprehensive set of functions for managing TLS handshakes, both for clients and servers. It includes the creation and management of TLS sessions, handling of cryptographic operations such as key exchange and signature verification, and the encoding and decoding of TLS protocol messages. The code is structured to support both client-side and server-side operations, with distinct functions for each role, such as [`fd_tls_client_handshake`](#fd_tls_client_handshake) and [`fd_tls_server_handshake`](#fd_tls_server_handshake).

The file includes several key components: pre-generated cryptographic keys and constants, functions for initializing and managing TLS session states, and detailed implementations of the TLS handshake process. It also defines functions for handling specific TLS messages like `ClientHello`, `ServerHello`, `Certificate`, and `Finished`. The code is designed to be integrated into a larger system, as indicated by its use of external headers and its structure, which suggests it is part of a modular library. The file does not define a main function, indicating it is not an executable but rather a library component intended to be used by other parts of a TLS implementation. Additionally, the file provides utility functions for error handling and logging, which are crucial for debugging and maintaining robust security protocols.
# Imports and Dependencies

---
- `fd_tls.h`
- `fd_tls_proto.h`
- `../../ballet/ed25519/fd_ed25519.h`
- `../../ballet/ed25519/fd_x25519.h`
- `../../ballet/hmac/fd_hmac.h`
- `assert.h`


# Global Variables

---
### fd\_tls13\_cli\_sign\_prefix
- **Type**: `char const[98]`
- **Description**: The `fd_tls13_cli_sign_prefix` is a static constant character array of size 98, initialized with 64 spaces followed by the string 'TLS 1.3, client CertificateVerify'. This prefix is used in the TLS 1.3 protocol during the client CertificateVerify message creation.
- **Use**: This variable is used as a prefix in the message that the client signs during the TLS 1.3 handshake process to verify its certificate.


---
### fd\_tls13\_srv\_sign\_prefix
- **Type**: `char const[98]`
- **Description**: The `fd_tls13_srv_sign_prefix` is a static constant character array of size 98, initialized with 64 spaces followed by the string 'TLS 1.3, server CertificateVerify'. This prefix is used in the TLS 1.3 protocol during the server's CertificateVerify message to ensure the integrity and authenticity of the server's certificate.
- **Use**: This variable is used as a prefix in the message that the server signs during the TLS 1.3 handshake process to verify its certificate.


---
### empty\_hash
- **Type**: `uchar const[32]`
- **Description**: The `empty_hash` is a static constant array of 32 unsigned characters, representing a precomputed SHA-256 hash of an empty input. The specific byte values correspond to the SHA-256 hash of an empty string, which is a well-known constant in cryptographic applications.
- **Use**: This variable is used as a default or initial hash value in cryptographic operations, particularly in the context of TLS handshake processes.


---
### handshake\_derived
- **Type**: `uchar const[32]`
- **Description**: The `handshake_derived` variable is a static constant array of 32 unsigned characters (bytes) that holds a precomputed value used in the TLS handshake process. This array is initialized with a specific sequence of hexadecimal values.
- **Use**: This variable is used as a salt in the HMAC-SHA256 function to derive the main handshake secret during the TLS handshake process.


# Functions

---
### fd\_tls\_align<!-- {{#callable:fd_tls_align}} -->
The `fd_tls_align` function returns the alignment requirement of the `fd_tls_t` type.
- **Inputs**: None
- **Control Flow**:
    - The function simply returns the result of the `alignof` operator applied to `fd_tls_t`.
- **Output**: The function outputs an `ulong` representing the alignment requirement of the `fd_tls_t` type.


---
### fd\_tls\_footprint<!-- {{#callable:fd_tls_footprint}} -->
The `fd_tls_footprint` function returns the size of the `fd_tls_t` structure.
- **Inputs**: None
- **Control Flow**:
    - The function simply returns the result of the `sizeof` operator applied to `fd_tls_t`.
- **Output**: The function outputs an `ulong` representing the size in bytes of the `fd_tls_t` structure.


---
### fd\_tls\_new<!-- {{#callable:fd_tls_new}} -->
The `fd_tls_new` function initializes a memory block for a TLS structure, ensuring it is non-null and properly aligned, and then zeroes out the memory.
- **Inputs**:
    - `mem`: A pointer to a memory block intended to be used for a TLS structure.
- **Control Flow**:
    - Check if the `mem` pointer is NULL; if so, log a warning and return NULL.
    - Check if the `mem` pointer is aligned according to [`fd_tls_align`](#fd_tls_align); if not, log a warning and return NULL.
    - Retrieve the footprint size of the TLS structure using [`fd_tls_footprint`](#fd_tls_footprint).
    - Zero out the memory block using `memset` with the footprint size.
    - Return the `mem` pointer.
- **Output**: Returns the `mem` pointer if successful, or NULL if the input is invalid or unaligned.
- **Functions called**:
    - [`fd_tls_align`](#fd_tls_align)
    - [`fd_tls_footprint`](#fd_tls_footprint)


---
### fd\_tls\_join<!-- {{#callable:fd_tls_join}} -->
The `fd_tls_join` function casts a given memory pointer to a `fd_tls_t` pointer and returns it.
- **Inputs**:
    - `mem`: A void pointer to a memory location that is expected to be of type `fd_tls_t`.
- **Control Flow**:
    - The function takes a single input parameter, `mem`, which is a void pointer.
    - It casts the `mem` pointer to a `fd_tls_t` pointer.
    - The function returns the casted pointer.
- **Output**: A pointer of type `fd_tls_t` that points to the same memory location as the input `mem`.


---
### fd\_tls\_leave<!-- {{#callable:fd_tls_leave}} -->
The `fd_tls_leave` function returns a pointer to the `fd_tls_t` server object passed to it.
- **Inputs**:
    - `server`: A pointer to an `fd_tls_t` object representing the server.
- **Control Flow**:
    - The function takes a single argument, `server`, which is a pointer to an `fd_tls_t` object.
    - It returns the `server` pointer cast to a `void *`.
- **Output**: A `void *` pointer to the `fd_tls_t` server object passed as input.


---
### fd\_tls\_delete<!-- {{#callable:fd_tls_delete}} -->
The `fd_tls_delete` function returns the memory pointer passed to it without any modification.
- **Inputs**:
    - `mem`: A pointer to a memory block that is intended to be deleted or freed.
- **Control Flow**:
    - The function takes a single argument, `mem`, which is a pointer to a memory block.
    - It simply returns the same pointer `mem` without performing any operations on it.
- **Output**: The function returns the same pointer `mem` that was passed as an argument.


---
### fd\_tls\_estate\_srv\_new<!-- {{#callable:fd_tls_estate_srv_new}} -->
The `fd_tls_estate_srv_new` function initializes a new server-side TLS handshake state structure with default values.
- **Inputs**:
    - `mem`: A pointer to a memory block where the new `fd_tls_estate_srv_t` structure will be initialized.
- **Control Flow**:
    - Cast the input `mem` pointer to a `fd_tls_estate_srv_t` pointer and assign it to `hs`.
    - Use `memset` to zero out the memory for the `fd_tls_estate_srv_t` structure pointed to by `hs`.
    - Set the `state` field of the `base` member of `hs` to `FD_TLS_HS_START`, indicating the start of the handshake process.
    - Set the `server` field of the `base` member of `hs` to `1`, indicating that this is a server-side handshake.
    - Return the pointer `hs`.
- **Output**: A pointer to the initialized `fd_tls_estate_srv_t` structure.


---
### fd\_tls\_estate\_cli\_new<!-- {{#callable:fd_tls_estate_cli_new}} -->
The `fd_tls_estate_cli_new` function initializes a new client-side TLS handshake state structure with a given memory block.
- **Inputs**:
    - `mem`: A pointer to a memory block where the new `fd_tls_estate_cli_t` structure will be initialized.
- **Control Flow**:
    - The function casts the input memory pointer to a `fd_tls_estate_cli_t` pointer.
    - It uses `memset` to zero out the memory for the `fd_tls_estate_cli_t` structure.
    - The `state` field of the `base` structure within `fd_tls_estate_cli_t` is set to `FD_TLS_HS_START`.
    - The function returns the initialized `fd_tls_estate_cli_t` pointer.
- **Output**: A pointer to the newly initialized `fd_tls_estate_cli_t` structure.


---
### fd\_tls\_hkdf\_expand\_label<!-- {{#callable:fd_tls_hkdf_expand_label}} -->
The `fd_tls_hkdf_expand_label` function performs the HKDF-Expand-Label operation as specified in TLS 1.3, using HMAC-SHA256 to derive a key material from a given secret, label, and context.
- **Inputs**:
    - `out`: A pointer to the output buffer where the derived key material will be stored.
    - `out_sz`: The size of the output buffer, which must be less than or equal to 32 bytes.
    - `secret`: A 32-byte array representing the secret key used in the HMAC operation.
    - `label`: A pointer to a string representing the label used in the HKDF-Expand-Label operation.
    - `label_sz`: The size of the label string.
    - `context`: A pointer to the context data used in the HKDF-Expand-Label operation.
    - `context_sz`: The size of the context data.
- **Control Flow**:
    - Check that the sizes of the label, context, and output buffer do not exceed their respective limits.
    - Initialize an `info` buffer to construct the HKDF info structure, starting with the length of the hash output.
    - Add the length-prefixed label, prefixed with 'tls13 ', to the `info` buffer.
    - Add the length-prefixed context to the `info` buffer.
    - Append a suffix byte (0x01) to the `info` buffer to complete the HKDF info structure.
    - Compute the HMAC-SHA256 hash of the `info` buffer using the provided secret.
    - Copy the first `out_sz` bytes of the hash to the output buffer `out`.
- **Output**: A pointer to the output buffer `out` containing the derived key material.


---
### fd\_tls\_has\_alpn<!-- {{#callable:fd_tls_has_alpn}} -->
The `fd_tls_has_alpn` function checks if a target ALPN protocol is present in a given list of ALPN protocols.
- **Inputs**:
    - `list`: A pointer to an array of unsigned characters representing the list of ALPN protocols.
    - `list_sz`: The size of the list of ALPN protocols.
    - `target`: A pointer to an array of unsigned characters representing the target ALPN protocol to search for.
    - `target_sz`: The size of the target ALPN protocol.
- **Control Flow**:
    - Check if the target size is less than or equal to 1; if so, return 0 indicating the target is invalid.
    - Calculate the end of the list by adding the list size to the list pointer.
    - Iterate over the list while the current position is less than the end of the list.
    - For each element, read the size of the element from the first byte and increment the list pointer.
    - Check if the element size is greater than the remaining list size; if so, return -1 indicating an error.
    - Increment the list pointer by the element size to move to the next element.
    - If the element size matches the target size minus one, compare the element with the target (excluding the first byte) using `memcmp`.
    - If a match is found, return 1 indicating the target is present in the list.
    - If no match is found after iterating through the list, return 0.
- **Output**: Returns 1 if the target ALPN protocol is found in the list, 0 if not found, and -1 if there is an error in processing the list.


---
### fd\_tls\_alert<!-- {{#callable:fd_tls_alert}} -->
The `fd_tls_alert` function sets a reason code in a TLS handshake state and returns a negated alert number.
- **Inputs**:
    - `hs`: A pointer to a `fd_tls_estate_base_t` structure representing the TLS handshake state.
    - `alert`: An unsigned integer representing the TLS alert number.
    - `reason`: An unsigned short representing the reason code for the alert.
- **Control Flow**:
    - Assign the `reason` parameter to the `reason` field of the `hs` structure.
    - Return the negated value of the `alert` parameter cast to a long.
- **Output**: Returns a negated long integer value of the alert number.


---
### fd\_tls\_send\_cert\_verify<!-- {{#callable:fd_tls_send_cert_verify}} -->
The `fd_tls_send_cert_verify` function generates and sends a CertificateVerify message during a TLS handshake, signing the current transcript hash and encoding the message for transmission.
- **Inputs**:
    - `this`: A pointer to the local client or server object (`fd_tls_t const *`).
    - `hs`: A pointer to the local handshake object (`fd_tls_estate_base_t *`).
    - `transcript`: A pointer to the SHA-256 state of the transcript hasher (`fd_sha256_t *`).
    - `is_client`: An integer indicating if the local role is a client (1) or server (0).
- **Control Flow**:
    - Copy the appropriate TLS 1.3 prefix (client or server) into the `sign_msg` buffer based on `is_client`.
    - Clone the current transcript hash and finalize it, appending the result to `sign_msg`.
    - Sign the `sign_msg` using the [`fd_tls_sign`](fd_tls.h.driver.md#fd_tls_sign) function and store the signature in `cert_verify_sig`.
    - Prepare a buffer `msg_buf` for the CertificateVerify message and leave space for the message header.
    - Construct a `fd_tls_cert_verify_t` structure with the signature algorithm and the signature, then encode it into `msg_buf`.
    - If encoding fails, return a TLS alert with the appropriate error code.
    - Encode the message header and calculate the total size of the CertificateVerify message.
    - Send the CertificateVerify message using the `sendmsg_fn` callback function.
    - If sending fails, return a TLS alert indicating an internal error.
    - Append the CertificateVerify message to the transcript hash to update it.
    - Return 0L to indicate success.
- **Output**: Returns 0L on success or a negated TLS alert number on failure.
- **Functions called**:
    - [`fd_tls_sign`](fd_tls.h.driver.md#fd_tls_sign)
    - [`fd_tls_encode_cert_verify`](fd_tls_proto.c.driver.md#fd_tls_encode_cert_verify)
    - [`fd_tls_alert`](#fd_tls_alert)
    - [`fd_uint_to_tls_u24`](fd_tls_proto.h.driver.md#fd_uint_to_tls_u24)


---
### fd\_tls\_server\_handshake<!-- {{#callable:fd_tls_server_handshake}} -->
The `fd_tls_server_handshake` function manages the state transitions of a TLS server handshake process based on the current state of the handshake.
- **Inputs**:
    - `server`: A pointer to a constant `fd_tls_t` structure representing the server.
    - `handshake`: A pointer to an `fd_tls_estate_srv_t` structure representing the current handshake state.
    - `msg`: A pointer to a constant void representing the message data received.
    - `msg_sz`: An unsigned long representing the size of the message data.
    - `encryption_level`: An unsigned integer representing the current encryption level of the handshake.
- **Control Flow**:
    - The function checks the current state of the handshake using a switch statement on `handshake->base.state`.
    - If the state is `FD_TLS_HS_START`, it calls [`fd_tls_server_hs_start`](#fd_tls_server_hs_start) with the provided parameters and returns its result.
    - If the state is `FD_TLS_HS_WAIT_FINISHED`, it calls [`fd_tls_server_hs_wait_finished`](#fd_tls_server_hs_wait_finished) with the provided parameters and returns its result.
    - For any other state, it returns an alert using [`fd_tls_alert`](#fd_tls_alert) indicating an illegal state.
- **Output**: The function returns a long integer, which is either the result of the called handshake function or a negative alert code indicating an error.
- **Functions called**:
    - [`fd_tls_server_hs_start`](#fd_tls_server_hs_start)
    - [`fd_tls_server_hs_wait_finished`](#fd_tls_server_hs_wait_finished)
    - [`fd_tls_alert`](#fd_tls_alert)


---
### fd\_tls\_server\_hs\_retry<!-- {{#callable:fd_tls_server_hs_retry}} -->
The `fd_tls_server_hs_retry` function handles the retry process for a TLS server handshake by constructing and sending a HelloRetryRequest message when the initial handshake attempt lacks the necessary X25519 key share.
- **Inputs**:
    - `server`: A constant pointer to an `fd_tls_t` structure representing the server.
    - `handshake`: A pointer to an `fd_tls_estate_srv_t` structure representing the server's handshake state.
    - `ch`: A constant pointer to an `fd_tls_client_hello_t` structure representing the client's hello message.
    - `ch1_hash`: A constant array of 32 unsigned characters representing the hash of the first client hello message.
- **Control Flow**:
    - Check if a retry has already been attempted by examining `handshake->hello_retry`; if true, return an alert indicating an illegal parameter.
    - Set `handshake->hello_retry` to 1 to indicate a retry is being attempted.
    - Initialize a message buffer `msg_buf` of size 512 bytes to construct the HelloRetryRequest message.
    - Initialize a SHA-256 transcript hasher and append a prefix and the hash of the first client hello message to it.
    - Construct a `fd_tls_server_hello_t` structure with the necessary cipher suite, key share, and session ID, and copy the server's public key into the key share.
    - Encode the HelloRetryRequest message into the message buffer and handle any encoding errors by returning an alert.
    - Send the HelloRetryRequest message using the server's `sendmsg_fn` callback and handle any sending errors by returning an alert.
    - Append the HelloRetryRequest message to the transcript hash.
    - Store the transcript hash state in the handshake's transcript.
    - Set the handshake state to `FD_TLS_HS_START` to indicate the start of a new handshake attempt.
- **Output**: Returns 0 on success, or a negative value representing a TLS alert code on failure.
- **Functions called**:
    - [`fd_tls_alert`](#fd_tls_alert)
    - [`fd_tls_encode_hello_retry_request`](fd_tls_proto.c.driver.md#fd_tls_encode_hello_retry_request)
    - [`fd_uint_to_tls_u24`](fd_tls_proto.h.driver.md#fd_uint_to_tls_u24)
    - [`fd_tls_transcript_store`](fd_tls_estate.h.driver.md#fd_tls_transcript_store)


---
### fd\_tls\_server\_hs\_start<!-- {{#callable:fd_tls_server_hs_start}} -->
The `fd_tls_server_hs_start` function initiates the server-side TLS handshake process by processing the client's initial message, negotiating cryptographic parameters, and sending the necessary server responses.
- **Inputs**:
    - `server`: A pointer to a constant `fd_tls_t` structure representing the server's TLS context.
    - `handshake`: A pointer to a `fd_tls_estate_srv_t` structure representing the server's handshake state.
    - `record`: A pointer to a constant unsigned character array containing the client's initial handshake message.
    - `record_sz`: An unsigned long integer representing the size of the client's initial handshake message.
    - `encryption_level`: An unsigned integer indicating the encryption level of the message, expected to be `FD_TLS_LEVEL_INITIAL`.
- **Control Flow**:
    - Initialize QUIC transport parameters if the server supports QUIC.
    - Check if the encryption level is `FD_TLS_LEVEL_INITIAL`, returning an alert if not.
    - Initialize a message buffer and a SHA-256 transcript hasher.
    - Decode the client's 'ClientHello' message from the record, returning an alert if decoding fails or if the message type is unexpected.
    - Verify the client's cryptographic compatibility, returning an alert if any required feature is unsupported.
    - Copy the client's random value for logging purposes.
    - If in QUIC mode, verify the presence of QUIC transport parameters and inform the user of the peer's parameters.
    - Check for ALPN (Application-Layer Protocol Negotiation) support, returning an alert if negotiation fails.
    - Append the 'ClientHello' message to the transcript hash.
    - If the client's key share is missing, initiate a retry process and return the result.
    - Generate a random server value and construct a 'ServerHello' message, encoding it into the message buffer.
    - Send the 'ServerHello' message to the client and append it to the transcript hash.
    - Derive handshake secrets using ECDH and HMAC-SHA256 operations, and call back with these secrets.
    - Construct and send an 'EncryptedExtensions' message, encoding it into the message buffer and appending it to the transcript hash.
    - Send the server's certificate, encoding it into the message buffer and appending it to the transcript hash.
    - Send a 'CertificateVerify' message, verifying the server's certificate signature.
    - Send a 'Finished' message, deriving and verifying the 'Finished' key and data, and appending it to the transcript hash.
    - Derive application secrets and call back with these secrets.
    - Store the transcript hash state and update the handshake state to `FD_TLS_HS_WAIT_FINISHED`.
- **Output**: Returns a long integer representing the size of the processed client message, or a negative value indicating an alert code if an error occurs.
- **Functions called**:
    - [`fd_tls_alert`](#fd_tls_alert)
    - [`fd_tls_transcript_load`](fd_tls_estate.h.driver.md#fd_tls_transcript_load)
    - [`fd_tls_decode_client_hello`](fd_tls_proto.c.driver.md#fd_tls_decode_client_hello)
    - [`fd_tls_has_alpn`](#fd_tls_has_alpn)
    - [`fd_tls_server_hs_retry`](#fd_tls_server_hs_retry)
    - [`fd_tls_rand`](fd_tls.h.driver.md#fd_tls_rand)
    - [`fd_tls_encode_server_hello`](fd_tls_proto.c.driver.md#fd_tls_encode_server_hello)
    - [`fd_uint_to_tls_u24`](fd_tls_proto.h.driver.md#fd_uint_to_tls_u24)
    - [`fd_tls_hkdf_expand_label`](#fd_tls_hkdf_expand_label)
    - [`fd_tls_encode_enc_ext`](fd_tls_proto.c.driver.md#fd_tls_encode_enc_ext)
    - [`fd_tls_encode_raw_public_key`](fd_tls_proto.c.driver.md#fd_tls_encode_raw_public_key)
    - [`fd_tls_encode_cert_x509`](fd_tls_proto.c.driver.md#fd_tls_encode_cert_x509)
    - [`fd_tls_send_cert_verify`](#fd_tls_send_cert_verify)
    - [`fd_tls_msg_hdr_bswap`](fd_tls_proto.h.driver.md#fd_tls_msg_hdr_bswap)
    - [`fd_tls_transcript_store`](fd_tls_estate.h.driver.md#fd_tls_transcript_store)


---
### fd\_tls\_handle\_cert\_chain<!-- {{#callable:fd_tls_handle_cert_chain}} -->
The `fd_tls_handle_cert_chain` function processes a certificate chain to extract and verify the public key, and optionally outputs the public key if required.
- **Inputs**:
    - `base`: A pointer to the TLS estate base structure, used for managing the TLS state and handling alerts.
    - `cert_chain`: A pointer to the certificate chain data to be processed.
    - `cert_chain_sz`: The size of the certificate chain data in bytes.
    - `expected_pubkey`: A pointer to the expected public key for verification, or NULL if no verification is needed.
    - `out_pubkey`: A pointer to a buffer where the extracted public key will be stored, or NULL if the public key is not needed.
    - `is_rpk`: An integer flag indicating whether the certificate chain is a raw public key (RPK) or an X.509 certificate.
- **Control Flow**:
    - Call [`fd_tls_extract_cert_pubkey`](fd_tls_proto.c.driver.md#fd_tls_extract_cert_pubkey) to extract the public key from the certificate chain, specifying the type based on `is_rpk`.
    - Check if the extraction was successful by verifying if `extract.pubkey` is not NULL; if it is NULL, trigger a TLS alert with the extracted alert and reason.
    - If `expected_pubkey` is provided, compare it with the extracted public key using `memcmp`; if they do not match, trigger a TLS alert for handshake failure due to wrong public key.
    - If `out_pubkey` is provided, copy the extracted public key to `out_pubkey` using `fd_memcpy`.
    - Return the size of the certificate chain as a long integer.
- **Output**: Returns the size of the certificate chain as a long integer, or a negative value indicating a TLS alert if an error occurs.
- **Functions called**:
    - [`fd_tls_extract_cert_pubkey`](fd_tls_proto.c.driver.md#fd_tls_extract_cert_pubkey)
    - [`fd_tls_alert`](#fd_tls_alert)


---
### fd\_tls\_handle\_cert\_verify<!-- {{#callable:fd_tls_handle_cert_verify}} -->
The `fd_tls_handle_cert_verify` function processes and verifies a CertificateVerify message in a TLS handshake, ensuring the signature is valid using the provided public key.
- **Inputs**:
    - `hs`: A pointer to the TLS handshake state structure (`fd_tls_estate_base_t`).
    - `transcript`: A constant pointer to the SHA-256 hash state of the handshake transcript (`fd_sha256_t`).
    - `record`: A constant pointer to the byte array containing the CertificateVerify message record.
    - `record_sz`: The size of the CertificateVerify message record in bytes.
    - `pubkey`: A constant array of 32 bytes representing the public key used for signature verification.
    - `is_client`: An integer indicating if the local role is a client (1) or server (0).
- **Control Flow**:
    - Initialize a `fd_tls_cert_verify_t` structure to store the decoded CertificateVerify message.
    - Decode the message header from the record and check for errors or unexpected message types.
    - Decode the CertificateVerify message and check for errors.
    - Verify that the signature algorithm is Ed25519; if not, return a handshake failure alert.
    - Prepare the message to be signed by copying the appropriate prefix and finalizing the transcript hash into the message buffer.
    - Verify the signature using the Ed25519 algorithm with the provided public key and the prepared message.
    - If the signature verification fails, return a decrypt error alert.
    - Return the size of the processed record.
- **Output**: Returns the size of the processed CertificateVerify message record on success, or a negative value indicating a TLS alert on failure.
- **Functions called**:
    - [`fd_tls_u24_to_uint`](fd_tls_proto.h.driver.md#fd_tls_u24_to_uint)
    - [`fd_tls_alert`](#fd_tls_alert)
    - [`fd_tls_decode_cert_verify`](fd_tls_proto.c.driver.md#fd_tls_decode_cert_verify)


---
### fd\_tls\_server\_hs\_wait\_finished<!-- {{#callable:fd_tls_server_hs_wait_finished}} -->
The `fd_tls_server_hs_wait_finished` function processes the client's 'Finished' message during a TLS handshake, verifying the message's integrity and updating the handshake state if successful.
- **Inputs**:
    - `server`: A constant pointer to the TLS server object, which is not used in this function.
    - `handshake`: A pointer to the server's handshake state structure, used to manage the handshake process and store state information.
    - `record`: A constant pointer to the incoming record data containing the client's 'Finished' message.
    - `record_sz`: The size of the incoming record data.
    - `encryption_level`: The encryption level of the incoming message, expected to be `FD_TLS_LEVEL_HANDSHAKE`.
- **Control Flow**:
    - The function first checks if the encryption level is `FD_TLS_LEVEL_HANDSHAKE`; if not, it returns an internal error alert.
    - The function restores the transcript state from the handshake structure.
    - It decodes the incoming 'Finished' message from the client, checking for errors in the message header and type.
    - The function calculates the expected 'Finished' verify data using the transcript hash and the derived 'Finished' key.
    - It compares the client's 'Finished' verify data with the expected data to ensure they match.
    - If the verify data does not match, it returns a decrypt error alert.
    - If successful, the function updates the handshake state to `FD_TLS_HS_CONNECTED` and returns the size of the processed record.
- **Output**: Returns the size of the processed record on success, or a negative value representing a TLS alert code on failure.
- **Functions called**:
    - [`fd_tls_alert`](#fd_tls_alert)
    - [`fd_tls_transcript_load`](fd_tls_estate.h.driver.md#fd_tls_transcript_load)
    - [`fd_tls_hkdf_expand_label`](#fd_tls_hkdf_expand_label)


---
### fd\_tls\_client\_handshake<!-- {{#callable:fd_tls_client_handshake}} -->
The `fd_tls_client_handshake` function manages the state transitions and processing of messages during a TLS handshake from the client's perspective.
- **Inputs**:
    - `client`: A pointer to a constant `fd_tls_t` structure representing the client.
    - `handshake`: A pointer to an `fd_tls_estate_cli_t` structure representing the client's handshake state.
    - `record`: A pointer to the incoming message or record data.
    - `record_sz`: The size of the incoming message or record data.
    - `encryption_level`: The current encryption level of the handshake process.
- **Control Flow**:
    - The function begins by checking the current state of the handshake using a switch statement on `handshake->base.state`.
    - If the state is `FD_TLS_HS_START`, it calls [`fd_tls_client_hs_start`](#fd_tls_client_hs_start) to initiate the handshake, ignoring the `record`, `record_sz`, and `encryption_level` arguments.
    - For `FD_TLS_HS_WAIT_SH`, it processes an incoming ServerHello message by calling [`fd_tls_client_hs_wait_sh`](#fd_tls_client_hs_wait_sh).
    - For `FD_TLS_HS_WAIT_EE`, it processes an incoming EncryptedExtensions message by calling [`fd_tls_client_hs_wait_ee`](#fd_tls_client_hs_wait_ee).
    - For `FD_TLS_HS_WAIT_CERT_CR`, it processes an incoming CertificateRequest or Certificate message by calling [`fd_tls_client_hs_wait_cert_cr`](#fd_tls_client_hs_wait_cert_cr).
    - For `FD_TLS_HS_WAIT_CERT`, it processes an incoming Certificate message by calling [`fd_tls_client_hs_wait_cert`](#fd_tls_client_hs_wait_cert).
    - For `FD_TLS_HS_WAIT_CV`, it processes an incoming CertificateVerify message by calling [`fd_tls_client_hs_wait_cert_verify`](#fd_tls_client_hs_wait_cert_verify).
    - For `FD_TLS_HS_WAIT_FINISHED`, it processes an incoming Server Finished message by calling [`fd_tls_client_hs_wait_finished`](#fd_tls_client_hs_wait_finished).
    - If the state is not recognized, it returns a handshake failure alert using [`fd_tls_alert`](#fd_tls_alert).
- **Output**: The function returns a `long` value, which is either the result of the called state-specific function or a negative value indicating a TLS alert in case of an error.
- **Functions called**:
    - [`fd_tls_client_hs_start`](#fd_tls_client_hs_start)
    - [`fd_tls_client_hs_wait_sh`](#fd_tls_client_hs_wait_sh)
    - [`fd_tls_client_hs_wait_ee`](#fd_tls_client_hs_wait_ee)
    - [`fd_tls_client_hs_wait_cert_cr`](#fd_tls_client_hs_wait_cert_cr)
    - [`fd_tls_client_hs_wait_cert`](#fd_tls_client_hs_wait_cert)
    - [`fd_tls_client_hs_wait_cert_verify`](#fd_tls_client_hs_wait_cert_verify)
    - [`fd_tls_client_hs_wait_finished`](#fd_tls_client_hs_wait_finished)
    - [`fd_tls_alert`](#fd_tls_alert)


---
### fd\_tls\_client\_hs\_start<!-- {{#callable:fd_tls_client_hs_start}} -->
The `fd_tls_client_hs_start` function initiates a TLS handshake from the client side by constructing and sending a ClientHello message, and updating the handshake state.
- **Inputs**:
    - `client`: A pointer to a constant `fd_tls_t` structure representing the client context.
    - `handshake`: A pointer to a `fd_tls_estate_cli_t` structure representing the client's handshake state.
- **Control Flow**:
    - Initialize a buffer for QUIC transport parameters and determine its size if QUIC is enabled.
    - Initialize a message buffer and a SHA-256 hasher for the handshake transcript.
    - Generate a random value for the client and store it in the handshake state.
    - Construct a ClientHello message with supported versions, groups, algorithms, cipher suites, and key shares.
    - Encode the ClientHello message and check for encoding errors.
    - Send the ClientHello message using the client's send message function and check for sending errors.
    - Append the ClientHello message to the transcript hash.
    - Update the handshake state to wait for the ServerHello response.
- **Output**: Returns 0 on success, or a negative TLS alert number on failure.
- **Functions called**:
    - [`fd_tls_alert`](#fd_tls_alert)
    - [`fd_tls_rand`](fd_tls.h.driver.md#fd_tls_rand)
    - [`fd_tls_encode_client_hello`](fd_tls_proto.c.driver.md#fd_tls_encode_client_hello)
    - [`fd_uint_to_tls_u24`](fd_tls_proto.h.driver.md#fd_uint_to_tls_u24)


---
### fd\_tls\_client\_hs\_wait\_sh<!-- {{#callable:fd_tls_client_hs_wait_sh}} -->
The `fd_tls_client_hs_wait_sh` function processes a ServerHello message during a TLS handshake, derives cryptographic secrets, and updates the handshake state.
- **Inputs**:
    - `client`: A constant pointer to an `fd_tls_t` structure representing the client.
    - `handshake`: A pointer to an `fd_tls_estate_cli_t` structure representing the client's handshake state.
    - `record`: A constant pointer to an unsigned char array containing the TLS record data.
    - `record_sz`: An unsigned long representing the size of the TLS record data.
    - `encryption_level`: An unsigned integer representing the encryption level of the message.
- **Control Flow**:
    - Check if the encryption level is `FD_TLS_LEVEL_INITIAL`; if not, return an internal error alert.
    - Initialize a `fd_tls_server_hello_t` structure to store the decoded ServerHello message.
    - Decode the message header and check if it is a ServerHello message; if not, return an unexpected message alert.
    - Decode the ServerHello message and update the read size.
    - Append the ServerHello message to the transcript hash.
    - Derive the handshake secrets using the ECDH key exchange and the transcript hash.
    - Call the client's `secrets_fn` callback with the derived handshake secrets.
    - Derive the master secret using the handshake secret and a predefined empty hash.
    - Update the handshake state to `FD_TLS_HS_WAIT_EE`.
- **Output**: Returns a long integer representing the number of bytes read from the record, or a negative value indicating an error alert.
- **Functions called**:
    - [`fd_tls_alert`](#fd_tls_alert)
    - [`fd_tls_decode_server_hello`](fd_tls_proto.c.driver.md#fd_tls_decode_server_hello)
    - [`fd_tls_hkdf_expand_label`](#fd_tls_hkdf_expand_label)


---
### fd\_tls\_client\_hs\_wait\_ee<!-- {{#callable:fd_tls_client_hs_wait_ee}} -->
The `fd_tls_client_hs_wait_ee` function processes the EncryptedExtensions message during a TLS handshake, verifying encryption level, decoding the message, updating the transcript hash, and handling certificate and QUIC parameters.
- **Inputs**:
    - `client`: A constant pointer to an `fd_tls_t` structure representing the TLS client.
    - `handshake`: A pointer to an `fd_tls_estate_cli_t` structure representing the client's handshake state.
    - `record`: A constant pointer to an unsigned character array containing the TLS record data.
    - `record_sz`: An unsigned long representing the size of the TLS record data.
    - `encryption_level`: An unsigned integer representing the encryption level of the message.
- **Control Flow**:
    - Check if the encryption level is `FD_TLS_LEVEL_HANDSHAKE`; if not, return an internal error alert.
    - Initialize an `fd_tls_enc_ext_t` structure to store the decoded EncryptedExtensions message.
    - Decode the message header and verify it is of type `FD_TLS_MSG_ENCRYPTED_EXT`; if not, return an unexpected message alert.
    - Decode the EncryptedExtensions message and update the `wire` pointer; if decoding fails, return a decode error alert.
    - Append the EncryptedExtensions message to the transcript hash using `fd_sha256_append`.
    - Check the server certificate type and update the handshake state accordingly; return an unsupported certificate alert if the type is invalid.
    - Check the client certificate type and update the handshake state accordingly; return an unsupported certificate alert if the type is invalid.
    - If in QUIC mode, verify the presence of QUIC transport parameters; if missing, return a missing extension alert.
    - Verify the ALPN extension if the client has specified ALPN; if missing or mismatched, return a handshake failure alert.
    - Check if the server requested an X.509 client certificate but only a raw public key is available; if so, return an unsupported certificate alert.
    - Update the handshake state to `FD_TLS_HS_WAIT_CERT_CR` and return the size of the read data.
- **Output**: Returns a long integer representing the size of the read data or a negative value indicating a TLS alert error.
- **Functions called**:
    - [`fd_tls_alert`](#fd_tls_alert)
    - [`fd_tls_decode_enc_ext`](fd_tls_proto.c.driver.md#fd_tls_decode_enc_ext)


---
### fd\_tls\_client\_handle\_cert\_req<!-- {{#callable:fd_tls_client_handle_cert_req}} -->
The `fd_tls_client_handle_cert_req` function processes a certificate request during a TLS handshake by setting the client's certificate status and updating the handshake state.
- **Inputs**:
    - `handshake`: A pointer to a `fd_tls_estate_cli_t` structure representing the client's handshake state.
    - `req`: A constant pointer to an unsigned character array representing the certificate request data.
    - `req_sz`: An unsigned long integer representing the size of the certificate request data.
- **Control Flow**:
    - The function begins by ignoring the content of the certificate request, as indicated by the comment and the use of `(void)req;` to suppress unused variable warnings.
    - It sets the `client_cert` field of the `handshake` structure to 1, indicating that a client certificate is expected or required.
    - The function updates the `state` field of the `handshake->base` structure to `FD_TLS_HS_WAIT_CERT`, indicating that the handshake is now waiting for a certificate.
    - Finally, the function returns the size of the certificate request (`req_sz`) cast to a `long`.
- **Output**: The function returns the size of the certificate request (`req_sz`) as a `long`.


---
### fd\_tls\_client\_handle\_cert\_chain<!-- {{#callable:fd_tls_client_handle_cert_chain}} -->
The `fd_tls_client_handle_cert_chain` function processes a certificate chain during a TLS handshake, verifying or updating the public key based on whether public key pinning is enabled.
- **Inputs**:
    - `hs`: A pointer to the client's handshake state structure (`fd_tls_estate_cli_t`).
    - `cert_chain`: A pointer to the certificate chain data to be processed.
    - `cert_chain_sz`: The size of the certificate chain data in bytes.
- **Control Flow**:
    - Determine if public key pinning is enabled by checking `hs->server_pubkey_pin`.
    - If pinning is enabled, set `expected_pubkey` to `hs->server_pubkey`; otherwise, set `out_pubkey` to `hs->server_pubkey`.
    - Call [`fd_tls_handle_cert_chain`](#fd_tls_handle_cert_chain) with the appropriate parameters to process the certificate chain.
- **Output**: Returns a long integer indicating the result of processing the certificate chain, which is typically the size of the certificate chain if successful, or a negative value indicating an error.
- **Functions called**:
    - [`fd_tls_handle_cert_chain`](#fd_tls_handle_cert_chain)


---
### fd\_tls\_client\_hs\_wait\_cert\_cr<!-- {{#callable:fd_tls_client_hs_wait_cert_cr}} -->
The function `fd_tls_client_hs_wait_cert_cr` processes a TLS handshake message to handle either a CertificateRequest or a Certificate message, updating the handshake state accordingly.
- **Inputs**:
    - `client`: A constant pointer to a `fd_tls_t` structure representing the TLS client.
    - `handshake`: A pointer to a `fd_tls_estate_cli_t` structure representing the client's handshake state.
    - `record`: A constant pointer to an unsigned character array containing the TLS record data to be processed.
    - `record_sz`: An unsigned long representing the size of the TLS record data.
    - `encryption_level`: An unsigned integer indicating the encryption level of the message.
- **Control Flow**:
    - The function first checks if the encryption level is `FD_TLS_LEVEL_HANDSHAKE`; if not, it returns an internal error alert.
    - It initializes variables for the next state and the size of data read.
    - A loop is used to process the TLS record, starting by decoding the message header using `fd_tls_decode_msg_hdr`.
    - If decoding fails, it returns a decode error alert.
    - The message size is extracted and checked against the remaining data size; if invalid, it returns a decode error alert.
    - Depending on the message type (`FD_TLS_MSG_CERT_REQ` or `FD_TLS_MSG_CERT`), it calls the appropriate handler function ([`fd_tls_client_handle_cert_req`](#fd_tls_client_handle_cert_req) or [`fd_tls_client_handle_cert_chain`](#fd_tls_client_handle_cert_chain)) and sets the next state accordingly.
    - If the handler function returns an error, it returns an alert with the appropriate error code.
    - The read size is updated based on the processed data.
    - The function appends the processed record data to the handshake transcript using `fd_sha256_append`.
    - Finally, it updates the handshake state to the next state and returns the size of the data read.
- **Output**: The function returns a long integer representing the size of the data read from the record, or a negative value indicating an error alert.
- **Functions called**:
    - [`fd_tls_alert`](#fd_tls_alert)
    - [`fd_tls_u24_to_uint`](fd_tls_proto.h.driver.md#fd_tls_u24_to_uint)
    - [`fd_tls_client_handle_cert_req`](#fd_tls_client_handle_cert_req)
    - [`fd_tls_client_handle_cert_chain`](#fd_tls_client_handle_cert_chain)


---
### fd\_tls\_client\_hs\_wait\_cert<!-- {{#callable:fd_tls_client_hs_wait_cert}} -->
The `fd_tls_client_hs_wait_cert` function processes a TLS handshake certificate message, verifies its structure, and updates the handshake state accordingly.
- **Inputs**:
    - `client`: A constant pointer to an `fd_tls_t` structure representing the TLS client.
    - `handshake`: A pointer to an `fd_tls_estate_cli_t` structure representing the client's handshake state.
    - `record`: A constant pointer to an unsigned character array containing the TLS record data.
    - `record_sz`: An unsigned long representing the size of the TLS record data.
    - `encryption_level`: An unsigned integer indicating the encryption level of the message.
- **Control Flow**:
    - The function first checks if the encryption level is `FD_TLS_LEVEL_HANDSHAKE`; if not, it returns an internal error alert.
    - It initializes a loop to process the certificate message, starting by setting pointers to the beginning and end of the record data.
    - The message header is decoded using `fd_tls_decode_msg_hdr`, and if decoding fails, a decode error alert is returned.
    - The function checks if the message type is `FD_TLS_MSG_CERT`; if not, an unexpected message alert is returned.
    - The message size is extracted and verified to ensure it does not exceed the remaining data size; otherwise, a decode error alert is returned.
    - The certificate chain is processed using [`fd_tls_client_handle_cert_chain`](#fd_tls_client_handle_cert_chain), and if processing fails, an alert with the specific error is returned.
    - The read size is calculated as the difference between the current and initial wire pointers.
    - The record data is appended to the handshake transcript using `fd_sha256_append`.
    - The handshake state is updated to `FD_TLS_HS_WAIT_CV`.
- **Output**: The function returns a long integer representing the number of bytes read from the record, or a negative value indicating an alert error.
- **Functions called**:
    - [`fd_tls_alert`](#fd_tls_alert)
    - [`fd_tls_u24_to_uint`](fd_tls_proto.h.driver.md#fd_tls_u24_to_uint)
    - [`fd_tls_client_handle_cert_chain`](#fd_tls_client_handle_cert_chain)


---
### fd\_tls\_client\_hs\_wait\_cert\_verify<!-- {{#callable:fd_tls_client_hs_wait_cert_verify}} -->
The `fd_tls_client_hs_wait_cert_verify` function processes the server's CertificateVerify message during a TLS handshake, verifying the signature and updating the handshake state.
- **Inputs**:
    - `client`: A constant pointer to the TLS client object, which is not used in this function.
    - `hs`: A pointer to the client's handshake state object, which maintains the current state and transcript of the handshake.
    - `record`: A pointer to the buffer containing the incoming CertificateVerify message from the server.
    - `record_sz`: The size of the incoming CertificateVerify message in bytes.
    - `encryption_level`: The current encryption level of the handshake, expected to be FD_TLS_LEVEL_HANDSHAKE.
- **Control Flow**:
    - The function first checks if the encryption level is FD_TLS_LEVEL_HANDSHAKE; if not, it returns an internal error alert.
    - It calls [`fd_tls_handle_cert_verify`](#fd_tls_handle_cert_verify) to decode and verify the CertificateVerify message using the server's public key.
    - If the verification fails, the function returns the error code from [`fd_tls_handle_cert_verify`](#fd_tls_handle_cert_verify).
    - If successful, it appends the verified message to the handshake transcript.
    - Finally, it updates the handshake state to FD_TLS_HS_WAIT_FINISHED and returns the result of the verification.
- **Output**: The function returns a long integer, which is the result of the CertificateVerify message processing, or a negative value indicating an error or alert.
- **Functions called**:
    - [`fd_tls_alert`](#fd_tls_alert)
    - [`fd_tls_handle_cert_verify`](#fd_tls_handle_cert_verify)


---
### fd\_tls\_client\_hs\_wait\_finished<!-- {{#callable:fd_tls_client_hs_wait_finished}} -->
The `fd_tls_client_hs_wait_finished` function processes the 'Finished' message from the server during a TLS handshake, verifies the message, and derives application secrets for secure communication.
- **Inputs**:
    - `client`: A pointer to the `fd_tls_t` structure representing the TLS client.
    - `hs`: A pointer to the `fd_tls_estate_cli_t` structure representing the client's handshake state.
    - `record`: A pointer to the buffer containing the TLS record data to be processed.
    - `record_sz`: The size of the TLS record data in bytes.
    - `encryption_level`: The encryption level of the incoming message, expected to be `FD_TLS_LEVEL_HANDSHAKE`.
- **Control Flow**:
    - Check if the encryption level is `FD_TLS_LEVEL_HANDSHAKE`; if not, return an internal error alert.
    - Export the transcript hash from the ClientHello to CertificateVerify messages.
    - Derive the 'Finished' key using the server handshake secret and the label 'finished'.
    - Compute the expected 'Finished' verify data using HMAC-SHA256 with the transcript hash and the derived 'Finished' key.
    - Decode the incoming 'Finished' message from the server and verify its type.
    - Record the 'Finished' message in the transcript hash.
    - Compare the server's 'Finished' verify data with the expected data; if they do not match, return a decrypt error alert.
    - Derive the client and server application secrets using the master secret and the transcript hash.
    - Invoke the client's `secrets_fn` callback with the derived application secrets.
    - If a client certificate is required, send the client certificate and CertificateVerify messages, updating the transcript hash accordingly.
    - Send the client's 'Finished' message, updating the transcript hash, and set the handshake state to `FD_TLS_HS_CONNECTED`.
- **Output**: Returns the number of bytes read from the record if successful, or a negative value indicating a TLS alert code on failure.
- **Functions called**:
    - [`fd_tls_alert`](#fd_tls_alert)
    - [`fd_tls_hkdf_expand_label`](#fd_tls_hkdf_expand_label)
    - [`fd_tls_encode_raw_public_key`](fd_tls_proto.c.driver.md#fd_tls_encode_raw_public_key)
    - [`fd_tls_encode_cert_x509`](fd_tls_proto.c.driver.md#fd_tls_encode_cert_x509)
    - [`fd_tls_send_cert_verify`](#fd_tls_send_cert_verify)
    - [`fd_uint_to_tls_u24`](fd_tls_proto.h.driver.md#fd_uint_to_tls_u24)
    - [`fd_tls_msg_hdr_bswap`](fd_tls_proto.h.driver.md#fd_tls_msg_hdr_bswap)


---
### fd\_tls\_alert\_cstr<!-- {{#callable:fd_tls_alert_cstr}} -->
The `fd_tls_alert_cstr` function returns a string representation of a TLS alert code.
- **Inputs**:
    - `alert`: An unsigned integer representing a TLS alert code.
- **Control Flow**:
    - The function uses a switch statement to match the input alert code against predefined constants representing various TLS alert codes.
    - For each case in the switch statement, a corresponding string message is returned that describes the alert.
    - If the alert code does not match any predefined case, a warning is logged, and the function returns the string "unknown alert".
- **Output**: A constant character pointer to a string describing the TLS alert.


---
### fd\_tls\_reason\_cstr<!-- {{#callable:fd_tls_reason_cstr}} -->
The `fd_tls_reason_cstr` function returns a human-readable string describing a TLS error reason code.
- **Inputs**:
    - `reason`: An unsigned integer representing a specific TLS error reason code.
- **Control Flow**:
    - The function uses a switch statement to match the input `reason` with predefined TLS error reason codes.
    - For each case, it returns a corresponding descriptive string explaining the error.
    - If the `reason` does not match any predefined case, it logs a warning and falls through to return 'unknown reason'.
- **Output**: A constant character pointer to a string describing the TLS error reason.


# Function Declarations (Public API)

---
### fd\_tls\_server\_hs\_start<!-- {{#callable_declaration:fd_tls_server_hs_start}} -->
Initiates the server-side TLS handshake process.
- **Description**: This function is used to start the server-side TLS handshake process in response to an initial ClientHello message. It should be called when a server receives a ClientHello record from a client. The function handles the cryptographic negotiation, including verifying client capabilities and preferences, and responds with the necessary handshake messages such as ServerHello, EncryptedExtensions, and Finished. It requires the encryption level to be set to FD_TLS_LEVEL_INITIAL and expects the server and handshake structures to be properly initialized. The function returns a negative value if an error occurs, indicating a specific TLS alert.
- **Inputs**:
    - `server`: A pointer to a constant fd_tls_t structure representing the server. Must not be null and should be properly initialized before calling this function.
    - `handshake`: A pointer to an fd_tls_estate_srv_t structure representing the handshake state. Must not be null and should be initialized to represent the start of a handshake.
    - `record`: A pointer to a buffer containing the ClientHello message. Must not be null and should contain a valid ClientHello message.
    - `record_sz`: The size of the record buffer in bytes. Must be a positive value representing the size of the ClientHello message.
    - `encryption_level`: An unsigned integer representing the encryption level. Must be set to FD_TLS_LEVEL_INITIAL for the initial handshake message.
- **Output**: Returns the number of bytes read from the record on success, or a negative value indicating a TLS alert on failure.
- **See also**: [`fd_tls_server_hs_start`](#fd_tls_server_hs_start)  (Implementation)


---
### fd\_tls\_server\_hs\_wait\_finished<!-- {{#callable_declaration:fd_tls_server_hs_wait_finished}} -->
Waits for and processes a client's Finished message during a TLS handshake.
- **Description**: This function is used during a TLS handshake to wait for and process the client's Finished message. It should be called when the server is in the FD_TLS_HS_WAIT_FINISHED state and expects a Finished message from the client. The function verifies the Finished message using the handshake's transcript and updates the handshake state to FD_TLS_HS_CONNECTED upon successful verification. It requires the encryption level to be FD_TLS_LEVEL_HANDSHAKE and will return an error if this condition is not met.
- **Inputs**:
    - `server`: A pointer to a constant fd_tls_t structure representing the server. This parameter is not used in the function.
    - `handshake`: A pointer to an fd_tls_estate_srv_t structure representing the server's handshake state. Must not be null and should be properly initialized.
    - `record`: A pointer to a buffer containing the client's Finished message. Must not be null and should point to a valid memory region of at least record_sz bytes.
    - `record_sz`: The size of the record buffer in bytes. Must accurately reflect the size of the client's Finished message.
    - `encryption_level`: An unsigned integer representing the encryption level. Must be FD_TLS_LEVEL_HANDSHAKE; otherwise, the function returns an error.
- **Output**: Returns the number of bytes read from the record buffer on success, or a negative value indicating a TLS alert code on failure.
- **See also**: [`fd_tls_server_hs_wait_finished`](#fd_tls_server_hs_wait_finished)  (Implementation)


---
### fd\_tls\_client\_hs\_start<!-- {{#callable_declaration:fd_tls_client_hs_start}} -->
Initiates a TLS client handshake process.
- **Description**: This function is used to start the TLS handshake process for a client, preparing and sending the initial ClientHello message. It should be called when a client is ready to initiate a secure connection. The function requires a valid client configuration and a handshake state object. It handles the generation of necessary cryptographic parameters and manages the handshake state transitions. The function must be called with valid, non-null pointers to the client and handshake objects, and it assumes that the client has been properly initialized with necessary cryptographic keys and parameters.
- **Inputs**:
    - `client`: A pointer to a constant fd_tls_t structure representing the client configuration. Must not be null and should be properly initialized with necessary cryptographic parameters.
    - `handshake`: A pointer to an fd_tls_estate_cli_t structure representing the handshake state. Must not be null and should be initialized to represent the start of a handshake process.
- **Output**: Returns 0 on success, or a negative value indicating a specific TLS alert code on failure.
- **See also**: [`fd_tls_client_hs_start`](#fd_tls_client_hs_start)  (Implementation)


---
### fd\_tls\_client\_hs\_wait\_sh<!-- {{#callable_declaration:fd_tls_client_hs_wait_sh}} -->
Processes a TLS ServerHello message during a client handshake.
- **Description**: This function is used during a TLS client handshake to process an incoming ServerHello message. It should be called when the client is in the FD_TLS_HS_WAIT_SH state and receives a ServerHello message at the initial encryption level. The function validates the encryption level, decodes the ServerHello message, updates the handshake transcript, and derives handshake secrets. It also invokes a callback with the derived secrets. The function transitions the handshake state to FD_TLS_HS_WAIT_EE upon successful processing. It is crucial to ensure that the encryption level is FD_TLS_LEVEL_INITIAL before calling this function.
- **Inputs**:
    - `client`: A pointer to a constant fd_tls_t structure representing the TLS client. The caller retains ownership and it must not be null.
    - `handshake`: A pointer to an fd_tls_estate_cli_t structure representing the client's handshake state. The caller retains ownership and it must not be null.
    - `record`: A pointer to a buffer containing the ServerHello message. The buffer must not be null and should contain a valid ServerHello message.
    - `record_sz`: The size of the record buffer in bytes. It must accurately reflect the size of the ServerHello message in the buffer.
    - `encryption_level`: An unsigned integer representing the encryption level. It must be FD_TLS_LEVEL_INITIAL; otherwise, the function returns an error.
- **Output**: Returns the number of bytes read from the record buffer as a long integer. If an error occurs, a negative value representing a TLS alert is returned.
- **See also**: [`fd_tls_client_hs_wait_sh`](#fd_tls_client_hs_wait_sh)  (Implementation)


---
### fd\_tls\_client\_hs\_wait\_ee<!-- {{#callable_declaration:fd_tls_client_hs_wait_ee}} -->
Processes the EncryptedExtensions message during a TLS handshake.
- **Description**: This function is used during a TLS handshake to process the EncryptedExtensions message received from the server. It should be called when the client is in the FD_TLS_HS_WAIT_EE state and the encryption level is FD_TLS_LEVEL_HANDSHAKE. The function validates the message type, updates the handshake transcript, and checks for QUIC transport parameters and ALPN protocol negotiation if applicable. It also handles certificate type negotiation and updates the handshake state accordingly. The function returns a negative value on error, indicating a TLS alert, or the number of bytes read on success.
- **Inputs**:
    - `client`: A pointer to a constant fd_tls_t structure representing the client. Must not be null.
    - `handshake`: A pointer to an fd_tls_estate_cli_t structure representing the client's handshake state. Must not be null.
    - `record`: A pointer to a buffer containing the TLS record data. Must not be null.
    - `record_sz`: The size of the record buffer in bytes. Must be a valid size for the provided buffer.
    - `encryption_level`: The encryption level of the message. Must be FD_TLS_LEVEL_HANDSHAKE; otherwise, the function returns an error.
- **Output**: Returns the number of bytes read from the record on success, or a negative value indicating a TLS alert on error.
- **See also**: [`fd_tls_client_hs_wait_ee`](#fd_tls_client_hs_wait_ee)  (Implementation)


---
### fd\_tls\_client\_hs\_wait\_cert\_cr<!-- {{#callable_declaration:fd_tls_client_hs_wait_cert_cr}} -->
Processes a TLS handshake message for a client, handling certificate requests and certificates.
- **Description**: This function is used during a TLS handshake to process incoming messages related to certificate requests and certificates for a client. It should be called when the client is in the FD_TLS_HS_WAIT_CERT_CR state and receives a message at the handshake encryption level. The function updates the handshake state based on the type of message received, either a CertificateRequest or a Certificate, and appends the processed message to the handshake transcript. It is crucial to ensure that the encryption level is set to FD_TLS_LEVEL_HANDSHAKE before calling this function, as incorrect levels will result in an internal error alert.
- **Inputs**:
    - `client`: A pointer to a constant fd_tls_t structure representing the client. The function does not modify this structure.
    - `handshake`: A pointer to an fd_tls_estate_cli_t structure representing the client's handshake state. This parameter must not be null, and the function updates its state based on the message processed.
    - `record`: A pointer to a buffer containing the TLS record to be processed. This buffer must not be null and should contain a valid TLS message.
    - `record_sz`: The size of the record buffer in bytes. It must accurately reflect the size of the data in the record buffer.
    - `encryption_level`: An unsigned integer representing the encryption level of the message. It must be FD_TLS_LEVEL_HANDSHAKE; otherwise, the function will return an internal error alert.
- **Output**: Returns the number of bytes read from the record on success, or a negative value indicating a TLS alert on failure.
- **See also**: [`fd_tls_client_hs_wait_cert_cr`](#fd_tls_client_hs_wait_cert_cr)  (Implementation)


---
### fd\_tls\_client\_hs\_wait\_cert<!-- {{#callable_declaration:fd_tls_client_hs_wait_cert}} -->
Processes a TLS handshake certificate message for a client.
- **Description**: This function is used during a TLS handshake to process a certificate message received by a client. It should be called when the client is in the handshake state expecting a certificate message. The function checks the encryption level and processes the certificate message, updating the handshake state and transcript hash accordingly. It is important to ensure that the encryption level is set to FD_TLS_LEVEL_HANDSHAKE before calling this function.
- **Inputs**:
    - `client`: A pointer to a constant fd_tls_t structure representing the client. The pointer must not be null, but the function does not use this parameter.
    - `handshake`: A pointer to an fd_tls_estate_cli_t structure representing the client's handshake state. This parameter must not be null and is updated by the function.
    - `record`: A pointer to a buffer containing the TLS record data. This parameter must not be null and should point to a valid memory region of size at least record_sz.
    - `record_sz`: The size of the record buffer in bytes. It must be a non-zero value representing the actual size of the data in the record buffer.
    - `encryption_level`: An unsigned integer representing the encryption level of the message. It must be set to FD_TLS_LEVEL_HANDSHAKE; otherwise, the function will return an error.
- **Output**: Returns the number of bytes read from the record on success, or a negative value indicating a TLS alert code on failure.
- **See also**: [`fd_tls_client_hs_wait_cert`](#fd_tls_client_hs_wait_cert)  (Implementation)


---
### fd\_tls\_client\_hs\_wait\_cert\_verify<!-- {{#callable_declaration:fd_tls_client_hs_wait_cert_verify}} -->
Processes a server CertificateVerify message during a TLS handshake.
- **Description**: This function is used during a TLS handshake to process an incoming server CertificateVerify message. It should be called when the client is in the FD_TLS_HS_WAIT_CV state and expects a CertificateVerify message from the server. The function verifies the message using the server's public key and updates the handshake state to FD_TLS_HS_WAIT_FINISHED upon successful verification. It requires the encryption level to be FD_TLS_LEVEL_HANDSHAKE and will return an error if this condition is not met.
- **Inputs**:
    - `client`: A pointer to a constant fd_tls_t structure representing the client. The function does not modify this structure.
    - `hs`: A pointer to an fd_tls_estate_cli_t structure representing the client's handshake state. This structure is updated by the function.
    - `record`: A pointer to a buffer containing the CertificateVerify message to be processed. The buffer must not be null.
    - `record_sz`: The size of the record buffer in bytes. Must be a valid size for the CertificateVerify message.
    - `encryption_level`: An unsigned integer representing the encryption level. Must be FD_TLS_LEVEL_HANDSHAKE; otherwise, the function returns an error.
- **Output**: Returns a long integer indicating the number of bytes processed from the record on success, or a negative value representing a TLS alert number on failure.
- **See also**: [`fd_tls_client_hs_wait_cert_verify`](#fd_tls_client_hs_wait_cert_verify)  (Implementation)


---
### fd\_tls\_client\_hs\_wait\_finished<!-- {{#callable_declaration:fd_tls_client_hs_wait_finished}} -->
Waits for and processes the server's Finished message during a TLS handshake.
- **Description**: This function is used during a TLS client's handshake process to wait for and verify the server's Finished message. It should be called when the client is in the FD_TLS_HS_WAIT_FINISHED state and expects a Finished message from the server. The function verifies the server's Finished message against the expected transcript hash and derives application secrets if the verification is successful. It requires the encryption level to be FD_TLS_LEVEL_HANDSHAKE and will return an error if this condition is not met. The function also handles sending the client's Certificate and CertificateVerify messages if required.
- **Inputs**:
    - `client`: A pointer to a constant fd_tls_t structure representing the TLS client. The caller retains ownership and it must not be null.
    - `hs`: A pointer to an fd_tls_estate_cli_t structure representing the client's handshake state. The caller retains ownership and it must not be null.
    - `record`: A pointer to a constant uchar array containing the server's Finished message. The caller retains ownership and it must not be null.
    - `record_sz`: An unsigned long representing the size of the record array. It must accurately reflect the size of the data in the record.
    - `encryption_level`: An unsigned integer representing the encryption level. It must be FD_TLS_LEVEL_HANDSHAKE; otherwise, the function will return an error.
- **Output**: Returns a long indicating the number of bytes read from the record on success, or a negative value representing a TLS alert code on failure.
- **See also**: [`fd_tls_client_hs_wait_finished`](#fd_tls_client_hs_wait_finished)  (Implementation)


